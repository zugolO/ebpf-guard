// Package collector provides eBPF event collection for DNS monitoring.
package collector

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/zugolO/ebpf-guard/internal/bpf"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// DNSCollector collects DNS events via eBPF tracepoints.
type DNSCollector struct {
	objs       *bpf.DNSObjects
	links      []link.Link
	reader     *ringbuf.Reader
	metrics    *dnsMetrics
	enabled    bool
	dropLogger *dropLogger
	strategy   BackpressureStrategy
	lostTotal  atomic.Uint64
}

// dnsMetrics holds Prometheus metrics for DNS collection.
type dnsMetrics struct {
	queriesTotal  *prometheus.CounterVec
	eventsDropped prometheus.Counter
}

// NewDNSCollector creates a new DNS collector.
func NewDNSCollector(enabled bool) (*DNSCollector, error) {
	if !enabled {
		return &DNSCollector{enabled: false, dropLogger: newDropLogger(5 * time.Second)}, nil
	}

	// Remove memory limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("dns: remove memlock: %w", err)
	}

	metrics := &dnsMetrics{
		queriesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ebpf_guard_dns_queries_total",
			Help: "Total number of DNS queries by QTYPE and RCODE",
		}, []string{"qtype", "rcode"}),
		eventsDropped: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ebpf_guard_dns_events_dropped_total",
			Help: "Total number of dropped DNS events due to ring buffer overflow",
		}),
	}

	return &DNSCollector{
		enabled:    enabled,
		metrics:    metrics,
		dropLogger: newDropLogger(5 * time.Second),
		strategy:   StrategyDrop,
	}, nil
}

// WithBackpressureStrategy sets the backpressure strategy for the event channel.
func (c *DNSCollector) WithBackpressureStrategy(s BackpressureStrategy) *DNSCollector {
	c.strategy = s
	return c
}

// RegisterMetrics registers Prometheus metrics.
func (c *DNSCollector) RegisterMetrics(reg prometheus.Registerer) error {
	if !c.enabled || c.metrics == nil {
		return nil
	}
	if err := reg.Register(c.metrics.queriesTotal); err != nil {
		return err
	}
	return reg.Register(c.metrics.eventsDropped)
}

// Start begins collecting DNS events.
func (c *DNSCollector) Start(ctx context.Context, out chan<- types.Event) error {
	if !c.enabled {
		slog.Info("dns: collector disabled, skipping")
		return nil
	}

	slog.Info("dns: starting collector")

	objs := &bpf.DNSObjects{}
	if err := bpf.LoadDNSObjects(objs, nil); err != nil {
		// The default Error() string only includes the last line or two of
		// the verifier log. %+v with no width prints every line the kernel
		// returned, which is what we need to see what's actually pushing
		// trace_sendmsg past the instruction limit.
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			if werr := os.WriteFile("/tmp/dns_verifier.log", []byte(fmt.Sprintf("%+v", verr)), 0644); werr != nil {
				slog.Error("dns: failed to write verifier log", slog.Any("error", werr))
			} else {
				slog.Error("dns: wrote full verifier log to /tmp/dns_verifier.log")
			}
		}
		return fmt.Errorf("dns: load objects: %w", err)
	}
	c.objs = objs

	links, err := c.attachTracepoints()
	if err != nil {
		c.objs.Close()
		return fmt.Errorf("dns: attach tracepoints: %w", err)
	}
	c.links = links

	reader, err := ringbuf.NewReader(c.objs.DnsEvents)
	if err != nil {
		c.Close()
		return fmt.Errorf("dns: create ringbuf reader: %w", err)
	}
	c.reader = reader

	go c.readLoop(ctx, out)

	<-ctx.Done()
	return nil
}

// attachTracepoints attaches eBPF programs to tracepoints.
func (c *DNSCollector) attachTracepoints() ([]link.Link, error) {
	var links []link.Link

	// Attach to sys_enter_sendmsg
	l1, err := link.Tracepoint("syscalls", "sys_enter_sendmsg", c.objs.TraceSendmsg, nil)
	if err != nil {
		return nil, fmt.Errorf("attach sendmsg tracepoint: %w", err)
	}
	links = append(links, l1)

	// Attach to sys_enter_sendto
	l2, err := link.Tracepoint("syscalls", "sys_enter_sendto", c.objs.TraceSendto, nil)
	if err != nil {
		return nil, fmt.Errorf("attach sendto tracepoint: %w", err)
	}
	links = append(links, l2)

	return links, nil
}

// readLoop reads events from the ring buffer.
func (c *DNSCollector) readLoop(ctx context.Context, out chan<- types.Event) {
	if c.reader == nil {
		slog.Warn("dns: no ring buffer reader, read loop exiting")
		return
	}

	defer c.reader.Close()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		record, err := c.reader.Read()
		if err != nil {
			if err == ringbuf.ErrClosed {
				return
			}
			slog.Error("dns: read from ringbuf", slog.Any("error", err))
			continue
		}
		event := c.parseEvent(record.RawSample)
		if event == nil {
			continue
		}

		// Update metrics
		c.metrics.queriesTotal.WithLabelValues(
			qtypeToString(event.DNS.QType),
			rcodeToString(event.DNS.RCode),
		).Inc()

		sendEvent(ctx, out, *event, c.strategy, func() {
			c.metrics.eventsDropped.Inc()
			c.dropLogger.record(slog.Default(), "dns")
			c.lostTotal.Add(1)
		})
	}
}

// LostEvents returns the total number of events lost in the BPF ring buffer
// since the collector started. Implements watchdog.DropTracker.
func (c *DNSCollector) LostEvents() uint64 {
	return c.lostTotal.Load()
}

// parseEvent parses a raw ring buffer record into a types.Event.
func (c *DNSCollector) parseEvent(raw []byte) *types.Event {
	// 4+8+4+4+4+16+128+32(pad)+2+2+1+1+1 = 207 bytes minimum (no response IPs)
	if len(raw) < 207 {
		return nil
	}

	// Parse dns_event structure from BPF
	// Layout matches struct dns_event in dns.bpf.c
	offset := 0

	// type (4 bytes)
	eventType := binary.LittleEndian.Uint32(raw[offset:])
	offset += 4

	if eventType != uint32(types.EventDNS) {
		return nil
	}

	// timestamp (8 bytes)
	timestamp := binary.LittleEndian.Uint64(raw[offset:])
	offset += 8

	// pid (4 bytes)
	pid := binary.LittleEndian.Uint32(raw[offset:])
	offset += 4

	// tgid (4 bytes)
	tgid := binary.LittleEndian.Uint32(raw[offset:])
	offset += 4

	// uid (4 bytes)
	uid := binary.LittleEndian.Uint32(raw[offset:])
	offset += 4

	// comm (16 bytes)
	var comm [16]byte
	copy(comm[:], raw[offset:])
	offset += 16

	// qname (128 bytes)
	qnameLen := 0
	for i := 0; i < 128 && raw[offset+i] != 0; i++ {
		qnameLen++
	}
	qname := string(raw[offset : offset+qnameLen])
	offset += 128

	// _qname_overflow_guard (32 bytes) - verifier headroom padding, not data
	offset += 32

	// qtype (2 bytes)
	qtype := binary.LittleEndian.Uint16(raw[offset:])
	offset += 2

	// rcode (2 bytes)
	rcode := binary.LittleEndian.Uint16(raw[offset:])
	offset += 2

	// direction (1 byte)
	direction := types.DNSDirection(raw[offset])
	offset += 1

	// qname_len (1 byte) - skip, we calculated it
	offset += 1

	// response_count (1 byte)
	responseCount := raw[offset]
	offset += 1

	// Parse response IPs — stored in network byte order (big-endian) by BPF.
	var responseIPs []string
	for i := 0; i < int(responseCount) && i < 8; i++ {
		if offset+4 <= len(raw) {
			ip := binary.BigEndian.Uint32(raw[offset:])
			responseIPs = append(responseIPs, intToIPv4(ip))
			offset += 4
		}
	}

	return &types.Event{
		Type:      types.EventDNS,
		Timestamp: timestamp,
		PID:       pid,
		TGID:      tgid,
		UID:       uid,
		Comm:      comm,
		DNS: &types.DNSEvent{
			QName:       qname,
			QType:       qtype,
			RCode:       rcode,
			Direction:   direction,
			ResponseIPs: responseIPs,
		},
	}
}

// intToIPv4 converts a uint32 IP in network byte order (big-endian, as stored by BPF)
// to dotted-decimal notation.
func intToIPv4(ip uint32) string {
	return net.IPv4(
		byte(ip>>24),
		byte(ip>>16),
		byte(ip>>8),
		byte(ip),
	).String()
}

// qtypeToString converts DNS QTYPE to string.
func qtypeToString(qtype uint16) string {
	switch qtype {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 6:
		return "SOA"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	case 255:
		return "ANY"
	default:
		return fmt.Sprintf("TYPE%d", qtype)
	}
}

// rcodeToString converts DNS RCODE to string.
func rcodeToString(rcode uint16) string {
	switch rcode {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE%d", rcode)
	}
}

// Name returns the collector name.
func (c *DNSCollector) Name() string {
	return "dns"
}

// Close releases all eBPF resources.
func (c *DNSCollector) Close() error {
	for _, l := range c.links {
		l.Close()
	}
	if c.reader != nil {
		c.reader.Close()
	}
	if c.objs != nil {
		c.objs.Close()
	}
	return nil
}

// Compile-time check that DNSCollector implements Collector interface.
var _ Collector = (*DNSCollector)(nil)
