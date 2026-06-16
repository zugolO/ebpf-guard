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
	"strings"
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

// dnsRawEventFixedLen is the size of struct dns_event in dns.bpf.c up to
// (but not including) the variable-meaningful payload bytes: type(4) +
// timestamp(8) + pid(4) + tgid(4) + uid(4) + comm(16) + direction(1) +
// payload_len(2) = 43. The struct is packed, so there is no padding.
const dnsRawEventFixedLen = 4 + 8 + 4 + 4 + 4 + 16 + 1 + 2

// dnsMaxPayload mirrors DNS_MAX_PAYLOAD in dns.bpf.c — the kernel side
// always reserves this many payload bytes in the ring buffer record,
// truncating longer messages rather than dropping them.
const dnsMaxPayload = 256

// dnsMaxNameJumps bounds compression-pointer chasing in decodeDNSName so a
// crafted or corrupted message can't cause an infinite loop. There is no
// BPF verifier here — this is a plain userspace safety limit.
const dnsMaxNameJumps = 32

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
//
// sendmsg/sendto cover callers that pass an explicit destination address.
// connect/close plus sendmmsg/recvmsg/write/writev/read/recvfrom cover the
// glibc stub resolver pattern (confirmed via strace against real `dig`):
// connect() a UDP socket once, then sendmmsg()/recvmsg() (or plain
// write()/read()) on it with no destination address in the syscall args
// for BPF to filter on (see the dns_socket_map comment in dns.bpf.c).
func (c *DNSCollector) attachTracepoints() ([]link.Link, error) {
	specs := []struct {
		category string
		name     string
		prog     *ebpf.Program
	}{
		{"syscalls", "sys_enter_sendmsg", c.objs.TraceSendmsg},
		{"syscalls", "sys_enter_sendto", c.objs.TraceSendto},
		{"syscalls", "sys_enter_connect", c.objs.TraceConnect},
		{"syscalls", "sys_enter_close", c.objs.TraceClose},
		{"syscalls", "sys_enter_sendmmsg", c.objs.TraceSendmmsg},
		{"syscalls", "sys_enter_write", c.objs.TraceWrite},
		{"syscalls", "sys_enter_writev", c.objs.TraceWritev},
		{"syscalls", "sys_enter_recvmsg", c.objs.TraceRecvmsgEnter},
		{"syscalls", "sys_exit_recvmsg", c.objs.TraceRecvmsgExit},
		{"syscalls", "sys_enter_read", c.objs.TraceReadEnter},
		{"syscalls", "sys_exit_read", c.objs.TraceReadExit},
		{"syscalls", "sys_enter_recvfrom", c.objs.TraceRecvfromEnter},
		{"syscalls", "sys_exit_recvfrom", c.objs.TraceRecvfromExit},
	}

	var links []link.Link
	for _, s := range specs {
		l, err := link.Tracepoint(s.category, s.name, s.prog, nil)
		if err != nil {
			for _, prev := range links {
				prev.Close()
			}
			return nil, fmt.Errorf("attach %s tracepoint: %w", s.name, err)
		}
		links = append(links, l)
	}

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
//
// The BPF side (dns.bpf.c) no longer decodes the DNS wire format — it just
// captures the raw UDP payload, so all QNAME/QTYPE/RCODE/answer parsing,
// including compression-pointer chasing, happens here where there's no
// verifier instruction budget to fight.
func (c *DNSCollector) parseEvent(raw []byte) *types.Event {
	if len(raw) < dnsRawEventFixedLen {
		return nil
	}

	// Parse the fixed dns_event header. Layout matches struct dns_event in
	// dns.bpf.c.
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

	// direction (1 byte)
	direction := types.DNSDirection(raw[offset])
	offset += 1

	// payload_len (2 bytes)
	payloadLen := binary.LittleEndian.Uint16(raw[offset:])
	offset += 2

	if int(payloadLen) > dnsMaxPayload || offset+int(payloadLen) > len(raw) {
		return nil
	}
	payload := raw[offset : offset+int(payloadLen)]

	msg, ok := parseDNSWireMessage(payload)
	if !ok {
		return nil
	}

	return &types.Event{
		Type:      types.EventDNS,
		Timestamp: timestamp,
		PID:       pid,
		TGID:      tgid,
		UID:       uid,
		Comm:      comm,
		DNS: &types.DNSEvent{
			QName:       msg.qname,
			QType:       msg.qtype,
			RCode:       msg.rcode,
			Direction:   direction,
			ResponseIPs: msg.responseIPs,
		},
	}
}

// dnsWireMessage holds the fields the rest of the system cares about,
// decoded from a raw DNS message captured by the BPF side.
type dnsWireMessage struct {
	qname       string
	qtype       uint16
	rcode       uint16
	responseIPs []string
}

// parseDNSWireMessage decodes a raw DNS message (header + question, and
// answer records for responses) per RFC 1035. Unlike the in-kernel decoder
// it replaces, this correctly follows compression pointers in QNAME/answer
// names since there's no verifier-imposed bound on loop complexity here.
func parseDNSWireMessage(payload []byte) (dnsWireMessage, bool) {
	var msg dnsWireMessage

	if len(payload) < 12 {
		return msg, false
	}

	flags := binary.BigEndian.Uint16(payload[2:4])
	isResponse := flags&0x8000 != 0
	msg.rcode = flags & 0x000f

	qdCount := binary.BigEndian.Uint16(payload[4:6])
	anCount := binary.BigEndian.Uint16(payload[6:8])
	if qdCount == 0 {
		return msg, false
	}

	pos := 12
	qname, pos, ok := decodeDNSName(payload, pos)
	if !ok {
		return msg, false
	}
	msg.qname = qname

	if pos+4 > len(payload) {
		// Got the name but not QTYPE/QCLASS; still useful to the caller.
		return msg, true
	}
	msg.qtype = binary.BigEndian.Uint16(payload[pos : pos+2])
	pos += 4 // QTYPE (2) + QCLASS (2)

	if isResponse {
		msg.responseIPs = decodeDNSAnswerIPs(payload, pos, anCount)
	}

	return msg, true
}

// decodeDNSAnswerIPs walks anCount answer records starting at pos and
// returns the A-record (IPv4) addresses found.
func decodeDNSAnswerIPs(payload []byte, pos int, anCount uint16) []string {
	var ips []string

	for i := 0; i < int(anCount); i++ {
		var ok bool
		_, pos, ok = decodeDNSName(payload, pos)
		if !ok {
			break
		}

		// TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) = 10 bytes.
		if pos+10 > len(payload) {
			break
		}
		rtype := binary.BigEndian.Uint16(payload[pos : pos+2])
		rdlen := int(binary.BigEndian.Uint16(payload[pos+8 : pos+10]))
		pos += 10

		if pos+rdlen > len(payload) {
			break
		}
		if rtype == 1 && rdlen == 4 { // A record
			ips = append(ips, net.IPv4(payload[pos], payload[pos+1], payload[pos+2], payload[pos+3]).String())
		}
		pos += rdlen
	}

	return ips
}

// decodeDNSName decodes a (possibly compressed) domain name starting at
// pos in payload, returning the dotted name and the position immediately
// after the name in the *original* stream (i.e. after a compression
// pointer, not after whatever it points to). jumps are capped at
// dnsMaxNameJumps to guarantee termination on malformed input.
func decodeDNSName(payload []byte, pos int) (string, int, bool) {
	var sb strings.Builder
	endPos := -1
	jumps := 0

	for {
		if pos < 0 || pos >= len(payload) {
			return "", 0, false
		}

		b := payload[pos]

		if b == 0 {
			pos++
			if endPos == -1 {
				endPos = pos
			}
			break
		}

		if b&0xC0 == 0xC0 {
			if pos+1 >= len(payload) {
				return "", 0, false
			}
			if endPos == -1 {
				endPos = pos + 2
			}
			jumps++
			if jumps > dnsMaxNameJumps {
				return "", 0, false
			}
			ptr := int(binary.BigEndian.Uint16(payload[pos:pos+2]) & 0x3FFF)
			pos = ptr
			continue
		}

		labelLen := int(b)
		pos++
		if pos+labelLen > len(payload) {
			return "", 0, false
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		sb.Write(payload[pos : pos+labelLen])
		pos += labelLen
	}

	if endPos == -1 {
		endPos = pos
	}
	return sb.String(), endPos, true
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
