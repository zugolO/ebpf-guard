// Package collector provides eBPF event collection for DNS monitoring.
package collector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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

// The DNS wire-format parsing logic (decodeDNSEvent, parseDNSWireMessage,
// decodeDNSName, decodeDNSAnswerIPs and the qtype/rcode string helpers) lives
// in dns_parse.go. It is kernel-independent and unit-tested directly; this file
// holds only the eBPF load/attach/read glue.

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
		event := decodeDNSEvent(record.RawSample)
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
