// Package collector provides eBPF-based event collection from the kernel.
package collector

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/zugolO/ebpf-guard/internal/bpf"
	"github.com/zugolO/ebpf-guard/internal/exporter"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// NetworkCollector collects TCP connection events using eBPF kprobes.
type NetworkCollector struct {
	logger      *slog.Logger
	objs        *bpf.NetworkObjects
	links       []link.Link
	reader      *bpf.RingbufReader
	loadError   error // Tracks if the collector failed to load (stub mode)
	dropLogger  *dropLogger
	status      StatusReporter
	strategy    BackpressureStrategy
	ringBufSize int // 0 = auto-detect
}

// NewNetworkCollector creates a new network event collector.
func NewNetworkCollector(logger *slog.Logger) (*NetworkCollector, error) {
	return &NetworkCollector{
		logger:     logger.With("collector", "network"),
		dropLogger: newDropLogger(5 * time.Second),
		status:     NoopStatusReporter{},
		strategy:   StrategyDrop,
	}, nil
}

// WithStatusReporter sets the StatusReporter used to signal up/down state.
func (c *NetworkCollector) WithStatusReporter(r StatusReporter) *NetworkCollector {
	c.status = r
	return c
}

// WithBackpressureStrategy sets the backpressure strategy for the event channel.
func (c *NetworkCollector) WithBackpressureStrategy(s BackpressureStrategy) *NetworkCollector {
	c.strategy = s
	return c
}

// WithRingBufSize sets the BPF ring buffer size in bytes for this collector.
// Zero (default) auto-detects the size from /proc/meminfo.
func (c *NetworkCollector) WithRingBufSize(sizeBytes int) *NetworkCollector {
	c.ringBufSize = sizeBytes
	return c
}

// Name returns the collector identifier.
func (c *NetworkCollector) Name() string {
	return "network"
}

// Start attaches eBPF programs and begins sending events.
// Blocks until ctx is cancelled.
func (c *NetworkCollector) Start(ctx context.Context, out chan<- types.Event) error {
	c.logger.Info("starting network collector")

	// Load eBPF objects
	if err := c.loadObjects(); err != nil {
		c.loadError = err
		c.status.SetUp("network", false)
		return fmt.Errorf("collector/network: load eBPF objects: %w", err)
	}

	// Attach kprobes
	if err := c.attachPrograms(); err != nil {
		c.loadError = err
		c.status.SetUp("network", false)
		c.Close()
		return fmt.Errorf("collector/network: attach programs: %w", err)
	}

	// Create ring buffer reader
	reader, err := bpf.NewRingbufReader(c.objs.Events)
	if err != nil {
		c.loadError = err
		c.status.SetUp("network", false)
		c.Close()
		return fmt.Errorf("collector/network: create ringbuf reader: %w", err)
	}
	c.reader = reader
	c.loadError = nil
	c.status.SetUp("network", true)

	// Start reading loop
	readLoopDone := runReadLoop(func() { c.readLoop(ctx, out) })

	// Wait for context cancellation, then for readLoop to actually stop
	// sending (5.8d) — Close() unblocks the ring buffer Read() readLoop may
	// be parked in, and Close() runs after ctx is already done.
	<-ctx.Done()
	c.logger.Info("stopping network collector")
	<-readLoopDone
	return nil
}

// IsHealthy returns true if the collector loaded successfully.
func (c *NetworkCollector) IsHealthy() bool {
	return c.loadError == nil && c.objs != nil
}

// LoadError returns the error from failed load, if any.
func (c *NetworkCollector) LoadError() error {
	return c.loadError
}

// GetPrograms returns the loaded BPF programs for attestation.
// Implements watchdog.BPFProgramProvider interface.
func (c *NetworkCollector) GetPrograms() map[string]*ebpf.Program {
	if c.objs == nil {
		return nil
	}
	return map[string]*ebpf.Program{
		"trace_tcp_connect": c.objs.TraceTcpConnect,
		"trace_tcp_close":   c.objs.TraceTcpClose,
	}
}

// IsAttached returns true if the BPF program is still attached.
// Implements watchdog.BPFProgramChecker interface.
func (c *NetworkCollector) IsAttached() bool {
	if c.objs == nil {
		return false
	}
	// Check if we have active links
	return len(c.links) > 0
}

// Reload attempts to reload the BPF program.
// Implements watchdog.BPFProgramChecker interface.
func (c *NetworkCollector) Reload() error {
	c.logger.Info("reloading network collector")

	// Close existing resources
	if err := c.Close(); err != nil {
		c.logger.Warn("error closing during reload", slog.Any("error", err))
	}

	// Reload objects
	if err := c.loadObjects(); err != nil {
		return fmt.Errorf("reload objects: %w", err)
	}

	// Re-attach programs
	if err := c.attachPrograms(); err != nil {
		c.Close()
		return fmt.Errorf("re-attach programs: %w", err)
	}

	c.logger.Info("network collector reloaded successfully")
	return nil
}

// Close releases all eBPF resources.
func (c *NetworkCollector) Close() error {
	c.logger.Info("closing network collector")

	if c.reader != nil {
		c.reader.Close()
		c.reader = nil
	}

	for _, l := range c.links {
		l.Close()
	}
	c.links = nil

	if c.objs != nil {
		c.objs.Close()
		c.objs = nil
	}

	return nil
}

// loadObjects loads the eBPF objects using bpf2go generated code.
func (c *NetworkCollector) loadObjects() error {
	ringSize := bpf.ComputeRingBufSize(bpf.RingBufSizeConfig{SizeBytes: c.ringBufSize})
	c.logger.Info("network collector ring buffer size", slog.Int("bytes", ringSize))
	c.objs = &bpf.NetworkObjects{}
	opts := &ebpf.CollectionOptions{}
	_ = ringSize // applied to spec.Maps["events"].MaxEntries in the real bpf2go loader
	if err := bpf.LoadNetworkObjects(c.objs, opts); err != nil {
		return err
	}
	return nil
}

// attachPrograms attaches the eBPF programs to kprobes.
func (c *NetworkCollector) attachPrograms() error {
	// Attach tcp_connect kprobe.
	l1, err := link.Kprobe("tcp_connect", c.objs.TraceTcpConnect, nil)
	if err != nil {
		return fmt.Errorf("attach tcp_connect kprobe: %w", err)
	}
	c.links = append(c.links, l1)

	// Attach tcp_close kprobe for connection duration tracking.
	l2, err := link.Kprobe("tcp_close", c.objs.TraceTcpClose, nil)
	if err != nil {
		return fmt.Errorf("attach tcp_close kprobe: %w", err)
	}
	c.links = append(c.links, l2)

	return nil
}

// readLoop reads events from the ring buffer and sends them to the output channel.
func (c *NetworkCollector) readLoop(ctx context.Context, out chan<- types.Event) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		record, err := c.reader.Read()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			c.logger.Error("failed to read from ringbuf", "error", err)
			continue
		}

		event := eventPool.Get().(*types.Event)
		if err := c.parseEvent(record.RawSample, event); err != nil {
			c.logger.Error("failed to parse event", "error", err)
			exporter.RecordDropped("network", "parse_error")
			event.Reset()
			eventPool.Put(event)
			continue
		}

		sendEvent(ctx, out, *event, c.strategy, func() {
			exporter.RecordEventDrop("network", "ringbuf_to_router", defaultEventPriority(event.Type))
			c.dropLogger.record(c.logger, "network")
		})
		event.Reset()
		eventPool.Put(event)
	}
}

// LostEvents returns the cumulative number of events lost to a full kernel
// ring buffer since the BPF program loaded (5.9.6a, №71) — read from
// ringbuf_full_counters, not from a userspace channel-drop counter, so the
// name watchdog.DropTracker publishes this under actually means what it says.
// Implements watchdog.DropTracker.
func (c *NetworkCollector) LostEvents() uint64 {
	m := c.RingbufFullMap()
	if m == nil {
		return 0
	}
	total, err := bpf.SumPerCPUUint64(m)
	if err != nil {
		c.logger.Warn("failed to read ringbuf_full_counters", "error", err)
		return 0
	}
	return total
}

// RingbufFullMap returns the ringbuf_full_counters BPF map backing
// LostEvents, or nil in stub/dry-run mode. Exposed so main.go can also drain
// it into ebpf_guard_events_dropped_total{reason="ringbuf_full"} (5.9.6a).
func (c *NetworkCollector) RingbufFullMap() *ebpf.Map {
	if c.objs == nil {
		return nil
	}
	return c.objs.RingbufFullCounters
}

// EmittedMap returns the events_emitted_counters BPF map — the kernel-side
// count of successful bpf_ringbuf_reserve() calls, i.e. events the kernel
// actually produced, the left-hand side of 5.9.6b's event balance identity
// (№72) — or nil in stub/dry-run mode.
func (c *NetworkCollector) EmittedMap() *ebpf.Map {
	if c.objs == nil {
		return nil
	}
	return c.objs.EventsEmittedCounters
}

// MapFullCountersMap returns the BPF map_full_counters PERCPU_ARRAY, or nil
// in stub/dry-run mode. Implements watchdog.MapFullTracker.
func (c *NetworkCollector) MapFullCountersMap() *ebpf.Map {
	if c.objs == nil {
		return nil
	}
	return c.objs.MapFullCounters
}

// SamplingConfigMap returns the sampling_config BPF map backing this
// collector's static sample-rate filter, or nil in stub mode.
func (c *NetworkCollector) SamplingConfigMap() *ebpf.Map {
	if c.objs == nil {
		return nil
	}
	return c.objs.SamplingConfig
}

// parseEvent converts raw bytes from the ring buffer into event, delegating to
// the kernel-independent decodeNetworkEvent for routing and decoding. event
// must be a pooled *types.Event from eventPool; caller handles Reset() and
// Put() after use.
func (c *NetworkCollector) parseEvent(raw []byte, event *types.Event) error {
	evt, err := decodeNetworkEvent(raw)
	if err != nil {
		return err
	}
	*event = evt
	return nil
}

// ObserverFilterMaps returns the observer_root_pid and
// observer_excluded_counters BPF maps backing the in-kernel measurement-harness
// exclusion (5.9.2g), or nil maps if the collector has not loaded (stub mode).
//
// Each BPF object carries its own copy of these maps — the same per-object
// arrangement that made P0-22 populate comm_filter_map separately per collector
// — so the root PID must be published to every collector that emits
// correlatable events, not just to one of them. observer_tree_cache is not
// returned: it is populated exclusively by the kernel walk and userspace has no
// reason to touch it.
func (c *NetworkCollector) ObserverFilterMaps() (rootMap, excludedCounters *ebpf.Map) {
	if c.objs == nil {
		return nil, nil
	}
	return c.objs.ObserverRootPid, c.objs.ObserverExcludedCounters
}
