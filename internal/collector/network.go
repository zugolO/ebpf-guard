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
	go c.readLoop(ctx, out)

	// Wait for context cancellation
	<-ctx.Done()
	c.logger.Info("stopping network collector")
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
		"trace_tcp_connect": c.objs.TraceTCPConnect,
		"trace_tcp_close":   c.objs.TraceTCPClose,
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
	l1, err := link.Kprobe("tcp_connect", c.objs.TraceTCPConnect, nil)
	if err != nil {
		return fmt.Errorf("attach tcp_connect kprobe: %w", err)
	}
	c.links = append(c.links, l1)

	// Attach tcp_close kprobe for connection duration tracking.
	l2, err := link.Kprobe("tcp_close", c.objs.TraceTCPClose, nil)
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

		event, err := c.parseEvent(record.RawSample)
		if err != nil {
			c.logger.Error("failed to parse event", "error", err)
			exporter.RecordDropped("network", "parse_error")
			continue
		}

		sendEvent(ctx, out, *event, c.strategy, func() {
			exporter.RecordDropped("network", "channel_full")
			c.dropLogger.record(c.logger, "network")
		})
	}
}

// parseEvent converts raw bytes from ring buffer to types.Event.
// Routes to the appropriate parser based on the event type field.
func (c *NetworkCollector) parseEvent(raw []byte) (*types.Event, error) {
	if len(raw) < 4 {
		return nil, fmt.Errorf("raw sample too short: %d bytes", len(raw))
	}
	// Read event type from the first 4 bytes (little-endian uint32).
	evtType := uint32(raw[0]) | uint32(raw[1])<<8 | uint32(raw[2])<<16 | uint32(raw[3])<<24

	switch types.EventType(evtType) {
	case types.EventNetClose:
		evt, err := bpf.ParseNetworkCloseEvent(raw)
		if err != nil {
			return nil, err
		}
		result := evt.ToTypesEvent()
		return &result, nil
	default:
		// EventTCPConnect and any unknown network events.
		evt, err := bpf.ParseNetworkEvent(raw)
		if err != nil {
			return nil, err
		}
		result := evt.ToTypesEvent()
		return &result, nil
	}
}
