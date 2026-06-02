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

// SyscallCollector collects syscall events using eBPF tracepoints.
type SyscallCollector struct {
	logger     *slog.Logger
	objs       *bpf.SyscallObjects
	links      []link.Link
	reader     *bpf.RingbufReader
	loadError  error // Tracks if the collector failed to load (stub mode)
	dropLogger *dropLogger
	status     StatusReporter
	strategy   BackpressureStrategy
}

// NewSyscallCollector creates a new syscall event collector.
func NewSyscallCollector(logger *slog.Logger) (*SyscallCollector, error) {
	return &SyscallCollector{
		logger:     logger.With("collector", "syscall"),
		dropLogger: newDropLogger(5 * time.Second),
		status:     NoopStatusReporter{},
		strategy:   StrategyDrop,
	}, nil
}

// WithStatusReporter sets the StatusReporter used to signal up/down state.
func (c *SyscallCollector) WithStatusReporter(r StatusReporter) *SyscallCollector {
	c.status = r
	return c
}

// WithBackpressureStrategy sets the backpressure strategy for the event channel.
func (c *SyscallCollector) WithBackpressureStrategy(s BackpressureStrategy) *SyscallCollector {
	c.strategy = s
	return c
}

// Name returns the collector identifier.
func (c *SyscallCollector) Name() string {
	return "syscall"
}

// Start attaches eBPF programs and begins sending events.
// Blocks until ctx is cancelled.
func (c *SyscallCollector) Start(ctx context.Context, out chan<- types.Event) error {
	c.logger.Info("starting syscall collector")

	// Load eBPF objects
	if err := c.loadObjects(); err != nil {
		c.loadError = err
		c.status.SetUp("syscall", false)
		return fmt.Errorf("collector/syscall: load eBPF objects: %w", err)
	}

	// Attach tracepoints
	if err := c.attachPrograms(); err != nil {
		c.loadError = err
		c.status.SetUp("syscall", false)
		c.Close()
		return fmt.Errorf("collector/syscall: attach programs: %w", err)
	}

	// Create ring buffer reader
	reader, err := bpf.NewRingbufReader(c.objs.Events)
	if err != nil {
		c.loadError = err
		c.status.SetUp("syscall", false)
		c.Close()
		return fmt.Errorf("collector/syscall: create ringbuf reader: %w", err)
	}
	c.reader = reader
	c.loadError = nil
	c.status.SetUp("syscall", true)

	// Start reading loop
	go c.readLoop(ctx, out)

	// Wait for context cancellation
	<-ctx.Done()
	c.logger.Info("stopping syscall collector")
	return nil
}

// IsHealthy returns true if the collector loaded successfully.
func (c *SyscallCollector) IsHealthy() bool {
	return c.loadError == nil && c.objs != nil
}

// LoadError returns the error from failed load, if any.
func (c *SyscallCollector) LoadError() error {
	return c.loadError
}

// IsAttached returns true if the BPF program is still attached.
// Implements watchdog.BPFProgramChecker interface.
func (c *SyscallCollector) IsAttached() bool {
	if c.objs == nil {
		return false
	}
	// Check if we have active links
	return len(c.links) > 0
}

// Reload attempts to reload the BPF program.
// Implements watchdog.BPFProgramChecker interface.
func (c *SyscallCollector) Reload() error {
	c.logger.Info("reloading syscall collector")

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

	c.logger.Info("syscall collector reloaded successfully")
	return nil
}

// Close releases all eBPF resources.
func (c *SyscallCollector) Close() error {
	c.logger.Info("closing syscall collector")

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
func (c *SyscallCollector) loadObjects() error {
	c.objs = &bpf.SyscallObjects{}
	if err := bpf.LoadSyscallObjects(c.objs, &ebpf.CollectionOptions{}); err != nil {
		return err
	}
	return nil
}

// attachPrograms attaches the eBPF programs to tracepoints.
func (c *SyscallCollector) attachPrograms() error {
	// Attach sys_enter tracepoint
	l1, err := link.Tracepoint("raw_syscalls", "sys_enter", c.objs.TraceSysEnter, nil)
	if err != nil {
		return fmt.Errorf("attach sys_enter: %w", err)
	}
	c.links = append(c.links, l1)

	// Attach sys_exit tracepoint
	l2, err := link.Tracepoint("raw_syscalls", "sys_exit", c.objs.TraceSysExit, nil)
	if err != nil {
		return fmt.Errorf("attach sys_exit: %w", err)
	}
	c.links = append(c.links, l2)

	return nil
}

// readLoop reads events from the ring buffer and sends them to the output channel.
func (c *SyscallCollector) readLoop(ctx context.Context, out chan<- types.Event) {
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

		// Parse raw event into types.Event
		event, err := c.parseEvent(record.RawSample)
		if err != nil {
			c.logger.Error("failed to parse event", "error", err)
			exporter.RecordDropped("syscall", "parse_error")
			continue
		}

		// Debug logging (guarded to avoid allocation when debug is off)
		if c.logger.Enabled(ctx, slog.LevelDebug) {
			c.logger.Debug("syscall event",
				slog.Uint64("pid", uint64(event.PID)),
				slog.Int64("syscall_nr", event.Syscall.Nr))
		}

		sendEvent(ctx, out, *event, c.strategy, func() {
			exporter.RecordDropped("syscall", "channel_full")
			c.dropLogger.record(c.logger, "syscall")
		})
	}
}

// parseEvent converts raw bytes from ring buffer to types.Event.
func (c *SyscallCollector) parseEvent(raw []byte) (*types.Event, error) {
	evt, err := bpf.ParseSyscallEvent(raw)
	if err != nil {
		return nil, err
	}
	result := evt.ToTypesEvent()
	return &result, nil
}
