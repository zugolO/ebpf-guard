// Package collector provides eBPF-based event collection from the kernel.
package collector

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/ebpf-guard/ebpf-guard/internal/bpf"
	"github.com/ebpf-guard/ebpf-guard/internal/exporter"
	"github.com/ebpf-guard/ebpf-guard/pkg/types"
)

// SyscallCollector collects syscall events using eBPF tracepoints.
type SyscallCollector struct {
	logger    *slog.Logger
	objs      *bpf.SyscallObjects
	links     []link.Link
	reader    *bpf.RingbufReader
	loadError error // Tracks if the collector failed to load (stub mode)
}

// NewSyscallCollector creates a new syscall event collector.
func NewSyscallCollector(logger *slog.Logger) (*SyscallCollector, error) {
	return &SyscallCollector{
		logger: logger.With("collector", "syscall"),
	}, nil
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
		exporter.SetCollectorUp("syscall", false)
		return fmt.Errorf("collector/syscall: load eBPF objects: %w", err)
	}

	// Attach tracepoints
	if err := c.attachPrograms(); err != nil {
		c.loadError = err
		exporter.SetCollectorUp("syscall", false)
		c.Close()
		return fmt.Errorf("collector/syscall: attach programs: %w", err)
	}

	// Create ring buffer reader
	reader, err := bpf.NewRingbufReader(c.objs.Events)
	if err != nil {
		c.loadError = err
		exporter.SetCollectorUp("syscall", false)
		c.Close()
		return fmt.Errorf("collector/syscall: create ringbuf reader: %w", err)
	}
	c.reader = reader
	c.loadError = nil
	exporter.SetCollectorUp("syscall", true)

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

		// Send event (non-blocking)
		select {
		case out <- *event:
		default:
			c.logger.Warn("event channel full, dropping event")
			exporter.RecordDropped("syscall", "channel_full")
		}
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
