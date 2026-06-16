// Package collector provides eBPF-based event collection from the kernel.
package collector

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/zugolO/ebpf-guard/internal/bpf"
	"github.com/zugolO/ebpf-guard/internal/exporter"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// IOUringCollector monitors io_uring activity via kprobes on io_uring_setup
// and io_uring_enter. io_uring bypasses traditional syscall tracepoints, making
// it a blind spot for tracepoint-based security agents. This collector closes
// that gap by emitting events for io_uring usage, allowing rules to alert on
// unexpected io_uring activity by processes outside an allowlist.
type IOUringCollector struct {
	logger      *slog.Logger
	objs        *bpf.IouringObjects
	links       []link.Link
	reader      *ringbuf.Reader
	loadError   error
	dropLogger  *dropLogger
	status      StatusReporter
	strategy    BackpressureStrategy
	ringBufSize int
	lostTotal   atomic.Uint64
}

// NewIOUringCollector creates a new io_uring event collector.
func NewIOUringCollector(logger *slog.Logger) (*IOUringCollector, error) {
	return &IOUringCollector{
		logger:     logger.With("collector", "iouring"),
		dropLogger: newDropLogger(5 * time.Second),
		status:     NoopStatusReporter{},
		strategy:   StrategyDrop,
	}, nil
}

// WithStatusReporter sets the StatusReporter used to signal up/down state.
func (c *IOUringCollector) WithStatusReporter(r StatusReporter) *IOUringCollector {
	c.status = r
	return c
}

// WithBackpressureStrategy sets the backpressure strategy for the event channel.
func (c *IOUringCollector) WithBackpressureStrategy(s BackpressureStrategy) *IOUringCollector {
	c.strategy = s
	return c
}

// WithRingBufSize sets the ring buffer size for the eBPF program.
func (c *IOUringCollector) WithRingBufSize(sizeBytes int) *IOUringCollector {
	c.ringBufSize = sizeBytes
	return c
}

// Name returns the collector identifier.
func (c *IOUringCollector) Name() string {
	return "iouring"
}

// Start attaches eBPF programs and begins sending events.
func (c *IOUringCollector) Start(ctx context.Context, out chan<- types.Event) error {
	c.logger.Info("starting iouring collector")

	if err := c.loadObjects(); err != nil {
		c.loadError = err
		c.status.SetUp("iouring", false)
		return fmt.Errorf("collector/iouring: load eBPF objects: %w", err)
	}

	if err := c.attachPrograms(); err != nil {
		c.loadError = err
		c.status.SetUp("iouring", false)
		c.Close()
		return fmt.Errorf("collector/iouring: attach programs: %w", err)
	}

	reader, err := ringbuf.NewReader(c.objs.IouringEvents)
	if err != nil {
		c.loadError = err
		c.status.SetUp("iouring", false)
		c.Close()
		return fmt.Errorf("collector/iouring: create ringbuf reader: %w", err)
	}
	c.reader = reader
	c.loadError = nil
	c.status.SetUp("iouring", true)

	go c.readLoop(ctx, out)

	<-ctx.Done()
	c.logger.Info("stopping iouring collector")
	return nil
}

// IsHealthy returns true if the collector loaded successfully.
func (c *IOUringCollector) IsHealthy() bool {
	return c.loadError == nil && c.objs != nil
}

// LoadError returns the error from failed load, if any.
func (c *IOUringCollector) LoadError() error {
	return c.loadError
}

// GetPrograms returns the loaded BPF programs for attestation.
func (c *IOUringCollector) GetPrograms() map[string]*ebpf.Program {
	if c.objs == nil {
		return nil
	}
	return map[string]*ebpf.Program{
		"trace_io_uring_setup": c.objs.TraceIoUringSetup,
		"trace_io_uring_enter": c.objs.TraceIoUringEnter,
	}
}

// IsAttached returns true if the BPF programs are still attached.
func (c *IOUringCollector) IsAttached() bool {
	return len(c.links) > 0
}

// Reload attempts to reload the BPF programs.
func (c *IOUringCollector) Reload() error {
	c.logger.Info("reloading iouring collector")
	if err := c.Close(); err != nil {
		c.logger.Warn("error closing during reload", slog.Any("error", err))
	}
	if err := c.loadObjects(); err != nil {
		return fmt.Errorf("reload objects: %w", err)
	}
	if err := c.attachPrograms(); err != nil {
		c.Close()
		return fmt.Errorf("re-attach programs: %w", err)
	}
	c.logger.Info("iouring collector reloaded successfully")
	return nil
}

// Close releases all eBPF resources.
func (c *IOUringCollector) Close() error {
	c.logger.Info("closing iouring collector")
	if c.reader != nil {
		c.reader.Close()
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

// LostEvents returns the total number of events lost in the BPF ring buffer.
func (c *IOUringCollector) LostEvents() uint64 {
	return c.lostTotal.Load()
}

// loadObjects loads the eBPF objects using bpf2go generated code.
func (c *IOUringCollector) loadObjects() error {
	ringSize := bpf.ComputeRingBufSize(bpf.RingBufSizeConfig{SizeBytes: c.ringBufSize})
	c.logger.Info("iouring collector ring buffer size", slog.Int("bytes", ringSize))
	c.objs = &bpf.IouringObjects{}
	opts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "",
		},
	}
	_ = ringSize
	if err := bpf.LoadIouringObjects(c.objs, opts); err != nil {
		return fmt.Errorf("load iouring objects: %w", err)
	}
	return nil
}

// attachPrograms attaches kprobes to io_uring syscalls.
func (c *IOUringCollector) attachPrograms() error {
	lnk, err := link.Kprobe("__x64_sys_io_uring_setup", c.objs.TraceIoUringSetup, nil)
	if err != nil {
		return fmt.Errorf("attach kprobe io_uring_setup: %w", err)
	}
	c.links = append(c.links, lnk)

	lnk, err = link.Kprobe("__x64_sys_io_uring_enter", c.objs.TraceIoUringEnter, nil)
	if err != nil {
		return fmt.Errorf("attach kprobe io_uring_enter: %w", err)
	}
	c.links = append(c.links, lnk)

	return nil
}

// readLoop reads events from the ring buffer and sends them to the output channel.
func (c *IOUringCollector) readLoop(ctx context.Context, out chan<- types.Event) {
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
			c.logger.Error("failed to read from iouring ringbuf", "error", err)
			continue
		}

		event := eventPool.Get().(*types.Event)
		if err := c.parseEvent(record.RawSample, event); err != nil {
			c.logger.Error("failed to parse iouring event", "error", err)
			exporter.RecordDropped("iouring", "parse_error")
			event.Reset()
			eventPool.Put(event)
			continue
		}

		if c.logger.Enabled(ctx, slog.LevelDebug) {
			c.logger.Debug("iouring event",
				slog.Uint64("pid", uint64(event.PID)),
				slog.Uint64("op", uint64(event.IOUring.Op)),
				slog.Int("fd", int(event.IOUring.Fd)),
			)
		}

		sendEvent(ctx, out, *event, c.strategy, func() {
			exporter.RecordDropped("iouring", "channel_full")
			c.dropLogger.record(c.logger, "iouring")
			c.lostTotal.Add(1)
		})
		event.Reset()
		eventPool.Put(event)
	}
}

// parseEvent converts raw bytes from the ring buffer into event.
func (c *IOUringCollector) parseEvent(raw []byte, event *types.Event) error {
	evt, err := bpf.ParseIOUringEvent(raw)
	if err != nil {
		return err
	}
	*event = evt.ToTypesEvent()
	return nil
}
