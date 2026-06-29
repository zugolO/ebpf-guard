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

// BPFMonitorCollector monitors the bpf() syscall via kprobe/kretprobe on
// __x64_sys_bpf. It captures BPF_PROG_LOAD and BPF_MAP_CREATE calls to
// detect malicious eBPF program loading by rootkits (TripleCross, ebpfkit,
// boopkit) that use BPF to hide traffic and processes.
type BPFMonitorCollector struct {
	logger      *slog.Logger
	objs        *bpf.BpfMonitorObjects
	links       []link.Link
	reader      *ringbuf.Reader
	loadError   error
	dropLogger  *dropLogger
	status      StatusReporter
	strategy    BackpressureStrategy
	ringBufSize int
	lostTotal   atomic.Uint64
}

// NewBPFMonitorCollector creates a new bpf() syscall monitoring collector.
func NewBPFMonitorCollector(logger *slog.Logger) (*BPFMonitorCollector, error) {
	return &BPFMonitorCollector{
		logger:     logger.With("collector", "bpfmonitor"),
		dropLogger: newDropLogger(5 * time.Second),
		status:     NoopStatusReporter{},
		strategy:   StrategyDrop,
	}, nil
}

// WithStatusReporter sets the StatusReporter used to signal up/down state.
func (c *BPFMonitorCollector) WithStatusReporter(r StatusReporter) *BPFMonitorCollector {
	c.status = r
	return c
}

// WithBackpressureStrategy sets the backpressure strategy for the event channel.
func (c *BPFMonitorCollector) WithBackpressureStrategy(s BackpressureStrategy) *BPFMonitorCollector {
	c.strategy = s
	return c
}

// WithRingBufSize sets the ring buffer size for the eBPF program.
func (c *BPFMonitorCollector) WithRingBufSize(sizeBytes int) *BPFMonitorCollector {
	c.ringBufSize = sizeBytes
	return c
}

// Name returns the collector identifier.
func (c *BPFMonitorCollector) Name() string {
	return "bpfmonitor"
}

// Start attaches eBPF programs and begins sending events.
func (c *BPFMonitorCollector) Start(ctx context.Context, out chan<- types.Event) error {
	c.logger.Info("starting bpfmonitor collector")

	if err := c.loadObjects(); err != nil {
		c.loadError = err
		c.status.SetUp("bpfmonitor", false)
		return fmt.Errorf("collector/bpfmonitor: load eBPF objects: %w", err)
	}

	if err := c.attachPrograms(); err != nil {
		c.loadError = err
		c.status.SetUp("bpfmonitor", false)
		c.Close()
		return fmt.Errorf("collector/bpfmonitor: attach programs: %w", err)
	}

	reader, err := ringbuf.NewReader(c.objs.BpfmonitorEvents)
	if err != nil {
		c.loadError = err
		c.status.SetUp("bpfmonitor", false)
		c.Close()
		return fmt.Errorf("collector/bpfmonitor: create ringbuf reader: %w", err)
	}
	c.reader = reader
	c.loadError = nil
	c.status.SetUp("bpfmonitor", true)

	go c.readLoop(ctx, out)

	<-ctx.Done()
	c.logger.Info("stopping bpfmonitor collector")
	return nil
}

// IsHealthy returns true if the collector loaded successfully.
func (c *BPFMonitorCollector) IsHealthy() bool {
	return c.loadError == nil && c.objs != nil
}

// LoadError returns the error from failed load, if any.
func (c *BPFMonitorCollector) LoadError() error {
	return c.loadError
}

// GetPrograms returns the loaded BPF programs for attestation.
func (c *BPFMonitorCollector) GetPrograms() map[string]*ebpf.Program {
	if c.objs == nil {
		return nil
	}
	return map[string]*ebpf.Program{
		"trace_bpf_enter": c.objs.TraceBpfEnter,
		"trace_bpf_exit":  c.objs.TraceBpfExit,
	}
}

// IsAttached returns true if the BPF programs are still attached.
func (c *BPFMonitorCollector) IsAttached() bool {
	return len(c.links) > 0
}

// Reload attempts to reload the BPF programs.
func (c *BPFMonitorCollector) Reload() error {
	c.logger.Info("reloading bpfmonitor collector")
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
	c.logger.Info("bpfmonitor collector reloaded successfully")
	return nil
}

// Close releases all eBPF resources.
func (c *BPFMonitorCollector) Close() error {
	c.logger.Info("closing bpfmonitor collector")
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
func (c *BPFMonitorCollector) LostEvents() uint64 {
	return c.lostTotal.Load()
}

// loadObjects loads the eBPF objects using bpf2go generated code.
func (c *BPFMonitorCollector) loadObjects() error {
	ringSize := bpf.ComputeRingBufSize(bpf.RingBufSizeConfig{SizeBytes: c.ringBufSize})
	c.logger.Info("bpfmonitor collector ring buffer size", slog.Int("bytes", ringSize))
	c.objs = &bpf.BpfMonitorObjects{}
	opts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "",
		},
	}
	_ = ringSize
	if err := bpf.LoadBpfMonitorObjects(c.objs, opts); err != nil {
		return fmt.Errorf("load bpf_monitor objects: %w", err)
	}
	return nil
}

// attachPrograms attaches kprobe and kretprobe to __x64_sys_bpf.
func (c *BPFMonitorCollector) attachPrograms() error {
	lnk, err := link.Kprobe("__x64_sys_bpf", c.objs.TraceBpfEnter, nil)
	if err != nil {
		return fmt.Errorf("attach kprobe __x64_sys_bpf: %w", err)
	}
	c.links = append(c.links, lnk)

	lnk, err = link.Kretprobe("__x64_sys_bpf", c.objs.TraceBpfExit, nil)
	if err != nil {
		return fmt.Errorf("attach kretprobe __x64_sys_bpf: %w", err)
	}
	c.links = append(c.links, lnk)

	return nil
}

// readLoop reads events from the ring buffer and sends them to the output channel.
func (c *BPFMonitorCollector) readLoop(ctx context.Context, out chan<- types.Event) {
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
			c.logger.Error("failed to read from bpfmonitor ringbuf", "error", err)
			continue
		}

		event := eventPool.Get().(*types.Event)
		if err := c.parseEvent(record.RawSample, event); err != nil {
			c.logger.Error("failed to parse bpfmonitor event", "error", err)
			exporter.RecordDropped("bpfmonitor", "parse_error")
			event.Reset()
			eventPool.Put(event)
			continue
		}

		if c.logger.Enabled(ctx, slog.LevelDebug) {
			c.logger.Debug("bpfmonitor event",
				slog.Uint64("pid", uint64(event.PID)),
				slog.Uint64("cmd", uint64(event.BPFProgram.Cmd)),
				slog.Uint64("prog_type", uint64(event.BPFProgram.ProgType)),
			)
		}

		sendEvent(ctx, out, *event, c.strategy, func() {
			exporter.RecordDropped("bpfmonitor", "channel_full")
			c.dropLogger.record(c.logger, "bpfmonitor")
			c.lostTotal.Add(1)
		})
		event.Reset()
		eventPool.Put(event)
	}
}

// parseEvent converts raw bytes from the ring buffer into event.
func (c *BPFMonitorCollector) parseEvent(raw []byte, event *types.Event) error {
	var bm bpf.BpfMonitorRawEvent
	if err := bpf.ParseBpfMonitorEventInto(raw, &bm); err != nil {
		return err
	}
	*event = bm.ToTypesEvent()
	return nil
}
