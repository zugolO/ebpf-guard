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
	"github.com/zugolO/ebpf-guard/internal/bpf"
	"github.com/zugolO/ebpf-guard/internal/exporter"
	"github.com/zugolO/ebpf-guard/internal/util"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// CapsToNames converts a capability bitmask to a slice of human-readable names.
// Delegates to the single shared table in internal/util so this and
// internal/sandbox's tamper-capability check never diverge (issue #271).
func CapsToNames(caps uint64) []string {
	return util.CapsToNames(caps)
}

// PrivescCollector collects privilege escalation events using eBPF programs
// attached to sys_enter_capset tracepoint and commit_creds kprobe.
type PrivescCollector struct {
	logger     *slog.Logger
	objs       *bpf.PrivescObjects
	links      []link.Link
	reader     *bpf.RingbufReader
	loadError  error
	dropLogger *dropLogger
	status     StatusReporter
	strategy   BackpressureStrategy
	lostTotal  atomic.Uint64
}

// NewPrivescCollector creates a new privilege escalation event collector.
func NewPrivescCollector(logger *slog.Logger) (*PrivescCollector, error) {
	return &PrivescCollector{
		logger:     logger.With("collector", "privesc"),
		dropLogger: newDropLogger(5 * time.Second),
		status:     NoopStatusReporter{},
		strategy:   StrategyDrop,
	}, nil
}

// WithStatusReporter sets the StatusReporter used to signal up/down state.
func (c *PrivescCollector) WithStatusReporter(r StatusReporter) *PrivescCollector {
	c.status = r
	return c
}

// WithBackpressureStrategy sets the backpressure strategy for the event channel.
func (c *PrivescCollector) WithBackpressureStrategy(s BackpressureStrategy) *PrivescCollector {
	c.strategy = s
	return c
}

// Name returns the collector identifier.
func (c *PrivescCollector) Name() string { return "privesc" }

// IsHealthy returns true if the collector loaded successfully.
func (c *PrivescCollector) IsHealthy() bool {
	return c.loadError == nil && c.objs != nil
}

// LoadError returns the error from a failed load, if any.
func (c *PrivescCollector) LoadError() error { return c.loadError }

// IsAttached returns true if the BPF programs are still attached.
func (c *PrivescCollector) IsAttached() bool {
	return c.objs != nil && len(c.links) > 0
}

// Start attaches eBPF programs and begins sending events. Blocks until ctx is cancelled.
func (c *PrivescCollector) Start(ctx context.Context, out chan<- types.Event) error {
	c.logger.Info("starting privesc collector")

	if err := c.loadObjects(); err != nil {
		c.loadError = err
		c.status.SetUp("privesc", false)
		return fmt.Errorf("collector/privesc: load eBPF objects: %w", err)
	}

	if err := c.attachPrograms(); err != nil {
		c.loadError = err
		c.status.SetUp("privesc", false)
		c.Close()
		return fmt.Errorf("collector/privesc: attach programs: %w", err)
	}

	reader, err := bpf.NewRingbufReader(c.objs.Events)
	if err != nil {
		c.loadError = err
		c.status.SetUp("privesc", false)
		c.Close()
		return fmt.Errorf("collector/privesc: create ringbuf reader: %w", err)
	}
	c.reader = reader
	c.loadError = nil
	c.status.SetUp("privesc", true)

	go c.readLoop(ctx, out)

	<-ctx.Done()
	c.logger.Info("stopping privesc collector")
	return nil
}

// Close releases all eBPF resources.
func (c *PrivescCollector) Close() error {
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

func (c *PrivescCollector) loadObjects() error {
	c.objs = &bpf.PrivescObjects{}
	if err := bpf.LoadPrivescObjects(c.objs, &ebpf.CollectionOptions{}); err != nil {
		return err
	}
	return nil
}

func (c *PrivescCollector) attachPrograms() error {
	// Attach sys_enter_capset tracepoint.
	l1, err := link.Tracepoint("syscalls", "sys_enter_capset", c.objs.TraceCapset, nil)
	if err != nil {
		return fmt.Errorf("attach sys_enter_capset: %w", err)
	}
	c.links = append(c.links, l1)

	// Attach commit_creds kprobe.
	l2, err := link.Kprobe("commit_creds", c.objs.TraceCommitCreds, nil)
	if err != nil {
		return fmt.Errorf("attach commit_creds kprobe: %w", err)
	}
	c.links = append(c.links, l2)

	return nil
}

func (c *PrivescCollector) readLoop(ctx context.Context, out chan<- types.Event) {
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
			c.logger.Error("failed to parse privesc event", "error", err)
			exporter.RecordDropped("privesc", "parse_error")
			continue
		}

		if c.logger.Enabled(ctx, slog.LevelDebug) {
			gained := CapsToNames(event.Privesc.NewCaps &^ event.Privesc.OldCaps)
			c.logger.Debug("privesc event",
				slog.Uint64("pid", uint64(event.PID)),
				slog.Any("caps_gained", gained))
		}

		sendEvent(ctx, out, *event, c.strategy, func() {
			exporter.RecordDropped("privesc", "channel_full")
			c.dropLogger.record(c.logger, "privesc")
			c.lostTotal.Add(1)
		})
	}
}

// LostEvents returns the total number of events lost in the BPF ring buffer
// since the collector started. Implements watchdog.DropTracker.
func (c *PrivescCollector) LostEvents() uint64 {
	return c.lostTotal.Load()
}

func (c *PrivescCollector) parseEvent(raw []byte) (*types.Event, error) {
	var pe bpf.PrivescRawEvent
	if err := bpf.ParsePrivescEventInto(raw, &pe); err != nil {
		return nil, err
	}
	result := pe.ToTypesEvent()
	return &result, nil
}
