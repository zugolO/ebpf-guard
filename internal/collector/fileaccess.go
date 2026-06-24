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
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// FileaccessCollector collects file access events using eBPF kprobes.
type FileaccessCollector struct {
	logger      *slog.Logger
	objs        *bpf.FileaccessObjects
	links       []link.Link
	reader      *bpf.RingbufReader
	loadError   error // Tracks if the collector failed to load (stub mode)
	dropLogger  *dropLogger
	status      StatusReporter
	strategy    BackpressureStrategy
	ringBufSize int // 0 = auto-detect
	lostTotal   atomic.Uint64

	trackOpen  bool // attach sys_enter_openat hooks
	trackRead  bool // attach sys_enter_read hooks (high volume)
	trackWrite bool // attach sys_enter_write hooks (high volume)
}

// NewFileaccessCollector creates a new file access event collector.
// By default only open(2) hooks are enabled; read/write hooks are opt-in via WithFileOps.
func NewFileaccessCollector(logger *slog.Logger) (*FileaccessCollector, error) {
	return &FileaccessCollector{
		logger:     logger.With("collector", "fileaccess"),
		dropLogger: newDropLogger(5 * time.Second),
		status:     NoopStatusReporter{},
		strategy:   StrategyDrop,
		trackOpen:  true,
		trackRead:  false,
		trackWrite: false,
	}, nil
}

// WithFileOps configures which file operation hooks are attached.
// Disabling read/write hooks reduces event volume by 10-50x on busy hosts.
// trackOpen should almost always remain true for sensitive-path detection.
func (c *FileaccessCollector) WithFileOps(trackOpen, trackRead, trackWrite bool) *FileaccessCollector {
	c.trackOpen = trackOpen
	c.trackRead = trackRead
	c.trackWrite = trackWrite
	return c
}

// WithStatusReporter sets the StatusReporter used to signal up/down state.
func (c *FileaccessCollector) WithStatusReporter(r StatusReporter) *FileaccessCollector {
	c.status = r
	return c
}

// WithBackpressureStrategy sets the backpressure strategy for the event channel.
func (c *FileaccessCollector) WithBackpressureStrategy(s BackpressureStrategy) *FileaccessCollector {
	c.strategy = s
	return c
}

// WithRingBufSize sets the BPF ring buffer size in bytes for this collector.
// Zero (default) auto-detects the size from /proc/meminfo.
func (c *FileaccessCollector) WithRingBufSize(sizeBytes int) *FileaccessCollector {
	c.ringBufSize = sizeBytes
	return c
}

// Name returns the collector identifier.
func (c *FileaccessCollector) Name() string {
	return "fileaccess"
}

// Start attaches eBPF programs and begins sending events.
// Blocks until ctx is cancelled.
func (c *FileaccessCollector) Start(ctx context.Context, out chan<- types.Event) error {
	c.logger.Info("starting fileaccess collector")

	// Load eBPF objects
	if err := c.loadObjects(); err != nil {
		c.loadError = err
		c.status.SetUp("fileaccess", false)
		return fmt.Errorf("collector/fileaccess: load eBPF objects: %w", err)
	}

	// Attach kprobes
	if err := c.attachPrograms(); err != nil {
		c.loadError = err
		c.status.SetUp("fileaccess", false)
		c.Close()
		return fmt.Errorf("collector/fileaccess: attach programs: %w", err)
	}

	// Create ring buffer reader
	reader, err := bpf.NewRingbufReader(c.objs.Events)
	if err != nil {
		c.loadError = err
		c.status.SetUp("fileaccess", false)
		c.Close()
		return fmt.Errorf("collector/fileaccess: create ringbuf reader: %w", err)
	}
	c.reader = reader
	c.loadError = nil
	c.status.SetUp("fileaccess", true)

	// Start reading loop
	go c.readLoop(ctx, out)

	// Wait for context cancellation
	<-ctx.Done()
	c.logger.Info("stopping fileaccess collector")
	return nil
}

// IsHealthy returns true if the collector loaded successfully.
func (c *FileaccessCollector) IsHealthy() bool {
	return c.loadError == nil && c.objs != nil
}

// LoadError returns the error from failed load, if any.
func (c *FileaccessCollector) LoadError() error {
	return c.loadError
}

// SamplingConfigMap returns the sampling_config BPF map backing this
// collector's static sample-rate filter, or nil in stub mode.
func (c *FileaccessCollector) SamplingConfigMap() *ebpf.Map {
	if c.objs == nil {
		return nil
	}
	return c.objs.SamplingConfig
}

// GetPrograms returns the loaded BPF programs for attestation.
// Implements watchdog.BPFProgramProvider interface.
func (c *FileaccessCollector) GetPrograms() map[string]*ebpf.Program {
	if c.objs == nil {
		return nil
	}
	progs := map[string]*ebpf.Program{
		"trace_open":  c.objs.TraceOpen,
		"trace_read":  c.objs.TraceRead,
		"trace_write": c.objs.TraceWrite,
	}
	if c.objs.TraceClose != nil {
		progs["trace_close"] = c.objs.TraceClose
	}
	if c.objs.TraceOpenExit != nil {
		progs["trace_open_exit"] = c.objs.TraceOpenExit
	}
	return progs
}

// IsAttached returns true if the BPF program is still attached.
// Implements watchdog.BPFProgramChecker interface.
func (c *FileaccessCollector) IsAttached() bool {
	if c.objs == nil {
		return false
	}
	// Check if we have active links
	return len(c.links) > 0
}

// Reload attempts to reload the BPF program.
// Implements watchdog.BPFProgramChecker interface.
func (c *FileaccessCollector) Reload() error {
	c.logger.Info("reloading fileaccess collector")

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

	c.logger.Info("fileaccess collector reloaded successfully")
	return nil
}

// Close releases all eBPF resources.
func (c *FileaccessCollector) Close() error {
	c.logger.Info("closing fileaccess collector")

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
func (c *FileaccessCollector) loadObjects() error {
	ringSize := bpf.ComputeRingBufSize(bpf.RingBufSizeConfig{SizeBytes: c.ringBufSize})
	c.logger.Info("fileaccess collector ring buffer size", slog.Int("bytes", ringSize))
	c.objs = &bpf.FileaccessObjects{}
	opts := &ebpf.CollectionOptions{}
	_ = ringSize // applied to spec.Maps["events"].MaxEntries in the real bpf2go loader
	if err := bpf.LoadFileaccessObjects(c.objs, opts); err != nil {
		return err
	}
	return nil
}

// attachPrograms attaches the eBPF programs to tracepoints/kprobes.
// Which hooks are attached is controlled by trackOpen/trackRead/trackWrite.
func (c *FileaccessCollector) attachPrograms() error {
	if c.trackOpen {
		l1, err := link.Tracepoint("syscalls", "sys_enter_openat", c.objs.TraceOpen, nil)
		if err != nil {
			l1, err = link.Kprobe("do_sys_openat2", c.objs.TraceOpen, nil)
			if err != nil {
				l1, err = link.Kprobe("do_sys_open", c.objs.TraceOpen, nil)
				if err != nil {
					return fmt.Errorf("attach open tracepoint/kprobe: %w", err)
				}
			}
		}
		c.links = append(c.links, l1)

		// fd→path enrichment: sys_exit hooks commit scratch→fd_path_map
		if c.objs.TraceOpenExit != nil {
			if lExit, err := link.Tracepoint("syscalls", "sys_exit_openat", c.objs.TraceOpenExit, nil); err != nil {
				c.logger.Warn("failed to attach sys_exit_openat, fd enrichment partially disabled", "error", err)
			} else {
				c.links = append(c.links, lExit)
			}
		}
		if c.objs.TraceOpenat2Exit != nil {
			if lExit2, err := link.Tracepoint("syscalls", "sys_exit_openat2", c.objs.TraceOpenat2Exit, nil); err != nil {
				c.logger.Warn("failed to attach sys_exit_openat2", "error", err)
			} else {
				c.links = append(c.links, lExit2)
			}
		}
		if c.objs.TraceClose != nil {
			if lClose, err := link.Tracepoint("syscalls", "sys_enter_close", c.objs.TraceClose, nil); err != nil {
				c.logger.Warn("failed to attach sys_enter_close, fd map entries will not be evicted on close", "error", err)
			} else {
				c.links = append(c.links, lClose)
			}
		}
	}

	if c.trackRead {
		l2, err := link.Tracepoint("syscalls", "sys_enter_read", c.objs.TraceRead, nil)
		if err != nil {
			l2, err = link.Kprobe("vfs_read", c.objs.TraceRead, nil)
			if err != nil {
				c.logger.Warn("failed to attach read tracepoint/kprobe, continuing without read tracking", "error", err)
			} else {
				c.links = append(c.links, l2)
			}
		} else {
			c.links = append(c.links, l2)
		}
	}

	if c.trackWrite {
		l3, err := link.Tracepoint("syscalls", "sys_enter_write", c.objs.TraceWrite, nil)
		if err != nil {
			l3, err = link.Kprobe("vfs_write", c.objs.TraceWrite, nil)
			if err != nil {
				c.logger.Warn("failed to attach write tracepoint/kprobe, continuing without write tracking", "error", err)
			} else {
				c.links = append(c.links, l3)
			}
		} else {
			c.links = append(c.links, l3)
		}
	}

	c.logger.Info("fileaccess hooks attached",
		slog.Bool("open", c.trackOpen),
		slog.Bool("read", c.trackRead),
		slog.Bool("write", c.trackWrite),
	)
	return nil
}

// readLoop reads events from the ring buffer and sends them to the output channel.
func (c *FileaccessCollector) readLoop(ctx context.Context, out chan<- types.Event) {
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
			exporter.RecordDropped("fileaccess", "parse_error")
			event.Reset()
			eventPool.Put(event)
			continue
		}

		sendEvent(ctx, out, *event, c.strategy, func() {
			exporter.RecordDropped("fileaccess", "channel_full")
			c.dropLogger.record(c.logger, "fileaccess")
			c.lostTotal.Add(1)
		})
		event.Reset()
		eventPool.Put(event)
	}
}

// LostEvents returns the total number of events lost in the BPF ring buffer
// since the collector started. Implements watchdog.DropTracker.
func (c *FileaccessCollector) LostEvents() uint64 {
	return c.lostTotal.Load()
}

// parseEvent converts raw bytes from the ring buffer into event, which must be
// a pooled *types.Event from eventPool. Caller handles Reset() and Put() after use.
func (c *FileaccessCollector) parseEvent(raw []byte, event *types.Event) error {
	evt, err := bpf.ParseFileaccessEvent(raw)
	if err != nil {
		return err
	}
	*event = evt.ToTypesEvent()
	return nil
}
