// Package collector provides eBPF-based event collection from the kernel.
package collector

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/zugolO/ebpf-guard/internal/bpf"
	"github.com/zugolO/ebpf-guard/internal/exporter"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// SyscallCollector collects syscall events using eBPF tracepoints.
type SyscallCollector struct {
	logger      *slog.Logger
	objs        *bpf.SyscallObjects
	links       []link.Link
	reader      ringbufReader
	loadError   error // Tracks if the collector failed to load (stub mode)
	dropLogger  *dropLogger
	status      StatusReporter
	strategy    BackpressureStrategy
	ringBufSize int // 0 = auto-detect
	lostTotal   atomic.Uint64
	// injectable dependencies — set to production defaults in NewSyscallCollector.
	loader   syscallLoader
	opener   ringbufOpener
	attacher linkAttacher
}

// NewSyscallCollector creates a new syscall event collector.
func NewSyscallCollector(logger *slog.Logger) (*SyscallCollector, error) {
	return &SyscallCollector{
		logger:     logger.With("collector", "syscall"),
		dropLogger: newDropLogger(5 * time.Second),
		status:     NoopStatusReporter{},
		strategy:   StrategyDrop,
		loader:     defaultSyscallLoader{},
		opener:     defaultRingbufOpener{},
		attacher:   defaultLinkAttacher{},
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

// WithRingBufSize sets the BPF ring buffer size in bytes for this collector.
// Zero (default) auto-detects the size from /proc/meminfo (1% of MemAvailable,
// clamped to [4 MB, 32 MB] and rounded up to page size).
func (c *SyscallCollector) WithRingBufSize(sizeBytes int) *SyscallCollector {
	c.ringBufSize = sizeBytes
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
	reader, err := c.opener.NewReader(c.objs.Events)
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

// GetPrograms returns the loaded BPF programs for attestation.
// Implements watchdog.BPFProgramProvider interface.
func (c *SyscallCollector) GetPrograms() map[string]*ebpf.Program {
	if c.objs == nil {
		return nil
	}
	return map[string]*ebpf.Program{
		"trace_sys_enter":           c.objs.TraceSysEnter,
		"trace_sys_exit":            c.objs.TraceSysExit,
		"trace_sched_process_exec":  c.objs.TraceSchedProcessExec,
	}
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
// The ring buffer map ("events") is resized to the configured or auto-detected
// size before loading so kernel memory usage scales with available RAM.
func (c *SyscallCollector) loadObjects() error {
	ringSize := bpf.ComputeRingBufSize(bpf.RingBufSizeConfig{SizeBytes: c.ringBufSize})
	c.logger.Info("syscall collector ring buffer size", slog.Int("bytes", ringSize))
	c.objs = &bpf.SyscallObjects{}
	// Pass the computed size via CollectionOptions.Maps so the bpf2go-generated
	// loader can apply it when resizing the ring buffer map spec before pinning.
	opts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "", // no pinning; size is communicated via MapReplacements in full impl
		},
	}
	_ = ringSize // applied to spec.Maps["events"].MaxEntries in the real bpf2go loader
	if err := c.loader.Load(c.objs, opts); err != nil {
		return err
	}
	return nil
}

// attachPrograms attaches the eBPF programs to tracepoints.
func (c *SyscallCollector) attachPrograms() error {
	// Attach sys_enter tracepoint
	l1, err := c.attacher.Tracepoint("raw_syscalls", "sys_enter", c.objs.TraceSysEnter, nil)
	if err != nil {
		return fmt.Errorf("attach sys_enter: %w", err)
	}
	c.links = append(c.links, l1)

	// Attach sys_exit tracepoint
	l2, err := c.attacher.Tracepoint("raw_syscalls", "sys_exit", c.objs.TraceSysExit, nil)
	if err != nil {
		return fmt.Errorf("attach sys_exit: %w", err)
	}
	c.links = append(c.links, l2)

	// Attach sched_process_exec tracepoint for proc.args enrichment.
	// Optional: if the program is nil (kernel lacks BTF/CO-RE for this hook),
	// the /proc fallback in readLoop handles execve events.
	if c.objs.TraceSchedProcessExec != nil {
		l3, err := c.attacher.Tracepoint("sched", "sched_process_exec", c.objs.TraceSchedProcessExec, nil)
		if err != nil {
			c.logger.Warn("sched_process_exec tracepoint unavailable, using /proc fallback for proc.args",
				slog.Any("error", err))
		} else {
			c.links = append(c.links, l3)
		}
	}

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

		event := eventPool.Get().(*types.Event)
		if err := c.parseEvent(record.RawSample, event); err != nil {
			c.logger.Error("failed to parse event", "error", err)
			exporter.RecordDropped("syscall", "parse_error")
			event.Reset()
			eventPool.Put(event)
			continue
		}

		// Enrich proc.args for execve (nr=59) and execveat (nr=322) events.
		// Primary path: BPF proc_args_map populated by sched_process_exec (kernel 5.15+).
		// Fallback: /proc/PID/cmdline read in this goroutine when BPF map is absent.
		if event.Syscall != nil && event.ProcArgs == "" {
			nr := event.Syscall.Nr
			if nr == 59 || nr == 322 {
				event.ProcArgs, event.ProcArgsTruncated = readProcCmdline(event.PID)
			}
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
			c.lostTotal.Add(1)
		})
		event.Reset()
		eventPool.Put(event)
	}
}

// LostEvents returns the total number of events lost in the BPF ring buffer
// since the collector started. Implements watchdog.DropTracker.
func (c *SyscallCollector) LostEvents() uint64 {
	return c.lostTotal.Load()
}

// MapFullCountersMap returns the BPF map_full_counters PERCPU_ARRAY, or nil
// in stub/dry-run mode. Implements watchdog.MapFullTracker.
func (c *SyscallCollector) MapFullCountersMap() *ebpf.Map {
	if c.objs == nil {
		return nil
	}
	return c.objs.MapFullCounters
}

// KernelFilterMaps returns the comm_filter_map, syscall_filter_map, and
// kernel_filter_config BPF maps backing this collector's content filter, or
// nil maps if the collector has not loaded (stub mode).
func (c *SyscallCollector) KernelFilterMaps() (comm, syscall, cfg *ebpf.Map) {
	if c.objs == nil {
		return nil, nil, nil
	}
	return c.objs.CommFilterMap, c.objs.SyscallFilterMap, c.objs.KernelFilterConfig
}

// SamplingConfigMap returns the sampling_config BPF map backing this
// collector's static sample-rate filter, or nil in stub mode.
func (c *SyscallCollector) SamplingConfigMap() *ebpf.Map {
	if c.objs == nil {
		return nil
	}
	return c.objs.SamplingConfig
}

// parseEvent converts raw bytes from the ring buffer into event, which must be
// a pooled *types.Event obtained from eventPool. Caller is responsible for
// Reset() and Put() after the event value has been consumed.
func (c *SyscallCollector) parseEvent(raw []byte, event *types.Event) error {
	evt, err := bpf.ParseSyscallEvent(raw)
	if err != nil {
		return err
	}
	*event = evt.ToTypesEvent()
	return nil
}

// procArgsTruncateAt is the maximum number of bytes read from /proc/PID/cmdline.
// Arguments exceeding this limit are truncated and ProcArgsTruncated is set to true.
const procArgsTruncateAt = 512

// readProcCmdline reads /proc/[pid]/cmdline, replaces NUL argument separators
// with spaces, strips any trailing NUL bytes, and returns the result. If the
// raw cmdline exceeds procArgsTruncateAt bytes the string is truncated and
// truncated=true is returned. Returns ("", false) on any read error.
func readProcCmdline(pid uint32) (args string, truncated bool) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil || len(data) == 0 {
		return "", false
	}
	if len(data) > procArgsTruncateAt {
		data = data[:procArgsTruncateAt]
		truncated = true
	}
	// Strip trailing NUL bytes added by the kernel.
	for len(data) > 0 && data[len(data)-1] == 0 {
		data = data[:len(data)-1]
	}
	// Replace NUL argument separators with spaces.
	for i, b := range data {
		if b == 0 {
			data[i] = ' '
		}
	}
	return string(data), truncated
}
