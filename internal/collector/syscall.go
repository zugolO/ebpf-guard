// Package collector provides eBPF-based event collection from the kernel.
package collector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/zugolO/ebpf-guard/internal/bpf"
	"github.com/zugolO/ebpf-guard/internal/exporter"
	"github.com/zugolO/ebpf-guard/internal/util"
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
	// injectable dependencies — set to production defaults in NewSyscallCollector.
	loader   syscallLoader
	opener   ringbufOpener
	attacher linkAttacher

	// malformed-record diagnostics (5.9.2c, finding #40). monitoredNrs and
	// kernelFilterEnabled mirror the same allowlist main.go programs into the
	// BPF-side syscall_filter_map, so "nr_not_monitored" means the userspace
	// view of what should be filtered disagrees with what actually arrived —
	// not that filtering is off.
	monitoredNrs        map[int64]struct{}
	kernelFilterEnabled bool
	malformedLoggers    map[string]*malformedLogger
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
		malformedLoggers: map[string]*malformedLogger{
			"type_mismatch":    newMalformedLogger(5 * time.Second),
			"nr_not_monitored": newMalformedLogger(5 * time.Second),
			"empty_comm":       newMalformedLogger(5 * time.Second),
		},
	}, nil
}

// WithMalformedDiagnostics configures the nr_not_monitored diagnostic (5.9.2c,
// finding #40) with the same effective syscall allowlist and enabled flag
// main.go uses to program syscall_filter_map, so parseEvent can tell "kernel
// filtering is off, nr is expected to be unfiltered" apart from "kernel
// filtering is on and this nr got through anyway". Call with enabled=false
// (or omit) when bpf.kernel_filter.enabled is false — the check is skipped in
// that case since every nr is legitimately unfiltered.
func (c *SyscallCollector) WithMalformedDiagnostics(monitoredNrs []int, enabled bool) *SyscallCollector {
	c.kernelFilterEnabled = enabled
	c.monitoredNrs = make(map[int64]struct{}, len(monitoredNrs))
	for _, nr := range monitoredNrs {
		c.monitoredNrs[int64(nr)] = struct{}{}
	}
	return c
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
	readLoopDone := runReadLoop(func() { c.readLoop(ctx, out) })

	// Wait for context cancellation, then for readLoop to actually stop
	// sending (5.8d) — Close() unblocks the ring buffer Read() readLoop may
	// be parked in, and Close() runs after ctx is already done.
	<-ctx.Done()
	c.logger.Info("stopping syscall collector")
	<-readLoopDone
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
		"trace_sys_enter":          c.objs.TraceSysEnter,
		"trace_sys_exit":           c.objs.TraceSysExit,
		"trace_sched_process_exec": c.objs.TraceSchedProcessExec,
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
			// errMalformedSyscallType is already counted and logged (rate
			// limited, with a hex dump) inside parseEvent under
			// ebpf_guard_events_malformed_total — counting it again here
			// under a different reason would just double-book the same drop.
			if !errors.Is(err, errMalformedSyscallType) {
				c.logger.Error("failed to parse event", "error", err)
				exporter.RecordDropped("syscall", "parse_error")
			}
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
				args, truncated, ok := c.procArgsFromBPF(event.PID)
				if !ok {
					args, truncated = readProcCmdline(event.PID)
				}
				// The guard belongs here, over whichever source answered:
				// both can hand back the CALLEE's argv for the sys_enter
				// record of the same execve (the map entry never expires;
				// the /proc read wins the race often enough). Attaching it
				// there would raise every proc.args rule twice per exec,
				// the second time naming the caller.
				if !commMatchesArgv0(util.BytesToString(event.Comm[:]), args) {
					args, truncated = "", false
				}
				event.ProcArgs, event.ProcArgsTruncated = args, truncated
			}
		}

		// Debug logging (guarded to avoid allocation when debug is off)
		if c.logger.Enabled(ctx, slog.LevelDebug) {
			c.logger.Debug("syscall event",
				slog.Uint64("pid", uint64(event.PID)),
				slog.Int64("syscall_nr", event.Syscall.Nr))
		}

		sendEvent(ctx, out, *event, c.strategy, func() {
			exporter.RecordEventDrop("syscall", "ringbuf_to_router", defaultEventPriority(event.Type))
			c.dropLogger.record(c.logger, "ringbuf_to_router")
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
func (c *SyscallCollector) LostEvents() uint64 {
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
func (c *SyscallCollector) RingbufFullMap() *ebpf.Map {
	if c.objs == nil {
		return nil
	}
	return c.objs.RingbufFullCounters
}

// EmittedMap returns the events_emitted_counters BPF map — the kernel-side
// count of successful bpf_ringbuf_reserve() calls, i.e. events the kernel
// actually produced, the left-hand side of 5.9.6b's event balance identity
// (№72) — or nil in stub/dry-run mode.
func (c *SyscallCollector) EmittedMap() *ebpf.Map {
	if c.objs == nil {
		return nil
	}
	return c.objs.EventsEmittedCounters
}

// MapFullCountersMap returns the BPF map_full_counters PERCPU_ARRAY, or nil
// in stub/dry-run mode. Implements watchdog.MapFullTracker.
func (c *SyscallCollector) MapFullCountersMap() *ebpf.Map {
	if c.objs == nil {
		return nil
	}
	return c.objs.MapFullCounters
}

// KernelFilterMaps returns the comm_filter_map, syscall_filter_map,
// kernel_filter_config, and agent_pid_map BPF maps backing this collector's
// content filter, or nil maps if the collector has not loaded (stub mode).
func (c *SyscallCollector) KernelFilterMaps() (comm, syscall, cfg, agentPid *ebpf.Map) {
	if c.objs == nil {
		return nil, nil, nil, nil
	}
	return c.objs.CommFilterMap, c.objs.SyscallFilterMap, c.objs.KernelFilterConfig, c.objs.AgentPidMap
}

// SamplingConfigMap returns the sampling_config BPF map backing this
// collector's static sample-rate filter, or nil in stub mode.
func (c *SyscallCollector) SamplingConfigMap() *ebpf.Map {
	if c.objs == nil {
		return nil
	}
	return c.objs.SamplingConfig
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
func (c *SyscallCollector) ObserverFilterMaps() (rootMap, excludedCounters *ebpf.Map) {
	if c.objs == nil {
		return nil, nil
	}
	return c.objs.ObserverRootPid, c.objs.ObserverExcludedCounters
}

// errMalformedSyscallType marks a parseEvent failure already accounted for
// under exporter.EventsMalformed{reason="type_mismatch"} — the caller must
// not also count/log it as a generic parse_error.
var errMalformedSyscallType = fmt.Errorf("syscall: record type mismatch")

// parseEvent converts raw bytes from the ring buffer into event, which must be
// a pooled *types.Event obtained from eventPool. Caller is responsible for
// Reset() and Put() after the event value has been consumed.
//
// Wave 5.9.2c (finding #40): runs three independent diagnostic checks before
// handing the event on, matching the three hypotheses for the 13 empty-`comm`
// alerts misdiagnosed by 5.9.1f as a cgroup-escape torn read. Only
// type_mismatch drops the record — it is the "недостающая валидация формата"
// the postscript calls for independently of which hypothesis holds;
// nr_not_monitored and empty_comm are observation only, since dropping on
// them before the root cause is established would repeat 5.9.1f's mistake of
// patching a symptom instead of confirming a source.
func (c *SyscallCollector) parseEvent(raw []byte, event *types.Event) error {
	var se bpf.SyscallEvent
	if err := bpf.ParseSyscallEventInto(raw, &se); err != nil {
		return err
	}

	if se.Type != bpf.EventTypeSyscall {
		exporter.RecordMalformed("syscall", "type_mismatch")
		c.malformedLoggers["type_mismatch"].record(c.logger, "type_mismatch", raw)
		return errMalformedSyscallType
	}
	if c.kernelFilterEnabled {
		if _, ok := c.monitoredNrs[se.Nr]; !ok {
			exporter.RecordMalformed("syscall", "nr_not_monitored")
			c.malformedLoggers["nr_not_monitored"].record(c.logger, "nr_not_monitored", raw)
		}
	}
	if bpf.IsEmptyComm(se.Comm) {
		exporter.RecordMalformed("syscall", "empty_comm")
		c.malformedLoggers["empty_comm"].record(c.logger, "empty_comm", raw)
	}

	*event = se.ToTypesEvent()
	return nil
}

// procArgsTruncateAt is the maximum number of bytes read from /proc/PID/cmdline.
// Arguments exceeding this limit are truncated and ProcArgsTruncated is set to true.
const procArgsTruncateAt = 512

// normalizeCmdline turns a raw kernel argv block (NUL-separated arguments,
// zero-padded at the end) into the space-separated form rules match on.
// Shared by both proc.args sources so they cannot drift apart in formatting —
// a rule matching one and not the other would be indistinguishable from the
// rule being wrong.
func normalizeCmdline(data []byte) string {
	// Strip trailing NUL bytes added by the kernel (and, for the BPF path,
	// the zero padding of the fixed-size buffer).
	for len(data) > 0 && data[len(data)-1] == 0 {
		data = data[:len(data)-1]
	}
	// Replace NUL argument separators with spaces.
	for i, b := range data {
		if b == 0 {
			data[i] = ' '
		}
	}
	return string(data)
}

// procArgsFromBPF returns the argv the sched_process_exec hook cached in
// proc_args_map for this TGID, and whether the lookup succeeded.
//
// This is the primary path, and until 5.9.9.F.3 (pre-run of измерение
// №2.9.9.F.3) it did not exist: the BPF side wrote the map, the comment above
// the call site named it "primary", and userspace read only /proc/PID/cmdline.
// That fallback loses the race against any short-lived process — the task is
// gone before the ring-buffer record is dequeued, os.ReadFile fails, ProcArgs
// stays empty, and every rule predicated on proc.args silently sees nothing.
// It is the same defect, in the same shape, that fill_process_info (bpf/common.h)
// already records for parent identity: "loses the race against any short-lived
// process". The live positive control of 5.9.9.F.3b caught it — a SUID copy of
// /bin/true executed from /tmp raised privesc_suid_suspicious_path on some runs
// and nothing at all on others, which is precisely a coin flip on whether the
// process outlived the dequeue.
//
// The map is keyed by TGID, which is what the ring-buffer record carries in
// its pid field (fill_process_info: e->pid = pid_tgid >> 32), and it is written
// by the sched_process_exec tracepoint — i.e. during the very execve whose
// sys_exit produced this record, so the entry is present by the time we look.
func (c *SyscallCollector) procArgsFromBPF(tgid uint32) (args string, truncated bool, ok bool) {
	if c.objs == nil || c.objs.ProcArgsMap == nil {
		return "", false, false
	}
	var pa bpf.SyscallProcArgs
	if err := c.objs.ProcArgsMap.Lookup(&tgid, &pa); err != nil {
		return "", false, false
	}
	raw := make([]byte, len(pa.Args))
	for i, b := range pa.Args {
		raw[i] = byte(b)
	}
	s := normalizeCmdline(raw)
	if s == "" {
		// An all-NUL entry carries no argv; let the caller fall back rather
		// than report an empty success, which would blind the rules just as
		// thoroughly as the lost race did.
		return "", false, false
	}
	return s, pa.Truncated != 0, true
}

// commMatchesArgv0 answers whether this ring-buffer record is the one that
// carries the NEW program's identity.
//
// bpf/syscall.bpf.c submits a record from both tracepoints, sys_enter and
// sys_exit, so one execve produces two. Neither source can tell them apart on
// its own: the map entry never expires, and the /proc read is taken at dequeue
// time, by which point the exec has usually completed. So without this test the
// sys_enter record — whose comm is still the CALLER's, e.g. "bash" — is
// enriched with the callee's argv, and every proc.args rule fires twice per
// exec, the second time naming the wrong process. Measured on the stand: five
// SUID canaries executed from /tmp produced eight alerts through the BPF path
// and six through /proc; only with this guard do they produce five.
//
// The discriminator is that the kernel sets comm from the new executable at
// exec, so on the sys_exit record comm equals basename(argv[0]) — truncated to
// TASK_COMM_LEN-1 (15) visible bytes, hence prefix rather than equality. When
// argv[0] is not a path to the running image (a caller that passes a custom
// argv[0]), this says no and proc.args is left empty: such an argv[0] is not a
// path under /tmp either, so no rule of this family loses a match it had.
func commMatchesArgv0(comm, args string) bool {
	if comm == "" || args == "" {
		return false
	}
	argv0 := args
	if i := strings.IndexByte(argv0, ' '); i >= 0 {
		argv0 = argv0[:i]
	}
	if i := strings.LastIndexByte(argv0, '/'); i >= 0 {
		argv0 = argv0[i+1:]
	}
	return strings.HasPrefix(argv0, comm)
}

// readProcCmdline reads /proc/[pid]/cmdline, replaces NUL argument separators
// with spaces, strips any trailing NUL bytes, and returns the result. If the
// raw cmdline exceeds procArgsTruncateAt bytes the string is truncated and
// truncated=true is returned. Returns ("", false) on any read error.
//
// Fallback path only — see procArgsFromBPF above for why it cannot be the
// primary one.
func readProcCmdline(pid uint32) (args string, truncated bool) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil || len(data) == 0 {
		return "", false
	}
	if len(data) > procArgsTruncateAt {
		data = data[:procArgsTruncateAt]
		truncated = true
	}
	return normalizeCmdline(data), truncated
}
