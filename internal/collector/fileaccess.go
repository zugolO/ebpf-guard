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

	trackOpen  bool // attach sys_enter_openat hooks
	trackRead  bool // attach sys_enter_read hooks (high volume)
	trackWrite bool // attach sys_enter_write hooks (high volume)
	// trackChmod attaches the chmod/fchmod/fchmodat hooks (волна 6.2.1, слой 3).
	// Включён по умолчанию и НЕ выведен в WithFileOps: три правила о смене прав
	// переведены на файловую ось и без этих хуков молчат, а выключатель, гасящий
	// правила без единой записи в логе, — это ровно тот тихий отказ, ради
	// которого волна и затевалась. Объём мал (chmod на порядки реже read/write),
	// так что торговаться тут не за что.
	trackChmod bool
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
		trackChmod: true,
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
	readLoopDone := runReadLoop(func() { c.readLoop(ctx, out) })

	// Wait for context cancellation, then for readLoop to actually stop
	// sending (5.8d) — Close() unblocks the ring buffer Read() readLoop may
	// be parked in, and Close() runs after ctx is already done.
	<-ctx.Done()
	c.logger.Info("stopping fileaccess collector")
	<-readLoopDone
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

// KernelFilterMaps returns the comm_filter_map, syscall_filter_map,
// kernel_filter_config, and agent_pid_map BPF maps backing this collector's
// content filter, or nil maps if the collector has not loaded (stub mode).
//
// These maps are declared in bpf/common.h, so every BPF object file gets its
// OWN instance of them — the fileaccess program does not see values written
// into the syscall collector's copies. Wave 0.5 (kernel_filter + agent
// self-exclusion in fileaccess.bpf.c) therefore requires populating this
// collector's maps separately; see enableKernelFilter in cmd/ebpf-guard.
func (c *FileaccessCollector) KernelFilterMaps() (comm, syscall, cfg, agentPid *ebpf.Map) {
	if c.objs == nil {
		return nil, nil, nil, nil
	}
	return c.objs.CommFilterMap, c.objs.SyscallFilterMap, c.objs.KernelFilterConfig, c.objs.AgentPidMap
}

// PathFilterMaps returns the path_filter_map and path_filter_drop_counters
// BPF maps backing this collector's path-prefix denylist (P1-18b), or nil
// maps if the collector has not loaded (stub mode).
//
// Only fileaccess.bpf.c consults path_filter_map — trace_open checks it
// against the raw filename before reserving a ring buffer slot, and
// trace_read/trace_write check it against the fd_path_map-resolved path,
// also before reserving. See bpf/fileaccess.bpf.c for the ordering rationale.
func (c *FileaccessCollector) PathFilterMaps() (pathMap, dropCounters *ebpf.Map) {
	if c.objs == nil {
		return nil, nil
	}
	return c.objs.PathFilterMap, c.objs.PathFilterDropCounters
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
func (c *FileaccessCollector) ObserverFilterMaps() (rootMap, excludedCounters *ebpf.Map) {
	if c.objs == nil {
		return nil, nil
	}
	return c.objs.ObserverRootPid, c.objs.ObserverExcludedCounters
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
	for name, p := range map[string]*ebpf.Program{
		"trace_chmod":    c.objs.TraceChmod,
		"trace_fchmodat": c.objs.TraceFchmodat,
		"trace_fchmod":   c.objs.TraceFchmod,
	} {
		if p != nil {
			progs[name] = p
		}
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

	// Волна 6.2.1, слой 3: смена прав на файловой оси. Три правила
	// (evasion_chmod_sensitive, sigma_chmod_executable_tmp,
	// sigma_sensitive_file_chmod) переехали сюда с syscall-оси, где путь не
	// разрешался и все три проверяли одно и то же «случился chmod».
	//
	// Неудача привязки НЕ тихая. sys_chmod и sys_fchmodat есть не на всякой
	// архитектуре (на arm64 chmod(2) отсутствует, glibc идёт через
	// fchmodat), поэтому промах одного хука — штатное разнообразие ядер, а не
	// поломка, и падать из-за него нельзя. Но и молчать нельзя: без счётчика
	// «ноль chmod-алертов за прогон» неотличим от «chmod никто не звал». Оба
	// исхода материализуются с нуля, чтобы прогон без единой привязки
	// отличался в /metrics от бинаря, который счётчика не знает.
	if c.trackChmod {
		chmodHooks := []struct {
			tp   string
			prog *ebpf.Program
		}{
			{"sys_enter_chmod", c.objs.TraceChmod},
			{"sys_enter_fchmodat", c.objs.TraceFchmodat},
			{"sys_enter_fchmod", c.objs.TraceFchmod},
		}
		attached := 0
		for _, h := range chmodHooks {
			if h.prog == nil {
				exporter.RecordFileHookAttach(h.tp, "missing")
				continue
			}
			l, err := link.Tracepoint("syscalls", h.tp, h.prog, nil)
			if err != nil {
				exporter.RecordFileHookAttach(h.tp, "error")
				c.logger.Warn("failed to attach chmod hook", "tracepoint", h.tp, "error", err)
				continue
			}
			exporter.RecordFileHookAttach(h.tp, "ok")
			c.links = append(c.links, l)
			attached++
		}
		if attached == 0 {
			// Ни одного хука — правила о смене прав на этом ядре мертвы
			// целиком. Это не повод падать (агент детектирует ещё сотнями
			// правил), но повод сказать вслух: критерий, считающий их
			// срабатывания, читать нельзя.
			c.logger.Error("no chmod hook attached: the file-axis chmod rules cannot fire on this kernel")
		}
	}

	c.logger.Info("fileaccess hooks attached",
		slog.Bool("open", c.trackOpen),
		slog.Bool("read", c.trackRead),
		slog.Bool("write", c.trackWrite),
		slog.Bool("chmod", c.trackChmod),
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
			exporter.RecordEventDrop("fileaccess", "ringbuf_to_router", defaultEventPriority(event.Type))
			c.dropLogger.record(c.logger, "ringbuf_to_router")
			// plan.md 5.9.8b (№91): a canary event dropped here never
			// reaches the point in main.go that counts stage="events" — it
			// has to be attributed to the canary series right here, or the
			// canary series would systematically undercount relative to N
			// under the very mode (drop) it exists to measure.
			if event.Type == types.EventFileAccess && event.File != nil && exporter.IsCountingCanaryPath(event.File.FDPath) {
				exporter.RecordCountingCanary("dropped")
			}
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
func (c *FileaccessCollector) LostEvents() uint64 {
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
func (c *FileaccessCollector) RingbufFullMap() *ebpf.Map {
	if c.objs == nil {
		return nil
	}
	return c.objs.RingbufFullCounters
}

// EmittedMap returns the events_emitted_counters BPF map — the kernel-side
// count of successful bpf_ringbuf_reserve() calls, i.e. events the kernel
// actually produced, the left-hand side of 5.9.6b's event balance identity
// (№72) — or nil in stub/dry-run mode.
func (c *FileaccessCollector) EmittedMap() *ebpf.Map {
	if c.objs == nil {
		return nil
	}
	return c.objs.EventsEmittedCounters
}

// parseEvent converts raw bytes from the ring buffer into event, which must be
// a pooled *types.Event from eventPool. Caller handles Reset() and Put() after use.
func (c *FileaccessCollector) parseEvent(raw []byte, event *types.Event) error {
	var fe bpf.FileaccessEvent
	if err := bpf.ParseFileaccessEventInto(raw, &fe); err != nil {
		return err
	}
	*event = fe.ToTypesEvent()

	// Волна 6.2.1, слой 3. chmod, чей путь не разрешился, — это fchmod(2) по
	// дескриптору, открытому до старта агента или вытесненному из LRU
	// fd→путь. Такое событие правилам с префиксом пути не подходит, то есть
	// не даёт алерта. Отличие «правила молчат, потому что никто не менял прав
	// в опасных местах» от «правила молчат, потому что мы не узнали путь»
	// держится ровно на этом счётчике: без него сужение слоя 3 выглядело бы
	// успешным в обоих случаях.
	if event.Type == types.EventFileAccess && event.File != nil &&
		event.File.Op == fileOpChmod && event.File.FDPath == "" {
		exporter.RecordChmodUnresolved()
	}
	return nil
}

// fileOpChmod — FILE_OP_CHMOD из bpf/common.h. Держится здесь, а не берётся
// из correlator.fileOpNames, чтобы коллектор не зависел от корреляционного
// слоя ради одной константы протокола.
const fileOpChmod uint8 = 3
