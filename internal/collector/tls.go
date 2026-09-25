// Package collector provides eBPF-based event collection from the kernel.
package collector

import (
	"bufio"
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/zugolO/ebpf-guard/internal/bpf"
	"github.com/zugolO/ebpf-guard/internal/exporter"
	"github.com/zugolO/ebpf-guard/pkg/types"
	"golang.org/x/sys/unix"
)

var tlsTrackedPIDsGauge = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "ebpf_guard_tls_tracked_pids_total",
	Help: "Current number of PIDs tracked by the TLS collector (processes with libssl uprobes attached).",
})

// tlsAttachFailuresCounter tracks why the TLS collector failed to attach to a
// process, split by reason. Volume 6.4 finding №379: with no counter, "collector
// never attached to anyone" and "no TLS traffic on this node" were the same log
// line (silence at debug level) — indistinguishable without a stand.
var tlsAttachFailuresCounter = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "ebpf_guard_tls_attach_failures_total",
	Help: "TLS uprobe attach failures by reason (objects_not_loaded, no_symbols, no_elf, no_symbol_found, attach_failed, libssl_mismatch).",
}, []string{"reason"})

// tlsAttachFailureReasons enumerates every label value
// ebpf_guard_tls_attach_failures_total can carry, and is materialized in init
// below. Finding №439: until this existed, a run where scanAndAttach never
// fired (№436) read the *absence* of the series as "0 attach failures" — the
// same number as a run that tried and succeeded. Materializing all reasons at
// init makes "0" mean "the binary knows this counter and it is zero" and
// leaves "series not present" as the only signal that the code path is dead.
var tlsAttachFailureReasons = []string{
	"objects_not_loaded",
	"no_elf",
	"no_symbols",
	"no_symbol_found",
	"libssl_mismatch",
	"attach_failed",
}

func init() {
	for _, reason := range tlsAttachFailureReasons {
		tlsAttachFailuresCounter.WithLabelValues(reason)
	}
}

// tlsScansCounter counts completed libssl discovery scans. Finding №445: the
// only evidence that scanAndAttach ran at all was tracked_pids > 0, which is a
// property of the NODE (are there libssl processes?) and not of the collector.
// On a node without a single libssl process a live collector and the dead
// stub-mode one of №436 printed the same zero, so "the discovery loop runs" was
// unmeasurable — the same overloaded zero as №439, one level up.
var tlsScansCounter = promauto.NewCounter(prometheus.CounterOpts{
	Name: "ebpf_guard_tls_scans_total",
	Help: "libssl discovery scans run (proof the discovery loop runs, independent of whether any libssl process exists or /proc is readable).",
})

// tlsAttachSuccessCounter counts successful uprobe attachments over the life of
// the process. Finding №449: tlsTrackedPIDsGauge is INSTANTANEOUS — a PID that
// exits is dropped by cleanupDeadPIDs and the gauge falls back to zero — while
// the verdict it feeds ("attachment succeeded for at least one process") is
// RETROSPECTIVE. The positive controls of wave 6.4 kill their own holder by
// design, so a run where attachment worked perfectly read tracked_pids=0 at
// verdict time and was indistinguishable from a run where it never attached.
// A monotonic counter answers the question the verdict actually asks.
var tlsAttachSuccessCounter = promauto.NewCounter(prometheus.CounterOpts{
	Name: "ebpf_guard_tls_attach_success_total",
	Help: "Successful libssl uprobe attachments since start (monotonic; unlike tracked_pids it survives the process exiting).",
})

// tlsScanCandidatesGauge reports how many processes the last scan saw mapping
// libssl. It separates "the scan ran and the node has no TLS" from "the scan
// ran and attachment failed" without reading attach_failures.
var tlsScanCandidatesGauge = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "ebpf_guard_tls_scan_candidates",
	Help: "Processes mapping libssl seen by the most recent discovery scan.",
})

// TLSCollector collects TLS plaintext events using eBPF uprobes on libssl.
// It attaches to SSL_write and SSL_read functions to capture data before encryption
// and after decryption.
//
// Requirements:
//   - CAP_SYS_PTRACE capability for uprobe attachment
//   - Target processes must use OpenSSL/libssl (Go crypto/tls is not supported)
//
// Limitations:
//   - Only captures first 256 bytes of each SSL_write/SSL_read call
//   - May miss data if buffer spans multiple calls
//   - Does not capture Go's native TLS implementation
type TLSCollector struct {
	logger          *slog.Logger
	objs            *tlsObjects
	links           []link.Link
	reader          *ringbuf.Reader
	loadError       error
	enabled         bool
	libsslPaths     map[uint32]string // pid -> libssl path
	mu              sync.RWMutex
	scanInterval    time.Duration
	cleanupInterval time.Duration
	maxDataSize     int // bytes of plaintext exposed downstream (default 256)
	dropLogger      *dropLogger
	ctx             context.Context
	cancel          context.CancelFunc
	status          StatusReporter
	strategy        BackpressureStrategy
	ringBufSize     int // 0 = auto-detect
	lostTotal       atomic.Uint64

	// loadObjectsFn is a test seam: when non-nil it replaces the BPF load,
	// letting tests force stub mode (№436) deterministically without a
	// kernel or a generated BPF object. Production leaves it nil.
	loadObjectsFn func() error
}

// tlsObjects holds eBPF objects for TLS collection (generated by bpf2go).
type tlsObjects struct {
	TlsEvents           *ebpf.Map     `ebpf:"tls_events"`
	SslReadContexts     *ebpf.Map     `ebpf:"ssl_read_contexts"`
	TraceSslWrite       *ebpf.Program `ebpf:"trace_ssl_write"`
	TraceSslReadEntry   *ebpf.Program `ebpf:"trace_ssl_read_entry"`
	TraceSslReadRetFull *ebpf.Program `ebpf:"trace_ssl_read_ret_full"`
}

// Close releases all eBPF resources.
func (o *tlsObjects) Close() error {
	return closeObjects(o)
}

// closeObjects is a helper to close all objects.
func closeObjects(objs *tlsObjects) error {
	var errs []error
	if objs.TraceSslWrite != nil {
		errs = append(errs, objs.TraceSslWrite.Close())
	}
	if objs.TraceSslReadEntry != nil {
		errs = append(errs, objs.TraceSslReadEntry.Close())
	}
	if objs.TraceSslReadRetFull != nil {
		errs = append(errs, objs.TraceSslReadRetFull.Close())
	}
	if objs.TlsEvents != nil {
		errs = append(errs, objs.TlsEvents.Close())
	}
	if objs.SslReadContexts != nil {
		errs = append(errs, objs.SslReadContexts.Close())
	}

	// Return first error if any
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// TLSEventRaw is the raw event structure from BPF.
type TLSEventRaw struct {
	Type        uint32
	Timestamp   uint64
	PID         uint32
	TGID        uint32
	PPID        uint32
	UID         uint32
	Comm        [16]byte
	ParentComm  [16]byte
	Direction   uint8
	DataLen     uint32
	CapturedLen uint32
	Data        [256]byte
	HasConnInfo uint8
	Saddr       [16]byte
	Daddr       [16]byte
	Sport       uint16
	Dport       uint16
}

// tlsEventRawSize is the wire size of struct tls_event (bpf/tls_uprobe.bpf.c,
// packed) — derived from the Go mirror above, never a literal (№471).
var tlsEventRawSize = binary.Size(TLSEventRaw{})

// ToTypesEvent converts a raw TLS event to the public types.Event.
func (e *TLSEventRaw) ToTypesEvent() types.Event {
	var direction types.TLSDirection
	if e.Direction == 0 {
		direction = types.TLSDirectionWrite
	} else {
		direction = types.TLSDirectionRead
	}

	return types.Event{
		Type:       types.EventTLS,
		Timestamp:  types.KtimeToEpoch(e.Timestamp),
		PID:        e.PID,
		TGID:       e.TGID,
		PPID:       e.PPID,
		UID:        e.UID,
		Comm:       e.Comm,
		ParentComm: e.ParentComm,
		TLS: &types.TLSEvent{
			Direction: direction,
			DataLen:   e.DataLen,
			// CapturedSet: the kernel filled captured_len for this record, so
			// zero means "nothing was read", not "unset" (№443).
			CapturedLen: e.CapturedLen,
			CapturedSet: true,
			Data:        e.Data,
		},
	}
}

// NewTLSCollector creates a new TLS event collector.
//
// The collector starts disabled. Call Start() to begin collection.
// If the collector fails to load (e.g., missing CAP_SYS_PTRACE), it enters
// "stub mode" where IsHealthy() returns false but the collector continues
// to run without crashing.
func NewTLSCollector(logger *slog.Logger, enabled bool) (*TLSCollector, error) {
	ctx, cancel := context.WithCancel(context.Background())

	return &TLSCollector{
		logger:          logger.With("collector", "tls"),
		enabled:         enabled,
		libsslPaths:     make(map[uint32]string),
		scanInterval:    30 * time.Second,
		cleanupInterval: 60 * time.Second,
		maxDataSize:     256,
		dropLogger:      newDropLogger(5 * time.Second),
		ctx:             ctx,
		cancel:          cancel,
		status:          NoopStatusReporter{},
		strategy:        StrategyDrop,
	}, nil
}

// WithStatusReporter sets the StatusReporter used to signal up/down state.
func (c *TLSCollector) WithStatusReporter(r StatusReporter) *TLSCollector {
	c.status = r
	return c
}

// WithBackpressureStrategy sets the backpressure strategy for the event channel.
func (c *TLSCollector) WithBackpressureStrategy(s BackpressureStrategy) *TLSCollector {
	c.strategy = s
	return c
}

// WithRingBufSize sets the BPF ring buffer size in bytes for this collector.
// Zero (default) auto-detects the size from /proc/meminfo.
func (c *TLSCollector) WithRingBufSize(sizeBytes int) *TLSCollector {
	c.ringBufSize = sizeBytes
	return c
}

// WithScanInterval overrides the libssl discovery scan interval
// (collectors.tls.scan_interval). Non-positive durations keep the default.
func (c *TLSCollector) WithScanInterval(d time.Duration) *TLSCollector {
	if d > 0 {
		c.scanInterval = d
	}
	return c
}

// WithMaxDataSize overrides how many captured plaintext bytes are exposed
// downstream (collectors.tls.max_data_size). The kernel caps capture at 256
// bytes (TLS_DATA_MAX in bpf/tls_uprobe.bpf.c), so larger values do not
// capture more; smaller values truncate the buffer before it reaches rules,
// alerts and the store. Non-positive values keep the default.
func (c *TLSCollector) WithMaxDataSize(n int) *TLSCollector {
	if n > 0 {
		c.maxDataSize = n
	}
	return c
}

// Name returns the collector identifier.
func (c *TLSCollector) Name() string {
	return "tls"
}

// Start attaches eBPF uprobes and begins sending events.
// Blocks until ctx is cancelled.
//
// If the collector is disabled (enabled=false in config), this returns immediately
// without loading any eBPF programs.
func (c *TLSCollector) Start(ctx context.Context, out chan<- types.Event) error {
	if !c.enabled {
		c.logger.Info("TLS collector disabled, skipping startup")
		c.status.SetUp("tls", true) // Mark as "up" but idle
		<-ctx.Done()
		return nil
	}

	c.logger.Info("starting TLS collector")

	// Load eBPF objects
	if err := c.loadObjects(); err != nil {
		c.loadError = err
		c.status.SetUp("tls", false)
		// №439: count the *stub-mode entry itself* as an attach failure. Before
		// this, the load stub (№436) returned before a single scanAndAttach ran,
		// so the counter was never touched and "0 failures" was indistinguishable
		// from "nothing was ever attempted".
		tlsAttachFailuresCounter.WithLabelValues("objects_not_loaded").Inc()
		c.logger.Error("failed to load TLS eBPF objects, entering stub mode", slog.Any("error", err))
		// Enter stub mode - wait for context cancellation
		<-ctx.Done()
		return nil
	}

	// Start libssl discovery goroutine
	go c.discoveryLoop(ctx)

	// Start dead-PID cleanup goroutine
	go c.cleanupDeadPIDs(ctx)

	// Create ring buffer reader
	reader, err := ringbuf.NewReader(c.objs.TlsEvents)
	if err != nil {
		c.loadError = err
		c.status.SetUp("tls", false)
		c.Close()
		c.logger.Error("failed to create ringbuf reader, entering stub mode", slog.Any("error", err))
		<-ctx.Done()
		return nil
	}
	c.reader = reader
	c.loadError = nil
	c.status.SetUp("tls", true)

	// Start reading loop
	readLoopDone := runReadLoop(func() { c.readLoop(ctx, out) })

	// Wait for context cancellation, then for readLoop to actually stop
	// sending (5.8d) — Close() unblocks the ring buffer Read() readLoop may
	// be parked in, and Close() runs after ctx is already done.
	<-ctx.Done()
	c.logger.Info("stopping TLS collector")
	<-readLoopDone
	return nil
}

// IsHealthy returns true if the collector loaded successfully.
func (c *TLSCollector) IsHealthy() bool {
	return !c.enabled || c.loadError == nil
}

// LoadError returns the error from failed load, if any.
func (c *TLSCollector) LoadError() error {
	return c.loadError
}

// IsAttached returns true if the BPF program is still attached.
func (c *TLSCollector) IsAttached() bool {
	if c.objs == nil {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.links) > 0
}

// Close releases all eBPF resources.
func (c *TLSCollector) Close() error {
	c.logger.Info("closing TLS collector")
	c.cancel()

	if c.reader != nil {
		c.reader.Close()
		c.reader = nil
	}

	c.mu.Lock()
	for _, l := range c.links {
		l.Close()
	}
	c.links = nil
	c.mu.Unlock()

	if c.objs != nil {
		c.objs.Close()
		c.objs = nil
	}

	return nil
}

// loadObjects loads the eBPF objects generated by bpf2go from
// bpf/tls_uprobe.bpf.c. №436: before this, the function was an unconditional
// stub — LoadTlsUprobeObjects existed but was never called from anywhere, so
// Start() entered stub mode *above* discoveryLoop and scanAndAttach never ran
// once in the process's lifetime.
//
// The tls_events ring buffer size is applied to the collection spec BEFORE
// loading, because a BPF ring buffer's max_entries is fixed at map-creation
// time; the previous code computed ComputeRingBufSize and threw it away.
func (c *TLSCollector) loadObjects() error {
	if c.loadObjectsFn != nil {
		return c.loadObjectsFn()
	}
	ringSize := bpf.ComputeRingBufSize(bpf.RingBufSizeConfig{SizeBytes: c.ringBufSize})
	c.logger.Info("TLS collector ring buffer size", slog.Int("bytes", ringSize))

	spec, err := bpf.LoadTlsUprobe()
	if err != nil {
		return fmt.Errorf("load tls_uprobe spec: %w", err)
	}
	mapSpec, ok := spec.Maps["tls_events"]
	if !ok || mapSpec == nil {
		return fmt.Errorf("tls_uprobe spec has no tls_events map")
	}
	mapSpec.MaxEntries = uint32(ringSize)

	objs := &bpf.TlsUprobeObjects{}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		return fmt.Errorf("load tls_uprobe objects: %w", err)
	}

	c.objs = &tlsObjects{
		TlsEvents:           objs.TlsEvents,
		SslReadContexts:     objs.SslReadContexts,
		TraceSslWrite:       objs.TraceSslWrite,
		TraceSslReadEntry:   objs.TraceSslReadEntry,
		TraceSslReadRetFull: objs.TraceSslReadRetFull,
	}
	return nil
}

// discoveryLoop periodically scans for processes using libssl and attaches uprobes.
func (c *TLSCollector) discoveryLoop(ctx context.Context) {
	ticker := time.NewTicker(c.scanInterval)
	defer ticker.Stop()

	// Initial scan
	c.scanAndAttach()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.scanAndAttach()
		}
	}
}

// cleanupDeadPIDs periodically removes entries for processes that no longer exist.
// Linux reuses PIDs, so stale entries would cause missed uprobe attachments for new processes.
func (c *TLSCollector) cleanupDeadPIDs(ctx context.Context) {
	ticker := time.NewTicker(c.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.mu.Lock()
			for pid := range c.libsslPaths {
				if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); os.IsNotExist(err) {
					delete(c.libsslPaths, pid)
				}
			}
			tlsTrackedPIDsGauge.Set(float64(len(c.libsslPaths)))
			c.mu.Unlock()
		}
	}
}

// scanAndAttach scans /proc for processes using libssl and attaches uprobes.
func (c *TLSCollector) scanAndAttach() {
	// №445: the scan is counted BEFORE it can fail, and counted even when it
	// attaches to nothing — so "the discovery loop runs" stops depending on
	// the node having libssl processes or on /proc being readable. A scan that
	// could not read /proc still moves the counter and leaves candidates at 0,
	// with the reason in the log.
	candidates := 0
	defer func() {
		tlsScansCounter.Inc()
		tlsScanCandidatesGauge.Set(float64(candidates))
	}()

	entries, err := os.ReadDir("/proc")
	if err != nil {
		c.logger.Warn("failed to read /proc", slog.Any("error", err))
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// Check if directory name is a PID
		pid, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue
		}

		// Check if we already attached to this PID
		c.mu.RLock()
		_, alreadyAttached := c.libsslPaths[uint32(pid)]
		c.mu.RUnlock()
		if alreadyAttached {
			// Still a candidate this scan saw — the gauge answers "how many
			// libssl processes are on this node", not "how many are new".
			candidates++
			continue
		}

		// Look for libssl in this process
		libsslPath := c.findLibsslInPID(uint32(pid))
		if libsslPath == "" {
			continue
		}
		candidates++

		// Try to attach uprobes
		if err := c.attachToPID(uint32(pid), libsslPath); err != nil {
			c.logger.Warn("failed to attach TLS uprobes",
				slog.Uint64("pid", pid),
				slog.String("libssl", libsslPath),
				slog.Any("error", err))
			continue
		}

		c.mu.Lock()
		c.libsslPaths[uint32(pid)] = libsslPath
		tlsTrackedPIDsGauge.Set(float64(len(c.libsslPaths)))
		c.mu.Unlock()
		// №449: monotonic, so a holder that has since exited still proves the
		// attachment happened.
		tlsAttachSuccessCounter.Inc()

		c.logger.Info("attached TLS uprobes",
			slog.Uint64("pid", pid),
			slog.String("libssl", libsslPath))
	}
}

// findLibsslInPID searches for libssl in a process's memory maps.
func (c *TLSCollector) findLibsslInPID(pid uint32) string {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	file, err := os.Open(mapsPath)
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// Look for libssl.so in the mapped files
		if strings.Contains(line, "libssl.so") {
			// Extract the path from the line
			parts := strings.Fields(line)
			if len(parts) >= 6 {
				path := parts[len(parts)-1]
				// Verify it's a real file
				if strings.HasPrefix(path, "/") && !strings.Contains(path, "(deleted)") {
					return path
				}
			}
		}
	}

	return ""
}

// attachToPID attaches uprobes to SSL_write and SSL_read in a process.
//
// libsslPath, as found by findLibsslInPID, is read from /proc/<pid>/maps —
// a path inside the PROCESS's mount namespace, not the host's. For a
// containerized process that path is opened here at /proc/<pid>/root/<path>
// (finding №380): opening it as a host-rooted path either misses (ENOENT) or,
// worse, silently resolves to a different, host-side file at the same path,
// which would attach the uprobe at the wrong offset. A device/inode identity
// check against what the process itself has mapped (from /proc/<pid>/maps)
// guards against that silent mismatch.
func (c *TLSCollector) attachToPID(pid uint32, libsslPath string) error {
	if c.objs == nil {
		return fmt.Errorf("eBPF objects not loaded")
	}

	nsPath := fmt.Sprintf("/proc/%d/root%s", pid, libsslPath)

	if err := verifyLibraryIdentity(nsPath, pid, libsslPath); err != nil {
		tlsAttachFailuresCounter.WithLabelValues("libssl_mismatch").Inc()
		return fmt.Errorf("libssl identity check: %w", err)
	}

	// Open the ELF file to find symbol offsets. DynamicSymbols() reads
	// .dynsym, which every shared library exports by construction;
	// Symbols() reads .symtab, which stripped libraries (stock Ubuntu
	// libssl.so.3, among others) do not carry at all (finding №379).
	f, err := elf.Open(nsPath)
	if err != nil {
		tlsAttachFailuresCounter.WithLabelValues("no_elf").Inc()
		return fmt.Errorf("open elf %s: %w", nsPath, err)
	}
	defer f.Close()

	hasWrite, hasRead, err := resolveSSLSymbols(f)
	if err != nil {
		tlsAttachFailuresCounter.WithLabelValues("no_symbols").Inc()
		return fmt.Errorf("get symbols: %w", err)
	}
	if !hasWrite && !hasRead {
		tlsAttachFailuresCounter.WithLabelValues("no_symbol_found").Inc()
		return fmt.Errorf("SSL_write and SSL_read symbols not found in %s", nsPath)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Attach SSL_write uprobe
	if hasWrite && c.objs.TraceSslWrite != nil {
		l, err := c.attachUprobe(nsPath, "SSL_write", c.objs.TraceSslWrite)
		if err != nil {
			tlsAttachFailuresCounter.WithLabelValues("attach_failed").Inc()
			return fmt.Errorf("attach SSL_write: %w", err)
		}
		c.links = append(c.links, l)
	}

	// Attach SSL_read entry uprobe
	if hasRead && c.objs.TraceSslReadEntry != nil {
		l, err := c.attachUprobe(nsPath, "SSL_read", c.objs.TraceSslReadEntry)
		if err != nil {
			tlsAttachFailuresCounter.WithLabelValues("attach_failed").Inc()
			return fmt.Errorf("attach SSL_read entry: %w", err)
		}
		c.links = append(c.links, l)
	}

	// Attach SSL_read return uprobe
	if hasRead && c.objs.TraceSslReadRetFull != nil {
		l, err := c.attachUretprobe(nsPath, "SSL_read", c.objs.TraceSslReadRetFull)
		if err != nil {
			tlsAttachFailuresCounter.WithLabelValues("attach_failed").Inc()
			return fmt.Errorf("attach SSL_read ret: %w", err)
		}
		c.links = append(c.links, l)
	}

	return nil
}

// resolveSSLSymbols locates SSL_write/SSL_read in an opened libssl ELF file.
// DynamicSymbols() reads .dynsym, which every shared library exports by
// construction (it's how the dynamic linker resolves the symbol at load
// time); Symbols() reads .symtab, which stripped libraries — stock Ubuntu's
// libssl.so.3 among them — do not carry at all (finding №379). Falling back
// to Symbols() only when DynamicSymbols() comes up empty keeps this working
// on libraries that DO ship a full symbol table too.
func resolveSSLSymbols(f *elf.File) (hasWrite, hasRead bool, err error) {
	symbols, err := f.DynamicSymbols()
	if err != nil || len(symbols) == 0 {
		symbols, err = f.Symbols()
	}
	if err != nil {
		return false, false, err
	}
	for _, sym := range symbols {
		if sym.Name == "SSL_write" {
			hasWrite = true
		}
		if sym.Name == "SSL_read" {
			hasRead = true
		}
	}
	return hasWrite, hasRead, nil
}

// verifyLibraryIdentity confirms that the mount-ns-resolved library file
// (nsPath, e.g. /proc/<pid>/root/usr/lib/.../libssl.so.3) is the SAME file the
// process actually has mapped, by comparing device+inode against the entry in
// /proc/<pid>/maps for libsslPath. A mismatch means the host-visible file at
// that path is a different build than what the process is running — attaching
// there would place the uprobe at the wrong offset without any visible error.
func verifyLibraryIdentity(nsPath string, pid uint32, libsslPath string) error {
	nsInfo, err := os.Stat(nsPath)
	if err != nil {
		return fmt.Errorf("stat %s: %w", nsPath, err)
	}

	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	file, err := os.Open(mapsPath)
	if err != nil {
		return fmt.Errorf("open %s: %w", mapsPath, err)
	}
	defer file.Close()

	// /proc/<pid>/maps device/inode fields are the identity the kernel itself
	// resolved for this mapping in the process's mount namespace — comparing
	// against them (rather than re-stat-ing by path a second time) is what
	// makes this a genuine identity check and not just a second path lookup.
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasSuffix(line, libsslPath) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		devField := fields[3] // "major:minor"
		devParts := strings.SplitN(devField, ":", 2)
		if len(devParts) != 2 {
			continue
		}
		major, errMaj := strconv.ParseUint(devParts[0], 16, 32)
		minor, errMin := strconv.ParseUint(devParts[1], 16, 32)
		if errMaj != nil || errMin != nil {
			continue
		}
		// dev 0:0 means the mapping isn't backed by a regular block device
		// (e.g. overlayfs quirks) — skip the check rather than false-reject.
		if major == 0 && minor == 0 {
			return nil
		}
		if sysInfo, ok := nsInfo.Sys().(*syscall.Stat_t); ok {
			gotMajor := uint64(unix.Major(uint64(sysInfo.Dev)))
			gotMinor := uint64(unix.Minor(uint64(sysInfo.Dev)))
			if gotMajor == major && gotMinor == minor {
				return nil
			}
			return fmt.Errorf("libssl device mismatch: process maps dev %d:%d, host-visible file at %s is dev %d:%d",
				major, minor, nsPath, gotMajor, gotMinor)
		}
		return nil
	}

	// libsslPath not found in maps anymore (process may have exited); not a
	// mismatch, just nothing left to verify against.
	return nil
}

// attachUprobe attaches a uprobe to the named symbol in libPath.
func (c *TLSCollector) attachUprobe(libPath string, symbol string, prog *ebpf.Program) (link.Link, error) {
	ex, err := link.OpenExecutable(libPath)
	if err != nil {
		return nil, fmt.Errorf("open executable %s: %w", libPath, err)
	}
	l, err := ex.Uprobe(symbol, prog, nil)
	if err != nil {
		return nil, fmt.Errorf("attach uprobe %s: %w", symbol, err)
	}
	return l, nil
}

// attachUretprobe attaches a uretprobe to the named symbol in libPath.
func (c *TLSCollector) attachUretprobe(libPath string, symbol string, prog *ebpf.Program) (link.Link, error) {
	ex, err := link.OpenExecutable(libPath)
	if err != nil {
		return nil, fmt.Errorf("open executable %s: %w", libPath, err)
	}
	l, err := ex.Uretprobe(symbol, prog, nil)
	if err != nil {
		return nil, fmt.Errorf("attach uretprobe %s: %w", symbol, err)
	}
	return l, nil
}

// applyMaxDataSize windows the captured plaintext to at most c.maxDataSize
// bytes and returns the effective captured length. The kernel already caps
// capture at 256 bytes (TLS_DATA_MAX), so a larger configured value has no
// effect.
//
// DataLen is deliberately NOT touched: it is the true TLS record length, and
// rules such as `data_len gt 1MB` (exfil_large_tls_upload,
// tls_unexpected_large_transfer) compare against it. The window is carried by
// CapturedLen, which consumers use to slice Data — so a lowered max_data_size
// narrows the visible payload without erasing the record size.
//
// An explicit CapturedLen == 0 (the kernel could not read the userspace
// buffer, or the write was empty) is NOT treated as "unset": Data is zeroed so
// stale ring-buffer bytes from a previous record are never attributed to this
// event, and CapturedSet is raised so consumers read the payload as empty
// rather than as DataLen zero bytes (№443). Only events no collector produced
// (fixtures/replay, CapturedSet false) fall back to DataLen.
func (c *TLSCollector) applyMaxDataSize(e *types.TLSEvent) uint32 {
	capturedLen := e.CapturedLen
	if capturedLen > uint32(len(e.Data)) {
		capturedLen = uint32(len(e.Data))
	}
	// The window this function computes is authoritative on EVERY path,
	// including the zero one: CapturedSet is what makes an explicit zero read
	// as "the kernel captured nothing" downstream instead of falling back to
	// DataLen and handing rules DataLen NUL bytes (№443).
	e.CapturedSet = true
	if capturedLen == 0 {
		for i := range e.Data {
			e.Data[i] = 0
		}
		e.CapturedLen = 0
		return 0
	}
	if c.maxDataSize > 0 && capturedLen > uint32(c.maxDataSize) {
		capturedLen = uint32(c.maxDataSize)
		for i := capturedLen; i < uint32(len(e.Data)); i++ {
			e.Data[i] = 0
		}
	}
	e.CapturedLen = capturedLen
	return capturedLen
}

// readLoop reads events from the ring buffer and sends them to the output channel.
func (c *TLSCollector) readLoop(ctx context.Context, out chan<- types.Event) {
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
			c.logger.Error("failed to read from ringbuf", slog.Any("error", err))
			continue
		}
		// Parse raw event into types.Event
		event, err := c.parseEvent(record.RawSample)
		if err != nil {
			c.logger.Error("failed to parse event", slog.Any("error", err))
			exporter.RecordDropped("tls", "parse_error")
			continue
		}

		// Scan TLS plaintext for W3C Trace Context headers (traceparent/tracestate).
		// This links APM spans to security events when the application is instrumented
		// with OpenTelemetry and passes W3C Trace Context in HTTP/gRPC headers.
		if event.TLS != nil {
			capturedLen := c.applyMaxDataSize(event.TLS)
			if tc := ExtractTraceContext(event.TLS.Data[:capturedLen]); tc != nil {
				event.TraceContext = tc
				if c.logger.Enabled(ctx, slog.LevelDebug) {
					c.logger.Debug("W3C trace context extracted from TLS payload",
						slog.Uint64("pid", uint64(event.PID)),
						slog.String("trace_id", tc.TraceID),
						slog.String("span_id", tc.SpanID),
						slog.String("trace_flags", tc.TraceFlags))
				}
			}
			// Mask sensitive HTTP headers (Authorization, Cookie, Set-Cookie, X-Api-Key,
			// X-Auth-Token) in the captured plaintext before the event propagates to
			// rules, alerts, and the store. The BPF-captured buffer may contain raw
			// HTTP/1.1 or gRPC header frames that include bearer tokens and session
			// cookies. We overwrite the value bytes in-place so no secret ever leaves
			// this function.
			maskSensitiveHeaders(event.TLS.Data[:capturedLen])
		}

		// Debug logging
		if c.logger.Enabled(ctx, slog.LevelDebug) {
			direction := "write"
			if event.TLS.Direction == types.TLSDirectionRead {
				direction = "read"
			}
			c.logger.Debug("TLS event",
				slog.Uint64("pid", uint64(event.PID)),
				slog.String("direction", direction),
				slog.Uint64("data_len", uint64(event.TLS.DataLen)))
		}

		sendEvent(ctx, out, *event, c.strategy, func() {
			exporter.RecordEventDrop("tls", "ringbuf_to_router", defaultEventPriority(event.Type))
			c.dropLogger.record(c.logger, "ringbuf_to_router")
			c.lostTotal.Add(1)
		})
	}
}

// LostEvents returns the total number of events lost in the BPF ring buffer
// since the collector started. Implements watchdog.DropTracker.
func (c *TLSCollector) LostEvents() uint64 {
	return c.lostTotal.Load()
}

// parseEvent converts raw bytes from ring buffer to types.Event.
func (c *TLSCollector) parseEvent(raw []byte) (*types.Event, error) {
	if len(raw) < 4 {
		return nil, fmt.Errorf("event too short: %d bytes", len(raw))
	}

	// Parse based on event type
	eventType := binary.LittleEndian.Uint32(raw[0:4])
	if eventType != uint32(types.EventTLS) {
		return nil, fmt.Errorf("unexpected event type: %d", eventType)
	}

	// №471: та же дисциплина, что у http_plaintext — граница ВЫЧИСЛЯЕТСЯ из
	// структуры. Здесь литерал 340 был не фатален (tls_event весит 362, то есть
	// проверка просто пропускала короткий буфер дальше, в binary.Read с менее
	// внятной ошибкой), но именно ОТСЮДА он был скопирован в http_uprobe.go,
	// где стал приборным нулём целого коллектора ([[fixes-must-migrate-to-sibling-controls]]).
	if len(raw) < tlsEventRawSize {
		return nil, fmt.Errorf("TLS event too short: %d bytes (need %d)", len(raw), tlsEventRawSize)
	}

	var rawEvent TLSEventRaw
	buf := bytes.NewReader(raw)
	if err := binary.Read(buf, binary.LittleEndian, &rawEvent); err != nil {
		return nil, fmt.Errorf("parse raw event: %w", err)
	}

	result := rawEvent.ToTypesEvent()
	return &result, nil
}

// GetAttachedPIDs returns the list of PIDs that have uprobes attached.
func (c *TLSCollector) GetAttachedPIDs() []uint32 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	pids := make([]uint32, 0, len(c.libsslPaths))
	for pid := range c.libsslPaths {
		pids = append(pids, pid)
	}
	return pids
}

// DetachFromPID detaches uprobes from a specific PID.
func (c *TLSCollector) DetachFromPID(pid uint32) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.libsslPaths, pid)

	// Note: In a full implementation, we would track which links belong to which PID
	// and close only those. For now, we don't support selective detachment.
	return nil
}

// sensitiveHeaderPrefixes lists HTTP header names whose values must be masked
// in TLS-captured plaintext before the data is forwarded to rules or stored.
// Matching is case-insensitive on the ASCII header name portion.
var sensitiveHeaderPrefixes = [][]byte{
	[]byte("authorization:"),
	[]byte("cookie:"),
	[]byte("set-cookie:"),
	[]byte("x-api-key:"),
	[]byte("x-auth-token:"),
	[]byte("x-amz-security-token:"),
	[]byte("proxy-authorization:"),
}

// schemeBearingHeaders are the sensitive headers whose value starts with an
// auth SCHEME token (RFC 7235: "Authorization: <scheme> <credentials>"). For
// these the scheme is preserved and only the credentials are masked.
//
// Finding №454: masking the whole value destroyed the only substring the
// detection rules match on. `tls_http_basic_auth` looks for
// "Authorization: Basic " and the mask turned that into "Authorization:****",
// so the rule could not fire on ANY node — the product blinded its own
// detection, and the offline fixture run of item 7 could not see it because
// fixtures build a TLSEvent directly and never pass through this readLoop.
//
// The scheme is not a secret and it IS the signal: "a Basic credential
// traveled here" is exactly what the alert reports. The base64 blob after it
// is the secret and stays masked, so the privacy guarantee of this function
// ("credentials never propagate beyond the TLS collector") is unchanged.
var schemeBearingHeaders = [][]byte{
	[]byte("authorization:"),
	[]byte("proxy-authorization:"),
}

// headerBearsScheme reports whether the value of this header name begins with
// an auth scheme token that must survive masking.
func headerBearsScheme(prefix []byte) bool {
	for _, h := range schemeBearingHeaders {
		if string(h) == string(prefix) {
			return true
		}
	}
	return false
}

// maskSensitiveHeaders overwrites the value portion of sensitive HTTP headers
// found in buf with asterisks ('*'). The buffer is modified in-place so that
// credentials never propagate beyond the TLS collector into rules, alerts, or
// the store.
//
// For scheme-bearing headers (Authorization, Proxy-Authorization) the auth
// SCHEME survives and only the credentials after it are masked — see
// schemeBearingHeaders and finding №454. Everything else keeps its entire
// value masked, because there the value IS the secret.
//
// Only HTTP/1.x header format (header-name ":" SP value CRLF) is handled.
// Binary TLS records that don't contain HTTP headers are left unchanged.
func maskSensitiveHeaders(buf []byte) {
	// Work line by line (split on LF; CR is handled naturally).
	start := 0
	for i, b := range buf {
		if b != '\n' {
			continue
		}
		line := buf[start:i]
		// Strip trailing CR if present.
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		for _, prefix := range sensitiveHeaderPrefixes {
			if len(line) <= len(prefix) {
				continue
			}
			// Case-insensitive compare of the header-name portion.
			headerPart := make([]byte, len(prefix))
			copy(headerPart, line[:len(prefix)])
			for j := range headerPart {
				if headerPart[j] >= 'A' && headerPart[j] <= 'Z' {
					headerPart[j] += 32
				}
			}
			if string(headerPart) == string(prefix) {
				// Where the masking starts. By default: everything after the
				// colon, including the leading space.
				maskFrom := start + len(prefix)
				if headerBearsScheme(prefix) {
					// №454: keep "<SP>scheme<SP>" and mask only the
					// credentials after it. The scheme token is the first
					// run of non-space bytes after the colon; masking begins
					// at the space that follows it, so the rule-visible text
					// stays exactly "Authorization: Basic " and the base64
					// credential is still destroyed.
					j := maskFrom
					for j < i && (buf[j] == ' ' || buf[j] == '\t') {
						j++ // leading whitespace before the scheme
					}
					schemeEnd := j
					for schemeEnd < i && buf[schemeEnd] != ' ' && buf[schemeEnd] != '\t' && buf[schemeEnd] != '\r' {
						schemeEnd++
					}
					// The separator whitespace between scheme and credentials
					// must SURVIVE: the rule matches "Authorization: Basic "
					// including that trailing space, so masking starts at the
					// credential itself, not at the separator.
					credStart := schemeEnd
					for credStart < i && (buf[credStart] == ' ' || buf[credStart] == '\t') {
						credStart++
					}
					// Preserve the scheme only when a real credential follows
					// it. A lone token before CRLF IS the value (no scheme at
					// all) and must be masked whole — otherwise a header like
					// "Authorization: <secret>" would leak entirely.
					if schemeEnd > j && credStart < i && buf[credStart] != '\r' {
						maskFrom = credStart
					}
				}
				for k := maskFrom; k < i; k++ {
					if buf[k] != '\r' {
						buf[k] = '*'
					}
				}
				break
			}
		}
		start = i + 1
	}
}
