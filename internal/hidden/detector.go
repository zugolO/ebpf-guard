// Package hidden provides hidden process detection by comparing the kernel
// task list (obtained via BPF iter/task on kernel 5.8+) against /proc
// enumeration. Any PID present in the kernel list but absent from /proc is a
// hidden process — a classic rootkit behaviour (LKM or LD_PRELOAD based).
//
// When the BPF task iterator is unavailable (kernel < 5.8 or BPF load failure),
// the detector logs a warning and stays in standby mode without emitting alerts.
package hidden

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/zugolO/ebpf-guard/internal/bpf"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// hiddenProcessesGauge reports the number of hidden processes detected
// in the most recent scan.
var hiddenProcessesGauge = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "ebpf_guard_hidden_processes_total",
	Help: "Number of processes visible to the kernel but hidden from /proc.",
})

// Config holds hidden process detector settings.
type Config struct {
	// Enabled activates periodic hidden process detection.
	Enabled bool
	// CheckInterval is the interval between kernel-vs-proc comparisons.
	// Default: 60s
	CheckInterval time.Duration
	// AlertSeverity is the severity applied to hidden process alerts.
	// Default: "critical"
	AlertSeverity string
}

// DefaultConfig returns a Config with safe defaults.
func DefaultConfig() Config {
	return Config{
		Enabled:        false,
		CheckInterval:  60 * time.Second,
		AlertSeverity:  "critical",
	}
}

// processInfo holds a single process entry from either kernel or /proc enumeration.
type processInfo struct {
	TGID uint32
	PID  uint32
	Comm string
}

// Detector periodically compares the kernel task list against /proc to find
// hidden processes.
type Detector struct {
	logger *slog.Logger
	cfg    Config

	mu           sync.Mutex
	objs         *bpf.HiddenProcessObjects
	iter         *link.Iter
	loadErr      error
	lastScanNano atomic.Int64 // Unix nanoseconds; written by scan goroutine, read by LastScan
}

// New creates a new hidden process Detector.
func New(logger *slog.Logger, cfg Config) *Detector {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.CheckInterval <= 0 {
		cfg.CheckInterval = 60 * time.Second
	}
	if cfg.AlertSeverity == "" {
		cfg.AlertSeverity = "critical"
	}
	return &Detector{
		logger: logger.With("component", "hidden"),
		cfg:    cfg,
	}
}

// Start begins periodic hidden process detection. The alertFn is called for
// each hidden process found. Blocks until ctx is cancelled or an error occurs.
func (d *Detector) Start(ctx context.Context, alertFn func(types.Alert)) error {
	if err := d.loadIterator(); err != nil {
		d.logger.Warn("hidden: BPF task iterator unavailable, detector in standby mode",
			slog.Any("error", err))
		d.loadErr = err
		// Still start the loop — it will skip scans when the iterator is unavailable.
	}

	d.logger.Info("hidden: starting periodic detection",
		slog.Duration("interval", d.cfg.CheckInterval))

	go func() {
		ticker := time.NewTicker(d.cfg.CheckInterval)
		defer ticker.Stop()

		// Run an initial scan after a short delay to avoid racing with other startup.
		initialDelay := d.cfg.CheckInterval / 2
		if initialDelay < 5*time.Second {
			initialDelay = 5 * time.Second
		}
		select {
		case <-time.After(initialDelay):
			d.scan(alertFn)
		case <-ctx.Done():
			return
		}

		for {
			select {
			case <-ticker.C:
				d.scan(alertFn)
			case <-ctx.Done():
				return
			}
		}
	}()

	<-ctx.Done()
	d.logger.Info("hidden: stopping periodic detection")
	d.Close()
	return nil
}

// scan performs a single kernel-vs-proc comparison and emits alerts.
func (d *Detector) scan(alertFn func(types.Alert)) {
	kernelTasks, err := d.enumerateKernelTasks()
	if err != nil {
		d.logger.Warn("hidden: failed to enumerate kernel tasks", slog.Any("error", err))
		hiddenProcessesGauge.Set(-1)
		return
	}

	procTasks, err := enumerateProc()
	if err != nil {
		d.logger.Warn("hidden: failed to enumerate proc", slog.Any("error", err))
		hiddenProcessesGauge.Set(-1)
		return
	}

	hidden := diffTasks(kernelTasks, procTasks)
	d.lastScanNano.Store(time.Now().UnixNano())
	hiddenProcessesGauge.Set(float64(len(hidden)))

	if len(hidden) > 0 {
		d.logger.Warn("hidden: detected processes visible to kernel but hidden from /proc",
			slog.Int("count", len(hidden)))

		for _, p := range hidden {
			sev := types.SeverityCritical
			if d.cfg.AlertSeverity == "warning" {
				sev = types.SeverityWarning
			}
			alertFn(types.Alert{
				RuleID:    "hidden_process",
				RuleName:  "Hidden Process Detected",
				Severity:  sev,
				PID:       p.TGID,
				Comm:      p.Comm,
				Message: fmt.Sprintf(
					"Process %s (TGID %d) is visible to the kernel but absent from /proc — this is a strong indicator of a rootkit hiding processes",
					p.Comm, p.TGID),
				Timestamp: time.Now(),
				Details: map[string]interface{}{
					"tgid":        p.TGID,
					"pid":         p.PID,
					"comm":        p.Comm,
					"description": "Kernel task list contains this PID but /proc does not — classic rootkit behaviour",
				},
			})
		}
	} else {
		d.logger.Debug("hidden: no hidden processes detected",
			slog.Int("kernel_tasks", len(kernelTasks)),
			slog.Int("proc_entries", len(procTasks)))
	}
}

// loadIterator loads the BPF task iterator program and attaches it.
func (d *Detector) loadIterator() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	objs := &bpf.HiddenProcessObjects{}
	if err := bpf.LoadHiddenProcessObjects(objs, nil); err != nil {
		d.loadErr = err
		return fmt.Errorf("load hidden process BPF objects: %w", err)
	}

	iter, err := link.AttachIter(link.IterOptions{Program: objs.DumpTask})
	if err != nil {
		objs.Close()
		d.loadErr = err
		return fmt.Errorf("attach iter/task: %w", err)
	}

	d.objs = objs
	d.iter = iter
	d.loadErr = nil
	return nil
}

// enumerateKernelTasks reads the kernel task list via the BPF task iterator.
func (d *Detector) enumerateKernelTasks() ([]processInfo, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.iter == nil {
		return nil, fmt.Errorf("hidden: BPF iterator not loaded: %w", d.loadErr)
	}

	reader, err := d.iter.Open()
	if err != nil {
		return nil, fmt.Errorf("open iterator: %w", err)
	}
	defer reader.Close()

	buf := make([]byte, 65536)
	n, err := reader.Read(buf)
	if err != nil && err.Error() != "EOF" {
		return nil, fmt.Errorf("read iterator: %w", err)
	}

	var tasks []processInfo
	lines := strings.Split(strings.TrimSpace(string(buf[:n])), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var tgid, pid uint32
		var comm string
		if _, err := fmt.Sscanf(line, "%d %d %s", &tgid, &pid, &comm); err != nil {
			continue
		}
		tasks = append(tasks, processInfo{TGID: tgid, PID: pid, Comm: comm})
	}
	return tasks, nil
}

// enumerateProc reads /proc to build a set of visible PIDs.
func enumerateProc() ([]processInfo, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("read /proc: %w", err)
	}

	var tasks []processInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue
		}

		comm := readProcComm(uint32(pid))
		tasks = append(tasks, processInfo{TGID: uint32(pid), PID: uint32(pid), Comm: comm})
	}
	return tasks, nil
}

// diffTasks returns process info entries present in kernel but absent from proc.
// Comparison is done on TGID (what userspace calls PID).
func diffTasks(kernel, proc []processInfo) []processInfo {
	procSet := make(map[uint32]bool, len(proc))
	for _, p := range proc {
		procSet[p.TGID] = true
	}

	var hidden []processInfo
	seen := make(map[uint32]bool, len(kernel))
	for _, k := range kernel {
		if procSet[k.TGID] || seen[k.TGID] {
			continue
		}
		seen[k.TGID] = true
		hidden = append(hidden, k)
	}
	sort.Slice(hidden, func(i, j int) bool { return hidden[i].TGID < hidden[j].TGID })
	return hidden
}

// readProcComm reads /proc/<pid>/comm for the process name.
func readProcComm(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// Close releases BPF resources.
func (d *Detector) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.iter != nil {
		d.iter.Close()
		d.iter = nil
	}
	if d.objs != nil {
		d.objs.Close()
		d.objs = nil
	}
}

// LastScan returns the time of the most recent scan.
func (d *Detector) LastScan() time.Time {
	ns := d.lastScanNano.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

// IsHealthy returns true when the BPF iterator loaded successfully.
func (d *Detector) IsHealthy() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.loadErr == nil && d.iter != nil
}
