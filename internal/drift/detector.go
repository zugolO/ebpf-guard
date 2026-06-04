package drift

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/zugolO/ebpf-guard/internal/util"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// DriftType identifies what changed relative to the container baseline.
type DriftType string

const (
	DriftNewSyscall  DriftType = "new_syscall"  // syscall not seen during baseline
	DriftNewExec     DriftType = "new_exec"      // new binary executed
	DriftNewLibrary  DriftType = "new_library"   // new shared library loaded
	DriftNewNetwork  DriftType = "new_network"   // new outbound IP or port
	DriftNewFileDir  DriftType = "new_file_dir"  // access to directory not in baseline
)

// DriftAlert is generated when container behaviour deviates from its baseline.
type DriftAlert struct {
	ContainerID string
	Namespace   string
	PodName     string
	DriftType   DriftType
	Detail      string    // human-readable description of what changed
	Severity    types.Severity
	Timestamp   time.Time
	PID         uint32
	Comm        string
}

// Detector maintains per-container baselines and emits DriftAlerts when
// post-baseline events deviate from observed normal behaviour.
type Detector struct {
	mu        sync.RWMutex
	baselines map[string]*ContainerBaseline // keyed by container ID

	window time.Duration // baseline learning window per container

	logger *slog.Logger

	// Prometheus metrics
	driftTotal      *prometheus.CounterVec // drift_detected_total{type, namespace}
	baselineTotal   prometheus.Gauge       // drift_baselines_total
	baselineLocked  prometheus.Gauge       // drift_baselines_locked_total
}

// DetectorConfig holds configuration for the drift Detector.
type DetectorConfig struct {
	// BaselineWindow is how long to observe a container before locking the baseline.
	// Default: 5 minutes.
	BaselineWindow time.Duration
	// Logger is the structured logger to use.
	Logger *slog.Logger
}

// NewDetector creates a Detector with the given configuration.
func NewDetector(cfg DetectorConfig) *Detector {
	window := cfg.BaselineWindow
	if window <= 0 {
		window = 5 * time.Minute
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	d := &Detector{
		baselines: make(map[string]*ContainerBaseline),
		window:    window,
		logger:    logger,
		driftTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ebpf_guard_drift_detected_total",
			Help: "Total container drift events detected, partitioned by type and namespace.",
		}, []string{"type", "namespace"}),
		baselineTotal: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ebpf_guard_drift_baselines_total",
			Help: "Number of container baselines currently tracked.",
		}),
		baselineLocked: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ebpf_guard_drift_baselines_locked_total",
			Help: "Number of container baselines past their learning window (drift-detection active).",
		}),
	}
	return d
}

// RegisterMetrics registers Prometheus metrics with reg.
func (d *Detector) RegisterMetrics(reg prometheus.Registerer) error {
	for _, c := range []prometheus.Collector{d.driftTotal, d.baselineTotal, d.baselineLocked} {
		if err := reg.Register(c); err != nil {
			return err
		}
	}
	return nil
}

// Ingest processes a single event and returns any drift alerts produced.
// Thread-safe; may be called from multiple goroutines.
func (d *Detector) Ingest(e types.Event) []DriftAlert {
	if e.Enrichment == nil || e.Enrichment.ContainerID == "" {
		return nil
	}

	cid := e.Enrichment.ContainerID
	ns := e.Enrichment.Namespace
	pod := e.Enrichment.PodName
	comm := util.BytesToString(e.Comm[:])

	bl := d.getOrCreate(cid, ns, pod)

	// Try to lock the baseline if the window has expired.
	locked := bl.tryLock()

	if !locked {
		// Still in learning phase — record behaviour without alerting.
		d.record(bl, e)
		return nil
	}

	// Baseline is locked — check for deviation.
	return d.checkDrift(bl, e, comm)
}

// getOrCreate returns an existing baseline for containerID or creates a new one.
func (d *Detector) getOrCreate(cid, namespace, podName string) *ContainerBaseline {
	d.mu.RLock()
	if bl, ok := d.baselines[cid]; ok {
		d.mu.RUnlock()
		return bl
	}
	d.mu.RUnlock()

	d.mu.Lock()
	defer d.mu.Unlock()
	// Double-check after acquiring write lock.
	if bl, ok := d.baselines[cid]; ok {
		return bl
	}
	bl := newContainerBaseline(cid, namespace, podName, d.window)
	d.baselines[cid] = bl
	d.baselineTotal.Set(float64(len(d.baselines)))
	d.logger.Info("drift: new container baseline",
		slog.String("container_id", cid),
		slog.String("namespace", namespace),
		slog.String("pod", podName),
		slog.Duration("window", d.window),
	)
	return bl
}

// record folds an event into the baseline (called during learning phase).
func (d *Detector) record(bl *ContainerBaseline, e types.Event) {
	switch e.Type {
	case types.EventSyscall:
		if e.Syscall != nil {
			bl.recordSyscall(e.Syscall.Nr)
		}
	case types.EventTCPConnect:
		if e.Network != nil {
			ip := util.FormatIP16(e.Network.Daddr, e.Network.Family)
			bl.recordNetworkPeer(ip, e.Network.Dport)
		}
	case types.EventFileAccess:
		if e.File != nil {
			path := util.BytesToString(e.File.Filename[:])
			if path == "" {
				return
			}
			dir := extractDir(path)
			if dir != "" {
				bl.recordFileDir(dir)
			}
			if isExecPath(path) {
				bl.recordExecPath(path)
			}
			if isLibPath(path) {
				bl.recordLibrary(path)
			}
		}
	}
}

// checkDrift evaluates an event against a locked baseline and returns alerts.
func (d *Detector) checkDrift(bl *ContainerBaseline, e types.Event, comm string) []DriftAlert {
	var alerts []DriftAlert

	switch e.Type {
	case types.EventSyscall:
		if e.Syscall != nil && !bl.hasSyscall(e.Syscall.Nr) {
			alerts = append(alerts, d.makeDriftAlert(bl, e, comm,
				DriftNewSyscall,
				fmt.Sprintf("new syscall %d not seen during baseline", e.Syscall.Nr),
				types.SeverityWarning,
			))
		}

	case types.EventTCPConnect:
		if e.Network != nil {
			ip := util.FormatIP16(e.Network.Daddr, e.Network.Family)
			port := e.Network.Dport
			if !bl.hasNetworkPeer(ip, port) {
				alerts = append(alerts, d.makeDriftAlert(bl, e, comm,
					DriftNewNetwork,
					fmt.Sprintf("new outbound connection to %s:%d not seen during baseline", ip, port),
					types.SeverityWarning,
				))
			}
		}

	case types.EventFileAccess:
		if e.File != nil {
			path := util.BytesToString(e.File.Filename[:])
			if path == "" {
				break
			}
			if isExecPath(path) && !bl.hasExecPath(path) {
				alerts = append(alerts, d.makeDriftAlert(bl, e, comm,
					DriftNewExec,
					fmt.Sprintf("new binary executed: %s (not in baseline)", path),
					types.SeverityCritical,
				))
			} else if isLibPath(path) && !bl.hasLibrary(path) {
				alerts = append(alerts, d.makeDriftAlert(bl, e, comm,
					DriftNewLibrary,
					fmt.Sprintf("new shared library loaded: %s (not in baseline)", path),
					types.SeverityWarning,
				))
			} else {
				dir := extractDir(path)
				if dir != "" && !bl.hasFileDir(dir) {
					alerts = append(alerts, d.makeDriftAlert(bl, e, comm,
						DriftNewFileDir,
						fmt.Sprintf("access to new directory %s (not in baseline)", dir),
						types.SeverityWarning,
					))
				}
			}
		}
	}

	for _, alert := range alerts {
		bl.incrementDrift()
		d.driftTotal.With(prometheus.Labels{
			"type":      string(alert.DriftType),
			"namespace": alert.Namespace,
		}).Inc()
		d.logger.Info("drift: deviation detected",
			slog.String("container_id", alert.ContainerID),
			slog.String("namespace", alert.Namespace),
			slog.String("pod", alert.PodName),
			slog.String("type", string(alert.DriftType)),
			slog.String("detail", alert.Detail),
		)
	}

	// Update locked-baseline gauge lazily.
	if len(alerts) > 0 {
		d.updateLockedGauge()
	}

	return alerts
}

func (d *Detector) makeDriftAlert(bl *ContainerBaseline, e types.Event, comm string, dt DriftType, detail string, sev types.Severity) DriftAlert {
	return DriftAlert{
		ContainerID: bl.ContainerID,
		Namespace:   bl.Namespace,
		PodName:     bl.PodName,
		DriftType:   dt,
		Detail:      detail,
		Severity:    sev,
		Timestamp:   time.Now(),
		PID:         e.PID,
		Comm:        comm,
	}
}

// updateLockedGauge refreshes the locked-baselines metric.
func (d *Detector) updateLockedGauge() {
	d.mu.RLock()
	defer d.mu.RUnlock()
	locked := 0
	for _, bl := range d.baselines {
		bl.mu.RLock()
		if bl.Locked {
			locked++
		}
		bl.mu.RUnlock()
	}
	d.baselineLocked.Set(float64(locked))
}

// PurgeStale removes baselines for containers that haven't been seen for ttl.
func (d *Detector) PurgeStale(ttl time.Duration) int {
	cutoff := time.Now().Add(-ttl)
	d.mu.Lock()
	defer d.mu.Unlock()
	removed := 0
	for cid, bl := range d.baselines {
		bl.mu.RLock()
		expiry := bl.BaselineExpiry
		bl.mu.RUnlock()
		if expiry.Before(cutoff) {
			delete(d.baselines, cid)
			removed++
		}
	}
	if removed > 0 {
		d.baselineTotal.Set(float64(len(d.baselines)))
	}
	return removed
}

// BaselineCount returns the number of tracked container baselines.
func (d *Detector) BaselineCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.baselines)
}

// AllStats returns a snapshot of all baseline stats.
func (d *Detector) AllStats() []BaselineStats {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]BaselineStats, 0, len(d.baselines))
	for _, bl := range d.baselines {
		out = append(out, bl.Stats())
	}
	return out
}

// DriftAlertToTypes converts a DriftAlert to a types.Alert for store/export.
func DriftAlertToTypes(da DriftAlert, seq uint64) types.Alert {
	details := map[string]interface{}{
		"drift_type":   string(da.DriftType),
		"detail":       da.Detail,
		"container_id": da.ContainerID,
		"pod_name":     da.PodName,
	}
	return types.Alert{
		ID:        fmt.Sprintf("drift-%s-%d", string(da.DriftType), seq),
		Timestamp: da.Timestamp,
		RuleID:    "drift_" + string(da.DriftType),
		RuleName:  "Container Drift: " + driftTypeName(da.DriftType),
		Severity:  da.Severity,
		PID:       da.PID,
		Comm:      da.Comm,
		Message:   da.Detail,
		Details:   details,
		Enrichment: types.EnrichmentInfo{
			ContainerID: da.ContainerID,
			Namespace:   da.Namespace,
			PodName:     da.PodName,
		},
	}
}

func driftTypeName(dt DriftType) string {
	switch dt {
	case DriftNewSyscall:
		return "New Syscall"
	case DriftNewExec:
		return "New Binary Executed"
	case DriftNewLibrary:
		return "New Library Loaded"
	case DriftNewNetwork:
		return "New Network Peer"
	case DriftNewFileDir:
		return "New File Directory"
	default:
		return string(dt)
	}
}

func extractDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i+1]
		}
	}
	return ""
}

func isExecPath(path string) bool {
	for _, prefix := range []string{"/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/local/bin/"} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func isLibPath(path string) bool {
	return strings.HasSuffix(path, ".so") ||
		strings.Contains(path, ".so.") ||
		strings.HasPrefix(path, "/lib/") ||
		strings.HasPrefix(path, "/usr/lib/")
}
