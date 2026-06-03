// Package watchdog provides heartbeat and BPF liveness monitoring.
package watchdog

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/zugolO/ebpf-guard/internal/bpf"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

var (
	// HeartbeatTimestamp is the Unix timestamp of the last heartbeat.
	// Used by Prometheus alert rule EbpfGuardAgentDown to detect agent death.
	HeartbeatTimestamp = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "ebpf_guard_heartbeat_timestamp_seconds",
			Help: "Unix timestamp of the last agent heartbeat",
		},
	)

	// BPFProgramsLoaded indicates whether each BPF program is loaded and attached.
	// 1 = loaded and attached, 0 = detached or not loaded.
	BPFProgramsLoaded = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ebpf_guard_bpf_programs_loaded",
			Help: "Whether each BPF program is loaded and attached (1) or not (0)",
		},
		[]string{"program"},
	)
)

// BPFProgramChecker is the interface for checking BPF program status.
type BPFProgramChecker interface {
	// IsAttached returns true if the BPF program is still attached.
	IsAttached() bool
	// Name returns the program name.
	Name() string
	// Reload attempts to reload the BPF program.
	Reload() error
}

// BPFProgramProvider extends BPFProgramChecker with access to the loaded
// *ebpf.Program handles so the watchdog can perform tag-based attestation.
// Collectors that implement this interface opt in to runtime tamper detection.
type BPFProgramProvider interface {
	BPFProgramChecker
	// GetPrograms returns the loaded *ebpf.Program handles keyed by program name.
	// Returns nil or an empty map when the programs are not yet loaded.
	GetPrograms() map[string]*ebpf.Program
}

// Watchdog monitors agent health and BPF program liveness.
type Watchdog struct {
	logger            *slog.Logger
	checkers          []BPFProgramChecker
	heartbeatInterval time.Duration
	checkInterval     time.Duration
	alertFunc         func(types.Alert)
	mu                sync.RWMutex
	running           bool

	attestor *bpf.Attestor

	reattachTotal  prometheus.Counter // ebpf_guard_bpf_program_reattach_total
	tamperingTotal prometheus.Counter // ebpf_guard_bpf_attestation_violations_total
	checksTotal    prometheus.Counter // ebpf_guard_bpf_attestation_checks_total
}

// Config holds watchdog configuration.
type Config struct {
	// HeartbeatInterval is how often to update the heartbeat metric.
	HeartbeatInterval time.Duration
	// CheckInterval is how often to check BPF program liveness.
	CheckInterval time.Duration
	// AlertFunc is called when a critical issue is detected.
	AlertFunc func(types.Alert)
}

// DefaultConfig returns default watchdog configuration.
func DefaultConfig() Config {
	return Config{
		HeartbeatInterval: 15 * time.Second,
		CheckInterval:     30 * time.Second,
		AlertFunc:         nil,
	}
}

// New creates a new watchdog instance.
func New(logger *slog.Logger, cfg Config) *Watchdog {
	if cfg.HeartbeatInterval == 0 {
		cfg.HeartbeatInterval = DefaultConfig().HeartbeatInterval
	}
	if cfg.CheckInterval == 0 {
		cfg.CheckInterval = DefaultConfig().CheckInterval
	}

	return &Watchdog{
		logger:            logger,
		checkers:          make([]BPFProgramChecker, 0),
		heartbeatInterval: cfg.HeartbeatInterval,
		checkInterval:     cfg.CheckInterval,
		alertFunc:         cfg.AlertFunc,
		attestor:          bpf.NewAttestor(),
		reattachTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ebpf_guard_bpf_program_reattach_total",
			Help: "Total number of successful BPF program reattachments after detach.",
		}),
		tamperingTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ebpf_guard_bpf_attestation_violations_total",
			Help: "Total number of BPF program tag mismatches indicating possible tampering.",
		}),
		checksTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ebpf_guard_bpf_attestation_checks_total",
			Help: "Total number of BPF program attestation checks performed.",
		}),
	}
}

// RegisterMetrics registers the Watchdog's Prometheus metrics with the given registerer.
func (w *Watchdog) RegisterMetrics(reg prometheus.Registerer) error {
	for _, c := range []prometheus.Collector{w.reattachTotal, w.tamperingTotal, w.checksTotal} {
		if c == nil {
			continue
		}
		if err := reg.Register(c); err != nil {
			return err
		}
	}
	return nil
}

// RegisterChecker adds a BPF program checker to the watchdog.
func (w *Watchdog) RegisterChecker(checker BPFProgramChecker) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.checkers = append(w.checkers, checker)
}

// Start begins the watchdog goroutines.
func (w *Watchdog) Start(ctx context.Context) {
	w.mu.Lock()
	if w.running {
		w.mu.Unlock()
		return
	}
	w.running = true
	w.mu.Unlock()

	w.logger.Info("watchdog started",
		slog.Duration("heartbeat_interval", w.heartbeatInterval),
		slog.Duration("check_interval", w.checkInterval),
	)

	// Initialize BPF program metrics
	for _, checker := range w.checkers {
		BPFProgramsLoaded.WithLabelValues(checker.Name()).Set(0)
	}

	// Start heartbeat goroutine
	go w.runHeartbeat(ctx)

	// Start BPF liveness check goroutine
	go w.runLivenessChecks(ctx)
}

// Stop stops the watchdog.
func (w *Watchdog) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.running = false
}

// IsRunning returns true if the watchdog is running.
func (w *Watchdog) IsRunning() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.running
}

// nowSeconds returns the current time as fractional Unix seconds. Sub-second
// precision keeps the heartbeat gauge monotonic even with short heartbeat
// intervals (e.g. 50ms), where whole-second Unix() would not advance between
// ticks. The metric unit (…_seconds) is unchanged.
func nowSeconds() float64 {
	return float64(time.Now().UnixNano()) / 1e9
}

// runHeartbeat periodically updates the heartbeat timestamp.
func (w *Watchdog) runHeartbeat(ctx context.Context) {
	ticker := time.NewTicker(w.heartbeatInterval)
	defer ticker.Stop()

	// Update immediately on start
	HeartbeatTimestamp.Set(nowSeconds())

	for {
		select {
		case <-ctx.Done():
			w.logger.Debug("heartbeat stopped")
			return
		case <-ticker.C:
			HeartbeatTimestamp.Set(nowSeconds())
			w.logger.Debug("heartbeat updated")
		}
	}
}

// runLivenessChecks periodically checks BPF program status.
func (w *Watchdog) runLivenessChecks(ctx context.Context) {
	ticker := time.NewTicker(w.checkInterval)
	defer ticker.Stop()

	// Check immediately on start
	w.checkAllPrograms()

	for {
		select {
		case <-ctx.Done():
			w.logger.Debug("liveness checks stopped")
			return
		case <-ticker.C:
			w.checkAllPrograms()
		}
	}
}

// checkAllPrograms checks all registered BPF programs.
func (w *Watchdog) checkAllPrograms() {
	w.mu.RLock()
	checkers := make([]BPFProgramChecker, len(w.checkers))
	copy(checkers, w.checkers)
	w.mu.RUnlock()

	for _, checker := range checkers {
		w.checkProgram(checker)
	}
}

// checkProgram checks a single BPF program and attempts reload if detached.
func (w *Watchdog) checkProgram(checker BPFProgramChecker) {
	name := checker.Name()
	isAttached := checker.IsAttached()

	if isAttached {
		BPFProgramsLoaded.WithLabelValues(name).Set(1)
		w.logger.Debug("BPF program attached",
			slog.String("program", name),
		)
		w.runAttestation(checker)
		return
	}

	// Program is detached - update metric
	BPFProgramsLoaded.WithLabelValues(name).Set(0)

	w.logger.Error("BPF program detached",
		slog.String("program", name),
	)

	// Send critical alert
	if w.alertFunc != nil {
		alert := types.Alert{
			RuleID:    "watchdog_bpf_detached",
			RuleName:  "BPF Program Detached",
			Severity:  types.SeverityCritical,
			Message:   fmt.Sprintf("BPF program %s has been detached, attempting reload", name),
			Timestamp: time.Now(),
			Details: map[string]interface{}{
				"program":     name,
				"description": fmt.Sprintf("BPF program %s is no longer attached", name),
			},
		}
		w.alertFunc(alert)
	}

	// Attempt to reload
	w.logger.Info("attempting to reload BPF program",
		slog.String("program", name),
	)

	if err := checker.Reload(); err != nil {
		w.logger.Error("failed to reload BPF program",
			slog.String("program", name),
			slog.Any("error", err),
		)

		// Send another alert for reload failure
		if w.alertFunc != nil {
			alert := types.Alert{
				RuleID:    "watchdog_bpf_reload_failed",
				RuleName:  "BPF Program Reload Failed",
				Severity:  types.SeverityCritical,
				Message:   fmt.Sprintf("BPF program %s reload failed: %v", name, err),
				Timestamp: time.Now(),
				Details: map[string]interface{}{
					"program":     name,
					"error":       err.Error(),
					"description": fmt.Sprintf("Failed to reload BPF program %s", name),
				},
			}
			w.alertFunc(alert)
		}
	} else {
		w.logger.Info("BPF program reloaded successfully",
			slog.String("program", name),
		)
		BPFProgramsLoaded.WithLabelValues(name).Set(1)
		if w.reattachTotal != nil {
			w.reattachTotal.Inc()
		}
	}
}

// runAttestation verifies BPF program tags for checkers that implement
// BPFProgramProvider.  A tag mismatch fires a critical tampering alert.
func (w *Watchdog) runAttestation(checker BPFProgramChecker) {
	provider, ok := checker.(BPFProgramProvider)
	if !ok {
		return
	}
	programs := provider.GetPrograms()
	if len(programs) == 0 {
		return
	}

	if w.checksTotal != nil {
		w.checksTotal.Add(float64(len(programs)))
	}

	if err := w.attestor.VerifyAll(programs); err != nil {
		if w.tamperingTotal != nil {
			w.tamperingTotal.Inc()
		}

		var violation bpf.AttestationViolation
		errors.As(err, &violation)
		programName := checker.Name()
		if violation.Program != "" {
			programName = violation.Program
		}

		w.logger.Error("BPF program tampering detected",
			slog.String("program", programName),
			slog.String("expected_tag", violation.ExpectedTag),
			slog.String("actual_tag", violation.ActualTag),
		)

		if w.alertFunc != nil {
			w.alertFunc(types.Alert{
				RuleID:    "watchdog_bpf_tampering",
				RuleName:  "BPF Program Tampering Detected",
				Severity:  types.SeverityCritical,
				Message:   err.Error(),
				Timestamp: time.Now(),
				Details: map[string]interface{}{
					"program":      programName,
					"expected_tag": violation.ExpectedTag,
					"actual_tag":   violation.ActualTag,
					"description":  "BPF program kernel tag changed — possible replacement or tampering",
				},
			})
		}
	}
}

// GetCheckerCount returns the number of registered checkers.
func (w *Watchdog) GetCheckerCount() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return len(w.checkers)
}
