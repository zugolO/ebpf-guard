// Package watchdog provides heartbeat and BPF liveness monitoring.
package watchdog

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/ebpf-guard/ebpf-guard/pkg/types"
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

// Watchdog monitors agent health and BPF program liveness.
type Watchdog struct {
	logger            *slog.Logger
	checkers          []BPFProgramChecker
	heartbeatInterval time.Duration
	checkInterval     time.Duration
	alertFunc         func(types.Alert)
	mu                sync.RWMutex
	running           bool
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
	}
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

// runHeartbeat periodically updates the heartbeat timestamp.
func (w *Watchdog) runHeartbeat(ctx context.Context) {
	ticker := time.NewTicker(w.heartbeatInterval)
	defer ticker.Stop()

	// Update immediately on start
	HeartbeatTimestamp.Set(float64(time.Now().Unix()))

	for {
		select {
		case <-ctx.Done():
			w.logger.Debug("heartbeat stopped")
			return
		case <-ticker.C:
			HeartbeatTimestamp.Set(float64(time.Now().Unix()))
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
	}
}

// GetCheckerCount returns the number of registered checkers.
func (w *Watchdog) GetCheckerCount() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return len(w.checkers)
}
