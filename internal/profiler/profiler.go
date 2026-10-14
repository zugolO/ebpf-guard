// Package profiler provides behavioral profiling and anomaly detection for processes.
package profiler

import (
	"context"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Profiler provides high-level behavioral profiling and anomaly detection.
type Profiler struct {
	detector  *AnomalyDetector
	sequence  *SequenceProfiler
	lineage   *LineageTracker
	allowlist *SyscallAllowlistProfiler
	threshold float64
	weight    float64
	ttl       time.Duration
}

// ProfilerStats contains profiler learning statistics for the debug endpoint.
type ProfilerStats struct {
	LearningComplete    bool    `json:"learning_complete"`
	LearningProgress    float64 `json:"learning_progress"` // 0.0-1.0
	ProfilesActive      int     `json:"profiles_active"`
	AnomaliesTotal      uint64  `json:"anomalies_total"`
	LearningSampleCount uint64  `json:"learning_sample_count"`
	// SeededObservationsTotal counts directory contributions suppressed by the
	// #364/#371 loader-prologue seeding (see SeededSuppressionsTotal). Paired
	// with AnomaliesTotal so a caller can tell "seeding ran and anomalies
	// still fire" from a silent double-zero (6.3.9.3).
	SeededObservationsTotal uint64 `json:"seeded_observations_total"`
}

// ProfilerConfig holds configuration for all profiler components.
type ProfilerConfig struct {
	Threshold      float64
	Weight         float64
	TTLSeconds     int
	MaxTrackedPIDs int
	Sequence       SequenceConfig
	Lineage        LineageConfig
	Allowlist      SyscallAllowlistConfig
}

// NewProfiler creates a new profiler with the given configuration.
// Deprecated: use NewProfilerWithContext to enable background cleanup goroutines.
func NewProfiler(cfg ProfilerConfig, logger *slog.Logger) *Profiler {
	return NewProfilerWithContext(context.Background(), cfg, logger)
}

// NewProfilerWithContext creates a new profiler whose background goroutines
// (ProfileManager cleanup, SequenceProfiler cleanup, LineageTracker cleanup,
// Allowlist persistence) exit when ctx is cancelled.
func NewProfilerWithContext(ctx context.Context, cfg ProfilerConfig, logger *slog.Logger) *Profiler {
	ttl := time.Duration(cfg.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	maxPIDs := cfg.MaxTrackedPIDs
	if maxPIDs <= 0 {
		maxPIDs = 65536
	}

	p := &Profiler{
		detector:  NewAnomalyDetectorWithContext(ctx, cfg.Threshold, time.Hour, cfg.Weight),
		sequence:  NewSequenceProfilerWithContext(ctx, cfg.Sequence, ttl, maxPIDs),
		lineage:   NewLineageTracker(cfg.Lineage, logger),
		allowlist: NewSyscallAllowlistProfilerWithContext(ctx, cfg.Allowlist, logger),
		threshold: cfg.Threshold,
		weight:    cfg.Weight,
		ttl:       ttl,
	}

	// Wire LineageTracker cleanup loop.
	lineageTTL := cfg.Lineage.TTL
	if lineageTTL <= 0 {
		lineageTTL = 5 * time.Minute
	}
	go func() {
		ticker := time.NewTicker(lineageCleanupInterval(lineageTTL))
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				p.lineage.Cleanup(time.Now())
			case <-ctx.Done():
				return
			}
		}
	}()

	return p
}

// lineageCleanupInterval — тик уборки LineageTracker: TTL/5, не реже раза в 10 с.
// Тик, равный TTL, держал запись до 2×TTL (10 мин): смок ночи 8.2 на боевом
// наборе — пик пода 156 МиБ > 150, рост живой кучи за пакет атак на 58% —
// LineageTracker. TTL (окно, в котором цепочка видна детекту) не меняется,
// сокращается только хвост после него: удержание ≤ TTL + TTL/5.
func lineageCleanupInterval(ttl time.Duration) time.Duration {
	iv := ttl / 5
	if iv < 10*time.Second {
		iv = 10 * time.Second
	}
	return iv
}

// RegisterMetrics registers Prometheus metrics for all profiler components.
func (p *Profiler) RegisterMetrics(reg prometheus.Registerer) error {
	if err := p.sequence.RegisterMetrics(reg); err != nil {
		return err
	}
	if p.allowlist.config.Enabled {
		if err := p.allowlist.RegisterMetrics(reg); err != nil {
			return err
		}
	}
	return nil
}

// IsLearningComplete returns true if the learning phase is complete.
func (p *Profiler) IsLearningComplete() bool {
	return p.detector.IsLearningComplete()
}

// LearningProgress returns the progress of the learning phase (0.0-1.0).
func (p *Profiler) LearningProgress() float64 {
	return p.detector.LearningProgress()
}

// Cleanup removes stale entries from all profilers.
func (p *Profiler) Cleanup(now time.Time) {
	p.sequence.Cleanup(now)
	p.lineage.Cleanup(now)
}

// GetSequenceProfiler returns the sequence profiler (for testing).
func (p *Profiler) GetSequenceProfiler() *SequenceProfiler {
	return p.sequence
}

// GetLineageTracker returns the lineage tracker (for testing).
func (p *Profiler) GetLineageTracker() *LineageTracker {
	return p.lineage
}

// GetAllowlistProfiler returns the syscall allowlist profiler (for testing).
func (p *Profiler) GetAllowlistProfiler() *SyscallAllowlistProfiler {
	return p.allowlist
}

// GetDetector returns the underlying anomaly detector (for metrics registration).
func (p *Profiler) GetDetector() *AnomalyDetector {
	return p.detector
}

// SaveAllowlistState persists the syscall allowlist profiles to path+".allowlist".
//
// P0-3: this used to be bundled into SaveState alongside p.detector's EWMA
// state, but p.detector never receives events once anomaly detection is
// enabled (IngestAsync routes exclusively through the correlation engine's
// per-worker detector pool — see CorrelationEngine.SaveState/LoadState in
// internal/correlator/engine.go). The allowlist profiler has no such
// split — ce.allowlistProfiler is the same instance as p.allowlist and is
// recorded/checked synchronously per-event — so its persistence stays here.
func (p *Profiler) SaveAllowlistState(path string) error {
	if p.allowlist.config.Enabled && p.allowlist.config.PersistPath == "" {
		return p.allowlist.SaveState(path + ".allowlist")
	}
	return nil
}

// LoadAllowlistState restores previously saved syscall allowlist profiles
// from path+".allowlist". See SaveAllowlistState for why this is split from
// anomaly-detector state.
func (p *Profiler) LoadAllowlistState(path string) {
	if p.allowlist.config.Enabled && p.allowlist.config.PersistPath == "" {
		if err := p.allowlist.loadState(path + ".allowlist"); err != nil {
			slog.Warn("profiler: failed to load allowlist state, starting fresh", "err", err)
		}
	}
}

// GetStats returns profiler statistics for the debug endpoint.
func (p *Profiler) GetStats() ProfilerStats {
	var anomaliesTotal uint64
	var profilesActive int

	if wpm := p.detector.GetProfileManager(); wpm != nil {
		profilesActive = wpm.Len()
		anomaliesTotal = p.countAnomalies(wpm)
	}

	return ProfilerStats{
		LearningComplete:        p.IsLearningComplete(),
		LearningProgress:        p.LearningProgress(),
		ProfilesActive:          profilesActive,
		AnomaliesTotal:          anomaliesTotal,
		SeededObservationsTotal: SeededSuppressionsTotal(),
	}
}

// countAnomalies counts total alert counts across all profiles.
func (p *Profiler) countAnomalies(wpm *WorkloadProfileManager) uint64 {
	return CountAlertTotal(wpm)
}
