// Package profiler provides behavioral profiling and anomaly detection for processes.
package profiler

import (
	"context"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/zugolO/ebpf-guard/pkg/types"
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

// Anomaly represents a detected behavioral anomaly.
type Anomaly struct {
	PID           uint32
	Comm          string
	Namespace     string // K8s namespace; empty for non-K8s processes
	AppLabel      string // pod label "app"; empty when absent
	Score         float64
	Contributions map[string]interface{}
	Type          AnomalyType
}

// AnomalyType identifies the type of anomaly detected.
type AnomalyType string

const (
	AnomalyTypeBehavior  AnomalyType = "behavior"  // EWMA-based anomaly
	AnomalyTypeSequence  AnomalyType = "sequence"  // Syscall sequence anomaly
	AnomalyTypeLineage   AnomalyType = "lineage"   // Process lineage anomaly
	AnomalyTypeAllowlist AnomalyType = "allowlist" // Syscall allowlist violation
)

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
		ticker := time.NewTicker(lineageTTL)
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

// Ingest processes an event and returns anomalies if detected.
// May return multiple anomalies from different detectors. When both the EWMA
// anomaly detector and the syscall allowlist profiler flag the same event,
// their scores are combined into a single boosted AnomalyTypeAllowlist anomaly.
func (p *Profiler) Ingest(e types.Event) []*Anomaly {
	var anomalies []*Anomaly

	// Run EWMA-based anomaly detection
	ewmaResult := p.detector.ProcessEvent(e, false)

	// Run syscall allowlist: always record (for learning), check for violations.
	allowlistViolation := p.allowlistCheck(e)

	// Collect per-event anomaly info for cross-detector combination.
	var behaviorAnomaly *Anomaly
	if ewmaResult != nil && ewmaResult.IsAnomaly {
		contributions := make(map[string]interface{})
		for _, c := range ewmaResult.Contributions {
			contributions[c.Field] = map[string]interface{}{
				"category": c.Category,
				"value":    c.Value,
				"score":    c.Contribution,
			}
		}
		behaviorAnomaly = &Anomaly{
			PID:           ewmaResult.PID,
			Comm:          ewmaResult.Comm,
			Namespace:     ewmaResult.Namespace,
			AppLabel:      ewmaResult.AppLabel,
			Score:         ewmaResult.Score,
			Contributions: contributions,
			Type:          AnomalyTypeBehavior,
		}
	}

	var allowlistAnomaly *Anomaly
	if allowlistViolation != nil {
		allowlistAnomaly = p.buildAllowlistAnomaly(e, allowlistViolation)
	}

	// ── Cross-detector signal fusion ──
	// When both the EWMA anomaly detector AND the syscall allowlist flag the
	// same event, combine the signals into a single boosted anomaly instead of
	// emitting two separate alerts. The combined score is a weighted blend:
	//   combined = max(ewmaScore, 1.0) * 0.5 + 0.5   (boosts allowlist certainty)
	// This catches novel attacks where the syscall itself was never seen AND
	// the behavioral profile also looks unusual.
	if behaviorAnomaly != nil && allowlistAnomaly != nil {
		boosted := behaviorAnomaly.Score
		if boosted < 1.0 {
			boosted = 1.0 // unknown syscall gives full baseline weight
		}
		allowlistAnomaly.Score = boosted*0.5 + 0.5
		allowlistAnomaly.Contributions["ewma_score"] = behaviorAnomaly.Score
		allowlistAnomaly.Contributions["ewma_contributions"] = behaviorAnomaly.Contributions
		allowlistAnomaly.Type = AnomalyTypeAllowlist
		anomalies = append(anomalies, allowlistAnomaly)
	} else if behaviorAnomaly != nil {
		anomalies = append(anomalies, behaviorAnomaly)
	} else if allowlistAnomaly != nil {
		anomalies = append(anomalies, allowlistAnomaly)
	}

	// Run sequence anomaly detection
	if dist, isAnomaly := p.sequence.Update(e); isAnomaly {
		ns, app := "", ""
		if e.Enrichment != nil {
			ns = e.Enrichment.Namespace
			app = e.Enrichment.Labels["app"]
		}
		anomalies = append(anomalies, &Anomaly{
			PID:       e.PID,
			Comm:      cleanComm(e.Comm[:]),
			Namespace: ns,
			AppLabel:  app,
			Score:     dist,
			Contributions: map[string]interface{}{
				"sequence_distance": dist,
				"threshold":         p.sequence.config.Threshold,
			},
			Type: AnomalyTypeSequence,
		})
	}

	// Run lineage tracking
	if match := p.lineage.Update(e); match != nil {
		severity := 0.8
		if match.Pattern.Severity == "critical" {
			severity = 1.0
		}
		ns, app := "", ""
		if e.Enrichment != nil {
			ns = e.Enrichment.Namespace
			app = e.Enrichment.Labels["app"]
		}
		anomalies = append(anomalies, &Anomaly{
			PID:       e.PID,
			Comm:      match.Comm,
			Namespace: ns,
			AppLabel:  app,
			Score:     severity,
			Contributions: map[string]interface{}{
				"pattern":     match.Pattern.Name,
				"description": match.Pattern.Description,
				"parent":      match.ParentComm,
				"parent_pid":  match.PPID,
				"severity":    match.Pattern.Severity,
			},
			Type: AnomalyTypeLineage,
		})
	}

	return anomalies
}

// allowlistCheck records the event for learning and checks for violations.
// Returns nil when allowlist is disabled, during learning, or for permitted syscalls.
// Audit-mode violations are logged but not returned (no alert generated).
func (p *Profiler) allowlistCheck(e types.Event) *AllowlistViolation {
	p.allowlist.Record(e)
	v := p.allowlist.Check(e)
	if v != nil && v.Action == AllowlistActionAudit {
		slog.Info("allowlist: audit violation (no alert)",
			"workload", v.WorkloadKey.String(),
			"syscall", v.SyscallNr,
			"source", v.Source,
		)
		return nil
	}
	return v
}

// buildAllowlistAnomaly constructs an Anomaly from an AllowlistViolation.
func (p *Profiler) buildAllowlistAnomaly(e types.Event, v *AllowlistViolation) *Anomaly {
	ns, app := "", ""
	if e.Enrichment != nil {
		ns = e.Enrichment.Namespace
		app = e.Enrichment.Labels["app"]
	}
	score := 0.8
	if v.Source == "global_deny" {
		score = 1.0
	}
	return &Anomaly{
		PID:       e.PID,
		Comm:      cleanComm(e.Comm[:]),
		Namespace: ns,
		AppLabel:  app,
		Score:     score,
		Contributions: map[string]interface{}{
			"syscall_nr": v.SyscallNr,
			"source":     v.Source,
			"action":     string(v.Action),
			"workload":   v.WorkloadKey.String(),
		},
		Type: AnomalyTypeAllowlist,
	}
}

// SetLineageMatchHandler sets the callback for lineage pattern matches.
func (p *Profiler) SetLineageMatchHandler(handler func(LineageMatch)) {
	p.lineage.SetMatchHandler(handler)
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

// SaveState serializes the EWMA learning state and allowlist profiles to path.
// Allowlist state is saved to path + ".allowlist".
func (p *Profiler) SaveState(path string) error {
	if err := p.detector.SaveState(path); err != nil {
		return err
	}
	if p.allowlist.config.Enabled && p.allowlist.config.PersistPath == "" {
		if err := p.allowlist.SaveState(path + ".allowlist"); err != nil {
			return err
		}
	}
	return nil
}

// LoadState restores a previously saved EWMA learning state and allowlist profiles.
// learningPeriod is the currently configured learning period used for the freshness check.
// Returns true if the state was valid and learning was already complete.
func (p *Profiler) LoadState(path string, learningPeriod time.Duration) (bool, error) {
	ready, err := p.detector.LoadState(path, learningPeriod)
	if err != nil {
		return false, err
	}
	if p.allowlist.config.Enabled && p.allowlist.config.PersistPath == "" {
		if err := p.allowlist.loadState(path + ".allowlist"); err != nil {
			slog.Warn("profiler: failed to load allowlist state, starting fresh", "err", err)
		}
	}
	return ready, nil
}
