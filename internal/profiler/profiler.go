// Package profiler provides behavioral profiling and anomaly detection for processes.
package profiler

import (
	"context"
	"log/slog"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/prometheus/client_golang/prometheus"
)

// Profiler provides high-level behavioral profiling and anomaly detection.
type Profiler struct {
	detector  *AnomalyDetector
	sequence  *SequenceProfiler
	lineage   *LineageTracker
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
	AnomalyTypeBehavior AnomalyType = "behavior" // EWMA-based anomaly
	AnomalyTypeSequence AnomalyType = "sequence" // Syscall sequence anomaly
	AnomalyTypeLineage  AnomalyType = "lineage"  // Process lineage anomaly
)

// ProfilerConfig holds configuration for all profiler components.
type ProfilerConfig struct {
	Threshold   float64
	Weight      float64
	TTLSeconds  int
	MaxTrackedPIDs int
	Sequence    SequenceConfig
	Lineage     LineageConfig
}

// NewProfiler creates a new profiler with the given configuration.
// Deprecated: use NewProfilerWithContext to enable background cleanup goroutines.
func NewProfiler(cfg ProfilerConfig, logger *slog.Logger) *Profiler {
	return NewProfilerWithContext(context.Background(), cfg, logger)
}

// NewProfilerWithContext creates a new profiler whose background goroutines
// (ProfileManager cleanup, SequenceProfiler cleanup, LineageTracker cleanup)
// exit when ctx is cancelled.
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
	return nil
}

// Ingest processes an event and returns anomalies if detected.
// May return multiple anomalies from different detectors.
func (p *Profiler) Ingest(e types.Event) []*Anomaly {
	var anomalies []*Anomaly

	// Run EWMA-based anomaly detection
	result := p.detector.ProcessEvent(e, false)
	if result != nil && result.IsAnomaly {
		contributions := make(map[string]interface{})
		for _, c := range result.Contributions {
			contributions[c.Field] = map[string]interface{}{
				"category": c.Category,
				"value":    c.Value,
				"score":    c.Contribution,
			}
		}
		anomalies = append(anomalies, &Anomaly{
			PID:           result.PID,
			Comm:          result.Comm,
			Namespace:     result.Namespace,
			AppLabel:      result.AppLabel,
			Score:         result.Score,
			Contributions: contributions,
			Type:          AnomalyTypeBehavior,
		})
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
