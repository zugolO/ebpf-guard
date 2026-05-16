// Package profiler provides behavioral profiling and anomaly detection for processes.
package profiler

import (
	"time"

	"github.com/ebpf-guard/ebpf-guard/pkg/types"
)

// Profiler provides high-level behavioral profiling and anomaly detection.
type Profiler struct {
	detector *AnomalyDetector
	threshold float64
	weight    float64
	ttl       time.Duration
}

// Anomaly represents a detected behavioral anomaly.
type Anomaly struct {
	PID           uint32
	Comm          string
	Score         float64
	Contributions map[string]interface{}
}

// NewProfiler creates a new profiler with the given configuration.
func NewProfiler(threshold, weight float64, ttlSeconds int) *Profiler {
	// Convert ttl from seconds to duration
	ttl := time.Duration(ttlSeconds) * time.Second
	
	return &Profiler{
		detector:  NewAnomalyDetector(threshold, time.Hour, weight),
		threshold: threshold,
		weight:    weight,
		ttl:       ttl,
	}
}

// Ingest processes an event and returns an anomaly if detected.
func (p *Profiler) Ingest(e types.Event) *Anomaly {
	result := p.detector.ProcessEvent(e)
	if result == nil || !result.IsAnomaly {
		return nil
	}
	
	// Convert contributions to map
	contributions := make(map[string]interface{})
	for _, c := range result.Contributions {
		contributions[c.Field] = map[string]interface{}{
			"category": c.Category,
			"value":    c.Value,
			"score":    c.Contribution,
		}
	}
	
	return &Anomaly{
		PID:           result.PID,
		Comm:          result.Comm,
		Score:         result.Score,
		Contributions: contributions,
	}
}

// IsLearningComplete returns true if the learning phase is complete.
func (p *Profiler) IsLearningComplete() bool {
	return p.detector.IsLearningComplete()
}

// LearningProgress returns the progress of the learning phase (0.0-1.0).
func (p *Profiler) LearningProgress() float64 {
	return p.detector.LearningProgress()
}
