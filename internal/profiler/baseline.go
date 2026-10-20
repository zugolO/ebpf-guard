// Package profiler provides behavioral profiling and anomaly detection for processes.
package profiler

import (
	"log/slog"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// EWMA (Exponentially Weighted Moving Average) tracks the moving average of a value.
// It gives more weight to recent observations, making it suitable for behavioral baselines.
type EWMA struct {
	mu     sync.RWMutex
	value  float64
	weight float64 // Smoothing factor (0 < weight < 1)
	count  uint64  // Number of updates
}

// NewEWMA creates a new EWMA with the given weight.
// weight must be in (0, 1); 1.0 is intentionally rejected — it would reduce
// the EWMA to a pure last-observation sampler with no smoothing. Use 0.99
// for near-instant adaptation.
func NewEWMA(weight float64) *EWMA {
	if weight <= 0 || weight > 1 {
		weight = 0.3 // Default weight
	}
	return &EWMA{
		weight: weight,
		value:  0,
		count:  0,
	}
}

// Update adds a new observation to the moving average.
func (e *EWMA) Update(observation float64) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.count == 0 {
		// First observation
		e.value = observation
	} else {
		// EWMA formula: new_value = weight * observation + (1 - weight) * old_value
		e.value = e.weight*observation + (1-e.weight)*e.value
	}
	e.count++
}

// UpdateN folds n identical observations into the average — the same state n
// sequential Update(observation) calls leave behind (wave 8.5 F2: the kernel
// counts events it filters out, and the profile must end up exactly as if
// each one had arrived). Closed form for the n-1 smoothing steps after the
// first observation: v ← o + (v − o)·(1−w)^(n−1).
func (e *EWMA) UpdateN(observation float64, n uint64) {
	if n == 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	rest := n
	if e.count == 0 {
		e.value = observation
		rest--
	}
	if rest > 0 {
		e.value = observation + (e.value-observation)*math.Pow(1-e.weight, float64(rest))
	}
	e.count += n
}

// Value returns the current EWMA value.
func (e *EWMA) Value() float64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.value
}

// Count returns the number of updates.
func (e *EWMA) Count() uint64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.count
}

// Reset resets the EWMA to zero.
func (e *EWMA) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.value = 0
	e.count = 0
}

// BaselineLearner manages the learning phase for behavioral baselines.
type BaselineLearner struct {
	mu sync.RWMutex

	// Learning period duration
	learningPeriod time.Duration
	// Start time of learning
	startTime time.Time
	// Whether learning is complete. Atomic since волна 9 (В8): the learner is shared by
	// every ingest worker and RecordSample ran under an exclusive mutex on EVERY event
	// of the learning phase — 15% of worker snapshots sat in that lock at host×8.
	learningComplete atomic.Bool
	// Minimum number of samples required
	minSamples uint64
	// Current sample count (atomic: see learningComplete)
	sampleCount atomic.Uint64
}

// NewBaselineLearner creates a new baseline learner.
func NewBaselineLearner(learningPeriod time.Duration, minSamples uint64) *BaselineLearner {
	return &BaselineLearner{
		learningPeriod: learningPeriod,
		startTime:      time.Now(),
		minSamples:     minSamples,
	}
}

// RecordSample records a new sample during the learning phase.
func (bl *BaselineLearner) RecordSample() {
	bl.sampleCount.Add(1)
}

// RecordSamples records n samples at once (wave 8.5 F2: events the kernel
// counted instead of delivering).
func (bl *BaselineLearner) RecordSamples(n uint64) {
	if n == 0 {
		return
	}
	bl.sampleCount.Add(n)
}

// IsLearningComplete checks if the learning phase is complete.
func (bl *BaselineLearner) IsLearningComplete() bool {
	if bl.learningComplete.Load() {
		return true
	}
	bl.mu.RLock()
	elapsed := time.Since(bl.startTime)
	bl.mu.RUnlock()
	samples := bl.sampleCount.Load()
	if elapsed >= bl.learningPeriod && samples >= bl.minSamples {
		if bl.learningComplete.CompareAndSwap(false, true) {
			slog.Info("profiler: learning complete",
				"samples", samples,
				"elapsed_seconds", elapsed.Seconds())
		}
		return true
	}
	return false
}

// LearningProgress returns the progress of learning (0.0 to 1.0).
func (bl *BaselineLearner) LearningProgress() float64 {
	if bl.learningComplete.Load() {
		return 1.0
	}
	bl.mu.RLock()
	defer bl.mu.RUnlock()

	// Progress based on time
	timeProgress := float64(time.Since(bl.startTime)) / float64(bl.learningPeriod)
	if timeProgress > 1.0 {
		timeProgress = 1.0
	}

	// Progress based on samples
	var sampleProgress float64
	if bl.minSamples > 0 {
		sampleProgress = float64(bl.sampleCount.Load()) / float64(bl.minSamples)
		if sampleProgress > 1.0 {
			sampleProgress = 1.0
		}
	} else {
		sampleProgress = 1.0
	}

	// Return minimum of time and sample progress
	if timeProgress < sampleProgress {
		return timeProgress
	}
	return sampleProgress
}

// TimeRemaining returns the time remaining in the learning phase.
func (bl *BaselineLearner) TimeRemaining() time.Duration {
	if bl.learningComplete.Load() {
		return 0
	}
	bl.mu.RLock()
	defer bl.mu.RUnlock()

	elapsed := time.Since(bl.startTime)
	remaining := bl.learningPeriod - elapsed
	if remaining < 0 {
		return 0
	}
	return remaining
}

// Reset resets the learning phase.
func (bl *BaselineLearner) Reset() {
	bl.mu.Lock()
	defer bl.mu.Unlock()
	bl.startTime = time.Now()
	bl.learningComplete.Store(false)
	bl.sampleCount.Store(0)
}

// GetSampleCount returns the current sample count.
func (bl *BaselineLearner) GetSampleCount() uint64 {
	return bl.sampleCount.Load()
}

// BaselineStats holds statistical information about a baseline.
type BaselineStats struct {
	Mean     float64
	Variance float64
	StdDev   float64
	Min      float64
	Max      float64
	Count    uint64
}

// CalculateStats calculates statistics from a slice of EWMA values.
func CalculateStats(values []float64) BaselineStats {
	if len(values) == 0 {
		return BaselineStats{}
	}

	var sum, min, max float64
	min = math.MaxFloat64
	max = -math.MaxFloat64
	count := uint64(len(values))

	for _, v := range values {
		sum += v
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}

	mean := sum / float64(count)

	// Calculate variance
	var variance float64
	for _, v := range values {
		diff := v - mean
		variance += diff * diff
	}
	variance /= float64(count)

	return BaselineStats{
		Mean:     mean,
		Variance: variance,
		StdDev:   math.Sqrt(variance),
		Min:      min,
		Max:      max,
		Count:    count,
	}
}

// ZScore calculates the z-score (standard deviations from mean).
// Higher absolute values indicate more anomalous behavior.
func ZScore(value, mean, stdDev float64) float64 {
	if stdDev == 0 {
		if value == mean {
			return 0
		}
		return math.Inf(1)
	}
	return (value - mean) / stdDev
}

// Normalize normalizes a value to [0, 1] range using min-max scaling.
func Normalize(value, min, max float64) float64 {
	if max == min {
		if value == min {
			return 0.5
		}
		return 1.0
	}
	normalized := (value - min) / (max - min)
	if normalized < 0 {
		return 0
	}
	if normalized > 1 {
		return 1
	}
	return normalized
}
