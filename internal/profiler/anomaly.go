// Package profiler provides behavioral profiling and anomaly detection for processes.
package profiler

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zugolO/ebpf-guard/internal/util"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// AnomalyDetector performs anomaly detection on process behavior.
type AnomalyDetector struct {
	mu sync.RWMutex

	// Configuration
	threshold      float64       // Anomaly score threshold (0.0-1.0)
	learningPeriod time.Duration // Initial learning period
	weight         float64       // EWMA weight

	// State
	learner        *BaselineLearner
	profileManager *ProfileManager

	// Learning phase tracking - atomic.Bool for hot path performance
	// This eliminates ~10,000 mutex acquisitions/sec after learning completes
	learningStartTime time.Time
	learningComplete  atomic.Bool

	// Controllable state for memory pressure handling
	enabled      bool
	samplingRate float64
}

// AnomalyResult contains the result of anomaly detection.
type AnomalyResult struct {
	PID           uint32
	Comm          string
	Score         float64
	IsAnomaly     bool
	Contributions []AnomalyContribution
	Timestamp     time.Time
}

// AnomalyContribution describes which aspect contributed to the anomaly score.
type AnomalyContribution struct {
	Category     string  // "network", "file", "syscall"
	Field        string  // Specific field (e.g., "dport", "directory")
	Value        string  // The observed value
	Expected     float64 // Expected frequency (baseline)
	Observed     float64 // Observed frequency
	Contribution float64 // Contribution to total score (0.0-1.0)
}

// NewAnomalyDetectorWithContext creates a new anomaly detector whose background
// cleanup goroutines (ProfileManager LRU eviction) exit when ctx is cancelled.
func NewAnomalyDetectorWithContext(ctx context.Context, threshold float64, learningPeriod time.Duration, weight float64) *AnomalyDetector {
	return NewAnomalyDetectorWithSamples(ctx, threshold, learningPeriod, weight, 100)
}

// NewAnomalyDetectorWithSamples is like NewAnomalyDetectorWithContext but allows
// the minimum number of learning samples to be configured. Learning completes
// only once both the learning period has elapsed and minSamples have been
// observed. A minSamples of 0 falls back to the default of 100.
func NewAnomalyDetectorWithSamples(ctx context.Context, threshold float64, learningPeriod time.Duration, weight float64, minSamples uint64) *AnomalyDetector {
	if minSamples == 0 {
		minSamples = 100
	}
	ad := &AnomalyDetector{
		threshold:         threshold,
		learningPeriod:    learningPeriod,
		weight:            weight,
		learner:           NewBaselineLearner(learningPeriod, minSamples),
		profileManager:    NewProfileManagerWithContext(ctx, weight, 24*time.Hour, 65536),
		learningStartTime: time.Now(),
		enabled:           true,
		samplingRate:      1.0,
	}
	return ad
}

// NewAnomalyDetector creates a new anomaly detector.
// Deprecated: use NewAnomalyDetectorWithContext to enable background cleanup goroutines.
func NewAnomalyDetector(threshold float64, learningPeriod time.Duration, weight float64) *AnomalyDetector {
	return NewAnomalyDetectorWithContext(context.Background(), threshold, learningPeriod, weight)
}

// ProcessEvent processes an event and returns anomaly results if detected.
//
// Invariant: This method must be called from a single goroutine per AnomalyDetector
// instance. The caller (CorrelationEngine.Ingest) ensures proper serialization.
// The profileManager.RecordEvent and calculateAnomalyScore calls are not
// thread-safe for the same PID and require external synchronization.
func (ad *AnomalyDetector) ProcessEvent(e types.Event) *AnomalyResult {
	if !ad.IsEnabled() {
		return nil
	}

	// During the learning phase, just fold the event into the baseline.
	if !ad.IsLearningComplete() {
		ad.profileManager.RecordEvent(e)
		ad.learner.RecordSample()
		return nil
	}

	// Score the event against the established baseline BEFORE recording it.
	// Recording first would fold the current observation into the profile
	// (e.g. add a never-before-seen destination port with EWMA value 1.0),
	// making the event look normal when scored against itself and defeating
	// the "new port / new behavior" detection.
	profile := ad.profileManager.Get(e.PID)
	var result *AnomalyResult
	if profile != nil {
		result = ad.calculateAnomalyScore(profile, e)
		profile.SetAnomalyScore(result.Score)
	}

	// Now fold the event into the profile so the baseline keeps adapting.
	ad.profileManager.RecordEvent(e)

	return result
}

// IsLearningComplete checks if the learning phase is complete.
// Uses atomic.Bool for the hot path to avoid mutex overhead after learning completes.
func (ad *AnomalyDetector) IsLearningComplete() bool {
	// Fast path: atomic read, no mutex
	if ad.learningComplete.Load() {
		return true
	}

	// Slow path: check learner and set atomic flag
	if ad.learner.IsLearningComplete() {
		ad.learningComplete.Store(true)
		return true
	}

	return false
}

// LearningProgress returns the progress of the learning phase (0.0-1.0).
func (ad *AnomalyDetector) LearningProgress() float64 {
	return ad.learner.LearningProgress()
}

// TimeRemaining returns the time remaining in the learning phase.
func (ad *AnomalyDetector) TimeRemaining() time.Duration {
	return ad.learner.TimeRemaining()
}

// GetProfileManager returns the underlying profile manager.
func (ad *AnomalyDetector) GetProfileManager() *ProfileManager {
	return ad.profileManager
}

// calculateAnomalyScore calculates the anomaly score for a process.
//
// Lock order invariant: pm.mu (ProfileManager) must be acquired before profile.mu.
// This is enforced by the call chain: ProcessEvent -> Get (holds pm.mu) -> calculateAnomalyScore.
// The invariant prevents deadlock between RecordEvent and calculateAnomalyScore.
func (ad *AnomalyDetector) calculateAnomalyScore(profile *ProcessProfile, event types.Event) *AnomalyResult {
	profile.mu.Lock()
	defer profile.mu.Unlock()

	result := &AnomalyResult{
		PID:       profile.PID,
		Comm:      profile.Comm,
		Timestamp: time.Now(),
	}

	var totalScore float64
	var contributions []AnomalyContribution

	// Analyze based on event type
	switch event.Type {
	case types.EventTCPConnect:
		if event.Network != nil {
			score, contrib := ad.analyzeNetworkBehavior(profile, event.Network)
			totalScore += score
			contributions = append(contributions, contrib...)
		}
	case types.EventFileAccess:
		if event.File != nil {
			score, contrib := ad.analyzeFileBehavior(profile, event.File)
			totalScore += score
			contributions = append(contributions, contrib...)
		}
	case types.EventSyscall:
		if event.Syscall != nil {
			score, contrib := ad.analyzeSyscallBehavior(profile, event.Syscall)
			totalScore += score
			contributions = append(contributions, contrib...)
		}
	}

	// Normalize score to [0, 1]
	result.Score = math.Min(totalScore, 1.0)
	result.IsAnomaly = result.Score >= ad.threshold
	result.Contributions = contributions

	return result
}

// analyzeNetworkBehavior analyzes network behavior for anomalies.
func (ad *AnomalyDetector) analyzeNetworkBehavior(profile *ProcessProfile, event *types.NetworkEvent) (float64, []AnomalyContribution) {
	var score float64
	var contributions []AnomalyContribution

	// Check destination port
	if portEWMA, exists := profile.NetworkProfile.DestPorts[event.Dport]; exists {
		freq := portEWMA.Value()
		// Low frequency = more anomalous
		portScore := 1.0 - freq
		if portScore > 0.5 {
			contributions = append(contributions, AnomalyContribution{
				Category:     "network",
				Field:        "dport",
				Value:        formatPort(event.Dport),
				Expected:     0.5, // Expected average frequency
				Observed:     freq,
				Contribution: portScore,
			})
			score += portScore * 0.5 // Port contributes 50% of network score
		}
	} else {
		// New port never seen before - highly anomalous
		contributions = append(contributions, AnomalyContribution{
			Category:     "network",
			Field:        "dport",
			Value:        formatPort(event.Dport),
			Expected:     0,
			Observed:     0,
			Contribution: 0.5,
		})
		score += 0.5
	}

	// Check destination address
	daddr := util.FormatIP16(event.Daddr, event.Family)
	if addrEWMA, exists := profile.NetworkProfile.DestAddrs[daddr]; exists {
		freq := addrEWMA.Value()
		addrScore := 1.0 - freq
		if addrScore > 0.5 {
			contributions = append(contributions, AnomalyContribution{
				Category:     "network",
				Field:        "daddr",
				Value:        daddr,
				Expected:     0.5,
				Observed:     freq,
				Contribution: addrScore,
			})
			score += addrScore * 0.5 // Address contributes 50% of network score
		}
	} else {
		// New address never seen before
		contributions = append(contributions, AnomalyContribution{
			Category:     "network",
			Field:        "daddr",
			Value:        daddr,
			Expected:     0,
			Observed:     0,
			Contribution: 0.5,
		})
		score += 0.5
	}

	return math.Min(score, 1.0), contributions
}

// analyzeFileBehavior analyzes file access behavior for anomalies.
func (ad *AnomalyDetector) analyzeFileBehavior(profile *ProcessProfile, event *types.FileEvent) (float64, []AnomalyContribution) {
	var score float64
	var contributions []AnomalyContribution

	filename := util.BytesToString(event.Filename[:])
	dir := extractDirectory(filename)

	// Check directory access
	if dir != "" {
		if dirEWMA, exists := profile.FileProfile.Directories[dir]; exists {
			freq := dirEWMA.Value()
			dirScore := 1.0 - freq
			if dirScore > 0.5 {
				contributions = append(contributions, AnomalyContribution{
					Category:     "file",
					Field:        "directory",
					Value:        dir,
					Expected:     0.5,
					Observed:     freq,
					Contribution: dirScore,
				})
				score += dirScore * 0.6 // Directory contributes 60% of file score
			}
		} else {
			// New directory
			contributions = append(contributions, AnomalyContribution{
				Category:     "file",
				Field:        "directory",
				Value:        dir,
				Expected:     0,
				Observed:     0,
				Contribution: 0.6,
			})
			score += 0.6
		}
	}

	// Check file extension
	ext := extractExtension(filename)
	if ext != "" {
		if extEWMA, exists := profile.FileProfile.Extensions[ext]; exists {
			freq := extEWMA.Value()
			extScore := 1.0 - freq
			if extScore > 0.5 {
				contributions = append(contributions, AnomalyContribution{
					Category:     "file",
					Field:        "extension",
					Value:        ext,
					Expected:     0.5,
					Observed:     freq,
					Contribution: extScore,
				})
				score += extScore * 0.4 // Extension contributes 40% of file score
			}
		} else {
			// New extension
			contributions = append(contributions, AnomalyContribution{
				Category:     "file",
				Field:        "extension",
				Value:        ext,
				Expected:     0,
				Observed:     0,
				Contribution: 0.4,
			})
			score += 0.4
		}
	}

	return math.Min(score, 1.0), contributions
}

// analyzeSyscallBehavior analyzes syscall patterns for anomalies.
func (ad *AnomalyDetector) analyzeSyscallBehavior(profile *ProcessProfile, event *types.SyscallEvent) (float64, []AnomalyContribution) {
	var score float64
	var contributions []AnomalyContribution

	// Check syscall number
	if scEWMA, exists := profile.SyscallProfile.Syscalls[event.Nr]; exists {
		freq := scEWMA.Value()
		scScore := 1.0 - freq
		if scScore > 0.5 {
			contributions = append(contributions, AnomalyContribution{
				Category:     "syscall",
				Field:        "nr",
				Value:        formatSyscall(event.Nr),
				Expected:     0.5,
				Observed:     freq,
				Contribution: scScore,
			})
			score += scScore
		}
	} else {
		// New syscall never seen before
		contributions = append(contributions, AnomalyContribution{
			Category:     "syscall",
			Field:        "nr",
			Value:        formatSyscall(event.Nr),
			Expected:     0,
			Observed:     0,
			Contribution: 1.0,
		})
		score += 1.0
	}

	return math.Min(score, 1.0), contributions
}

// Helper functions

func formatPort(port uint16) string {
	return strconv.FormatUint(uint64(port), 10)
}

func formatSyscall(nr int64) string {
	return fmt.Sprintf("syscall_%d", nr)
}


// Enable activates the anomaly detector.
func (ad *AnomalyDetector) Enable() {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	ad.enabled = true
}

// Disable deactivates the anomaly detector.
func (ad *AnomalyDetector) Disable() {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	ad.enabled = false
}

// IsEnabled returns true if the anomaly detector is currently active.
func (ad *AnomalyDetector) IsEnabled() bool {
	ad.mu.RLock()
	defer ad.mu.RUnlock()
	return ad.enabled
}

// SetSamplingRate adjusts the anomaly detector's sampling rate.
// rate must be in range [0.0, 1.0] where 1.0 means 100% sampling.
func (ad *AnomalyDetector) SetSamplingRate(rate float64) {
	if rate < 0.0 {
		rate = 0.0
	}
	if rate > 1.0 {
		rate = 1.0
	}
	ad.mu.Lock()
	defer ad.mu.Unlock()
	ad.samplingRate = rate
}

// GetSamplingRate returns the current sampling rate.
func (ad *AnomalyDetector) GetSamplingRate() float64 {
	ad.mu.RLock()
	defer ad.mu.RUnlock()
	return ad.samplingRate
}
