// Package profiler provides syscall sequence anomaly detection.
package profiler

import (
	"math"
)

// seqVecSize is the number of syscall slots for Markov chain indexing.
// Must match sequence.go's seqVecSize (512).
const markovVecSize = 512

// MarkovConfig holds configuration for Markov-chain transition modeling.
type MarkovConfig struct {
	// Enabled activates Markov-chain transition scoring alongside cosine distance.
	Enabled bool
	// MaxUniqueSyscalls caps the number of unique syscall numbers tracked per
	// workload. Beyond this limit, the least-frequent syscalls are pruned.
	// Default: 64.
	MaxUniqueSyscalls int
	// FloorProbability is the log10 probability assigned to transitions that
	// were never observed during learning. Smaller values = more aggressive
	// anomaly scoring for novel transitions.
	// Default: -3.0 (equivalent to 0.001 probability).
	FloorProbability float64
	// Threshold is the anomaly score above which the Markov contribution
	// is considered anomalous. Range [0.0, 1.0].
	// Default: 0.35.
	Threshold float64
}

// DefaultMarkovConfig returns sensible defaults.
func DefaultMarkovConfig() MarkovConfig {
	return MarkovConfig{
		Enabled:           true,
		MaxUniqueSyscalls: 64,
		FloorProbability:  -3.0,
		Threshold:         0.35,
	}
}

// MarkovChain models first-order syscall transition probabilities for anomaly
// detection. It captures the ordering of syscalls (syscall A → syscall B),
// complementing the frequency-based cosine distance used by SequenceProfiler.
//
// During the learning phase, transition counts are accumulated (RecordTransition).
// After sufficient samples, the model is finalized (Finalize) — counts are
// normalized into log10 probabilities, and the baseline average log-likelihood
// is computed.
//
// At detection time, ScoreWindow computes the average log-likelihood of the
// observed transitions and normalizes it into an anomaly score in [0, 1].
//
// Performance: O(W) where W is the window size. Transition lookup is O(1)
// via direct map access. The model is keyed by workload class, and all
// replicas of the same workload share one MarkovChain instance.
type MarkovChain struct {
	// Transition counts accumulated during learning.
	// counts[from][to] = number of times syscall 'to' followed syscall 'from'.
	counts map[int64]map[int64]uint32

	// Log10 probabilities computed after finalization.
	// logProbs[from][to] = log10(P(to | from)).
	// Unobserved transitions use floorProb during scoring.
	logProbs map[int64]map[int64]float64

	// Transition probabilities (linear scale), computed after finalization.
	// probs[from][to] = count / total for that 'from' syscall.
	probs map[int64]map[int64]float64

	// floorProb is the log10 probability for unseen transitions.
	floorProb float64

	// baselineAvgLL is the average log-likelihood of transitions during
	// the learning period, computed at Finalize time.
	baselineAvgLL float64

	// baselineLLSet is true once baselineAvgLL has been computed.
	baselineLLSet bool

	// totalTransitions counts all recorded transitions.
	totalTransitions uint64

	// uniqueSyscalls tracks the set of syscalls that have appeared as 'from'.
	uniqueSyscalls map[int64]struct{}

	// maxUnique caps the number of unique from-syscalls tracked.
	maxUnique int

	// finalized is set to true once Finalize() has been called.
	finalized bool

	// sampleCount tracks the number of transitions fed to the model.
	sampleCount uint64
}

// NewMarkovChain creates a Markov chain model with the given configuration.
func NewMarkovChain(cfg MarkovConfig) *MarkovChain {
	mc := &MarkovChain{
		counts:         make(map[int64]map[int64]uint32),
		uniqueSyscalls: make(map[int64]struct{}),
		maxUnique:      cfg.MaxUniqueSyscalls,
		floorProb:      cfg.FloorProbability,
	}
	if mc.maxUnique <= 0 {
		mc.maxUnique = 64
	}
	if mc.floorProb > 0 {
		mc.floorProb = -3.0
	}
	return mc
}

// RecordTransition records a transition from syscall 'from' to syscall 'to'.
// Called during the learning phase for each consecutive syscall pair.
//
// Bounds: if the number of unique from-syscalls exceeds maxUnique, the
// transition is silently dropped to keep memory bounded.
func (mc *MarkovChain) RecordTransition(from, to int64) {
	if mc.finalized {
		return
	}
	if from < 0 || from >= markovVecSize || to < 0 || to >= markovVecSize {
		return
	}

	if _, ok := mc.uniqueSyscalls[from]; !ok {
		if len(mc.uniqueSyscalls) >= mc.maxUnique {
			return // at capacity, drop
		}
		mc.uniqueSyscalls[from] = struct{}{}
	}

	toMap, ok := mc.counts[from]
	if !ok {
		toMap = make(map[int64]uint32)
		mc.counts[from] = toMap
	}
	toMap[to]++
	mc.totalTransitions++
	mc.sampleCount++
}

// Finalize computes log10 transition probabilities from accumulated counts
// and stores the baseline average log-likelihood. After finalization,
// RecordTransition is a no-op and ScoreWindow can be called.
//
// Returns the baseline average log-likelihood.
func (mc *MarkovChain) Finalize() float64 {
	if mc.finalized {
		return mc.baselineAvgLL
	}
	mc.finalized = true

	mc.logProbs = make(map[int64]map[int64]float64, len(mc.counts))
	mc.probs = make(map[int64]map[int64]float64, len(mc.counts))

	var totalLL float64
	var totalTransitions float64

	for from, toMap := range mc.counts {
		logM := make(map[int64]float64, len(toMap))
		probM := make(map[int64]float64, len(toMap))
		var total uint32
		for _, count := range toMap {
			total += count
		}
		if total == 0 {
			continue
		}
		for to, count := range toMap {
			p := float64(count) / float64(total)
			probM[to] = p
			logProb := math.Log10(p)
			logM[to] = logProb
			totalLL += logProb * float64(count)
			totalTransitions += float64(count)
		}
		mc.logProbs[from] = logM
		mc.probs[from] = probM
	}

	if totalTransitions > 0 {
		mc.baselineAvgLL = totalLL / totalTransitions
		mc.baselineLLSet = true
	} else {
		mc.baselineAvgLL = mc.floorProb
		mc.baselineLLSet = true
	}

	return mc.baselineAvgLL
}

// ScoreWindow computes a Markov-chain anomaly score for a window of syscall
// numbers. The window should be an ordered slice of syscall numbers
// representing recent events.
//
// Scoring:
//  1. Compute the average log10 probability of all transitions in the window.
//  2. Normalize to [0, 1] based on how far below the baseline average
//     log-likelihood the current window falls.
//
// A score of 0 means the transitions are as likely as the baseline.
// A score near 1 means the transitions are extremely unlikely.
//
// Returns 0 if there are fewer than 2 syscalls in the window, or if the
// model has not been finalized.
func (mc *MarkovChain) ScoreWindow(window []int64) (score float64, isAnomaly bool, threshold float64) {
	if len(window) < 2 || !mc.finalized || !mc.baselineLLSet {
		return 0, false, 0.35
	}

	var totalLL float64
	var count int

	for i := 1; i < len(window); i++ {
		from := window[i-1]
		to := window[i]

		if from < 0 || from >= markovVecSize || to < 0 || to >= markovVecSize {
			continue
		}

		if logM, ok := mc.logProbs[from]; ok {
			if lp, ok := logM[to]; ok {
				totalLL += lp
			} else {
				totalLL += mc.floorProb
			}
		} else {
			totalLL += mc.floorProb
		}
		count++
	}

	if count == 0 {
		return 0, false, 0.35
	}

	avgLL := totalLL / float64(count)

	// delta = how much worse the current window is than the baseline.
	// Positive delta means less likely transitions.
	delta := mc.baselineAvgLL - avgLL
	if delta < 0 {
		delta = 0
	}

	// Normalize: baselineAvgLL is typically around -1 to -2.
	// A delta of 3 means current transitions are 1000x less likely.
	// Score = min(delta / 3.0, 1.0) for intuitive 0-1 range.
	score = delta / 3.0
	if score > 1.0 {
		score = 1.0
	}
	if score < 0 {
		score = 0
	}

	threshold = 0.35
	return score, score > threshold, threshold
}

// IsFinalized returns true if the model has been finalized.
func (mc *MarkovChain) IsFinalized() bool {
	return mc.finalized
}

// SampleCount returns the number of transitions recorded.
func (mc *MarkovChain) SampleCount() uint64 {
	return mc.sampleCount
}

// BaselineAvgLL returns the baseline average log-likelihood.
func (mc *MarkovChain) BaselineAvgLL() float64 {
	return mc.baselineAvgLL
}

// UniqueFromSyscallCount returns the number of unique source syscalls tracked.
func (mc *MarkovChain) UniqueFromSyscallCount() int {
	return len(mc.uniqueSyscalls)
}
