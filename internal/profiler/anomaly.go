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

// portStrings is a pre-computed lookup table that maps every valid port number
// (0–65535) to its decimal string representation.  Eliminates per-event
// strconv allocations on the anomaly-scoring hot path.
var portStrings [65536]string

// maxSyscallNr is the upper bound of the pre-computed syscall string cache.
// Linux x86-64 currently defines ~451 syscalls; 512 gives a small safety margin
// without a meaningful memory cost (512 × ~10 B ≈ 5 KB).
const maxSyscallNr = 512

// syscallStrings caches "syscall_N" string representations for syscall numbers
// in [0, maxSyscallNr).  The ~5 KB table is initialised once at package load.
var syscallStrings [maxSyscallNr]string

func init() {
	for i := range portStrings {
		portStrings[i] = strconv.Itoa(i)
	}
	for i := range syscallStrings {
		syscallStrings[i] = fmt.Sprintf("syscall_%d", i)
	}
}

// anomalyResultPool recycles AnomalyResult objects across ProcessEvent calls,
// eliminating one heap allocation per call on the hot path.
// Callers MUST call result.Release() once they have finished reading all fields.
var anomalyResultPool = sync.Pool{
	New: func() any {
		return &AnomalyResult{
			Contributions: make([]AnomalyContribution, 0, 4),
		}
	},
}

// AnomalyDetector performs anomaly detection on process behavior.
type AnomalyDetector struct {
	mu sync.RWMutex

	// Configuration
	threshold      float64       // Anomaly score threshold (0.0-1.0)
	learningPeriod time.Duration // Initial learning period
	weight         float64       // EWMA weight

	// State
	learner        *BaselineLearner
	profileManager *WorkloadProfileManager // keyed by WorkloadKey for per-workload baselines

	// Learning phase tracking - atomic.Bool for hot path performance
	// This eliminates ~10,000 mutex acquisitions/sec after learning completes
	learningStartTime time.Time
	learningComplete  atomic.Bool

	// Controllable state for memory pressure handling.
	// enabled uses atomic.Bool so IsEnabled() can avoid acquiring mu on the hot path.
	enabled      atomic.Bool
	samplingRate float64
}

// AnomalyResult contains the result of anomaly detection.
type AnomalyResult struct {
	PID           uint32
	Comm          string
	Namespace     string // K8s namespace; empty for non-K8s processes
	AppLabel      string // pod label "app"; empty when absent
	Score         float64
	IsAnomaly     bool
	Contributions []AnomalyContribution
	Timestamp     time.Time
}

// Release returns r to the shared pool.  The caller must not read or write
// any field of r after calling Release.
func (r *AnomalyResult) Release() {
	anomalyResultPool.Put(r)
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
	return NewAnomalyDetectorWithSamples(ctx, threshold, learningPeriod, weight, 100, 0)
}

// NewAnomalyDetectorWithSamples is like NewAnomalyDetectorWithContext but allows
// the minimum number of learning samples and the maximum number of tracked
// workload profiles to be configured.
// A minSamples of 0 falls back to 100; a maxPIDs of 0 falls back to 65536.
func NewAnomalyDetectorWithSamples(ctx context.Context, threshold float64, learningPeriod time.Duration, weight float64, minSamples uint64, maxPIDs int) *AnomalyDetector {
	if minSamples == 0 {
		minSamples = 100
	}
	if maxPIDs <= 0 {
		maxPIDs = 65536
	}
	ad := &AnomalyDetector{
		threshold:         threshold,
		learningPeriod:    learningPeriod,
		weight:            weight,
		learner:           NewBaselineLearner(learningPeriod, minSamples),
		profileManager:    NewWorkloadProfileManager(ctx, weight, 24*time.Hour, maxPIDs),
		learningStartTime: time.Now(),
		samplingRate:      1.0,
	}
	ad.enabled.Store(true)
	return ad
}

// NewAnomalyDetector creates a new anomaly detector.
// Deprecated: use NewAnomalyDetectorWithContext to enable background cleanup goroutines.
func NewAnomalyDetector(threshold float64, learningPeriod time.Duration, weight float64) *AnomalyDetector {
	return NewAnomalyDetectorWithContext(context.Background(), threshold, learningPeriod, weight)
}

// ProcessEvent processes an event and returns anomaly results if detected.
// ruleConfirmed indicates that a detection rule (YAML, WASM, or IOC) already
// flagged this event as malicious. Confirmed events are excluded from the EWMA
// baseline during the learning phase so attacks present at startup are not
// normalised into the behavioural profile and later evade scoring.
//
// Invariant: This method must be called from a single goroutine per AnomalyDetector
// instance. The caller (CorrelationEngine.Ingest) ensures proper serialization.
// The profileManager.RecordEvent and calculateAnomalyScore calls are not
// thread-safe for the same PID and require external synchronization.
func (ad *AnomalyDetector) ProcessEvent(e types.Event, ruleConfirmed bool) *AnomalyResult {
	if !ad.IsEnabled() {
		return nil
	}

	// During the learning phase, fold the event into the baseline — but skip
	// events already confirmed malicious by rule/IOC detection so that active
	// attacks present during startup do not get embedded in the EWMA baseline.
	if !ad.IsLearningComplete() {
		if !ruleConfirmed {
			ad.profileManager.RecordEvent(e)
		}
		ad.learner.RecordSample()
		return nil
	}

	// key + ks computed once; getOrCreateByKeyStrAt uses a single wpm.mu.Lock and
	// scoreAndRecordLockedAt uses a single profile.mu.Lock — replacing the old
	// GetByKeyStr (RLock) + calculateAnomalyScore (profile.mu) + RecordEventByKeyStr
	// (wpm.mu.Lock + profile.mu) sequence with two total mutex acquisitions.
	// time.Now() is called once here and reused for both LRU touch and LastSeenAt
	// update, eliminating a second vDSO call in analyzeRecord* and lruIndex.touch.
	now := time.Now()
	key := WorkloadKeyFromEvent(e)
	ks := key.String()

	// Lookup or create the workload profile under one wpm.mu.Lock cycle.
	profile, created := ad.profileManager.getOrCreateByKeyStrAt(ks, key, now)

	profile.mu.Lock()
	var result *AnomalyResult
	if !created {
		// Existing profile: score first (compares against current baseline), then
		// record (updates baseline) — all under a single profile.mu.Lock.
		result = ad.scoreAndRecordLockedAt(profile, e, key, now)
	} else {
		// Newly-created profile: no baseline to score against yet; just record.
		profile.PID = e.PID
		switch e.Type {
		case types.EventTCPConnect:
			if e.Network != nil {
				profile.recordNetworkEventLocked(e.Network, ad.weight)
			}
		case types.EventFileAccess:
			if e.File != nil {
				profile.recordFileEventLocked(e.File, ad.weight)
			}
		case types.EventSyscall:
			if e.Syscall != nil {
				profile.recordSyscallEventLocked(e.Syscall, ad.weight)
			}
		}
	}
	profile.mu.Unlock()

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

// GetProfileManager returns the underlying workload profile manager.
func (ad *AnomalyDetector) GetProfileManager() *WorkloadProfileManager {
	return ad.profileManager
}

// calculateAnomalyScore calculates the anomaly score for a workload profile.
//
// Lock order invariant: wpm.mu must be released before profile.mu is acquired.
// The call chain (ProcessEvent → getOrCreateByKeyStr releases wpm.mu → scoreAndRecordLocked
// acquires profile.mu) satisfies this invariant.
//
// The returned *AnomalyResult is obtained from anomalyResultPool.  Callers MUST
// call result.Release() once they are done reading fields.
func (ad *AnomalyDetector) calculateAnomalyScore(profile *ProcessProfile, event types.Event, key WorkloadKey) *AnomalyResult {
	profile.mu.Lock()
	defer profile.mu.Unlock()
	return ad.scoreProfileLocked(profile, event, key)
}

// scoreProfileLocked computes the anomaly result.  Caller MUST hold profile.mu.
func (ad *AnomalyDetector) scoreProfileLocked(profile *ProcessProfile, event types.Event, key WorkloadKey) *AnomalyResult {
	result := anomalyResultPool.Get().(*AnomalyResult)
	result.PID = event.PID
	result.Comm = profile.Comm
	result.Namespace = key.Namespace
	result.AppLabel = key.AppLabel
	result.Timestamp = time.Unix(0, int64(event.Timestamp))
	result.Score = 0
	result.IsAnomaly = false
	result.Contributions = result.Contributions[:0]

	var totalScore float64
	switch event.Type {
	case types.EventTCPConnect:
		if event.Network != nil {
			totalScore = ad.analyzeNetworkBehavior(profile, event.Network, &result.Contributions)
		}
	case types.EventFileAccess:
		if event.File != nil {
			totalScore = ad.analyzeFileBehavior(profile, event.File, &result.Contributions)
		}
	case types.EventSyscall:
		if event.Syscall != nil {
			totalScore = ad.analyzeSyscallBehavior(profile, event.Syscall, &result.Contributions)
		}
	}

	result.Score = math.Min(totalScore, 1.0)
	result.IsAnomaly = result.Score >= ad.threshold
	profile.AnomalyScore = result.Score
	return result
}

// scoreAndRecordLockedAt scores the event then records it into the profile baseline.
// Caller MUST hold profile.mu.  Scoring happens before recording so the current
// observation is compared against the pre-event baseline rather than itself.
// now is a caller-supplied timestamp reused for result.Timestamp and profile.LastSeenAt,
// avoiding extra time.Now() calls inside the analyzeRecord* helpers.
//
// For each EWMA-tracked field, a single map lookup serves both the anomaly score
// calculation and the baseline update, halving the number of hash lookups compared
// to calling the separate analyze and record functions sequentially.
func (ad *AnomalyDetector) scoreAndRecordLockedAt(profile *ProcessProfile, e types.Event, key WorkloadKey, now time.Time) *AnomalyResult {
	result := anomalyResultPool.Get().(*AnomalyResult)
	result.PID = e.PID
	result.Comm = profile.Comm
	result.Namespace = key.Namespace
	result.AppLabel = key.AppLabel
	result.Timestamp = now
	result.Score = 0
	result.IsAnomaly = false
	result.Contributions = result.Contributions[:0]
	profile.PID = e.PID
	profile.LastSeenAt = now

	var totalScore float64
	switch e.Type {
	case types.EventTCPConnect:
		if e.Network != nil {
			totalScore = ad.analyzeRecordNetwork(profile, e.Network, &result.Contributions)
		}
	case types.EventFileAccess:
		if e.File != nil {
			totalScore = ad.analyzeRecordFile(profile, e.File, &result.Contributions)
		}
	case types.EventSyscall:
		if e.Syscall != nil {
			totalScore = ad.analyzeRecordSyscall(profile, e.Syscall, &result.Contributions)
		}
	}

	result.Score = math.Min(totalScore, 1.0)
	result.IsAnomaly = result.Score >= ad.threshold
	profile.AnomalyScore = result.Score
	return result
}

// analyzeRecordNetwork scores and records a network event in one pass — each EWMA
// is looked up once for both anomaly scoring and baseline update.
// profile.LastSeenAt must be set by the caller (scoreAndRecordLockedAt) before this.
func (ad *AnomalyDetector) analyzeRecordNetwork(profile *ProcessProfile, event *types.NetworkEvent, out *[]AnomalyContribution) float64 {
	var score float64
	profile.NetworkProfile.TotalConnections++

	portEWMA := profile.NetworkProfile.DestPorts[event.Dport]
	if portEWMA != nil {
		freq := portEWMA.Value()
		portScore := 1.0 - freq
		if portScore > 0.5 {
			*out = append(*out, AnomalyContribution{
				Category: "network", Field: "dport",
				Value: formatPort(event.Dport), Expected: 0.5,
				Observed: freq, Contribution: portScore,
			})
			score += portScore * 0.5
		}
	} else {
		*out = append(*out, AnomalyContribution{
			Category: "network", Field: "dport",
			Value: formatPort(event.Dport), Contribution: 0.5,
		})
		score += 0.5
		portEWMA = NewEWMA(ad.weight)
		profile.NetworkProfile.DestPorts[event.Dport] = portEWMA
	}
	portEWMA.Update(1.0)

	addrEWMA := profile.NetworkProfile.DestAddrs[event.Daddr]
	if addrEWMA != nil {
		freq := addrEWMA.Value()
		addrScore := 1.0 - freq
		if addrScore > 0.5 {
			*out = append(*out, AnomalyContribution{
				Category: "network", Field: "daddr",
				Value: util.FormatIP16(event.Daddr, event.Family), Expected: 0.5,
				Observed: freq, Contribution: addrScore,
			})
			score += addrScore * 0.5
		}
	} else {
		*out = append(*out, AnomalyContribution{
			Category: "network", Field: "daddr",
			Value: util.FormatIP16(event.Daddr, event.Family), Contribution: 0.5,
		})
		score += 0.5
		addrEWMA = NewEWMA(ad.weight)
		profile.NetworkProfile.DestAddrs[event.Daddr] = addrEWMA
	}
	addrEWMA.Update(1.0)

	return math.Min(score, 1.0)
}

// analyzeRecordFile scores and records a file access event in one pass.
// profile.LastSeenAt must be set by the caller (scoreAndRecordLockedAt) before this.
func (ad *AnomalyDetector) analyzeRecordFile(profile *ProcessProfile, event *types.FileEvent, out *[]AnomalyContribution) float64 {
	var score float64
	profile.FileProfile.TotalOperations++

	filename := util.BytesToString(event.Filename[:])
	dir := extractDirectory(filename)
	if dir != "" {
		dirEWMA := profile.FileProfile.Directories[dir]
		if dirEWMA != nil {
			freq := dirEWMA.Value()
			dirScore := 1.0 - freq
			if dirScore > 0.5 {
				*out = append(*out, AnomalyContribution{
					Category: "file", Field: "directory",
					Value: dir, Expected: 0.5, Observed: freq, Contribution: dirScore,
				})
				score += dirScore * 0.6
			}
		} else {
			*out = append(*out, AnomalyContribution{
				Category: "file", Field: "directory",
				Value: dir, Contribution: 0.6,
			})
			score += 0.6
			dirEWMA = NewEWMA(ad.weight)
			profile.FileProfile.Directories[dir] = dirEWMA
		}
		dirEWMA.Update(1.0)
	}

	ext := extractExtension(filename)
	if ext != "" {
		extEWMA := profile.FileProfile.Extensions[ext]
		if extEWMA != nil {
			freq := extEWMA.Value()
			extScore := 1.0 - freq
			if extScore > 0.5 {
				*out = append(*out, AnomalyContribution{
					Category: "file", Field: "extension",
					Value: ext, Expected: 0.5, Observed: freq, Contribution: extScore,
				})
				score += extScore * 0.4
			}
		} else {
			*out = append(*out, AnomalyContribution{
				Category: "file", Field: "extension",
				Value: ext, Contribution: 0.4,
			})
			score += 0.4
			extEWMA = NewEWMA(ad.weight)
			profile.FileProfile.Extensions[ext] = extEWMA
		}
		extEWMA.Update(1.0)
	}

	return math.Min(score, 1.0)
}

// analyzeRecordSyscall scores and records a syscall event in one pass.
// profile.LastSeenAt must be set by the caller (scoreAndRecordLockedAt) before this.
func (ad *AnomalyDetector) analyzeRecordSyscall(profile *ProcessProfile, event *types.SyscallEvent, out *[]AnomalyContribution) float64 {
	profile.SyscallProfile.TotalSyscalls++

	scEWMA := profile.SyscallProfile.Syscalls[event.Nr]
	if scEWMA != nil {
		freq := scEWMA.Value()
		scScore := 1.0 - freq
		if scScore > 0.5 {
			*out = append(*out, AnomalyContribution{
				Category: "syscall", Field: "nr",
				Value: formatSyscall(event.Nr), Expected: 0.5,
				Observed: freq, Contribution: scScore,
			})
			scEWMA.Update(1.0)
			return math.Min(scScore, 1.0)
		}
		scEWMA.Update(1.0)
		return 0
	}
	*out = append(*out, AnomalyContribution{
		Category: "syscall", Field: "nr",
		Value: formatSyscall(event.Nr), Contribution: 1.0,
	})
	scEWMA = NewEWMA(ad.weight)
	profile.SyscallProfile.Syscalls[event.Nr] = scEWMA
	scEWMA.Update(1.0)
	return 1.0
}

// analyzeNetworkBehavior analyzes network behavior for anomalies.
// Contributions are appended directly to *out so the caller's pre-allocated
// backing array is reused without a fresh heap allocation.
func (ad *AnomalyDetector) analyzeNetworkBehavior(profile *ProcessProfile, event *types.NetworkEvent, out *[]AnomalyContribution) float64 {
	var score float64

	// Check destination port
	if portEWMA, exists := profile.NetworkProfile.DestPorts[event.Dport]; exists {
		freq := portEWMA.Value()
		portScore := 1.0 - freq
		if portScore > 0.5 {
			*out = append(*out, AnomalyContribution{
				Category:     "network",
				Field:        "dport",
				Value:        formatPort(event.Dport),
				Expected:     0.5,
				Observed:     freq,
				Contribution: portScore,
			})
			score += portScore * 0.5
		}
	} else {
		*out = append(*out, AnomalyContribution{
			Category:     "network",
			Field:        "dport",
			Value:        formatPort(event.Dport),
			Expected:     0,
			Observed:     0,
			Contribution: 0.5,
		})
		score += 0.5
	}

	// Check destination address — use the raw [16]byte key so no string allocation
	// is needed for the map lookup.  FormatIP16 is called only when a contribution
	// is actually appended (anomalous address), keeping the common case alloc-free.
	if addrEWMA, exists := profile.NetworkProfile.DestAddrs[event.Daddr]; exists {
		freq := addrEWMA.Value()
		addrScore := 1.0 - freq
		if addrScore > 0.5 {
			*out = append(*out, AnomalyContribution{
				Category:     "network",
				Field:        "daddr",
				Value:        util.FormatIP16(event.Daddr, event.Family),
				Expected:     0.5,
				Observed:     freq,
				Contribution: addrScore,
			})
			score += addrScore * 0.5
		}
	} else {
		*out = append(*out, AnomalyContribution{
			Category:     "network",
			Field:        "daddr",
			Value:        util.FormatIP16(event.Daddr, event.Family),
			Expected:     0,
			Observed:     0,
			Contribution: 0.5,
		})
		score += 0.5
	}

	return math.Min(score, 1.0)
}

// analyzeFileBehavior analyzes file access behavior for anomalies.
func (ad *AnomalyDetector) analyzeFileBehavior(profile *ProcessProfile, event *types.FileEvent, out *[]AnomalyContribution) float64 {
	var score float64

	filename := util.BytesToString(event.Filename[:])
	dir := extractDirectory(filename)

	// Check directory access
	if dir != "" {
		if dirEWMA, exists := profile.FileProfile.Directories[dir]; exists {
			freq := dirEWMA.Value()
			dirScore := 1.0 - freq
			if dirScore > 0.5 {
				*out = append(*out, AnomalyContribution{
					Category:     "file",
					Field:        "directory",
					Value:        dir,
					Expected:     0.5,
					Observed:     freq,
					Contribution: dirScore,
				})
				score += dirScore * 0.6
			}
		} else {
			*out = append(*out, AnomalyContribution{
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
				*out = append(*out, AnomalyContribution{
					Category:     "file",
					Field:        "extension",
					Value:        ext,
					Expected:     0.5,
					Observed:     freq,
					Contribution: extScore,
				})
				score += extScore * 0.4
			}
		} else {
			*out = append(*out, AnomalyContribution{
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

	return math.Min(score, 1.0)
}

// analyzeSyscallBehavior analyzes syscall patterns for anomalies.
func (ad *AnomalyDetector) analyzeSyscallBehavior(profile *ProcessProfile, event *types.SyscallEvent, out *[]AnomalyContribution) float64 {
	var score float64

	// Check syscall number
	if scEWMA, exists := profile.SyscallProfile.Syscalls[event.Nr]; exists {
		freq := scEWMA.Value()
		scScore := 1.0 - freq
		if scScore > 0.5 {
			*out = append(*out, AnomalyContribution{
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
		*out = append(*out, AnomalyContribution{
			Category:     "syscall",
			Field:        "nr",
			Value:        formatSyscall(event.Nr),
			Expected:     0,
			Observed:     0,
			Contribution: 1.0,
		})
		score += 1.0
	}

	return math.Min(score, 1.0)
}

// Helper functions

func formatPort(port uint16) string {
	return portStrings[port]
}

func formatSyscall(nr int64) string {
	if nr >= 0 && nr < maxSyscallNr {
		return syscallStrings[nr]
	}
	return fmt.Sprintf("syscall_%d", nr)
}

// Enable activates the anomaly detector.
func (ad *AnomalyDetector) Enable() {
	ad.enabled.Store(true)
}

// Disable deactivates the anomaly detector.
func (ad *AnomalyDetector) Disable() {
	ad.enabled.Store(false)
}

// IsEnabled returns true if the anomaly detector is currently active.
func (ad *AnomalyDetector) IsEnabled() bool {
	return ad.enabled.Load()
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
