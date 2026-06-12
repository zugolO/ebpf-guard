// Package profiler provides behavioral profiling and anomaly detection for processes.
package profiler

import (
	"context"
	"math"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zugolO/ebpf-guard/internal/util"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// portStrings is a pre-computed string table for all 65536 port numbers so that
// formatPort never allocates on the hot path.
var portStrings [65536]string

// syscallStrings covers syscall numbers 0-511 (all Linux x86-64 syscalls as of 6.x).
var syscallStrings [512]string

func init() {
	for i := range portStrings {
		portStrings[i] = strconv.Itoa(i)
	}
	for i := range syscallStrings {
		syscallStrings[i] = "syscall_" + strconv.Itoa(i)
	}
}

// anomalyResultPool recycles AnomalyResult objects (including their Contributions
// backing arrays) across ProcessEvent calls.  Callers must call ReleaseResult when
// they are finished with the returned *AnomalyResult.
var anomalyResultPool = sync.Pool{
	New: func() any {
		return &AnomalyResult{
			// Pre-allocate enough capacity for the worst-case contribution count
			// (TCP: 2, file: 2, syscall: 1) so hot-path appends never reallocate.
			Contributions: make([]AnomalyContribution, 0, 8),
		}
	},
}

// ReleaseResult returns r to the internal pool so its backing memory can be
// reused by the next ProcessEvent call.  After calling ReleaseResult the caller
// MUST NOT read any field of r, including any string inside r.Contributions.
func ReleaseResult(r *AnomalyResult) {
	anomalyResultPool.Put(r)
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

	// Controllable state for memory pressure handling
	enabled      bool
	samplingRate float64

	// samplingCorrections maps event type strings to inverse sampling factors
	// (1.0 / samplingRate) set by the ring-buffer adaptive load controller.
	// When BPF-side sampling is at 25%, the correction factor is 4.0 so each
	// sampled event is weighted as if 4 events were observed, keeping EWMA
	// baselines unbiased. A nil map means no corrections are active.
	samplingCorrections map[string]float64
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
		// Apply BPF sampling correction: if the ring-buffer adaptive sampler is
		// dropping N-1 out of every N events, count each seen event as N samples
		// so the minimum-sample gate and the learning-period timer both reflect
		// the true event rate rather than the sampled rate.
		factor := ad.SamplingCorrectionFactor(eventTypeSamplingKey(e.Type))
		n := int(math.Round(factor))
		if n < 1 {
			n = 1
		}
		for i := 0; i < n; i++ {
			ad.learner.RecordSample()
		}
		return nil
	}

	// Score the event against the established baseline BEFORE recording it.
	// Recording first would fold the current observation into the profile
	// (e.g. add a never-before-seen destination port with EWMA value 1.0),
	// making the event look normal when scored against itself and defeating
	// the "new port / new behavior" detection.
	//
	// Profile is keyed by workload class (comm + namespace + pod app label) so
	// all replicas of the same workload share one baseline.
	key := WorkloadKeyFromEvent(e)
	profile := ad.profileManager.GetByKey(key)
	var result *AnomalyResult
	if profile != nil {
		result = ad.calculateAnomalyScore(profile, e, key)
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

// GetProfileManager returns the underlying workload profile manager.
func (ad *AnomalyDetector) GetProfileManager() *WorkloadProfileManager {
	return ad.profileManager
}

// calculateAnomalyScore calculates the anomaly score for a workload profile.
//
// Lock order invariant: wpm.mu (WorkloadProfileManager) must be acquired before
// profile.mu. This is enforced by the call chain:
//   ProcessEvent -> GetByKey (holds wpm.mu) -> calculateAnomalyScore.
// The invariant prevents deadlock between RecordEvent and calculateAnomalyScore.
func (ad *AnomalyDetector) calculateAnomalyScore(profile *ProcessProfile, event types.Event, key WorkloadKey) *AnomalyResult {
	profile.mu.Lock()
	defer profile.mu.Unlock()

	// Get a recycled result from the pool and reset its reusable fields.
	result := anomalyResultPool.Get().(*AnomalyResult)
	result.PID = event.PID // from event, not profile — profile is shared across PIDs
	result.Comm = profile.Comm
	result.Namespace = key.Namespace
	result.AppLabel = key.AppLabel
	result.Timestamp = time.Now()
	result.Score = 0
	result.IsAnomaly = false
	result.Contributions = result.Contributions[:0] // reset length, keep backing array

	var totalScore float64

	// Analyze based on event type; analyze* functions append directly into
	// result.Contributions so no intermediate slice allocation is needed.
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
	case types.EventGPU:
		if event.GPU != nil {
			totalScore = ad.analyzeGPUBehavior(profile, event.GPU, &result.Contributions)
		}
	}

	// Normalize score to [0, 1]
	result.Score = math.Min(totalScore, 1.0)
	result.IsAnomaly = result.Score >= ad.threshold

	return result
}

// analyzeNetworkBehavior analyzes network behavior for anomalies.
// Contributions are appended directly to out so no intermediate slice is allocated.
func (ad *AnomalyDetector) analyzeNetworkBehavior(profile *ProcessProfile, event *types.NetworkEvent, out *[]AnomalyContribution) float64 {
	var score float64

	// Check destination port — portStrings lookup is allocation-free.
	if portEWMA, exists := profile.NetworkProfile.DestPorts[event.Dport]; exists {
		freq := portEWMA.Value()
		portScore := 1.0 - freq
		if portScore > 0.5 {
			*out = append(*out, AnomalyContribution{
				Category:     "network",
				Field:        "dport",
				Value:        portStrings[event.Dport],
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
			Value:        portStrings[event.Dport],
			Expected:     0,
			Observed:     0,
			Contribution: 0.5,
		})
		score += 0.5
	}

	// Check destination address — DestAddrs is keyed by raw [16]byte so the map
	// lookup never needs to allocate a string.  FormatIP16 is deferred to the
	// rare branches that actually produce a contribution.
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
// Contributions are appended directly to out so no intermediate slice is allocated.
func (ad *AnomalyDetector) analyzeFileBehavior(profile *ProcessProfile, event *types.FileEvent, out *[]AnomalyContribution) float64 {
	var score float64

	// Use zero-alloc string for map lookups and comparison; only allocate a heap
	// string when we need to store the value in an AnomalyContribution (which
	// may outlive the event buffer).
	filenameUnsafe := util.UnsafeBytesToString(event.Filename[:])
	dir := extractDirectory(filenameUnsafe)

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
	ext := extractExtension(filenameUnsafe)
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

// gpuOpNames maps GPUOpType constants to human-readable names, matching the
// string table in internal/correlator/rules.go getFieldValue.
var gpuOpNames = [6]string{"alloc", "free", "memcpy_htod", "memcpy_dtoh", "memcpy_dtod", "kernel_launch"}

// gpuOpName returns the string name for a GPU operation.
func gpuOpName(op types.GPUOpType) string {
	if int(op) < len(gpuOpNames) {
		return gpuOpNames[op]
	}
	return strconv.FormatUint(uint64(op), 10)
}

// analyzeGPUBehavior analyzes GPU operation behavior for anomalies.
// Contributions are appended directly to out so no intermediate slice is allocated.
//
// Key detection: if TotalOps == 0 (workload never used GPU during learning),
// any GPU event scores 1.0 — this catches CPU-only workloads that suddenly
// start using the GPU (cryptominer startup, attacker gaining CUDA access).
func (ad *AnomalyDetector) analyzeGPUBehavior(profile *ProcessProfile, event *types.GPUEvent, out *[]AnomalyContribution) float64 {
	if profile.GPUProfile.TotalOps == 0 {
		*out = append(*out, AnomalyContribution{
			Category:     "gpu",
			Field:        "gpu_op",
			Value:        gpuOpName(event.Op),
			Expected:     0,
			Observed:     0,
			Contribution: 1.0,
		})
		return 1.0
	}

	var score float64

	// Check GPU operation type frequency.
	if opEWMA, exists := profile.GPUProfile.OpCounts[event.Op]; exists {
		freq := opEWMA.Value()
		opScore := 1.0 - freq
		if opScore > 0.5 {
			*out = append(*out, AnomalyContribution{
				Category:     "gpu",
				Field:        "gpu_op",
				Value:        gpuOpName(event.Op),
				Expected:     0.5,
				Observed:     freq,
				Contribution: opScore,
			})
			score += opScore * 0.6
		}
	} else {
		*out = append(*out, AnomalyContribution{
			Category:     "gpu",
			Field:        "gpu_op",
			Value:        gpuOpName(event.Op),
			Expected:     0,
			Observed:     0,
			Contribution: 0.6,
		})
		score += 0.6
	}

	// Check GPU transfer size bucket frequency.
	if event.Size > 0 {
		bucket := gpuSizeBucket(event.Size)
		if sizeEWMA, exists := profile.GPUProfile.AllocSizeBuckets[bucket]; exists {
			freq := sizeEWMA.Value()
			sizeScore := 1.0 - freq
			if sizeScore > 0.5 {
				*out = append(*out, AnomalyContribution{
					Category:     "gpu",
					Field:        "gpu_size",
					Value:        strconv.FormatUint(event.Size, 10),
					Expected:     0.5,
					Observed:     freq,
					Contribution: sizeScore,
				})
				score += sizeScore * 0.4
			}
		} else {
			*out = append(*out, AnomalyContribution{
				Category:     "gpu",
				Field:        "gpu_size",
				Value:        strconv.FormatUint(event.Size, 10),
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
// Contributions are appended directly to out so no intermediate slice is allocated.
func (ad *AnomalyDetector) analyzeSyscallBehavior(profile *ProcessProfile, event *types.SyscallEvent, out *[]AnomalyContribution) float64 {
	var score float64

	// Check syscall number — syscallStrings lookup is allocation-free for nr 0-511.
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

// formatPort returns a pre-computed decimal string for port — never allocates.
func formatPort(port uint16) string {
	return portStrings[port]
}

// formatSyscall returns a string like "syscall_N".  For nr 0-511 the result comes
// from the pre-computed table (no allocation).  Unusual numbers fall back to a
// one-off allocation which is acceptable off the hot path.
func formatSyscall(nr int64) string {
	if nr >= 0 && int(nr) < len(syscallStrings) {
		return syscallStrings[nr]
	}
	var buf [32]byte
	b := append(buf[:0], "syscall_"...)
	b = strconv.AppendInt(b, nr, 10)
	return string(b)
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

// SetSamplingCorrections stores per-event-type inverse sampling factors supplied
// by the ring-buffer adaptive load controller. The factor for event type T is
// 1.0 / bpfSamplingRate(T); passing nil or an empty map clears all corrections.
//
// Effect: during the learning phase, each RecordSample() call is counted
// factor times so the learned baseline reflects the true event rate even when
// BPF is down-sampling. This keeps anomaly thresholds from drifting low and
// avoids false positives when sampling is later restored.
func (ad *AnomalyDetector) SetSamplingCorrections(corrections map[string]float64) {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	if len(corrections) == 0 {
		ad.samplingCorrections = nil
		return
	}
	m := make(map[string]float64, len(corrections))
	for k, v := range corrections {
		if v > 1.0 {
			m[k] = v
		}
	}
	if len(m) == 0 {
		ad.samplingCorrections = nil
	} else {
		ad.samplingCorrections = m
	}
}

// SamplingCorrectionFactor returns the EWMA correction factor for the given
// event type. Returns 1.0 when no correction is set (full sampling or unknown type).
func (ad *AnomalyDetector) SamplingCorrectionFactor(eventType string) float64 {
	ad.mu.RLock()
	defer ad.mu.RUnlock()
	if ad.samplingCorrections == nil {
		return 1.0
	}
	if f, ok := ad.samplingCorrections[eventType]; ok {
		return f
	}
	return 1.0
}

// eventTypeSamplingKey maps an EventType to the string key used in the
// samplingCorrections map (matching the keys used by RingBufLoadController).
func eventTypeSamplingKey(et types.EventType) string {
	switch et {
	case types.EventSyscall:
		return "syscall"
	case types.EventTCPConnect, types.EventNetClose:
		return "network"
	case types.EventFileAccess:
		return "file"
	case types.EventDNS:
		return "dns"
	case types.EventTLS:
		return "tls"
	default:
		return ""
	}
}
