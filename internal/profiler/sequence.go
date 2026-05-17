// Package profiler provides syscall sequence anomaly detection using frequency vectors.
package profiler

import (
	"context"
	"math"
	"strconv"
	"sync"
	"time"

	"github.com/ebpf-guard/ebpf-guard/pkg/types"
	"github.com/prometheus/client_golang/prometheus"
)

// SequenceConfig holds configuration for sequence profiling.
type SequenceConfig struct {
	Enabled    bool
	WindowSize int
	Threshold  float64
}

// DefaultSequenceConfig returns default sequence profiling configuration.
func DefaultSequenceConfig() SequenceConfig {
	return SequenceConfig{
		Enabled:    true,
		WindowSize: 64,
		Threshold:  0.3,
	}
}

// FrequencyVector represents syscall frequency distribution over a time window.
type FrequencyVector map[int]float64

// syscallWindow is a ring buffer of recent syscall numbers.
type syscallWindow struct {
	syscalls []int
	head     int
	size     int
	full     bool
}

func newSyscallWindow(capacity int) *syscallWindow {
	return &syscallWindow{
		syscalls: make([]int, capacity),
	}
}

func (w *syscallWindow) capacity() int { return len(w.syscalls) }

func (w *syscallWindow) push(syscallNr int) {
	w.syscalls[w.head] = syscallNr
	w.head = (w.head + 1) % len(w.syscalls)
	if !w.full && w.head == 0 {
		w.full = true
	}
	if w.size < len(w.syscalls) {
		w.size++
	}
}

func (w *syscallWindow) toVector() FrequencyVector {
	if w.size == 0 {
		return FrequencyVector{}
	}

	vec := make(FrequencyVector)
	count := w.size
	if w.full {
		count = len(w.syscalls)
	}

	start := 0
	if w.full {
		start = w.head
	}

	for i := 0; i < count; i++ {
		idx := (start + i) % len(w.syscalls)
		vec[w.syscalls[idx]]++
	}

	// Normalize to frequencies
	for k := range vec {
		vec[k] /= float64(count)
	}

	return vec
}

// pidSequenceState tracks sequence state for a single PID.
type pidSequenceState struct {
	window      *syscallWindow
	baseline    FrequencyVector
	sampleCount int
	lastUpdate  time.Time
}

// SequenceProfiler detects anomalies in syscall sequences using frequency vectors.
type SequenceProfiler struct {
	config       SequenceConfig
	states       map[uint32]*pidSequenceState
	mu           sync.RWMutex
	distance     *prometheus.GaugeVec
	ttl          time.Duration
	maxPIDs      int
	enabled      bool
	samplingRate float64
}

// NewSequenceProfiler creates a new sequence profiler.
// Deprecated: use NewSequenceProfilerWithContext to enable background cleanup.
func NewSequenceProfiler(config SequenceConfig, ttl time.Duration) *SequenceProfiler {
	return newSequenceProfiler(config, ttl, 65536)
}

// NewSequenceProfilerWithContext creates a sequence profiler with a background
// cleanup goroutine that exits when ctx is cancelled.
func NewSequenceProfilerWithContext(ctx context.Context, config SequenceConfig, ttl time.Duration, maxPIDs int) *SequenceProfiler {
	if maxPIDs <= 0 {
		maxPIDs = 65536
	}
	sp := newSequenceProfiler(config, ttl, maxPIDs)
	go sp.cleanupLoop(ctx)
	return sp
}

func newSequenceProfiler(config SequenceConfig, ttl time.Duration, maxPIDs int) *SequenceProfiler {
	if config.WindowSize <= 0 {
		config.WindowSize = 64
	}
	if config.Threshold <= 0 {
		config.Threshold = 0.3
	}
	return &SequenceProfiler{
		config: config,
		states: make(map[uint32]*pidSequenceState),
		distance: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ebpf_guard_profiler_sequence_distance",
			Help: "Cosine distance between current and baseline syscall frequency vectors",
		}, []string{"pid", "comm"}),
		ttl:          ttl,
		maxPIDs:      maxPIDs,
		enabled:      config.Enabled,
		samplingRate: 1.0,
	}
}

// cleanupLoop periodically evicts stale PID states until ctx is cancelled.
func (sp *SequenceProfiler) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			sp.Cleanup(time.Now())
		case <-ctx.Done():
			return
		}
	}
}

// RegisterMetrics registers Prometheus metrics.
func (sp *SequenceProfiler) RegisterMetrics(reg prometheus.Registerer) error {
	return reg.Register(sp.distance)
}

// Update processes a syscall event and returns distance if anomaly detected.
func (sp *SequenceProfiler) Update(e types.Event) (distance float64, isAnomaly bool) {
	if !sp.enabled || e.Type != types.EventSyscall || e.Syscall == nil {
		return 0, false
	}

	sp.mu.Lock()
	defer sp.mu.Unlock()

	state, exists := sp.states[e.PID]
	if !exists {
		if sp.maxPIDs > 0 && len(sp.states) >= sp.maxPIDs {
			sp.evictLRULocked()
		}
		state = &pidSequenceState{
			window:     newSyscallWindow(sp.config.WindowSize),
			lastUpdate: time.Now(),
		}
		sp.states[e.PID] = state
	}

	state.window.push(int(e.Syscall.Nr))
	state.sampleCount++
	state.lastUpdate = time.Now()

	currentVec := state.window.toVector()

	// Learning phase: build baseline
	if state.sampleCount < sp.config.WindowSize {
		// Still collecting initial samples
		return 0, false
	}

	if len(state.baseline) == 0 {
		// First baseline established
		state.baseline = currentVec
		return 0, false
	}

	// Calculate cosine distance
	distance = cosineDistance(currentVec, state.baseline)

	// Update metric
	comm := string(e.Comm[:])
	// Trim null bytes
	for i := 0; i < len(comm); i++ {
		if comm[i] == 0 {
			comm = comm[:i]
			break
		}
	}
	sp.distance.WithLabelValues(strconv.FormatUint(uint64(e.PID), 10), comm).Set(distance)

	// Check threshold
	isAnomaly = distance > sp.config.Threshold

	// Update baseline with EWMA-like smoothing
	if !isAnomaly {
		// Gradually adapt baseline for normal behavior
		state.baseline = mergeVectors(state.baseline, currentVec, 0.1)
	}

	return distance, isAnomaly
}

// GetState returns the current sequence state for a PID (for testing).
func (sp *SequenceProfiler) GetState(pid uint32) (*pidSequenceState, bool) {
	sp.mu.RLock()
	defer sp.mu.RUnlock()
	state, ok := sp.states[pid]
	return state, ok
}

// evictLRULocked removes the state with the oldest lastUpdate timestamp.
// Caller must hold sp.mu (write lock).
func (sp *SequenceProfiler) evictLRULocked() {
	var lruPID uint32
	var lruTime time.Time
	first := true
	for pid, s := range sp.states {
		if first || s.lastUpdate.Before(lruTime) {
			lruPID = pid
			lruTime = s.lastUpdate
			first = false
		}
	}
	if !first {
		delete(sp.states, lruPID)
	}
}

// Cleanup removes stale PID states.
func (sp *SequenceProfiler) Cleanup(now time.Time) {
	sp.mu.Lock()
	defer sp.mu.Unlock()

	for pid, state := range sp.states {
		if now.Sub(state.lastUpdate) > sp.ttl {
			delete(sp.states, pid)
		}
	}
}

// Enable activates the profiler.
func (sp *SequenceProfiler) Enable() {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	sp.enabled = true
}

// Disable deactivates the profiler.
func (sp *SequenceProfiler) Disable() {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	sp.enabled = false
}

// IsEnabled returns true if the profiler is currently active.
func (sp *SequenceProfiler) IsEnabled() bool {
	sp.mu.RLock()
	defer sp.mu.RUnlock()
	return sp.enabled
}

// SetSamplingRate adjusts the profiler's sampling rate.
// rate must be in range [0.0, 1.0] where 1.0 means 100% sampling.
func (sp *SequenceProfiler) SetSamplingRate(rate float64) {
	if rate < 0.0 {
		rate = 0.0
	}
	if rate > 1.0 {
		rate = 1.0
	}
	sp.mu.Lock()
	defer sp.mu.Unlock()
	sp.samplingRate = rate
}

// GetSamplingRate returns the current sampling rate.
func (sp *SequenceProfiler) GetSamplingRate() float64 {
	sp.mu.RLock()
	defer sp.mu.RUnlock()
	return sp.samplingRate
}

// cosineDistance calculates the cosine distance between two frequency vectors.
// Returns 0.0 for identical vectors, 1.0 for orthogonal vectors.
func cosineDistance(a, b FrequencyVector) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 1.0
	}

	// Calculate dot product and magnitudes
	dotProduct := 0.0
	normA := 0.0
	normB := 0.0

	// Iterate over union of keys
	allKeys := make(map[int]struct{})
	for k := range a {
		allKeys[k] = struct{}{}
	}
	for k := range b {
		allKeys[k] = struct{}{}
	}

	for k := range allKeys {
		va := a[k]
		vb := b[k]
		dotProduct += va * vb
		normA += va * va
		normB += vb * vb
	}

	if normA == 0 || normB == 0 {
		return 1.0
	}

	cosineSim := dotProduct / (math.Sqrt(normA) * math.Sqrt(normB))

	// Clamp to [-1, 1] to handle floating point errors
	if cosineSim > 1.0 {
		cosineSim = 1.0
	} else if cosineSim < -1.0 {
		cosineSim = -1.0
	}

	// Cosine distance = 1 - cosine similarity
	return 1.0 - cosineSim
}

// mergeVectors merges two frequency vectors with given weight for the second vector.
func mergeVectors(base, update FrequencyVector, updateWeight float64) FrequencyVector {
	result := make(FrequencyVector)

	// Copy base
	for k, v := range base {
		result[k] = v * (1 - updateWeight)
	}

	// Add weighted update
	for k, v := range update {
		result[k] += v * updateWeight
	}

	return result
}
