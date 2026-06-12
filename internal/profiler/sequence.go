// Package profiler provides syscall sequence anomaly detection using frequency vectors.
package profiler

import (
	"container/heap"
	"context"
	"math"
	"math/rand"
	"sync"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/prometheus/client_golang/prometheus"
)

// seqVecSize is the number of syscall slots in a dense frequency vector.
// Linux x86-64 has ~450 syscalls; 512 covers all current numbers with headroom.
const seqVecSize = 512

// FrequencyVector is a dense normalized syscall-frequency array of length seqVecSize.
// Index i holds the normalized frequency of syscall number i.
type FrequencyVector []float32

// seqVecPool recycles fixed-size array buffers on the hot path so that
// SequenceProfiler.Update allocates zero bytes per call after the first baseline is built.
// A *[seqVecSize]float32 is a pointer type and therefore fits inline in an interface{}
// value, making Put/Get truly zero-alloc (unlike pooling a []float32 slice header).
var seqVecPool = sync.Pool{
	New: func() any { return new([seqVecSize]float32) },
}

// SequenceConfig holds configuration for sequence profiling.
type SequenceConfig struct {
	Enabled    bool
	WindowSize int
	Threshold  float64
	// Markov enables first-order Markov chain transition modeling alongside
	// the frequency-vector cosine distance. Captures syscall ordering anomalies.
	Markov MarkovConfig
}

// DefaultSequenceConfig returns default sequence profiling configuration.
func DefaultSequenceConfig() SequenceConfig {
	return SequenceConfig{
		Enabled:    true,
		WindowSize: 64,
		Threshold:  0.3,
	}
}

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

// toVector fills dst with the normalized syscall frequencies for the current window.
// dst must have length >= seqVecSize. It is zeroed before use.
// Syscall numbers >= seqVecSize are silently ignored (Linux x86-64 has ~450 syscalls).
func (w *syscallWindow) toVector(dst FrequencyVector) {
	for i := range dst {
		dst[i] = 0
	}
	if w.size == 0 {
		return
	}
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
		nr := w.syscalls[idx]
		if nr >= 0 && nr < seqVecSize {
			dst[nr]++
		}
	}
	norm := float32(count)
	for i := range dst {
		if dst[i] != 0 {
			dst[i] /= norm
		}
	}
}

// pidSequenceState tracks sequence state for a single workload key.
type pidSequenceState struct {
	window      *syscallWindow
	baseline    *[seqVecSize]float32 // nil until first baseline is established
	sampleCount int
	lastUpdate  time.Time

	// Markov chain transition model — captures syscall ordering (A → B).
	// Populated during learning, scored during detection alongside cosine distance.
	markov *MarkovChain

	// Previous syscall for Markov transition recording.
	prevSyscall    int64
	prevSyscallSet bool

	// Scratch buffer for Markov window scoring (reusable, zero-alloc after init).
	markovScratch []int64
}

// SequenceProfiler detects anomalies in syscall sequences using frequency vectors.
// State is keyed by WorkloadKey so all replicas of a workload share one baseline.
type SequenceProfiler struct {
	config       SequenceConfig
	states       map[WorkloadKey]*pidSequenceState
	mu           sync.RWMutex
	distance     *prometheus.GaugeVec
	markovScore  *prometheus.GaugeVec // Markov transition anomaly score
	ttl          time.Duration
	maxPIDs      int
	enabled      bool
	samplingRate float64

	// LRU eviction structures — O(log n) eviction via a min-heap.
	lruHeap  lruWorkloadKeyHeap
	lruIndex lruWorkloadKeyIndex
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
	if config.Markov.MaxUniqueSyscalls <= 0 {
		config.Markov.MaxUniqueSyscalls = 64
	}
	if config.Markov.FloorProbability >= 0 {
		config.Markov.FloorProbability = -3.0
	}
	return &SequenceProfiler{
		config: config,
		states: make(map[WorkloadKey]*pidSequenceState),
		distance: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ebpf_guard_profiler_sequence_distance",
			Help: "Cosine distance between current and baseline syscall frequency vectors per workload class.",
		}, []string{"comm", "namespace", "app"}),
		markovScore: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ebpf_guard_profiler_sequence_markov_score",
			Help: "Markov-chain transition anomaly score per workload class. 0=normal, 1=extremely unlikely transitions.",
		}, []string{"comm", "namespace", "app"}),
		ttl:          ttl,
		maxPIDs:      maxPIDs,
		enabled:      config.Enabled,
		samplingRate: 1.0,
		lruIndex:     make(lruWorkloadKeyIndex),
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
	for _, c := range []prometheus.Collector{sp.distance, sp.markovScore} {
		if err := reg.Register(c); err != nil {
			return err
		}
	}
	return nil
}

// Update processes a syscall event and returns distance if anomaly detected.
// State is keyed by workload class so all replicas train the same baseline.
// The hot path (existing state, established baseline) performs zero heap allocations.
func (sp *SequenceProfiler) Update(e types.Event) (distance float64, isAnomaly bool) {
	if !sp.enabled || e.Type != types.EventSyscall || e.Syscall == nil {
		return 0, false
	}

	key := WorkloadKeyFromEvent(e)

	sp.mu.Lock()
	defer sp.mu.Unlock()

	// Under memory pressure the watchdog reduces samplingRate via SetSamplingRate.
	// Drop events probabilistically so the profiler doesn't contribute to OOM.
	if sp.samplingRate < 1.0 && rand.Float64() >= sp.samplingRate {
		return 0, false
	}

	state, exists := sp.states[key]
	if !exists {
		if sp.maxPIDs > 0 && len(sp.states) >= sp.maxPIDs {
			sp.evictLRULocked()
		}
		state = &pidSequenceState{
			window:     newSyscallWindow(sp.config.WindowSize),
			lastUpdate: time.Now(),
			markov:     NewMarkovChain(sp.config.Markov),
		}
		sp.states[key] = state
		sp.lruIndex.push(&sp.lruHeap, key)
	} else {
		sp.lruIndex.touch(&sp.lruHeap, key)
	}

	// Record Markov transition before pushing to window (from previous syscall).
	currSyscall := e.Syscall.Nr
	if state.prevSyscallSet && state.markov != nil {
		state.markov.RecordTransition(state.prevSyscall, currSyscall)
	}
	state.prevSyscall = currSyscall
	state.prevSyscallSet = true

	state.window.push(int(currSyscall))
	state.sampleCount++
	state.lastUpdate = time.Now()

	// Learning phase: not enough samples yet to compute a meaningful vector.
	if state.sampleCount < sp.config.WindowSize {
		return 0, false
	}

	// Get a pooled scratch buffer. A *[seqVecSize]float32 pointer fits inline in
	// interface{} so Put/Get are zero-alloc. toVector zeros the array before filling.
	buf := seqVecPool.Get().(*[seqVecSize]float32)
	state.window.toVector(buf[:])

	if state.baseline == nil {
		// First baseline: transfer ownership of the pooled buffer to state.
		// The pool will allocate a fresh buffer on the next call.
		state.baseline = buf
		// Finalize Markov chain at the same time as the frequency baseline.
		if state.markov != nil {
			state.markov.Finalize()
		}
		return 0, false
	}

	// Calculate cosine distance between current window and established baseline.
	cosineDist := cosineDistance(buf[:], state.baseline[:])

	sp.distance.WithLabelValues(key.Comm, key.Namespace, key.AppLabel).Set(cosineDist)

	// Compute Markov transition score when enabled.
	markovScore := 0.0
	if sp.config.Markov.Enabled && state.markov != nil && state.markov.IsFinalized() {
		// Build an int64 window from the ring buffer, reusing scratch buffer.
		count := state.window.size
		if state.window.full {
			count = len(state.window.syscalls)
		}
		if cap(state.markovScratch) < count {
			state.markovScratch = make([]int64, count)
		} else {
			state.markovScratch = state.markovScratch[:count]
		}
		start := 0
		if state.window.full {
			start = state.window.head
		}
		for i := 0; i < count; i++ {
			idx := (start + i) % len(state.window.syscalls)
			state.markovScratch[i] = int64(state.window.syscalls[idx])
		}
		markovScore, _, _ = state.markov.ScoreWindow(state.markovScratch)

		sp.markovScore.WithLabelValues(key.Comm, key.Namespace, key.AppLabel).Set(markovScore)
	}

	// Combined score: use the maximum of cosine distance and Markov score.
	// This catches both frequency anomalies (cosine) and ordering anomalies (Markov).
	distance = cosineDist
	if markovScore > distance {
		distance = markovScore
	}

	isAnomaly = distance > sp.config.Threshold

	// Record the combined distance metric for observability.
	// The Prometheus gauge reports the cosine distance; Markov score is folded in.

	// Gradually adapt baseline for normal behavior (EWMA update in-place).
	if !isAnomaly {
		mergeVectors(state.baseline[:], buf[:], 0.1)
	}

	// Return the scratch buffer to the pool (baseline owns its own buffer).
	seqVecPool.Put(buf)

	return distance, isAnomaly
}

// GetStateByKey returns the current sequence state for a workload key (for testing).
func (sp *SequenceProfiler) GetStateByKey(key WorkloadKey) (*pidSequenceState, bool) {
	sp.mu.RLock()
	defer sp.mu.RUnlock()
	state, ok := sp.states[key]
	return state, ok
}

// evictLRULocked removes the state with the oldest last-access time.
// Caller must hold sp.mu (write lock). O(log n) via the min-heap.
func (sp *SequenceProfiler) evictLRULocked() {
	if sp.lruHeap.Len() == 0 {
		return
	}
	e := heap.Pop(&sp.lruHeap).(*lruWorkloadKeyEntry)
	delete(sp.lruIndex, e.key)
	delete(sp.states, e.key)
}

// Cleanup removes stale workload states.
func (sp *SequenceProfiler) Cleanup(now time.Time) {
	sp.mu.Lock()
	defer sp.mu.Unlock()

	for k, state := range sp.states {
		if now.Sub(state.lastUpdate) > sp.ttl {
			sp.lruIndex.remove(&sp.lruHeap, k)
			delete(sp.states, k)
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
// Operates on dense []float32 slices — no allocation required.
func cosineDistance(a, b FrequencyVector) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 1.0
	}
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	var dotProduct, normA, normB float64
	for i := 0; i < n; i++ {
		va := float64(a[i])
		vb := float64(b[i])
		dotProduct += va * vb
		normA += va * va
		normB += vb * vb
	}
	if normA == 0 || normB == 0 {
		return 1.0
	}
	cosineSim := dotProduct / (math.Sqrt(normA) * math.Sqrt(normB))
	if cosineSim > 1.0 {
		cosineSim = 1.0
	} else if cosineSim < -1.0 {
		cosineSim = -1.0
	}
	return 1.0 - cosineSim
}

// mergeVectors updates base in-place: base[i] = base[i]*(1-w) + update[i]*w.
// No allocation — the caller owns both slices.
func mergeVectors(base, update FrequencyVector, w float64) {
	bw := float32(1 - w)
	uw := float32(w)
	n := len(base)
	if len(update) < n {
		n = len(update)
	}
	for i := 0; i < n; i++ {
		base[i] = base[i]*bw + update[i]*uw
	}
}
