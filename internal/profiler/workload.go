package profiler

import (
	"container/heap"
	"context"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unique"
	"unsafe"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/prometheus/client_golang/prometheus"
)

// readSystemPIDMax reads /proc/sys/kernel/pid_max and returns its value.
// Falls back to 65536 if the file is unavailable (non-Linux, containers without procfs).
func readSystemPIDMax() int {
	data, err := os.ReadFile("/proc/sys/kernel/pid_max")
	if err != nil {
		return 65536
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || v <= 0 {
		return 65536
	}
	return v
}

// WorkloadKey identifies a workload class for behavioral profiling.
// Processes sharing the same (comm, namespace, app label) tuple are grouped
// under one shared baseline so all replicas of a workload train and score
// against the same profile — nginx in prod and nginx in dev get separate baselines.
type WorkloadKey struct {
	Comm      string
	Namespace string
	AppLabel  string // value of pod label "app"; empty for non-K8s processes
}

// String returns a canonical form suitable for use as a map key.
func (k WorkloadKey) String() string {
	return k.Comm + "|" + k.Namespace + "|" + k.AppLabel
}

// internComm returns a deduplicated string for the comm bytes using the
// runtime's unique.Handle table (Go 1.23+). This is 3× faster than the
// previous map+RWMutex approach: no lock contention and no per-process-name
// map entry — the runtime manages deduplication with a lock-free weak-pointer
// table. The returned string is valid for the lifetime of the program.
//
// unsafe.String creates a transient no-alloc view of comm for the hot-path
// lookup. unique.Make stores its own canonical copy for new entries, so the
// transient pointer never escapes beyond the duration of the Make call.
func internComm(comm [16]byte) string {
	// Find null terminator.
	n := 16
	for i, c := range comm {
		if c == 0 {
			n = i
			break
		}
	}
	if n == 0 {
		return ""
	}
	transient := unsafe.String(unsafe.SliceData(comm[:]), n)
	return unique.Make(transient).Value()
}

// WorkloadKeyFromEvent derives a WorkloadKey from an event.
// When Kubernetes enrichment is absent, namespace and app label are empty,
// so all processes with the same comm share one baseline (non-K8s fallback).
// The comm string is interned to avoid heap allocation on repeated calls.
func WorkloadKeyFromEvent(e types.Event) WorkloadKey {
	comm := internComm(e.Comm)
	if e.Enrichment == nil {
		return WorkloadKey{Comm: comm}
	}
	return WorkloadKey{
		Comm:      comm,
		Namespace: e.Enrichment.Namespace,
		AppLabel:  e.Enrichment.Labels["app"],
	}
}

// WorkloadProfileManager manages behavioral profiles keyed by WorkloadKey.
// Multiple PIDs in the same workload share one ProcessProfile, so baselines
// are trained on whole-workload behavior rather than single-process noise.
//
// Profiles are sharded across 16 buckets by a FNV-1a hash of the workload key.
// This eliminates the central mutex bottleneck: GetByKey and RecordEvent acquire
// only their target shard's lock, allowing all N ingest workers to operate on
// disjoint workload classes without contention (P1-3 in AUDIT-PERF-2026-06-13).
type WorkloadProfileManager struct {
	shards  [workloadShardCount]*workloadShard
	weight  float64
	ttl     time.Duration
	maxKeys int

	// entryCount tracks the total number of profiles across all shards.
	// Used with atomic operations to enforce the global maxKeys limit
	// while per-shard locks handle the LRU heaps independently.
	entryCount atomic.Int64

	evictionsTotal prometheus.Counter
	trackedGauge   prometheus.Gauge
	memBytesGauge  prometheus.Gauge
}

const workloadShardCount = 16

type workloadShard struct {
	mu       sync.RWMutex
	profiles map[WorkloadKey]*ProcessProfile
	lruHeap  lruWorkloadKeyHeap
	lruIndex lruWorkloadKeyIndex
	maxKeys  int
}

// hashWorkloadKey returns an FNV-1a 32-bit hash of the workload key, zero-allocation.
func hashWorkloadKey(key WorkloadKey) uint32 {
	var h uint32 = 2166136261
	for i := 0; i < len(key.Comm); i++ {
		h ^= uint32(key.Comm[i])
		h *= 16777619
	}
	h ^= uint32('|')
	h *= 16777619
	for i := 0; i < len(key.Namespace); i++ {
		h ^= uint32(key.Namespace[i])
		h *= 16777619
	}
	h ^= uint32('|')
	h *= 16777619
	for i := 0; i < len(key.AppLabel); i++ {
		h ^= uint32(key.AppLabel[i])
		h *= 16777619
	}
	return h
}

func (wpm *WorkloadProfileManager) shardFor(key WorkloadKey) *workloadShard {
	return wpm.shards[int(hashWorkloadKey(key))%workloadShardCount]
}

// NewWorkloadProfileManager creates a WorkloadProfileManager whose background
// cleanup goroutines exit when ctx is cancelled.
// Pass maxKeys=0 to auto-detect the limit from /proc/sys/kernel/pid_max.
func NewWorkloadProfileManager(ctx context.Context, weight float64, ttl time.Duration, maxKeys int) *WorkloadProfileManager {
	if maxKeys <= 0 {
		maxKeys = readSystemPIDMax()
	}
	perShardMax := maxKeys / workloadShardCount
	if perShardMax < 1 {
		perShardMax = 1
	}
	wpm := &WorkloadProfileManager{
		weight:  weight,
		ttl:     ttl,
		maxKeys: maxKeys,
		trackedGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ebpf_guard_workload_profiles_total",
			Help: "Number of workload classes currently tracked by the profiler.",
		}),
		evictionsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ebpf_guard_workload_profile_evictions_total",
			Help: "Total workload profile evictions due to capacity cap.",
		}),
		memBytesGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ebpf_guard_workload_profiler_memory_bytes",
			Help: "Estimated memory used by workload behavioral profiles.",
		}),
	}
	for i := range wpm.shards {
		wpm.shards[i] = &workloadShard{
			profiles: make(map[WorkloadKey]*ProcessProfile),
			lruIndex: make(lruWorkloadKeyIndex),
			maxKeys:  perShardMax,
		}
	}
	go wpm.cleanupLoop(ctx)
	go wpm.metricsLoop(ctx)
	return wpm
}

// RegisterMetrics registers the manager's Prometheus metrics.
func (wpm *WorkloadProfileManager) RegisterMetrics(reg prometheus.Registerer) error {
	for _, c := range []prometheus.Collector{
		wpm.trackedGauge,
		wpm.evictionsTotal,
		wpm.memBytesGauge,
	} {
		if c == nil {
			continue
		}
		if err := reg.Register(c); err != nil {
			return err
		}
	}
	return nil
}

func (wpm *WorkloadProfileManager) cleanupLoop(ctx context.Context) {
	interval := wpm.ttl / 4
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			wpm.CleanupExpired()
		case <-ctx.Done():
			return
		}
	}
}

func (wpm *WorkloadProfileManager) metricsLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n := 0
			for i := range wpm.shards {
				wpm.shards[i].mu.RLock()
				n += len(wpm.shards[i].profiles)
				wpm.shards[i].mu.RUnlock()
			}
			if wpm.trackedGauge != nil {
				wpm.trackedGauge.Set(float64(n))
			}
			if wpm.memBytesGauge != nil {
				const perProfileEstimate = int(unsafe.Sizeof(ProcessProfile{})) + 512
				wpm.memBytesGauge.Set(float64(n * perProfileEstimate))
			}
		}
	}
}

// GetByKey returns the profile for key, or nil if not found.
func (wpm *WorkloadProfileManager) GetByKey(key WorkloadKey) *ProcessProfile {
	sh := wpm.shardFor(key)
	sh.mu.RLock()
	defer sh.mu.RUnlock()
	return sh.profiles[key]
}

// GetOrCreateByKey returns an existing profile or creates one, evicting LRU if at capacity.
func (wpm *WorkloadProfileManager) GetOrCreateByKey(key WorkloadKey) *ProcessProfile {
	wpm.evictIfOverCapacity()

	sh := wpm.shardFor(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()

	if p, ok := sh.profiles[key]; ok {
		sh.lruIndex.touch(&sh.lruHeap, key)
		return p
	}
	p := NewProcessProfileForWorkload(key)
	sh.profiles[key] = p
	sh.lruIndex.push(&sh.lruHeap, key)
	wpm.entryCount.Add(1)
	return p
}

// RecordEvent records an event into the workload profile derived from the event's
// enrichment. PID is updated on the profile for last-seen context in alerts.
//
// Two-phase locking: the shard lock is held only for the lookup/create, then
// released before the profile update runs under the per-profile mutex.
// This avoids holding the shard lock across the (potentially slower) EWMA update.
func (wpm *WorkloadProfileManager) RecordEvent(e types.Event) {
	key := WorkloadKeyFromEvent(e)
	sh := wpm.shardFor(key)

	// Evict BEFORE acquiring shard lock to avoid RWMutex reentrancy:
	// evictIfOverCapacity takes RLock on all shards, including this one.
	wpm.evictIfOverCapacity()

	sh.mu.Lock()
	p, ok := sh.profiles[key]
	if !ok {
		p = NewProcessProfileForWorkload(key)
		sh.profiles[key] = p
		sh.lruIndex.push(&sh.lruHeap, key)
		wpm.entryCount.Add(1)
	} else {
		sh.lruIndex.touch(&sh.lruHeap, key)
	}
	sh.mu.Unlock()

	p.mu.Lock()
	p.PID = e.PID // last-seen PID for alert context
	switch e.Type {
	case types.EventTCPConnect:
		if e.Network != nil {
			p.recordNetworkEventLocked(e.Network, wpm.weight)
		}
	case types.EventFileAccess:
		if e.File != nil {
			p.recordFileEventLocked(e.File, wpm.weight)
		}
	case types.EventSyscall:
		if e.Syscall != nil {
			p.recordSyscallEventLocked(e.Syscall, wpm.weight)
		}
	case types.EventGPU:
		if e.GPU != nil {
			p.recordGPUEventLocked(e.GPU, wpm.weight)
		}
	}
	p.mu.Unlock()
}

// evictIfOverCapacity evicts the globally-oldest LRU entry when the total entry
// count has reached maxKeys. Scans all shards for the oldest access time to ensure
// true LRU ordering across shards. Best-effort: if no shard has any entries
// the insert proceeds without eviction.
func (wpm *WorkloadProfileManager) evictIfOverCapacity() {
	if wpm.maxKeys <= 0 || wpm.entryCount.Load() < int64(wpm.maxKeys) {
		return
	}
	var oldestShard int
	var oldestTime time.Time
	found := false
	for i := range wpm.shards {
		sh := wpm.shards[i]
		sh.mu.RLock()
		if sh.lruHeap.Len() > 0 {
			t := sh.lruHeap[0].lastAccess
			if !found || t.Before(oldestTime) {
				oldestTime = t
				oldestShard = i
				found = true
			}
		}
		sh.mu.RUnlock()
	}
	if !found {
		return
	}
	sh := wpm.shards[oldestShard]
	sh.mu.Lock()
	if sh.lruHeap.Len() > 0 && sh.lruHeap[0].lastAccess.Equal(oldestTime) {
		e := heap.Pop(&sh.lruHeap).(*lruWorkloadKeyEntry)
		delete(sh.lruIndex, e.key)
		delete(sh.profiles, e.key)
		wpm.entryCount.Add(-1)
		if wpm.evictionsTotal != nil {
			wpm.evictionsTotal.Inc()
		}
	}
	sh.mu.Unlock()
}

// CleanupExpired removes workload profiles that have not been updated within TTL.
func (wpm *WorkloadProfileManager) CleanupExpired() int {
	removed := 0
	for i := range wpm.shards {
		sh := wpm.shards[i]
		sh.mu.Lock()
		for k, p := range sh.profiles {
			if p.IsExpired(wpm.ttl) {
				sh.lruIndex.remove(&sh.lruHeap, k)
				delete(sh.profiles, k)
				wpm.entryCount.Add(-1)
				removed++
			}
		}
		sh.mu.Unlock()
	}
	return removed
}

// evictLRULocked removes the workload profile with the oldest last-access time.
// Caller must hold sh.mu write lock. O(log n) via the min-heap.
func (sh *workloadShard) evictLRULocked(wpm *WorkloadProfileManager) {
	if sh.lruHeap.Len() == 0 {
		return
	}
	e := heap.Pop(&sh.lruHeap).(*lruWorkloadKeyEntry)
	delete(sh.lruIndex, e.key)
	delete(sh.profiles, e.key)
	wpm.entryCount.Add(-1)
	if wpm.evictionsTotal != nil {
		wpm.evictionsTotal.Inc()
	}
}

// Keys returns all currently tracked workload keys.
func (wpm *WorkloadProfileManager) Keys() []WorkloadKey {
	keys := make([]WorkloadKey, 0, wpm.Len())
	for i := range wpm.shards {
		sh := wpm.shards[i]
		sh.mu.RLock()
		for _, p := range sh.profiles {
			keys = append(keys, p.WorkloadKey)
		}
		sh.mu.RUnlock()
	}
	return keys
}

// GetAll returns a copy of all workload profiles keyed by WorkloadKey.String().
func (wpm *WorkloadProfileManager) GetAll() map[string]*ProcessProfile {
	result := make(map[string]*ProcessProfile, wpm.Len())
	for i := range wpm.shards {
		sh := wpm.shards[i]
		sh.mu.RLock()
		for k, v := range sh.profiles {
			result[k.String()] = v
		}
		sh.mu.RUnlock()
	}
	return result
}

// Len returns the number of tracked workload profiles.
func (wpm *WorkloadProfileManager) Len() int {
	n := 0
	for i := range wpm.shards {
		sh := wpm.shards[i]
		sh.mu.RLock()
		n += len(sh.profiles)
		sh.mu.RUnlock()
	}
	return n
}

// Flush removes all profiles and resets LRU structures, releasing their memory.
// Intended for use during worker teardown — not safe to call concurrently with
// RecordEvent or GetOrCreateByKey.
func (wpm *WorkloadProfileManager) Flush() {
	for i := range wpm.shards {
		sh := wpm.shards[i]
		sh.mu.Lock()
		sh.profiles = make(map[WorkloadKey]*ProcessProfile)
		for j := range sh.lruHeap {
			sh.lruHeap[j] = nil
		}
		sh.lruHeap = sh.lruHeap[:0]
		sh.lruIndex = make(lruWorkloadKeyIndex)
		sh.mu.Unlock()
	}
	wpm.entryCount.Store(0)
}
