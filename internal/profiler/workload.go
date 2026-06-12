package profiler

import (
	"container/heap"
	"context"
	"os"
	"strconv"
	"strings"
	"sync"
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
type WorkloadProfileManager struct {
	mu       sync.RWMutex
	profiles map[WorkloadKey]*ProcessProfile
	weight   float64
	ttl      time.Duration
	maxKeys  int

	// LRU eviction structures — O(log n) eviction via a min-heap.
	lruHeap  lruWorkloadKeyHeap
	lruIndex lruWorkloadKeyIndex

	evictionsTotal prometheus.Counter
	trackedGauge   prometheus.Gauge
	memBytesGauge  prometheus.Gauge
}

// NewWorkloadProfileManager creates a WorkloadProfileManager whose background
// cleanup goroutines exit when ctx is cancelled.
// Pass maxKeys=0 to auto-detect the limit from /proc/sys/kernel/pid_max.
func NewWorkloadProfileManager(ctx context.Context, weight float64, ttl time.Duration, maxKeys int) *WorkloadProfileManager {
	if maxKeys <= 0 {
		maxKeys = readSystemPIDMax()
	}
	wpm := &WorkloadProfileManager{
		profiles: make(map[WorkloadKey]*ProcessProfile),
		weight:   weight,
		ttl:      ttl,
		maxKeys:  maxKeys,
		lruIndex: make(lruWorkloadKeyIndex),
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
			wpm.mu.RLock()
			n := len(wpm.profiles)
			wpm.mu.RUnlock()
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
	wpm.mu.RLock()
	defer wpm.mu.RUnlock()
	return wpm.profiles[key]
}

// GetOrCreateByKey returns an existing profile or creates one, evicting LRU if at capacity.
func (wpm *WorkloadProfileManager) GetOrCreateByKey(key WorkloadKey) *ProcessProfile {
	wpm.mu.Lock()
	defer wpm.mu.Unlock()

	if p, ok := wpm.profiles[key]; ok {
		wpm.lruIndex.touch(&wpm.lruHeap, key)
		return p
	}
	if wpm.maxKeys > 0 && len(wpm.profiles) >= wpm.maxKeys {
		wpm.evictLRULocked()
	}
	p := NewProcessProfileForWorkload(key)
	wpm.profiles[key] = p
	wpm.lruIndex.push(&wpm.lruHeap, key)
	return p
}

// RecordEvent records an event into the workload profile derived from the event's
// enrichment. PID is updated on the profile for last-seen context in alerts.
//
// Two-phase locking: the map lock is held only for the lookup/create, then
// released before the profile update runs under the per-profile mutex.
func (wpm *WorkloadProfileManager) RecordEvent(e types.Event) {
	key := WorkloadKeyFromEvent(e)

	wpm.mu.Lock()
	p, ok := wpm.profiles[key]
	if !ok {
		if wpm.maxKeys > 0 && len(wpm.profiles) >= wpm.maxKeys {
			wpm.evictLRULocked()
		}
		p = NewProcessProfileForWorkload(key)
		wpm.profiles[key] = p
		wpm.lruIndex.push(&wpm.lruHeap, key)
	} else {
		wpm.lruIndex.touch(&wpm.lruHeap, key)
	}
	wpm.mu.Unlock()

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

// CleanupExpired removes workload profiles that have not been updated within TTL.
func (wpm *WorkloadProfileManager) CleanupExpired() int {
	wpm.mu.Lock()
	defer wpm.mu.Unlock()
	removed := 0
	for k, p := range wpm.profiles {
		if p.IsExpired(wpm.ttl) {
			wpm.lruIndex.remove(&wpm.lruHeap, k)
			delete(wpm.profiles, k)
			removed++
		}
	}
	return removed
}

// evictLRULocked removes the workload profile with the oldest last-access time.
// Caller must hold wpm.mu write lock. O(log n) via the min-heap.
func (wpm *WorkloadProfileManager) evictLRULocked() {
	if wpm.lruHeap.Len() == 0 {
		return
	}
	e := heap.Pop(&wpm.lruHeap).(*lruWorkloadKeyEntry)
	delete(wpm.lruIndex, e.key)
	delete(wpm.profiles, e.key)
	if wpm.evictionsTotal != nil {
		wpm.evictionsTotal.Inc()
	}
}

// Keys returns all currently tracked workload keys.
func (wpm *WorkloadProfileManager) Keys() []WorkloadKey {
	wpm.mu.RLock()
	defer wpm.mu.RUnlock()
	keys := make([]WorkloadKey, 0, len(wpm.profiles))
	for _, p := range wpm.profiles {
		keys = append(keys, p.WorkloadKey)
	}
	return keys
}

// GetAll returns a copy of all workload profiles keyed by WorkloadKey.String().
func (wpm *WorkloadProfileManager) GetAll() map[string]*ProcessProfile {
	wpm.mu.RLock()
	defer wpm.mu.RUnlock()
	result := make(map[string]*ProcessProfile, len(wpm.profiles))
	for k, v := range wpm.profiles {
		result[k.String()] = v
	}
	return result
}

// Len returns the number of tracked workload profiles.
func (wpm *WorkloadProfileManager) Len() int {
	wpm.mu.RLock()
	defer wpm.mu.RUnlock()
	return len(wpm.profiles)
}

// Flush removes all profiles and resets LRU structures, releasing their memory.
// Intended for use during worker teardown — not safe to call concurrently with
// RecordEvent or GetOrCreateByKey.
func (wpm *WorkloadProfileManager) Flush() {
	wpm.mu.Lock()
	defer wpm.mu.Unlock()
	wpm.profiles = make(map[WorkloadKey]*ProcessProfile)
	for i := range wpm.lruHeap {
		wpm.lruHeap[i] = nil
	}
	wpm.lruHeap = wpm.lruHeap[:0]
	wpm.lruIndex = make(lruWorkloadKeyIndex)
}
