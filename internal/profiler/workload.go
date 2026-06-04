package profiler

import (
	"container/heap"
	"context"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
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

// WorkloadKeyFromEvent derives a WorkloadKey from an event.
// When Kubernetes enrichment is absent, namespace and app label are empty,
// so all processes with the same comm share one baseline (non-K8s fallback).
func WorkloadKeyFromEvent(e types.Event) WorkloadKey {
	comm := string(bytesToString(e.Comm[:]))
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
	profiles map[string]*ProcessProfile // key: WorkloadKey.String()
	weight   float64
	ttl      time.Duration
	maxKeys  int

	// LRU eviction structures — O(log n) eviction via a min-heap.
	lruHeap  lruStringHeap
	lruIndex lruStringIndex

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
		profiles: make(map[string]*ProcessProfile),
		weight:   weight,
		ttl:      ttl,
		maxKeys:  maxKeys,
		lruIndex: make(lruStringIndex),
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
	return wpm.GetByKeyStr(key.String())
}

// GetByKeyStr returns the profile for a pre-computed key string.
// Use when the caller has already called key.String() to avoid a second allocation.
func (wpm *WorkloadProfileManager) GetByKeyStr(ks string) *ProcessProfile {
	wpm.mu.RLock()
	defer wpm.mu.RUnlock()
	return wpm.profiles[ks]
}

// getOrCreateByKeyStr returns the profile for ks (creating it when absent) and a
// flag indicating whether this is a newly-created profile.  A single wpm.mu.Lock
// cycle handles the lookup, possible creation, and LRU update — avoiding the two
// separate wpm.mu acquisitions that GetByKeyStr + RecordEventByKeyStr would require.
func (wpm *WorkloadProfileManager) getOrCreateByKeyStr(ks string, key WorkloadKey) (p *ProcessProfile, created bool) {
	return wpm.getOrCreateByKeyStrAt(ks, key, time.Now())
}

// getOrCreateByKeyStrAt is like getOrCreateByKeyStr but accepts a caller-supplied
// timestamp for the LRU touch/push, eliminating an extra time.Now() syscall when
// the caller already holds a current timestamp.
func (wpm *WorkloadProfileManager) getOrCreateByKeyStrAt(ks string, key WorkloadKey, now time.Time) (p *ProcessProfile, created bool) {
	wpm.mu.Lock()
	p = wpm.profiles[ks]
	if p == nil {
		created = true
		if wpm.maxKeys > 0 && len(wpm.profiles) >= wpm.maxKeys {
			wpm.evictLRULocked()
		}
		p = NewProcessProfileForWorkload(key)
		wpm.profiles[ks] = p
		wpm.lruIndex.pushAt(&wpm.lruHeap, ks, now)
	} else {
		wpm.lruIndex.touchAt(&wpm.lruHeap, ks, now)
	}
	wpm.mu.Unlock()
	return
}

// RecordEventByKeyStr records an event using a pre-computed profile key string and
// the WorkloadKey (needed only when the profile does not yet exist).  Callers that
// already hold key and ks should prefer this over RecordEvent to avoid recomputing
// both values.
func (wpm *WorkloadProfileManager) RecordEventByKeyStr(ks string, key WorkloadKey, e types.Event) {
	wpm.mu.Lock()
	p, ok := wpm.profiles[ks]
	if !ok {
		if wpm.maxKeys > 0 && len(wpm.profiles) >= wpm.maxKeys {
			wpm.evictLRULocked()
		}
		p = NewProcessProfileForWorkload(key)
		wpm.profiles[ks] = p
		wpm.lruIndex.push(&wpm.lruHeap, ks)
	} else {
		wpm.lruIndex.touch(&wpm.lruHeap, ks)
	}
	wpm.mu.Unlock()

	p.mu.Lock()
	p.PID = e.PID
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
	}
	p.mu.Unlock()
}

// GetOrCreateByKey returns an existing profile or creates one, evicting LRU if at capacity.
func (wpm *WorkloadProfileManager) GetOrCreateByKey(key WorkloadKey) *ProcessProfile {
	wpm.mu.Lock()
	defer wpm.mu.Unlock()

	ks := key.String()
	if p, ok := wpm.profiles[ks]; ok {
		wpm.lruIndex.touch(&wpm.lruHeap, ks)
		return p
	}
	if wpm.maxKeys > 0 && len(wpm.profiles) >= wpm.maxKeys {
		wpm.evictLRULocked()
	}
	p := NewProcessProfileForWorkload(key)
	wpm.profiles[ks] = p
	wpm.lruIndex.push(&wpm.lruHeap, ks)
	return p
}

// RecordEvent records an event into the workload profile derived from the event's
// enrichment. PID is updated on the profile for last-seen context in alerts.
//
// Two-phase locking: the map lock is held only for the lookup/create, then
// released before the profile update runs under the per-profile mutex.
func (wpm *WorkloadProfileManager) RecordEvent(e types.Event) {
	key := WorkloadKeyFromEvent(e)
	ks := key.String()

	wpm.mu.Lock()
	p, ok := wpm.profiles[ks]
	if !ok {
		if wpm.maxKeys > 0 && len(wpm.profiles) >= wpm.maxKeys {
			wpm.evictLRULocked()
		}
		p = NewProcessProfileForWorkload(key)
		wpm.profiles[ks] = p
		wpm.lruIndex.push(&wpm.lruHeap, ks)
	} else {
		wpm.lruIndex.touch(&wpm.lruHeap, ks)
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
	}
	p.mu.Unlock()
}

// CleanupExpired removes workload profiles that have not been updated within TTL.
func (wpm *WorkloadProfileManager) CleanupExpired() int {
	wpm.mu.Lock()
	defer wpm.mu.Unlock()
	removed := 0
	for ks, p := range wpm.profiles {
		if p.IsExpired(wpm.ttl) {
			wpm.lruIndex.remove(&wpm.lruHeap, ks)
			delete(wpm.profiles, ks)
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
	e := heap.Pop(&wpm.lruHeap).(*lruEntry)
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
		result[k] = v
	}
	return result
}

// Len returns the number of tracked workload profiles.
func (wpm *WorkloadProfileManager) Len() int {
	wpm.mu.RLock()
	defer wpm.mu.RUnlock()
	return len(wpm.profiles)
}
