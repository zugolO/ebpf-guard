package util

import (
	"container/list"
	"sync"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	internerShards     = 16
	internerDefaultMax = 4096
)

// internShard is one LRU bucket of the StringInterner.
type internShard struct {
	mu      sync.Mutex
	entries map[string]*list.Element
	lru     *list.List
	size    int
}

// StringInterner is a bounded, sharded LRU cache that returns canonical interned
// copies of strings. Thread-safe. Memory-bounded: the LRU evicts the least-recently
// used entry when a shard reaches capacity, preventing unbounded growth even when
// comm values are attacker-controlled.
//
// Use InternBytes for null-terminated [N]byte comm fields from BPF; use InternString
// for k8s namespace, pod name, and other string-typed metadata that repeats across events.
type StringInterner struct {
	shards   [internerShards]internShard
	perShard int

	hits   atomic.Int64
	misses atomic.Int64

	// Prometheus descriptors created at construction time.
	descHits   *prometheus.Desc
	descMisses *prometheus.Desc
	descSize   *prometheus.Desc
}

// NewStringInterner creates a StringInterner with the given total entry limit.
// If maxSize <= 0, it defaults to 4096.
func NewStringInterner(maxSize int) *StringInterner {
	if maxSize <= 0 {
		maxSize = internerDefaultMax
	}
	perShard := maxSize / internerShards
	if perShard < 1 {
		perShard = 1
	}
	si := &StringInterner{
		perShard: perShard,
		descHits: prometheus.NewDesc(
			"ebpf_guard_interner_hits_total",
			"Number of string interner cache hits (avoided allocations).",
			nil, nil,
		),
		descMisses: prometheus.NewDesc(
			"ebpf_guard_interner_misses_total",
			"Number of string interner cache misses (new string allocations).",
			nil, nil,
		),
		descSize: prometheus.NewDesc(
			"ebpf_guard_interner_size",
			"Current number of entries in the string interner cache.",
			nil, nil,
		),
	}
	for i := range si.shards {
		si.shards[i].entries = make(map[string]*list.Element, perShard+1)
		si.shards[i].lru = list.New()
	}
	return si
}

// Describe implements prometheus.Collector.
func (si *StringInterner) Describe(ch chan<- *prometheus.Desc) {
	ch <- si.descHits
	ch <- si.descMisses
	ch <- si.descSize
}

// Collect implements prometheus.Collector.
func (si *StringInterner) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(si.descHits, prometheus.CounterValue, float64(si.hits.Load()))
	ch <- prometheus.MustNewConstMetric(si.descMisses, prometheus.CounterValue, float64(si.misses.Load()))
	var total int64
	for i := range si.shards {
		sh := &si.shards[i]
		sh.mu.Lock()
		total += int64(sh.size)
		sh.mu.Unlock()
	}
	ch <- prometheus.MustNewConstMetric(si.descSize, prometheus.GaugeValue, float64(total))
}

// InternBytes interns a null-terminated byte slice, returning a canonical string
// from the cache. Typical input is a [16]byte BPF comm field.
// The returned string is safe to use beyond the lifetime of b.
func (si *StringInterner) InternBytes(b []byte) string {
	// Trim at the first NUL byte.
	n := len(b)
	for i, c := range b {
		if c == 0 {
			n = i
			break
		}
	}
	if n == 0 {
		return ""
	}
	b = b[:n]
	// Wave 8.2, C2 (№540): no unsafe string view and no shared internKey path.
	// The lookup converts with string(b) inside the map index, which the compiler
	// does without copying, and a miss makes its own copy — so b provably never
	// leaks. The previous shape (key view + raw) made escape analysis treat b as
	// retained, which moved every caller's types.Event to the heap on each event.
	sh := &si.shards[int(b[0])&(internerShards-1)]
	sh.mu.Lock()
	if elem, ok := sh.entries[string(b)]; ok {
		sh.lru.MoveToFront(elem)
		val := elem.Value.(string)
		sh.mu.Unlock()
		si.hits.Add(1)
		return val
	}
	val := string(b)
	si.insertLocked(sh, val)
	sh.mu.Unlock()
	si.misses.Add(1)
	return val
}

// InternString returns a canonical copy of s from the cache.
func (si *StringInterner) InternString(s string) string {
	if s == "" {
		return ""
	}
	return si.internKey(s)
}

// internKey performs the shard lookup and LRU insertion for a real Go string.
func (si *StringInterner) internKey(key string) string {
	idx := int(key[0]) & (internerShards - 1)
	sh := &si.shards[idx]

	sh.mu.Lock()
	if elem, ok := sh.entries[key]; ok {
		sh.lru.MoveToFront(elem)
		val := elem.Value.(string)
		sh.mu.Unlock()
		si.hits.Add(1)
		return val
	}
	si.insertLocked(sh, key)
	sh.mu.Unlock()
	si.misses.Add(1)
	return key
}

// insertLocked adds val to shard sh and evicts the LRU entry when the shard is
// full. The caller holds sh.mu and passes a string it owns.
func (si *StringInterner) insertLocked(sh *internShard, val string) {
	elem := sh.lru.PushFront(val)
	sh.entries[val] = elem
	sh.size++
	if sh.size > si.perShard {
		back := sh.lru.Back()
		if back != nil {
			evicted := back.Value.(string)
			sh.lru.Remove(back)
			delete(sh.entries, evicted)
			sh.size--
		}
	}
}

// Stats returns a snapshot of hit/miss counts and total cached entries.
func (si *StringInterner) Stats() (hits, misses, size int64) {
	hits = si.hits.Load()
	misses = si.misses.Load()
	for i := range si.shards {
		sh := &si.shards[i]
		sh.mu.Lock()
		size += int64(sh.size)
		sh.mu.Unlock()
	}
	return
}

// DefaultInterner is the process-wide string interner for BPF comm fields and k8s
// metadata. Register it with prometheus.MustRegister(util.DefaultInterner) at
// startup to expose hit/miss/size metrics.
var DefaultInterner = NewStringInterner(internerDefaultMax)

// InternBytes interns a null-terminated byte slice using DefaultInterner.
func InternBytes(b []byte) string { return DefaultInterner.InternBytes(b) }

// InternString interns a string using DefaultInterner.
func InternString(s string) string { return DefaultInterner.InternString(s) }
