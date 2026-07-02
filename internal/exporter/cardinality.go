// Package exporter provides Prometheus metrics with cardinality guards.
package exporter

import (
	"container/heap"
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"
)

const (
	// MaxAnomalyScoreSeries is the maximum number of time series for anomaly scores.
	MaxAnomalyScoreSeries = 10000
	// AnomalyScoreEvictionThreshold is the score below which a series can be evicted.
	AnomalyScoreEvictionThreshold = 0.1
	// AnomalyScoreEvictionInterval is how often to check for evictions.
	AnomalyScoreEvictionInterval = 5 * time.Minute
)

// AnomalyScoreEntry tracks a single anomaly score series for eviction.
type AnomalyScoreEntry struct {
	PID       string
	Comm      string
	Score     float64
	UpdatedAt time.Time
	Index     int // Index in the heap
}

// AnomalyScoreHeap implements a min-heap based on score for eviction.
type AnomalyScoreHeap []*AnomalyScoreEntry

func (h AnomalyScoreHeap) Len() int           { return len(h) }
func (h AnomalyScoreHeap) Less(i, j int) bool { return h[i].Score < h[j].Score }
func (h AnomalyScoreHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].Index = i
	h[j].Index = j
}

func (h *AnomalyScoreHeap) Push(x interface{}) {
	n := len(*h)
	item := x.(*AnomalyScoreEntry)
	item.Index = n
	*h = append(*h, item)
}

func (h *AnomalyScoreHeap) Pop() interface{} {
	old := *h
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	item.Index = -1
	*h = old[0 : n-1]
	return item
}

// AnomalyScoreGuard provides cardinality-limited anomaly score tracking.
type AnomalyScoreGuard struct {
	mu       sync.RWMutex
	entries  map[string]*AnomalyScoreEntry
	heap     AnomalyScoreHeap
	maxSize  int
	threshold float64
}

// NewAnomalyScoreGuard creates a new cardinality guard.
func NewAnomalyScoreGuard() *AnomalyScoreGuard {
	g := &AnomalyScoreGuard{
		entries:   make(map[string]*AnomalyScoreEntry),
		heap:      make(AnomalyScoreHeap, 0),
		maxSize:   MaxAnomalyScoreSeries,
		threshold: AnomalyScoreEvictionThreshold,
	}
	heap.Init(&g.heap)
	return g
}

// SetAnomalyScore sets an anomaly score with cardinality guard.
// If the limit is reached, low-score entries are evicted.
func (g *AnomalyScoreGuard) SetAnomalyScore(pid, comm string, score float64) {
	key := pid + "/" + comm

	g.mu.Lock()
	defer g.mu.Unlock()

	// Update existing entry
	if entry, exists := g.entries[key]; exists {
		entry.Score = score
		entry.UpdatedAt = time.Now()
		heap.Fix(&g.heap, entry.Index)
		ProfilerAnomalyScore.WithLabelValues(pid, comm).Set(score)
		return
	}

	// Check if we need to evict
	if len(g.entries) >= g.maxSize {
		g.evictLowest()
	}

	// Add new entry
	entry := &AnomalyScoreEntry{
		PID:       pid,
		Comm:      comm,
		Score:     score,
		UpdatedAt: time.Now(),
	}
	g.entries[key] = entry
	heap.Push(&g.heap, entry)
	ProfilerAnomalyScore.WithLabelValues(pid, comm).Set(score)
}

// evictLowest removes the lowest scoring entry.
// Called only when len(entries) >= maxSize, so always evicts to prevent unbounded growth.
func (g *AnomalyScoreGuard) evictLowest() {
	if g.heap.Len() == 0 {
		return
	}

	lowest := heap.Pop(&g.heap).(*AnomalyScoreEntry)
	key := lowest.PID + "/" + lowest.Comm
	delete(g.entries, key)
	ProfilerAnomalyScore.DeleteLabelValues(lowest.PID, lowest.Comm)
}

// Cleanup removes stale entries (not updated recently).
// Uses two-pass deletion to prevent heap index invalidation during iteration.
func (g *AnomalyScoreGuard) Cleanup(maxAge time.Duration) int {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now()

	// First pass: collect stale entries
	var stale []*AnomalyScoreEntry
	for _, entry := range g.entries {
		if now.Sub(entry.UpdatedAt) > maxAge {
			stale = append(stale, entry)
		}
	}

	// Second pass: remove from heap and map
	// Remove from heap in reverse index order to minimize heap.Fix operations
	for i := len(stale) - 1; i >= 0; i-- {
		entry := stale[i]
		if entry.Index >= 0 && entry.Index < g.heap.Len() {
			heap.Remove(&g.heap, entry.Index)
		}
	}

	// Remove from map and delete Prometheus metrics
	for _, entry := range stale {
		key := entry.PID + "/" + entry.Comm
		delete(g.entries, key)
		ProfilerAnomalyScore.DeleteLabelValues(entry.PID, entry.Comm)
	}

	return len(stale)
}

// Size returns the current number of tracked entries.
func (g *AnomalyScoreGuard) Size() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.entries)
}

// CardinalityLimiter provides generic cardinality limiting for CounterVec/GaugeVec metrics.
// When the number of unique label combinations exceeds maxSeries, excess labels are
// collapsed into "other" to prevent unbounded metric cardinality.
type CardinalityLimiter struct {
	mu        sync.RWMutex
	series    map[string]bool // Tracks seen label combinations
	maxSeries int
}

// NewCardinalityLimiter creates a new cardinality limiter with the given max series count.
func NewCardinalityLimiter(maxSeries int) *CardinalityLimiter {
	if maxSeries <= 0 {
		maxSeries = 1000 // Conservative default
	}
	return &CardinalityLimiter{
		series:    make(map[string]bool),
		maxSeries: maxSeries,
	}
}

// Normalize returns the labels, potentially modified to enforce cardinality limits.
// If the series would exceed maxSeries, the high-cardinality label indices given
// by labelKeys are all replaced with "other" (e.g. for AlertsTotal: namespace,
// pod, and node), which bounds the total series count to the product of the
// remaining low-cardinality labels. Collapsing every high-cardinality dimension
// — not just one — is what makes the guard a hard ceiling even when several
// labels churn or are misconfigured.
func (cl *CardinalityLimiter) Normalize(labels []string, labelKeys ...int) []string {
	key := strings.Join(labels, "|")

	// Fast path: a series we've already admitted is by far the common case on
	// the per-event hot path. Take only a read lock and avoid mutating anything.
	cl.mu.RLock()
	seen := cl.series[key]
	cl.mu.RUnlock()
	if seen {
		return labels // Seen before; pass through unchanged
	}

	cl.mu.Lock()
	defer cl.mu.Unlock()

	// Re-check under the write lock: another goroutine may have admitted this
	// exact series between the RUnlock above and acquiring the write lock.
	if cl.series[key] {
		return labels
	}

	// Check if adding this series would exceed the limit
	if len(cl.series) >= cl.maxSeries {
		// Collapse every high-cardinality label to "other".
		labels = append([]string{}, labels...) // Copy to avoid modifying caller's slice
		for _, k := range labelKeys {
			if k >= 0 && k < len(labels) {
				labels[k] = "other"
			}
		}
		key = strings.Join(labels, "|")
	}

	// Mark this series as seen
	cl.series[key] = true
	return labels
}

// Size returns the current number of tracked series.
func (cl *CardinalityLimiter) Size() int {
	cl.mu.RLock()
	defer cl.mu.RUnlock()
	return len(cl.series)
}

// globalGuard is the singleton cardinality guard instance.
var globalGuard = NewAnomalyScoreGuard()

// SetAnomalyScoreWithGuard sets an anomaly score with cardinality protection.
func SetAnomalyScoreWithGuard(pid, comm string, score float64) {
	globalGuard.SetAnomalyScore(pid, comm, score)
}

// StartAnomalyScoreCleanup starts a background goroutine to clean up stale entries.
func StartAnomalyScoreCleanup(ctx context.Context, interval, maxAge time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			removed := globalGuard.Cleanup(maxAge)
			if removed > 0 {
				slog.Debug("exporter/cardinality: cleaned up stale anomaly score entries",
					slog.Int("removed", removed),
					slog.Int("remaining", globalGuard.Size()))
			}
		}
	}
}
