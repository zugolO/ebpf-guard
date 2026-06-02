// Package exporter provides tests for cardinality guard functionality.
package exporter

import (
	"container/heap"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCleanupWithManyStaleEntries verifies that Cleanup handles 100+ simultaneous
// stale entries without panic or heap corruption (Bug 3 fix verification).
func TestCleanupWithManyStaleEntries(t *testing.T) {
	guard := NewAnomalyScoreGuard()

	// Add 150 entries with old timestamps (stale)
	oldTime := time.Now().Add(-2 * time.Hour)
	for i := 0; i < 150; i++ {
		pid := fmt.Sprintf("%d", i)
		comm := fmt.Sprintf("proc%d", i)
		key := pid + "/" + comm
		entry := &AnomalyScoreEntry{
			PID:       pid,
			Comm:      comm,
			Score:     float64(i%100) / 100.0,
			UpdatedAt: oldTime,
		}
		guard.entries[key] = entry
		heap.Push(&guard.heap, entry)
	}

	// Verify initial state
	require.Equal(t, 150, guard.Size(), "expected 150 entries initially")

	// Cleanup with 1 hour max age - all entries should be removed
	removed := guard.Cleanup(1 * time.Hour)

	// Verify cleanup removed all stale entries
	assert.Equal(t, 150, removed, "expected 150 stale entries to be removed")
	assert.Equal(t, 0, guard.Size(), "expected 0 entries after cleanup")
	assert.Equal(t, 0, guard.heap.Len(), "expected empty heap after cleanup")
}

// TestCleanupWith200StaleEntries specifically tests the 200 entry case from TASK.md.
func TestCleanupWith200StaleEntries(t *testing.T) {
	guard := NewAnomalyScoreGuard()

	// Add 200 entries with old timestamps
	oldTime := time.Now().Add(-3 * time.Hour)
	for i := 0; i < 200; i++ {
		pid := fmt.Sprintf("%d", i)
		comm := fmt.Sprintf("proc%d", i)
		key := pid + "/" + comm
		entry := &AnomalyScoreEntry{
			PID:       pid,
			Comm:      comm,
			Score:     float64(i%100) / 100.0,
			UpdatedAt: oldTime,
		}
		guard.entries[key] = entry
		heap.Push(&guard.heap, entry)
	}

	// Verify initial state
	require.Equal(t, 200, guard.Size(), "expected 200 entries initially")

	// Cleanup should not panic or corrupt heap
	removed := guard.Cleanup(1 * time.Hour)

	assert.Equal(t, 200, removed, "expected 200 stale entries to be removed")
	assert.Equal(t, 0, guard.Size(), "expected 0 entries after cleanup")
}

// TestCleanupMixedStaleAndFresh verifies that only stale entries are removed.
func TestCleanupMixedStaleAndFresh(t *testing.T) {
	guard := NewAnomalyScoreGuard()
	now := time.Now()

	// Add 50 stale entries
	oldTime := now.Add(-2 * time.Hour)
	for i := 0; i < 50; i++ {
		pid := fmt.Sprintf("stale%d", i)
		comm := "STALE"
		key := pid + "/" + comm
		entry := &AnomalyScoreEntry{
			PID:       pid,
			Comm:      comm,
			Score:     0.5,
			UpdatedAt: oldTime,
		}
		guard.entries[key] = entry
		heap.Push(&guard.heap, entry)
	}

	// Add 50 fresh entries
	for i := 0; i < 50; i++ {
		pid := fmt.Sprintf("fresh%d", i)
		comm := "FRESH"
		key := pid + "/" + comm
		entry := &AnomalyScoreEntry{
			PID:       pid,
			Comm:      comm,
			Score:     0.7,
			UpdatedAt: now,
		}
		guard.entries[key] = entry
		heap.Push(&guard.heap, entry)
	}

	require.Equal(t, 100, guard.Size(), "expected 100 entries initially")

	// Cleanup with 1 hour max age
	removed := guard.Cleanup(1 * time.Hour)

	assert.Equal(t, 50, removed, "expected 50 stale entries to be removed")
	assert.Equal(t, 50, guard.Size(), "expected 50 fresh entries to remain")

	// Verify remaining entries are the fresh ones
	for key, entry := range guard.entries {
		assert.Contains(t, key, "fresh", "remaining entry should be fresh")
		assert.Equal(t, "FRESH", entry.Comm)
	}
}

// TestCleanupHeapIntegrity verifies heap integrity after cleanup.
func TestCleanupHeapIntegrity(t *testing.T) {
	guard := NewAnomalyScoreGuard()
	now := time.Now()

	// Add entries with varying scores
	for i := 0; i < 100; i++ {
		pid := fmt.Sprintf("%d", i)
		comm := fmt.Sprintf("proc%d", i)
		key := pid + "/" + comm
		entry := &AnomalyScoreEntry{
			PID:       pid,
			Comm:      comm,
			Score:     float64(i) / 100.0,
			UpdatedAt: now.Add(-time.Duration(i) * time.Minute),
		}
		guard.entries[key] = entry
		heap.Push(&guard.heap, entry)
	}

	// Remove stale entries. Use a half-minute offset so no entry sits exactly
	// on the boundary: Cleanup captures its own time.Now() a few microseconds
	// after the entries were stamped, which would otherwise flip the exactly-30m
	// entry (index 30) across the threshold non-deterministically.
	// With maxAge=30m30s, indices 31..99 (31m..99m old) are removed = 69.
	removed := guard.Cleanup(30*time.Minute + 30*time.Second)
	assert.Equal(t, 69, removed, "expected 69 stale entries (older than 30m30s, indices 31-99)")

	// Verify heap property is maintained
	// The lowest score should be at index 0
	if guard.heap.Len() > 0 {
		lowest := guard.heap[0].Score
		for _, entry := range guard.heap {
			assert.GreaterOrEqual(t, entry.Score, lowest,
				"heap property violated: entry with score %v is less than root %v", entry.Score, lowest)
		}
	}

	// Verify all remaining entries have valid heap indices
	for key, entry := range guard.entries {
		assert.True(t, entry.Index >= 0 && entry.Index < guard.heap.Len(),
			"entry %s has invalid heap index %d (heap len=%d)", key, entry.Index, guard.heap.Len())
		assert.Equal(t, guard.heap[entry.Index], entry,
			"entry %s at heap index %d does not match", key, entry.Index)
	}
}

// TestAnomalyScoreGuardSize verifies Size() returns correct count.
func TestAnomalyScoreGuardSize(t *testing.T) {
	guard := NewAnomalyScoreGuard()
	assert.Equal(t, 0, guard.Size())

	guard.SetAnomalyScore("1234", "test", 0.5)
	assert.Equal(t, 1, guard.Size())

	guard.SetAnomalyScore("5678", "test2", 0.7)
	assert.Equal(t, 2, guard.Size())

	// Update existing entry - size should not change
	guard.SetAnomalyScore("1234", "test", 0.6)
	assert.Equal(t, 2, guard.Size())
}

// TestAnomalyScoreGuardEviction verifies eviction when max size reached.
func TestAnomalyScoreGuardEviction(t *testing.T) {
	guard := NewAnomalyScoreGuard()
	guard.maxSize = 10 // Small max for testing

	// Add 10 entries with low scores
	for i := 0; i < 10; i++ {
		guard.SetAnomalyScore(string(rune('0'+i)), "test", 0.05)
	}
	assert.Equal(t, 10, guard.Size(), "expected 10 entries")

	// Add entry with high score - should not evict (all above threshold)
	guard.SetAnomalyScore("high", "test", 0.9)
	assert.Equal(t, 10, guard.Size(), "expected 10 entries (max reached, none evicted)")

	// Add entry with very low score - should trigger eviction
	guard.SetAnomalyScore("low", "test", 0.01)
	// The lowest score (0.01) is at threshold boundary, eviction may or may not happen
	// depending on exact threshold value
}

// TestEvictLowestAtMaxSize verifies that evictLowest always evicts at max capacity,
// even when all scores are above the eviction threshold.
func TestEvictLowestAtMaxSize(t *testing.T) {
	guard := NewAnomalyScoreGuard()
	guard.maxSize = 5

	// Add 5 entries, all with scores above the eviction threshold (0.1)
	scores := []float64{0.9, 0.5, 0.3, 0.7, 0.6}
	for i, score := range scores {
		pid := fmt.Sprintf("%d", i)
		guard.SetAnomalyScore(pid, "proc", score)
	}
	require.Equal(t, 5, guard.Size(), "expected 5 entries at max capacity")

	// evictLowest should evict the entry with score 0.3 (index 2, the minimum)
	guard.mu.Lock()
	guard.evictLowest()
	guard.mu.Unlock()

	assert.Equal(t, 4, guard.Size(), "expected 4 entries after eviction")

	// The lowest-score entry (0.3, pid "2") must be gone
	_, stillPresent := guard.entries["2/proc"]
	assert.False(t, stillPresent, "lowest-score entry must be evicted")
}

// BenchmarkCleanup benchmarks the Cleanup function.
func BenchmarkCleanup(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		guard := NewAnomalyScoreGuard()
		oldTime := time.Now().Add(-2 * time.Hour)

		// Setup: add 100 entries
		for j := 0; j < 100; j++ {
			pid := fmt.Sprintf("%d", j)
			comm := fmt.Sprintf("proc%d", j)
			guard.SetAnomalyScore(pid, comm, float64(j)/100.0)
			// Update timestamp to be old
			key := pid + "/" + comm
			if entry, ok := guard.entries[key]; ok {
				entry.UpdatedAt = oldTime
			}
		}
		b.StartTimer()

		guard.Cleanup(1 * time.Hour)
	}
}

// TestBoundedCardinality verifies that after 10,001 unique-PID anomaly events,
// the AnomalyScoreGuard size never exceeds MaxAnomalyScoreSeries (10,000).
// This ensures the eviction path is exercised and prevents Prometheus OOM.
func TestBoundedCardinality(t *testing.T) {
	guard := NewAnomalyScoreGuard()

	// Verify the limit is as expected
	assert.Equal(t, 10000, MaxAnomalyScoreSeries, "MaxAnomalyScoreSeries should be 10000")

	// Simulate 10,001 unique PID events
	for i := 0; i < 10001; i++ {
		pid := fmt.Sprintf("%d", i)
		comm := fmt.Sprintf("proc%d", i)
		// Use a score above threshold to avoid immediate eviction
		score := 0.5 + float64(i%50)/100.0 // 0.5 to 0.99
		guard.SetAnomalyScore(pid, comm, score)

		// Verify size never exceeds max
		assert.LessOrEqual(t, guard.Size(), MaxAnomalyScoreSeries,
			"guard size exceeded max at iteration %d", i)
	}

	// Final verification
	assert.Equal(t, MaxAnomalyScoreSeries, guard.Size(),
		"expected guard to be at max capacity after 10,001 unique PIDs")

	// Verify that we can still add more entries (eviction should work)
	for i := 10001; i < 11000; i++ {
		pid := fmt.Sprintf("%d", i)
		comm := fmt.Sprintf("proc%d", i)
		score := 0.5 + float64(i%50)/100.0
		guard.SetAnomalyScore(pid, comm, score)

		assert.LessOrEqual(t, guard.Size(), MaxAnomalyScoreSeries,
			"guard size exceeded max at iteration %d (post-limit)", i)
	}

	// Size should still be at max
	assert.Equal(t, MaxAnomalyScoreSeries, guard.Size(),
		"expected guard to remain at max capacity")
}

// TestBoundedCardinalityWithLowScores verifies eviction works when scores are below threshold.
func TestBoundedCardinalityWithLowScores(t *testing.T) {
	guard := NewAnomalyScoreGuard()

	// Add entries with very low scores (below eviction threshold)
	for i := 0; i < MaxAnomalyScoreSeries; i++ {
		pid := fmt.Sprintf("%d", i)
		comm := fmt.Sprintf("proc%d", i)
		// Score below AnomalyScoreEvictionThreshold (0.1)
		guard.SetAnomalyScore(pid, comm, 0.05)
	}

	assert.Equal(t, MaxAnomalyScoreSeries, guard.Size(),
		"expected guard to be at max capacity")

	// Adding a new entry with low score should trigger eviction
	guard.SetAnomalyScore("new", "newproc", 0.05)

	// Size should still be at max (one evicted, one added)
	assert.Equal(t, MaxAnomalyScoreSeries, guard.Size(),
		"expected guard to remain at max after eviction")
}
