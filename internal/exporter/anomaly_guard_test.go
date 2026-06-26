package exporter

import (
	"container/heap"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnomalyScoreGuard(t *testing.T) {
	g := &AnomalyScoreGuard{
		entries:   make(map[string]*AnomalyScoreEntry),
		heap:      make(AnomalyScoreHeap, 0),
		maxSize:   2,
		threshold: 0.5,
	}
	heap.Init(&g.heap)

	g.SetAnomalyScore("1", "a", 0.9)
	g.SetAnomalyScore("2", "b", 0.7)
	require.Equal(t, 2, g.Size())

	// Updating an existing entry does not grow the set.
	g.SetAnomalyScore("1", "a", 0.95)
	assert.Equal(t, 2, g.Size())

	// A third distinct entry exceeds maxSize and evicts the lowest-scoring one.
	g.SetAnomalyScore("3", "c", 0.99)
	assert.Equal(t, 2, g.Size())

	// Cleanup with a negative max-age treats every entry as stale.
	removed := g.Cleanup(-time.Hour)
	assert.GreaterOrEqual(t, removed, 1)
	assert.Equal(t, 0, g.Size())
}
