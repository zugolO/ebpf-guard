// Package store provides storage backends for alerts and profiles.
package store

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryStore_StoreAndQuery(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	alert := types.Alert{
		ID:        "test-1",
		Timestamp: time.Now(),
		RuleID:    "rule-001",
		Severity:  types.SeverityWarning,
		PID:       1234,
		Comm:      "test-process",
		Message:   "Test alert",
	}

	err := store.Store(ctx, alert)
	require.NoError(t, err)

	// Query by ID
	result, err := store.QueryByID(ctx, "test-1")
	require.NoError(t, err)
	assert.Equal(t, alert.ID, result.ID)
	assert.Equal(t, alert.RuleID, result.RuleID)
}

func TestMemoryStore_QueryWithFilters(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	now := time.Now()
	alerts := []types.Alert{
		{ID: "1", Timestamp: now, RuleID: "rule-a", Severity: types.SeverityWarning, PID: 100, Comm: "proc1"},
		{ID: "2", Timestamp: now.Add(-time.Hour), RuleID: "rule-b", Severity: types.SeverityCritical, PID: 200, Comm: "proc2"},
		{ID: "3", Timestamp: now.Add(-2 * time.Hour), RuleID: "rule-a", Severity: types.SeverityWarning, PID: 100, Comm: "proc1"},
	}

	for _, alert := range alerts {
		require.NoError(t, store.Store(ctx, alert))
	}

	tests := []struct {
		name     string
		filters  QueryFilters
		expected int
	}{
		{
			name:     "no filters returns all",
			filters:  QueryFilters{},
			expected: 3,
		},
		{
			name:     "filter by rule_id",
			filters:  QueryFilters{RuleIDs: []string{"rule-a"}},
			expected: 2,
		},
		{
			name:     "filter by severity",
			filters:  QueryFilters{Severity: []types.Severity{types.SeverityCritical}},
			expected: 1,
		},
		{
			name:     "filter by pid",
			filters:  QueryFilters{PIDs: []uint32{100}},
			expected: 2,
		},
		{
			name:     "filter by comm substring case-insensitive",
			filters:  QueryFilters{Comm: "ROC1"},
			expected: 2,
		},
		{
			name:     "filter by comm no match",
			filters:  QueryFilters{Comm: "nonexistent"},
			expected: 0,
		},
		{
			name:     "filter by time range",
			filters:  QueryFilters{Since: now.Add(-30 * time.Minute)},
			expected: 1,
		},
		{
			name:     "limit results",
			filters:  QueryFilters{Limit: 2},
			expected: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := store.Query(ctx, tt.filters)
			require.NoError(t, err)
			assert.Len(t, results, tt.expected)
		})
	}
}

func TestMemoryStore_StoreBatch(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	alerts := []types.Alert{
		{ID: "1", Timestamp: time.Now(), RuleID: "rule-1", Severity: types.SeverityWarning},
		{ID: "2", Timestamp: time.Now(), RuleID: "rule-2", Severity: types.SeverityCritical},
		{ID: "3", Timestamp: time.Now(), RuleID: "rule-3", Severity: types.SeverityWarning},
	}

	err := store.StoreBatch(ctx, alerts)
	require.NoError(t, err)

	count, err := store.Count(ctx, QueryFilters{})
	require.NoError(t, err)
	assert.Equal(t, int64(3), count)
}

func TestMemoryStore_Delete(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	oldAlert := types.Alert{
		ID:        "old",
		Timestamp: time.Now().Add(-48 * time.Hour),
		RuleID:    "rule-1",
		Severity:  types.SeverityWarning,
	}
	newAlert := types.Alert{
		ID:        "new",
		Timestamp: time.Now(),
		RuleID:    "rule-2",
		Severity:  types.SeverityCritical,
	}

	require.NoError(t, store.Store(ctx, oldAlert))
	require.NoError(t, store.Store(ctx, newAlert))

	deleted, err := store.Delete(ctx, 24*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, int64(1), deleted)

	count, err := store.Count(ctx, QueryFilters{})
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)
}

func TestMemoryStore_Healthy(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	assert.True(t, store.Healthy(ctx))
}

func TestMemoryProfileStore(t *testing.T) {
	store := NewMemoryProfileStore()
	ctx := context.Background()

	profile := &types.ProcessProfile{
		Comm:      "nginx",
		Namespace: "production",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		SyscallCounts: map[int]float64{
			0: 100, // read
			1: 50,  // write
		},
	}

	err := store.Store(ctx, profile)
	require.NoError(t, err)

	// Load by key
	key := profileKey(profile)
	loaded, err := store.Load(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, profile.Comm, loaded.Comm)
	assert.Equal(t, profile.Namespace, loaded.Namespace)

	// Load all
	all, err := store.LoadAll(ctx)
	require.NoError(t, err)
	assert.Len(t, all, 1)

	// Delete
	err = store.Delete(ctx, key)
	require.NoError(t, err)

	_, err = store.Load(ctx, key)
	assert.Error(t, err)
}

// TestMemoryStore_ConcurrentStoreBatch verifies that concurrent Store and
// StoreBatch calls do not lose data and do not race (-race detector must pass).
func TestMemoryStore_ConcurrentStoreBatch(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	const singles = 50
	const batchWorkers = 10
	const batchSize = 10

	var wg sync.WaitGroup
	errCh := make(chan error, singles+batchWorkers)

	// Concurrent single-alert stores.
	for i := 0; i < singles; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			alert := types.Alert{
				ID:        fmt.Sprintf("single-%d", i),
				Timestamp: time.Now(),
				RuleID:    "rule-1",
				Severity:  types.SeverityWarning,
			}
			if err := store.Store(ctx, alert); err != nil {
				errCh <- err
			}
		}(i)
	}

	// Concurrent batch stores.
	for i := 0; i < batchWorkers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			batch := make([]types.Alert, batchSize)
			for j := range batch {
				batch[j] = types.Alert{
					ID:        fmt.Sprintf("batch-%d-%d", i, j),
					Timestamp: time.Now(),
					RuleID:    "rule-2",
					Severity:  types.SeverityCritical,
				}
			}
			if err := store.StoreBatch(ctx, batch); err != nil {
				errCh <- err
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Error(err)
	}

	// All alerts must be present.
	const want = singles + batchWorkers*batchSize
	count, err := store.Count(ctx, QueryFilters{})
	require.NoError(t, err)
	assert.Equal(t, int64(want), count)

	// byTime must be sorted DESC (newest first).
	store.mu.RLock()
	for i := 1; i < len(store.byTime); i++ {
		assert.False(t, store.byTime[i].ts.After(store.byTime[i-1].ts),
			"byTime[%d].ts (%v) is after byTime[%d].ts (%v) — index not sorted DESC",
			i, store.byTime[i].ts, i-1, store.byTime[i-1].ts)
	}
	store.mu.RUnlock()
}

func TestMatchesFilters(t *testing.T) {
	now := time.Now()
	alert := types.Alert{
		Timestamp: now,
		RuleID:    "rule-1",
		Severity:  types.SeverityWarning,
		PID:       1234,
		Comm:      "nginx-proxy",
		Enrichment: types.EnrichmentInfo{
			PodName:   "test-pod",
			Namespace: "default",
		},
	}

	tests := []struct {
		name    string
		filters QueryFilters
		want    bool
	}{
		{
			name:    "empty filters matches",
			filters: QueryFilters{},
			want:    true,
		},
		{
			name:    "matching rule_id",
			filters: QueryFilters{RuleIDs: []string{"rule-1"}},
			want:    true,
		},
		{
			name:    "non-matching rule_id",
			filters: QueryFilters{RuleIDs: []string{"rule-2"}},
			want:    false,
		},
		{
			name:    "matching severity",
			filters: QueryFilters{Severity: []types.Severity{types.SeverityWarning}},
			want:    true,
		},
		{
			name:    "non-matching severity",
			filters: QueryFilters{Severity: []types.Severity{types.SeverityCritical}},
			want:    false,
		},
		{
			name:    "matching pid",
			filters: QueryFilters{PIDs: []uint32{1234}},
			want:    true,
		},
		{
			name:    "non-matching pid",
			filters: QueryFilters{PIDs: []uint32{5678}},
			want:    false,
		},
		{
			name:    "matching comm substring case-insensitive",
			filters: QueryFilters{Comm: "NGINX"},
			want:    true,
		},
		{
			name:    "non-matching comm",
			filters: QueryFilters{Comm: "bash"},
			want:    false,
		},
		{
			name:    "matching pod name",
			filters: QueryFilters{PodName: "test-pod"},
			want:    true,
		},
		{
			name:    "non-matching pod name",
			filters: QueryFilters{PodName: "other-pod"},
			want:    false,
		},
		{
			name:    "matching namespace",
			filters: QueryFilters{Namespace: "default"},
			want:    true,
		},
		{
			name:    "non-matching namespace",
			filters: QueryFilters{Namespace: "kube-system"},
			want:    false,
		},
		{
			name:    "time range includes alert",
			filters: QueryFilters{Since: now.Add(-time.Hour), Until: now.Add(time.Hour)},
			want:    true,
		},
		{
			name:    "time range excludes alert (before)",
			filters: QueryFilters{Until: now.Add(-time.Hour)},
			want:    false,
		},
		{
			name:    "time range excludes alert (after)",
			filters: QueryFilters{Since: now.Add(time.Hour)},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesFilters(alert, tt.filters)
			assert.Equal(t, tt.want, got)
		})
	}
}
