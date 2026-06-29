// Package store provides storage backends for alerts and profiles.
package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_Backends(t *testing.T) {
	t.Run("memory", func(t *testing.T) {
		s, err := New(Config{Backend: "memory"})
		require.NoError(t, err)
		require.NotNil(t, s)
		assert.NoError(t, s.Close())
	})

	t.Run("opensearch", func(t *testing.T) {
		// No connection is made by the constructor; it only builds an HTTP client.
		s, err := New(Config{
			Backend:    "opensearch",
			OpenSearch: OpenSearchConfig{Addresses: []string{"https://localhost:9200"}},
		})
		require.NoError(t, err)
		require.NotNil(t, s)
	})

	t.Run("opensearch missing address errors", func(t *testing.T) {
		_, err := New(Config{Backend: "opensearch"})
		require.Error(t, err)
	})

	t.Run("unknown backend errors", func(t *testing.T) {
		_, err := New(Config{Backend: "bogus"})
		require.Error(t, err)
	})
}

// invalidSQLitePath returns a path that SQLite cannot open as a database file:
// a sub-path of a regular file (not a directory). Works both with CGO enabled
// (sqlite3 cannot create a file inside a file) and without CGO (NewSQLiteStore
// returns ErrNoCGO before touching the filesystem).
func invalidSQLitePath(t *testing.T) string {
	t.Helper()
	notADir := filepath.Join(t.TempDir(), "notadir")
	require.NoError(t, os.WriteFile(notADir, []byte("x"), 0o600))
	return filepath.Join(notADir, "child.db")
}

// TestNewWithContext_SQLiteError verifies that a SQLite open failure is wrapped
// and propagated from NewWithContext.
func TestNewWithContext_SQLiteError(t *testing.T) {
	ctx := context.Background()
	_, err := NewWithContext(ctx, Config{
		Backend: "sqlite",
		SQLite:  SQLiteConfig{Path: invalidSQLitePath(t)},
	})
	require.Error(t, err)
}

// TestNewProfileStore_SQLiteError verifies that a SQLite open failure is wrapped
// and propagated from NewProfileStore.
func TestNewProfileStore_SQLiteError(t *testing.T) {
	_, err := NewProfileStore(Config{
		Backend: "sqlite",
		SQLite:  SQLiteConfig{Path: invalidSQLitePath(t)},
	})
	require.Error(t, err)
}

func TestNewWithContext_MemoryRetention(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s, err := NewWithContext(ctx, Config{
		Backend: "memory",
		Memory: MemoryStoreOptions{
			RetentionPeriod: 40 * time.Millisecond,
		},
	})
	require.NoError(t, err)

	// Insert an alert old enough to be evicted by the retention loop.
	require.NoError(t, s.Store(ctx, types.Alert{
		ID:        "old",
		Timestamp: time.Now().Add(-time.Hour),
		Severity:  types.SeverityWarning,
	}))

	// retentionLoop ticks every RetentionPeriod/4; wait for at least one tick.
	require.Eventually(t, func() bool {
		c, _ := s.Count(ctx, QueryFilters{})
		return c == 0
	}, time.Second, 10*time.Millisecond, "retention loop should evict the old alert")

	// Cancelling the context stops the retention goroutine cleanly.
	cancel()
}

func TestNewProfileStore_Backends(t *testing.T) {
	t.Run("memory", func(t *testing.T) {
		ps, err := NewProfileStore(Config{Backend: "memory"})
		require.NoError(t, err)
		require.NotNil(t, ps)
		assert.NoError(t, ps.Close())
	})

	t.Run("unknown errors", func(t *testing.T) {
		_, err := NewProfileStore(Config{Backend: "bogus"})
		require.Error(t, err)
	})
}

func TestInstrumentedStore(t *testing.T) {
	ctx := context.Background()
	inner := NewMemoryStore()
	is := NewInstrumentedStore(inner)

	reg := prometheus.NewRegistry()
	require.NoError(t, is.RegisterMetrics(reg))
	// Double-registration of the same collectors must fail.
	require.Error(t, is.RegisterMetrics(reg))

	require.NoError(t, is.Store(ctx, types.Alert{ID: "a", Timestamp: time.Now(), Severity: types.SeverityWarning}))
	require.NoError(t, is.StoreBatch(ctx, []types.Alert{
		{ID: "b", Timestamp: time.Now(), Severity: types.SeverityCritical},
		{ID: "c", Timestamp: time.Now(), Severity: types.SeverityWarning},
	}))

	got, err := is.QueryByID(ctx, "a")
	require.NoError(t, err)
	assert.Equal(t, "a", got.ID)

	results, err := is.Query(ctx, QueryFilters{})
	require.NoError(t, err)
	assert.Len(t, results, 3)

	count, err := is.Count(ctx, QueryFilters{})
	require.NoError(t, err)
	assert.Equal(t, int64(3), count)

	assert.True(t, is.Healthy(ctx))
	require.NoError(t, is.Flush(ctx))

	deleted, err := is.Delete(ctx, time.Nanosecond)
	require.NoError(t, err)
	assert.Equal(t, int64(3), deleted)

	require.NoError(t, is.Close())

	// The metrics counter must have advanced (1 single + 2 batch = 3).
	mfs, err := reg.Gather()
	require.NoError(t, err)
	var total float64
	for _, mf := range mfs {
		if mf.GetName() == "ebpf_guard_store_alerts_total" {
			total = mf.GetMetric()[0].GetCounter().GetValue()
		}
	}
	assert.Equal(t, float64(3), total)
}

func TestMemoryStore_EvictOldestOnMaxAlerts(t *testing.T) {
	ctx := context.Background()
	s := newMemoryStore(MemoryStoreOptions{MaxAlerts: 3})

	now := time.Now()
	for i := 0; i < 6; i++ {
		require.NoError(t, s.Store(ctx, types.Alert{
			ID:        string(rune('a' + i)),
			Timestamp: now.Add(time.Duration(i) * time.Minute),
			Severity:  types.SeverityWarning,
		}))
	}

	count, err := s.Count(ctx, QueryFilters{})
	require.NoError(t, err)
	assert.Equal(t, int64(3), count, "store must cap at MaxAlerts")

	// The three newest (d, e, f) survive; the oldest were evicted.
	_, err = s.QueryByID(ctx, "f")
	require.NoError(t, err)
	_, err = s.QueryByID(ctx, "a")
	require.Error(t, err)
}

func TestMemoryStore_EvictOnBatch(t *testing.T) {
	ctx := context.Background()
	s := newMemoryStore(MemoryStoreOptions{MaxAlerts: 2})

	now := time.Now()
	batch := []types.Alert{
		{ID: "1", Timestamp: now, Severity: types.SeverityWarning},
		{ID: "2", Timestamp: now.Add(time.Minute), Severity: types.SeverityCritical},
		{ID: "3", Timestamp: now.Add(2 * time.Minute), Severity: types.SeverityWarning},
	}
	require.NoError(t, s.StoreBatch(ctx, batch))

	count, err := s.Count(ctx, QueryFilters{})
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)
}

func TestMemoryStore_UpdateExisting(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	now := time.Now()
	require.NoError(t, s.Store(ctx, types.Alert{ID: "x", Timestamp: now, Severity: types.SeverityWarning, Message: "v1"}))
	// Re-store with the same ID updates in place (exercises removeFromIndexes).
	require.NoError(t, s.Store(ctx, types.Alert{ID: "x", Timestamp: now.Add(time.Minute), Severity: types.SeverityCritical, Message: "v2"}))

	count, err := s.Count(ctx, QueryFilters{})
	require.NoError(t, err)
	assert.Equal(t, int64(1), count, "update must not increase count")

	got, err := s.QueryByID(ctx, "x")
	require.NoError(t, err)
	assert.Equal(t, "v2", got.Message)
	assert.Equal(t, types.SeverityCritical, got.Severity)
}

func TestMemoryStore_GeneratesIDAndTimestamp(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	require.NoError(t, s.Store(ctx, types.Alert{Severity: types.SeverityWarning}))
	results, err := s.Query(ctx, QueryFilters{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.NotEmpty(t, results[0].ID, "Store must assign an ID when empty")
	assert.False(t, results[0].Timestamp.IsZero(), "Store must assign a timestamp when zero")
}

func TestMemoryStore_QueryFastPathAndPagination(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	now := time.Now()
	for i := 0; i < 5; i++ {
		sev := types.SeverityWarning
		if i%2 == 0 {
			sev = types.SeverityCritical
		}
		require.NoError(t, s.Store(ctx, types.Alert{
			ID:        string(rune('a' + i)),
			Timestamp: now.Add(time.Duration(i) * time.Minute),
			Severity:  sev,
			Enrichment: types.EnrichmentInfo{Namespace: "ns1"},
		}))
	}

	// Fast path: single severity, no time range.
	crit, err := s.Query(ctx, QueryFilters{Severity: []types.Severity{types.SeverityCritical}})
	require.NoError(t, err)
	assert.Len(t, crit, 3)

	// Fast path with Namespaces filter.
	critNs, err := s.Query(ctx, QueryFilters{
		Severity:   []types.Severity{types.SeverityCritical},
		Namespaces: []string{"ns1"},
	})
	require.NoError(t, err)
	assert.Len(t, critNs, 3)

	critOtherNs, err := s.Query(ctx, QueryFilters{
		Severity:   []types.Severity{types.SeverityCritical},
		Namespaces: []string{"other"},
	})
	require.NoError(t, err)
	assert.Empty(t, critOtherNs)

	// Offset pagination on the standard path.
	page, err := s.Query(ctx, QueryFilters{Offset: 2, Limit: 2})
	require.NoError(t, err)
	assert.Len(t, page, 2)

	// Release returns the slice to the pool without panicking.
	s.Release(page)
	s.Release(nil)
}

func TestMemoryStore_QueryNamespacesStandardPath(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	now := time.Now()
	require.NoError(t, s.Store(ctx, types.Alert{ID: "1", Timestamp: now, Severity: types.SeverityWarning, Enrichment: types.EnrichmentInfo{Namespace: "a"}}))
	require.NoError(t, s.Store(ctx, types.Alert{ID: "2", Timestamp: now.Add(time.Minute), Severity: types.SeverityWarning, Enrichment: types.EnrichmentInfo{Namespace: "b"}}))

	// Standard path (multiple severities forces it) with Namespaces filter.
	res, err := s.Query(ctx, QueryFilters{
		Severity:   []types.Severity{types.SeverityWarning, types.SeverityCritical},
		Namespaces: []string{"b"},
	})
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Equal(t, "2", res[0].ID)

	// Single-namespace filter on the standard path.
	res2, err := s.Query(ctx, QueryFilters{
		Since:     now.Add(-time.Hour),
		Namespace: "a",
	})
	require.NoError(t, err)
	require.Len(t, res2, 1)
	assert.Equal(t, "1", res2[0].ID)
}

func TestMemoryStore_FlushAndClose(t *testing.T) {
	s := NewMemoryStore()
	require.NoError(t, s.Flush(context.Background()))
	require.NoError(t, s.Close())
}
