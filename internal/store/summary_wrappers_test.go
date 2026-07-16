package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// assertErr is a sentinel used to drive the Query-error fallback branches.
var assertErr = errors.New("query failed")

// nonSummarizerStore is a minimal AlertStore that deliberately does NOT
// implement Summarizer, so the wrapper Summarize methods exercise their
// Query + SummarizeAlerts fallback branch.
type nonSummarizerStore struct {
	alerts   []types.Alert
	queryErr error
}

func (m *nonSummarizerStore) Store(_ context.Context, a types.Alert) error {
	m.alerts = append(m.alerts, a)
	return nil
}
func (m *nonSummarizerStore) StoreBatch(_ context.Context, a []types.Alert) error {
	m.alerts = append(m.alerts, a...)
	return nil
}
func (m *nonSummarizerStore) Query(_ context.Context, _ QueryFilters) ([]types.Alert, error) {
	return m.alerts, m.queryErr
}
func (m *nonSummarizerStore) QueryByID(_ context.Context, _ string) (*types.Alert, error) {
	return nil, nil
}
func (m *nonSummarizerStore) Count(_ context.Context, _ QueryFilters) (int64, error) {
	return int64(len(m.alerts)), nil
}
func (m *nonSummarizerStore) Delete(_ context.Context, _ time.Duration) (int64, error) {
	return 0, nil
}
func (m *nonSummarizerStore) Flush(_ context.Context) error  { return nil }
func (m *nonSummarizerStore) Close() error                   { return nil }
func (m *nonSummarizerStore) Healthy(_ context.Context) bool { return true }

func sampleAlerts(now time.Time) []types.Alert {
	return []types.Alert{
		{ID: "1", Timestamp: now, RuleID: "r1", Severity: types.SeverityCritical, Comm: "a", Message: "m"},
		{ID: "2", Timestamp: now, RuleID: "r1", Severity: types.SeverityWarning, Comm: "b", Message: "m"},
	}
}

// TestInstrumentedStore_Summarize covers both the delegation path (inner is a
// Summarizer) and the Query-fallback path (inner is not), plus the error branch.
func TestInstrumentedStore_Summarize(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()

	t.Run("delegates to inner Summarizer", func(t *testing.T) {
		mem := NewMemoryStore()
		require.NoError(t, mem.StoreBatch(ctx, sampleAlerts(now)))
		is := NewInstrumentedStore(mem)
		s, err := is.Summarize(ctx, QueryFilters{})
		require.NoError(t, err)
		assert.Equal(t, 2, s.Total)
		assert.Equal(t, 1, s.BySeverity["critical"])
	})

	t.Run("falls back to Query when inner is not a Summarizer", func(t *testing.T) {
		is := NewInstrumentedStore(&nonSummarizerStore{alerts: sampleAlerts(now)})
		s, err := is.Summarize(ctx, QueryFilters{})
		require.NoError(t, err)
		assert.Equal(t, 2, s.Total)
	})

	t.Run("propagates Query error in fallback", func(t *testing.T) {
		is := NewInstrumentedStore(&nonSummarizerStore{queryErr: assertErr})
		_, err := is.Summarize(ctx, QueryFilters{})
		require.Error(t, err)
	})
}

// TestBatchingStore_Summarize mirrors the above for the batching decorator.
func TestBatchingStore_Summarize(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()

	t.Run("delegates to inner Summarizer", func(t *testing.T) {
		mem := NewMemoryStore()
		require.NoError(t, mem.StoreBatch(ctx, sampleAlerts(now)))
		bs := NewBatchingStore(mem, BatchingStoreConfig{})
		t.Cleanup(func() { _ = bs.Close() })
		s, err := bs.Summarize(ctx, QueryFilters{})
		require.NoError(t, err)
		assert.Equal(t, 2, s.Total)
		assert.Equal(t, 1, s.BySeverity["warning"])
	})

	t.Run("falls back to Query when inner is not a Summarizer", func(t *testing.T) {
		bs := NewBatchingStore(&nonSummarizerStore{alerts: sampleAlerts(now)}, BatchingStoreConfig{})
		t.Cleanup(func() { _ = bs.Close() })
		s, err := bs.Summarize(ctx, QueryFilters{})
		require.NoError(t, err)
		assert.Equal(t, 2, s.Total)
	})

	t.Run("propagates Query error in fallback", func(t *testing.T) {
		bs := NewBatchingStore(&nonSummarizerStore{queryErr: assertErr}, BatchingStoreConfig{})
		t.Cleanup(func() { _ = bs.Close() })
		_, err := bs.Summarize(ctx, QueryFilters{})
		require.Error(t, err)
	})
}

// TestMemorySummarize_Filters exercises the namespace pre-filter branches and
// the Until window narrowing in the memory Summarize path.
func TestMemorySummarize_Filters(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	mem := NewMemoryStore()
	require.NoError(t, mem.StoreBatch(ctx, []types.Alert{
		{ID: "a", Timestamp: now, RuleID: "r", Severity: types.SeverityWarning, Comm: "x", Message: "m",
			Enrichment: types.EnrichmentInfo{Namespace: "team-a"}},
		{ID: "b", Timestamp: now, RuleID: "r", Severity: types.SeverityWarning, Comm: "x", Message: "m",
			Enrichment: types.EnrichmentInfo{Namespace: "team-b"}},
		{ID: "c", Timestamp: now.Add(-3 * time.Hour), RuleID: "r", Severity: types.SeverityWarning, Comm: "x", Message: "m",
			Enrichment: types.EnrichmentInfo{Namespace: "team-a"}},
	}))

	t.Run("single namespace", func(t *testing.T) {
		s, err := mem.Summarize(ctx, QueryFilters{Namespace: "team-a"})
		require.NoError(t, err)
		assert.Equal(t, 2, s.Total)
	})

	t.Run("multi namespace (OR)", func(t *testing.T) {
		s, err := mem.Summarize(ctx, QueryFilters{Namespaces: []string{"team-b", "team-c"}})
		require.NoError(t, err)
		assert.Equal(t, 1, s.Total)
	})

	t.Run("until window excludes newer", func(t *testing.T) {
		s, err := mem.Summarize(ctx, QueryFilters{Until: now.Add(-1 * time.Hour)})
		require.NoError(t, err)
		assert.Equal(t, 1, s.Total) // only the -3h alert
	})

	t.Run("empty result", func(t *testing.T) {
		s, err := mem.Summarize(ctx, QueryFilters{Namespace: "nope"})
		require.NoError(t, err)
		assert.Zero(t, s.Total)
		assert.Empty(t, s.TopRules)
		assert.Empty(t, s.Timeline)
	})
}
