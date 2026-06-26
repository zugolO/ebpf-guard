//go:build cgo
// +build cgo

package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

func newSQLiteAlertStore(t *testing.T) *SQLiteStore {
	t.Helper()
	s, err := NewSQLiteStore(SQLiteConfig{Path: ":memory:"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestSQLiteStore_StoreQueryByID(t *testing.T) {
	ctx := context.Background()
	s := newSQLiteAlertStore(t)

	alert := types.Alert{
		ID:        "a-1",
		Timestamp: time.Now(),
		RuleID:    "rule-001",
		Severity:  types.SeverityCritical,
		PID:       4242,
		Comm:      "evil",
		Message:   "boom",
		Enrichment: types.EnrichmentInfo{
			PodName:   "pod-a",
			Namespace: "ns-a",
		},
	}
	require.NoError(t, s.Store(ctx, alert))

	got, err := s.QueryByID(ctx, "a-1")
	require.NoError(t, err)
	assert.Equal(t, "a-1", got.ID)
	assert.Equal(t, "rule-001", got.RuleID)
	assert.Equal(t, uint32(4242), got.PID)

	_, err = s.QueryByID(ctx, "missing")
	require.Error(t, err)
}

func TestSQLiteStore_StoreBatchAndCount(t *testing.T) {
	ctx := context.Background()
	s := newSQLiteAlertStore(t)

	now := time.Now()
	batch := make([]types.Alert, 0, 5)
	for i := 0; i < 5; i++ {
		sev := types.SeverityWarning
		if i%2 == 0 {
			sev = types.SeverityCritical
		}
		batch = append(batch, types.Alert{
			ID:        fmt.Sprintf("b-%d", i),
			Timestamp: now.Add(time.Duration(i) * time.Minute),
			RuleID:    "rule-batch",
			Severity:  sev,
			PID:       uint32(1000 + i),
			Comm:      "proc",
		})
	}
	require.NoError(t, s.StoreBatch(ctx, batch))

	// Empty batch is a no-op.
	require.NoError(t, s.StoreBatch(ctx, nil))

	total, err := s.Count(ctx, QueryFilters{})
	require.NoError(t, err)
	assert.Equal(t, int64(5), total)

	crit, err := s.Count(ctx, QueryFilters{Severity: []types.Severity{types.SeverityCritical}})
	require.NoError(t, err)
	assert.Equal(t, int64(3), crit)
}

func TestSQLiteStore_QueryFilters(t *testing.T) {
	ctx := context.Background()
	s := newSQLiteAlertStore(t)

	now := time.Now()
	alerts := []types.Alert{
		{ID: "1", Timestamp: now, RuleID: "rule-a", Severity: types.SeverityWarning, PID: 100, Enrichment: types.EnrichmentInfo{Namespace: "ns1", PodName: "p1"}},
		{ID: "2", Timestamp: now.Add(-time.Hour), RuleID: "rule-b", Severity: types.SeverityCritical, PID: 200, Enrichment: types.EnrichmentInfo{Namespace: "ns2", PodName: "p2"}},
		{ID: "3", Timestamp: now.Add(-2 * time.Hour), RuleID: "rule-a", Severity: types.SeverityWarning, PID: 100, Enrichment: types.EnrichmentInfo{Namespace: "ns1", PodName: "p3"}},
	}
	require.NoError(t, s.StoreBatch(ctx, alerts))

	cases := []struct {
		name    string
		filters QueryFilters
		want    int
	}{
		{"all", QueryFilters{}, 3},
		{"by rule", QueryFilters{RuleIDs: []string{"rule-a"}}, 2},
		{"by severity", QueryFilters{Severity: []types.Severity{types.SeverityCritical}}, 1},
		{"by pid", QueryFilters{PIDs: []uint32{100}}, 2},
		{"by namespace", QueryFilters{Namespace: "ns1"}, 2},
		{"by namespaces", QueryFilters{Namespaces: []string{"ns1", "ns2"}}, 3},
		{"by pod name", QueryFilters{PodName: "p2"}, 1},
		{"since", QueryFilters{Since: now.Add(-90 * time.Minute)}, 2},
		{"limit", QueryFilters{Limit: 1}, 1},
		{"limit+offset", QueryFilters{Limit: 10, Offset: 1}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := s.Query(ctx, tc.filters)
			require.NoError(t, err)
			assert.Len(t, res, tc.want)
		})
	}
}

func TestSQLiteStore_FlushHealthyDelete(t *testing.T) {
	ctx := context.Background()
	s := newSQLiteAlertStore(t)

	assert.True(t, s.Healthy(ctx))
	require.NoError(t, s.Flush(ctx))

	now := time.Now()
	require.NoError(t, s.Store(ctx, types.Alert{ID: "old", Timestamp: now.Add(-48 * time.Hour), Severity: types.SeverityWarning}))
	require.NoError(t, s.Store(ctx, types.Alert{ID: "new", Timestamp: now, Severity: types.SeverityCritical}))

	deleted, err := s.Delete(ctx, 24*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, int64(1), deleted)

	remaining, err := s.Count(ctx, QueryFilters{})
	require.NoError(t, err)
	assert.Equal(t, int64(1), remaining)

	require.NoError(t, s.Flush(ctx))
}
