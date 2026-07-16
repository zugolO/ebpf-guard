//go:build cgo
// +build cgo

package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// TestSQLiteStore_ReapUpsertPersistsCount reproduces issue #301: alert
// aggregation forwards the first occurrence immediately and later re-emits the
// SAME alert ID with the final count when the window closes. A plain INSERT
// failed the UNIQUE(id) constraint and rolled back the whole StoreBatch, so the
// aggregated count was never persisted. The upsert must instead update the row.
func TestSQLiteStore_ReapUpsertPersistsCount(t *testing.T) {
	ctx := context.Background()
	s := newSQLiteAlertStore(t)

	first := time.Now().Add(-30 * time.Second)
	last := time.Now()

	head := types.Alert{
		ID: "agg-1", Timestamp: first, RuleID: "rule-001",
		Severity: types.SeverityCritical, PID: 1, Comm: "curl",
		Message: "first", Count: 1, FirstSeen: first, LastSeen: first,
	}
	// Ingest forwards the head immediately.
	require.NoError(t, s.StoreBatch(ctx, []types.Alert{head}))

	// Reap re-emits the same ID with the final aggregate — must not error.
	final := head
	final.Message = "folded"
	final.Count = 5
	final.LastSeen = last
	require.NoError(t, s.StoreBatch(ctx, []types.Alert{final}),
		"reap upsert must not fail on the existing id")

	// Exactly one row, carrying the final count and timestamps.
	got, err := s.QueryByID(ctx, "agg-1")
	require.NoError(t, err)
	assert.Equal(t, 5, got.Count)
	assert.Equal(t, "folded", got.Message)
	assert.WithinDuration(t, first, got.FirstSeen, time.Second)
	assert.WithinDuration(t, last, got.LastSeen, time.Second)

	count, err := s.Count(ctx, QueryFilters{})
	require.NoError(t, err)
	assert.Equal(t, int64(1), count, "upsert must not create a second row")
}

// TestSQLiteStore_AggregatorIntegration wires the real correlator aggregator to
// the SQLite store end-to-end: Ingest → StoreBatch → Reap → StoreBatch, which
// is exactly the path cmd/ebpf-guard/main.go uses.
func TestSQLiteStore_AggregatorIntegration(t *testing.T) {
	ctx := context.Background()
	s := newSQLiteAlertStore(t)

	agg := correlator.NewAlertAggregator(correlator.AlertAggregationConfig{
		Enabled: true,
		Window:  50 * time.Millisecond,
	})

	mk := func() types.Alert {
		return types.Alert{
			ID: "dup", RuleID: "rule-x", Severity: types.SeverityWarning,
			PID: 7, Comm: "sh", Message: "repeat",
		}
	}

	now := time.Now()
	// First occurrence opens the window and is forwarded immediately.
	forwarded := agg.Ingest([]types.Alert{mk()}, now)
	require.Len(t, forwarded, 1)
	require.NoError(t, s.StoreBatch(ctx, forwarded))

	// Two more repeats within the window are folded (not forwarded).
	require.Empty(t, agg.Ingest([]types.Alert{mk()}, now.Add(5*time.Millisecond)))
	require.Empty(t, agg.Ingest([]types.Alert{mk()}, now.Add(10*time.Millisecond)))

	// Close the window and forward the final aggregate.
	reaped := agg.Reap(now.Add(time.Second))
	require.Len(t, reaped, 1)
	assert.Equal(t, 3, reaped[0].Count)
	require.NoError(t, s.StoreBatch(ctx, reaped))

	got, err := s.QueryByID(ctx, "dup")
	require.NoError(t, err)
	assert.Equal(t, 3, got.Count, "final aggregated count must be persisted")

	count, err := s.Count(ctx, QueryFilters{})
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)
}

// TestSQLiteStore_MigrateAggregationColumns verifies the ADD COLUMN migration
// path: a database created without the aggregation columns gains them, and
// existing rows read back with zero-value count/first_seen/last_seen.
func TestSQLiteStore_MigrateAggregationColumns(t *testing.T) {
	ctx := context.Background()
	s := newSQLiteAlertStore(t)

	// Simulate a legacy DB: drop the new columns, insert a pre-migration row.
	for _, col := range []string{"count", "first_seen", "last_seen"} {
		_, err := s.db.Exec("ALTER TABLE alerts DROP COLUMN " + col)
		require.NoError(t, err)
	}
	_, err := s.db.Exec(`INSERT INTO alerts
		(id, timestamp, rule_id, severity, pid, comm, message, details, trace_id, pod_name, namespace, container_id, labels)
		VALUES ('legacy', ?, 'r', 'warning', 1, 'sh', 'old', '', '', '', '', '', '')`, time.Now())
	require.NoError(t, err)

	// Re-run the migration; it should add the columns back without touching data.
	require.NoError(t, s.migrateAggregationColumns())

	got, err := s.QueryByID(ctx, "legacy")
	require.NoError(t, err)
	assert.Equal(t, 0, got.Count)
	assert.True(t, got.FirstSeen.IsZero())

	// New aggregated writes now persist correctly on the migrated schema.
	require.NoError(t, s.Store(ctx, types.Alert{
		ID: "new", Timestamp: time.Now(), RuleID: "r", Severity: types.SeverityWarning,
		PID: 2, Comm: "sh", Message: "m", Count: 4,
	}))
	got, err = s.QueryByID(ctx, "new")
	require.NoError(t, err)
	assert.Equal(t, 4, got.Count)
}
