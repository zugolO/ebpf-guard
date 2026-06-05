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

// TestSQLiteStore_VacuumRotation verifies that after performMaintenance the
// number of stored alerts is trimmed to at most maxAlerts.
func TestSQLiteStore_VacuumRotation(t *testing.T) {
	const maxAlerts = 10

	s, err := NewSQLiteStore(SQLiteConfig{
		Path:           ":memory:",
		MaxAlerts:      maxAlerts,
		VacuumInterval: time.Hour, // won't fire during the test
	})
	require.NoError(t, err)
	defer s.Close()

	ctx := context.Background()

	// Insert maxAlerts+1 records with distinct timestamps so ordering is stable.
	for i := 0; i <= maxAlerts; i++ {
		alert := types.Alert{
			ID:        fmt.Sprintf("alert-%d", i),
			Timestamp: time.Now().Add(time.Duration(i) * time.Millisecond),
			RuleID:    "rule-vacuum",
			Severity:  types.SeverityWarning,
			PID:       uint32(1000 + i),
			Comm:      "test",
			Message:   "vacuum test alert",
		}
		require.NoError(t, s.Store(ctx, alert))
	}

	// Confirm maxAlerts+1 rows exist before maintenance.
	before, err := s.Count(ctx, QueryFilters{})
	require.NoError(t, err)
	assert.Equal(t, int64(maxAlerts+1), before, "expected maxAlerts+1 rows before maintenance")

	// Run maintenance synchronously.
	s.performMaintenance(ctx)

	// After maintenance, the count must be <= maxAlerts.
	after, err := s.Count(ctx, QueryFilters{})
	require.NoError(t, err)
	assert.LessOrEqual(t, after, int64(maxAlerts),
		"expected count <= maxAlerts after maintenance, got %d", after)
}

// TestSQLiteStore_CheckpointNoPrune verifies that when maxAlerts is 0
// performMaintenance does not delete any rows.
func TestSQLiteStore_CheckpointNoPrune(t *testing.T) {
	s, err := NewSQLiteStore(SQLiteConfig{
		Path:           ":memory:",
		MaxAlerts:      0, // pruning disabled
		VacuumInterval: time.Hour,
	})
	require.NoError(t, err)
	defer s.Close()

	ctx := context.Background()

	for i := 0; i < 5; i++ {
		alert := types.Alert{
			ID:        fmt.Sprintf("alert-%d", i),
			Timestamp: time.Now().Add(time.Duration(i) * time.Millisecond),
			RuleID:    "rule-no-prune",
			Severity:  types.SeverityWarning,
			PID:       uint32(2000 + i),
			Comm:      "test",
			Message:   "no-prune test",
		}
		require.NoError(t, s.Store(ctx, alert))
	}

	s.performMaintenance(ctx)

	count, err := s.Count(ctx, QueryFilters{})
	require.NoError(t, err)
	assert.Equal(t, int64(5), count, "no rows should be deleted when maxAlerts=0")
}
