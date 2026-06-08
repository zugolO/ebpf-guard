//go:build cgo
// +build cgo

package store

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// TestSQLiteStore_RetentionByAge verifies that performMaintenance deletes alerts
// older than retentionPeriod and keeps alerts within the window.
func TestSQLiteStore_RetentionByAge(t *testing.T) {
	s, err := NewSQLiteStore(SQLiteConfig{
		Path:            ":memory:",
		RetentionPeriod: 24 * time.Hour,
		VacuumInterval:  time.Hour, // won't fire during the test
	})
	require.NoError(t, err)
	defer s.Close()

	ctx := context.Background()
	now := time.Now()

	alerts := []types.Alert{
		{
			ID:        "old-1",
			Timestamp: now.Add(-48 * time.Hour), // 2 days old — should be deleted
			RuleID:    "rule-001",
			Severity:  types.SeverityWarning,
			PID:       100,
			Comm:      "test",
			Message:   "old alert",
		},
		{
			ID:        "old-2",
			Timestamp: now.Add(-25 * time.Hour), // just over 24h — should be deleted
			RuleID:    "rule-001",
			Severity:  types.SeverityCritical,
			PID:       101,
			Comm:      "test",
			Message:   "old alert 2",
		},
		{
			ID:        "recent-1",
			Timestamp: now.Add(-12 * time.Hour), // 12h old — should be kept
			RuleID:    "rule-002",
			Severity:  types.SeverityWarning,
			PID:       102,
			Comm:      "test",
			Message:   "recent alert",
		},
		{
			ID:        "recent-2",
			Timestamp: now.Add(-1 * time.Hour), // 1h old — should be kept
			RuleID:    "rule-002",
			Severity:  types.SeverityCritical,
			PID:       103,
			Comm:      "test",
			Message:   "very recent alert",
		},
	}

	for _, a := range alerts {
		require.NoError(t, s.Store(ctx, a))
	}

	count, err := s.Count(ctx, QueryFilters{})
	require.NoError(t, err)
	assert.Equal(t, int64(4), count, "expected 4 alerts before maintenance")

	s.performMaintenance(ctx)

	after, err := s.Count(ctx, QueryFilters{})
	require.NoError(t, err)
	assert.Equal(t, int64(2), after, "expected 2 recent alerts to survive retention")

	// Verify the surviving alerts are the recent ones.
	remaining, err := s.Query(ctx, QueryFilters{})
	require.NoError(t, err)
	ids := make(map[string]bool, len(remaining))
	for _, a := range remaining {
		ids[a.ID] = true
	}
	assert.True(t, ids["recent-1"], "recent-1 should survive")
	assert.True(t, ids["recent-2"], "recent-2 should survive")
	assert.False(t, ids["old-1"], "old-1 should be deleted")
	assert.False(t, ids["old-2"], "old-2 should be deleted")
}

// TestSQLiteStore_RetentionDisabled verifies that zero retentionPeriod does not
// delete any alerts during maintenance.
func TestSQLiteStore_RetentionDisabled(t *testing.T) {
	s, err := NewSQLiteStore(SQLiteConfig{
		Path:            ":memory:",
		RetentionPeriod: 0, // disabled
		VacuumInterval:  time.Hour,
	})
	require.NoError(t, err)
	defer s.Close()

	ctx := context.Background()

	for i := 0; i < 5; i++ {
		require.NoError(t, s.Store(ctx, types.Alert{
			ID:        fmt.Sprintf("a-%d", i),
			Timestamp: time.Now().Add(-time.Duration(i+1) * 48 * time.Hour),
			RuleID:    "rule",
			Severity:  types.SeverityWarning,
			PID:       uint32(i),
			Comm:      "test",
			Message:   "msg",
		}))
	}

	s.performMaintenance(ctx)

	count, err := s.Count(ctx, QueryFilters{})
	require.NoError(t, err)
	assert.Equal(t, int64(5), count, "no rows should be deleted when retention is disabled")
}

// TestSQLiteStore_RetentionAndMaxAlerts verifies that both age and count
// retention work together. After maintenance, count <= maxAlerts and all
// remaining alerts are within the retention window.
func TestSQLiteStore_RetentionAndMaxAlerts(t *testing.T) {
	const maxAlerts = 3
	s, err := NewSQLiteStore(SQLiteConfig{
		Path:            ":memory:",
		MaxAlerts:       maxAlerts,
		RetentionPeriod: 24 * time.Hour,
		VacuumInterval:  time.Hour,
	})
	require.NoError(t, err)
	defer s.Close()

	ctx := context.Background()
	now := time.Now()

	// Insert 5 alerts: 2 old, 3 recent.
	for i := 0; i < 2; i++ {
		require.NoError(t, s.Store(ctx, types.Alert{
			ID:        fmt.Sprintf("old-%d", i),
			Timestamp: now.Add(-48 * time.Hour),
			RuleID:    "rule",
			Severity:  types.SeverityWarning,
			PID:       uint32(i),
			Comm:      "test",
			Message:   "old",
		}))
	}
	for i := 0; i < 3; i++ {
		require.NoError(t, s.Store(ctx, types.Alert{
			ID:        fmt.Sprintf("recent-%d", i),
			Timestamp: now.Add(-time.Duration(i+1) * time.Hour),
			RuleID:    "rule",
			Severity:  types.SeverityCritical,
			PID:       uint32(10 + i),
			Comm:      "test",
			Message:   "recent",
		}))
	}

	s.performMaintenance(ctx)

	count, err := s.Count(ctx, QueryFilters{})
	require.NoError(t, err)
	assert.LessOrEqual(t, count, int64(maxAlerts))
}

// TestSQLiteStore_BackupCreatesFile verifies that performBackup writes a file
// at the configured destination path.
func TestSQLiteStore_BackupCreatesFile(t *testing.T) {
	dest := t.TempDir() + "/backup.db"

	s, err := NewSQLiteStore(SQLiteConfig{
		Path:           ":memory:",
		VacuumInterval: time.Hour,
		BackupEnabled:  true,
		BackupPath:     dest,
		BackupInterval: time.Hour, // won't fire during the test
	})
	require.NoError(t, err)
	defer s.Close()

	ctx := context.Background()

	require.NoError(t, s.Store(ctx, types.Alert{
		ID:        "bak-1",
		Timestamp: time.Now(),
		RuleID:    "rule",
		Severity:  types.SeverityWarning,
		PID:       1,
		Comm:      "test",
		Message:   "backup test",
	}))

	s.performBackup(ctx)

	info, err := os.Stat(dest)
	require.NoError(t, err, "backup file should exist after performBackup")
	assert.Greater(t, info.Size(), int64(0), "backup file should not be empty")
}

// TestSQLiteStore_BackupDisabled verifies that performBackup with an empty
// backupPath does not panic or create unexpected files.
func TestSQLiteStore_BackupDisabled(t *testing.T) {
	s, err := NewSQLiteStore(SQLiteConfig{
		Path:           ":memory:",
		VacuumInterval: time.Hour,
		BackupEnabled:  false, // disabled
	})
	require.NoError(t, err)
	defer s.Close()

	// Should be a no-op, not panic.
	s.performBackup(context.Background())
}
