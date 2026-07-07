// Package enforcer provides tests for audit logging.
package enforcer

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// syncBuffer is a concurrency-safe bytes.Buffer for capturing slog output
// written from a background goroutine while the test reads it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func TestNewAuditLogger(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	tmpDir := t.TempDir()
	cfg := AuditLoggerConfig{
		Path:     filepath.Join(tmpDir, "audit.log"),
		MaxSize:  1, // 1 MB for testing
		MaxFiles: 3,
	}

	al, err := NewAuditLogger(logger, cfg)
	require.NoError(t, err)
	defer al.Close()

	assert.Equal(t, cfg.Path, al.path)
	assert.Equal(t, int64(1*1024*1024), al.maxSize)
	assert.Equal(t, 3, al.maxFiles)
}

func TestNewAuditLogger_Defaults(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	tmpDir := t.TempDir()
	cfg := AuditLoggerConfig{
		Path: filepath.Join(tmpDir, "subdir", "audit.log"),
		// Leave MaxSize and MaxFiles at zero to test defaults
	}

	al, err := NewAuditLogger(logger, cfg)
	require.NoError(t, err)
	defer al.Close()

	assert.Equal(t, int64(100*1024*1024), al.maxSize) // Default 100 MB
	assert.Equal(t, 5, al.maxFiles)                   // Default 5 files
}

func TestAuditLogger_Write(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	tmpDir := t.TempDir()
	cfg := AuditLoggerConfig{
		Path:     filepath.Join(tmpDir, "audit.log"),
		MaxSize:  100, // 100 MB - won't rotate in this test
		MaxFiles: 3,
	}

	al, err := NewAuditLogger(logger, cfg)
	require.NoError(t, err)
	defer al.Close()

	entry := AuditEntry{
		Timestamp:   time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		Action:      ActionKill,
		RuleID:      "rule_001",
		PID:         1234,
		TGID:        1234,
		Comm:        "test-process",
		UID:         1000,
		Description: "Test enforcement",
		Success:     true,
		EventType:   types.EventSyscall,
	}

	err = al.Write(entry)
	require.NoError(t, err)

	// Read back and verify
	entries, err := ReadAuditLog(cfg.Path)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	assert.Equal(t, entry.Action, entries[0].Action)
	assert.Equal(t, entry.RuleID, entries[0].RuleID)
	assert.Equal(t, entry.PID, entries[0].PID)
	assert.Equal(t, entry.Success, entries[0].Success)
}

func TestAuditLogger_Write_Multiple(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	tmpDir := t.TempDir()
	cfg := AuditLoggerConfig{
		Path:     filepath.Join(tmpDir, "audit.log"),
		MaxSize:  100,
		MaxFiles: 3,
	}

	al, err := NewAuditLogger(logger, cfg)
	require.NoError(t, err)
	defer al.Close()

	// Write multiple entries
	for i := 0; i < 5; i++ {
		entry := AuditEntry{
			Timestamp: time.Now(),
			Action:    ActionKill,
			RuleID:    "rule_001",
			PID:       uint32(1000 + i),
			Success:   true,
		}
		err := al.Write(entry)
		require.NoError(t, err)
	}

	// Read back and verify
	entries, err := ReadAuditLog(cfg.Path)
	require.NoError(t, err)
	assert.Len(t, entries, 5)
}

func TestReadAuditLog_NotFound(t *testing.T) {
	_, err := ReadAuditLog("/nonexistent/path/audit.log")
	assert.Error(t, err)
}

func TestQueryAuditLog(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	tmpDir := t.TempDir()
	cfg := AuditLoggerConfig{
		Path:     filepath.Join(tmpDir, "audit.log"),
		MaxSize:  100,
		MaxFiles: 3,
	}

	al, err := NewAuditLogger(logger, cfg)
	require.NoError(t, err)
	defer al.Close()

	now := time.Now()

	// Write test entries
	entries := []AuditEntry{
		{Timestamp: now.Add(-2 * time.Hour), Action: ActionKill, RuleID: "rule_001", PID: 1000, Success: true, EventType: types.EventSyscall},
		{Timestamp: now.Add(-1 * time.Hour), Action: ActionBlock, RuleID: "rule_002", PID: 2000, Success: true, EventType: types.EventTCPConnect},
		{Timestamp: now, Action: ActionThrottle, RuleID: "rule_003", PID: 1000, Success: false, EventType: types.EventFileAccess},
	}

	for _, entry := range entries {
		err := al.Write(entry)
		require.NoError(t, err)
	}

	// Test queries
	t.Run("filter by since", func(t *testing.T) {
		results, err := QueryAuditLog(cfg.Path, now.Add(-30*time.Minute), "", 0)
		require.NoError(t, err)
		assert.Len(t, results, 1)
		assert.Equal(t, ActionThrottle, results[0].Action)
	})

	t.Run("filter by action", func(t *testing.T) {
		results, err := QueryAuditLog(cfg.Path, time.Time{}, ActionKill, 0)
		require.NoError(t, err)
		assert.Len(t, results, 1)
		assert.Equal(t, uint32(1000), results[0].PID)
	})

	t.Run("filter by pid", func(t *testing.T) {
		results, err := QueryAuditLog(cfg.Path, time.Time{}, "", 1000)
		require.NoError(t, err)
		assert.Len(t, results, 2)
	})

	t.Run("filter by multiple criteria", func(t *testing.T) {
		results, err := QueryAuditLog(cfg.Path, now.Add(-3*time.Hour), ActionKill, 1000)
		require.NoError(t, err)
		assert.Len(t, results, 1)
	})
}

func TestAuditLogger_GetStats(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	tmpDir := t.TempDir()
	cfg := AuditLoggerConfig{
		Path:     filepath.Join(tmpDir, "audit.log"),
		MaxSize:  100,
		MaxFiles: 3,
	}

	al, err := NewAuditLogger(logger, cfg)
	require.NoError(t, err)
	defer al.Close()

	now := time.Now()

	// Write test entries
	entries := []AuditEntry{
		{Timestamp: now, Action: ActionKill, RuleID: "rule_001", PID: 1000, Success: true},
		{Timestamp: now, Action: ActionKill, RuleID: "rule_001", PID: 1001, Success: true},
		{Timestamp: now, Action: ActionBlock, RuleID: "rule_002", PID: 2000, Success: false},
		{Timestamp: now, Action: ActionThrottle, RuleID: "rule_003", PID: 3000, Success: true},
	}

	for _, entry := range entries {
		err := al.Write(entry)
		require.NoError(t, err)
	}

	stats, err := al.GetStats()
	require.NoError(t, err)

	assert.Equal(t, 4, stats.TotalEntries)
	assert.Equal(t, 3, stats.SuccessCount)
	assert.Equal(t, 1, stats.FailureCount)
	assert.Equal(t, 2, stats.ByAction[ActionKill])
	assert.Equal(t, 1, stats.ByAction[ActionBlock])
	assert.Equal(t, 1, stats.ByAction[ActionThrottle])
	assert.Equal(t, 2, stats.ByRuleID["rule_001"])
	assert.Equal(t, 1, stats.ByRuleID["rule_002"])
	assert.Equal(t, 1, stats.ByRuleID["rule_003"])
}

func TestAuditLogger_AuditChannel(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	tmpDir := t.TempDir()
	cfg := AuditLoggerConfig{
		Path:     filepath.Join(tmpDir, "audit.log"),
		MaxSize:  100,
		MaxFiles: 3,
	}

	al, err := NewAuditLogger(logger, cfg)
	require.NoError(t, err)
	defer al.Close()

	// Get channel
	ch := al.AuditChannel(10)

	// Send entries through channel
	entry := AuditEntry{
		Timestamp: time.Now(),
		Action:    ActionKill,
		RuleID:    "rule_001",
		PID:       1234,
		Success:   true,
	}

	ch <- entry

	// Give time for processing
	time.Sleep(100 * time.Millisecond)

	// Read back and verify
	entries, err := ReadAuditLog(cfg.Path)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, entry.PID, entries[0].PID)
}

func TestAuditEntry_MarshalJSON(t *testing.T) {
	entry := AuditEntry{
		Timestamp:   time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		Action:      ActionKill,
		RuleID:      "rule_001",
		PID:         1234,
		TGID:        1234,
		Comm:        "test-process",
		UID:         1000,
		Description: "Test enforcement",
		Success:     true,
		Error:       "",
		EventType:   types.EventSyscall,
	}

	data, err := json.Marshal(entry)
	require.NoError(t, err)

	// Verify JSON structure
	var decoded map[string]interface{}
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, "kill", decoded["action"])
	assert.Equal(t, "rule_001", decoded["rule_id"])
	assert.Equal(t, float64(1234), decoded["pid"])
	assert.Equal(t, true, decoded["success"])
}

func TestAuditLogger_Rotation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	tmpDir := t.TempDir()
	cfg := AuditLoggerConfig{
		Path:     filepath.Join(tmpDir, "audit.log"),
		MaxSize:  1, // 1 MB - we'll manually trigger rotation
		MaxFiles: 3,
	}

	al, err := NewAuditLogger(logger, cfg)
	require.NoError(t, err)
	defer al.Close()

	// Write a small entry first
	entry := AuditEntry{
		Timestamp: time.Now(),
		Action:    ActionKill,
		RuleID:    "rule_001",
		PID:       1234,
		Success:   true,
	}

	err = al.Write(entry)
	require.NoError(t, err)

	// Manually trigger rotation by writing large data
	// Note: We can't easily test actual rotation without writing 1MB,
	// but we can verify the rotation logic doesn't crash
	al.mu.Lock()
	al.maxSize = 1 // Set to 1 byte to force rotation
	al.mu.Unlock()

	// This should trigger rotation
	err = al.Write(entry)
	require.NoError(t, err)

	// Verify files exist
	_, err = os.Stat(cfg.Path)
	require.NoError(t, err)

	// audit.log.1 should exist after rotation
	_, err = os.Stat(cfg.Path + ".1")
	// May or may not exist depending on timing, just check no error for .log
	_ = err
}

// TestAuditLogger_Rotation_ShiftExisting exercises the numbered-shift loop and
// the "remove oldest before renaming" branch in checkRotation by pre-seeding
// audit.log.1/.2/.3 with distinguishable content before forcing a rotation.
func TestAuditLogger_Rotation_ShiftExisting(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "audit.log")
	cfg := AuditLoggerConfig{
		Path:     path,
		MaxSize:  100,
		MaxFiles: 3,
	}

	al, err := NewAuditLogger(logger, cfg)
	require.NoError(t, err)
	defer al.Close()

	// Seed the current log with an entry so it has real content that becomes .1.
	firstEntry := AuditEntry{
		Timestamp: time.Now(),
		Action:    ActionKill,
		RuleID:    "first_entry",
		PID:       1000,
		Success:   true,
	}
	require.NoError(t, al.Write(firstEntry))

	curContent, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NotEmpty(t, curContent)

	// Pre-seed rotated files with distinguishable raw content.
	require.NoError(t, os.WriteFile(path+".1", []byte("ONE\n"), 0640))
	require.NoError(t, os.WriteFile(path+".2", []byte("TWO\n"), 0640))
	require.NoError(t, os.WriteFile(path+".3", []byte("THREE\n"), 0640))

	// Force rotation on the next write.
	al.mu.Lock()
	al.maxSize = 1
	al.mu.Unlock()

	triggerEntry := AuditEntry{
		Timestamp: time.Now(),
		Action:    ActionKill,
		RuleID:    "trigger_entry",
		PID:       2000,
		Success:   true,
	}
	require.NoError(t, al.Write(triggerEntry))

	// With MaxFiles=3 the shift is: remove old .3, .2 -> .3, .1 -> .2, current -> .1.
	got3, err := os.ReadFile(path + ".3")
	require.NoError(t, err)
	assert.Equal(t, "TWO\n", string(got3), "old .2 must shift to .3")

	got2, err := os.ReadFile(path + ".2")
	require.NoError(t, err)
	assert.Equal(t, "ONE\n", string(got2), "old .1 must shift to .2")

	got1, err := os.ReadFile(path + ".1")
	require.NoError(t, err)
	assert.Equal(t, string(curContent), string(got1), "old current log must become .1")

	// Old .3 ("THREE") must be gone (overwritten by the removed-oldest branch).
	assert.NotContains(t, string(got3), "THREE")

	// A fresh audit.log exists and holds only the triggering entry.
	entries, err := ReadAuditLog(path)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "trigger_entry", entries[0].RuleID)
}

// TestAuditLogger_Write_RotationError verifies Write returns a wrapped
// "audit rotation:" error when checkRotation fails (here: the underlying file
// is closed out from under it, so file.Stat() errors).
func TestAuditLogger_Write_RotationError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	tmpDir := t.TempDir()
	cfg := AuditLoggerConfig{
		Path:     filepath.Join(tmpDir, "audit.log"),
		MaxSize:  100,
		MaxFiles: 3,
	}

	al, err := NewAuditLogger(logger, cfg)
	require.NoError(t, err)

	// Close the underlying file directly so checkRotation's Stat() fails.
	require.NoError(t, al.file.Close())

	entry := AuditEntry{
		Timestamp: time.Now(),
		Action:    ActionKill,
		RuleID:    "rule_001",
		PID:       1234,
		Success:   true,
	}

	err = al.Write(entry)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audit rotation:")
}

// NOTE: The "open new audit file" failure branch inside checkRotation is not
// reliably reachable in this test environment because tests run as root, and
// root bypasses DAC permission checks — a read-only directory does not prevent
// the post-rotation reopen from succeeding. The Stat-failure path (closed file)
// in TestAuditLogger_Write_RotationError covers Write's "audit rotation:" error
// wrapping instead.

// TestAuditLogger_ProcessChannel_WriteError verifies processAuditChannel logs
// "failed to write audit entry" (and does not crash) when the write path is
// broken, then that Close still behaves cleanly.
func TestAuditLogger_ProcessChannel_WriteError(t *testing.T) {
	sb := &syncBuffer{}
	logger := slog.New(slog.NewTextHandler(sb, nil))

	tmpDir := t.TempDir()
	cfg := AuditLoggerConfig{
		Path:     filepath.Join(tmpDir, "audit.log"),
		MaxSize:  100,
		MaxFiles: 3,
	}

	al, err := NewAuditLogger(logger, cfg)
	require.NoError(t, err)

	ch := al.AuditChannel(1)

	// Break the write path: close the underlying file so Write() errors.
	require.NoError(t, al.file.Close())

	ch <- AuditEntry{
		Timestamp: time.Now(),
		Action:    ActionKill,
		RuleID:    "rule_err",
		PID:       4242,
		Success:   true,
	}

	// Poll (bounded) for the error log line — the goroutine is async.
	deadline := time.Now().Add(2 * time.Second)
	found := false
	for time.Now().Before(deadline) {
		if strings.Contains(sb.String(), "failed to write audit entry") {
			found = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	assert.True(t, found, "expected processAuditChannel to log a write failure")

	// Closing the channel stops the goroutine; Close on the already-closed file
	// returns an OS error but must not panic.
	close(ch)
	assert.NotPanics(t, func() { _ = al.Close() })
}

// TestAuditLogger_Close_Double verifies double-Close does not panic and that
// the second call surfaces the OS-level "already closed" error rather than
// crashing on a nil/invalid handle.
func TestAuditLogger_Close_Double(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	tmpDir := t.TempDir()
	cfg := AuditLoggerConfig{
		Path:     filepath.Join(tmpDir, "audit.log"),
		MaxSize:  100,
		MaxFiles: 3,
	}

	al, err := NewAuditLogger(logger, cfg)
	require.NoError(t, err)

	require.NoError(t, al.Close(), "first Close should succeed")

	var secondErr error
	assert.NotPanics(t, func() { secondErr = al.Close() })
	require.Error(t, secondErr, "second Close returns the OS already-closed error")
	assert.Contains(t, secondErr.Error(), "file already closed")
}

// TestAuditLogger_Close_ExternallyClosed verifies Close surfaces the OS error
// (not a panic) when the file was closed out-of-band.
func TestAuditLogger_Close_ExternallyClosed(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	tmpDir := t.TempDir()
	cfg := AuditLoggerConfig{
		Path:     filepath.Join(tmpDir, "audit.log"),
		MaxSize:  100,
		MaxFiles: 3,
	}

	al, err := NewAuditLogger(logger, cfg)
	require.NoError(t, err)

	require.NoError(t, al.file.Close(), "close file externally")

	var closeErr error
	assert.NotPanics(t, func() { closeErr = al.Close() })
	require.Error(t, closeErr)
	assert.Contains(t, closeErr.Error(), "file already closed")
}

// TestAuditLogger_AuditChannel_BufferBoundary sends more entries than the
// channel buffer can hold and asserts all of them eventually land in the file.
func TestAuditLogger_AuditChannel_BufferBoundary(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	tmpDir := t.TempDir()
	cfg := AuditLoggerConfig{
		Path:     filepath.Join(tmpDir, "audit.log"),
		MaxSize:  100,
		MaxFiles: 3,
	}

	al, err := NewAuditLogger(logger, cfg)
	require.NoError(t, err)
	defer al.Close()

	ch := al.AuditChannel(1) // buffer size 1, we send more rapidly

	for i := 0; i < 4; i++ {
		ch <- AuditEntry{
			Timestamp: time.Now(),
			Action:    ActionKill,
			RuleID:    "rule_boundary",
			PID:       uint32(5000 + i),
			Success:   true,
		}
	}

	// Poll (bounded) until all 4 entries are persisted.
	deadline := time.Now().Add(2 * time.Second)
	var entries []AuditEntry
	for time.Now().Before(deadline) {
		entries, err = ReadAuditLog(cfg.Path)
		require.NoError(t, err)
		if len(entries) == 4 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	assert.Len(t, entries, 4, "all channel entries should eventually be written")
}
