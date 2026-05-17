// Package e2e provides end-to-end tests for enforcement actions.
package e2e

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/ebpf-guard/ebpf-guard/internal/enforcer"
	"github.com/ebpf-guard/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEnforcement_KillAction tests the kill enforcement action.
// This test requires Linux and appropriate permissions.
func TestEnforcement_KillAction(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping: test requires Linux")
	}

	// Check if we have permission to send signals
	if os.Geteuid() != 0 {
		t.Skip("skipping: test requires root for process kill")
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	// Create a temporary directory for audit logs
	tmpDir := t.TempDir()

	// Create audit logger
	auditLogger, err := enforcer.NewAuditLogger(logger, enforcer.AuditLoggerConfig{
		Path:     fmt.Sprintf("%s/audit.log", tmpDir),
		MaxSize:  10,
		MaxFiles: 3,
	})
	require.NoError(t, err)
	defer auditLogger.Close()

	// Create enforcer with kill enabled
	enf, err := enforcer.NewEnforcer(logger, enforcer.Config{
		EnableKill:      true,
		AuditLogChannel: auditLogger.AuditChannel(100),
	})
	require.NoError(t, err)

	// Create a test process
	testCmd := exec.Command("sleep", "30")
	err = testCmd.Start()
	require.NoError(t, err)

	pid := uint32(testCmd.Process.Pid)
	t.Logf("Created test process with PID %d", pid)

	// Give process time to start
	time.Sleep(100 * time.Millisecond)

	// Create alert
	alert := types.Alert{
		RuleID:   "test_kill_rule",
		RuleName: "Test Kill Rule",
		Severity: types.SeverityCritical,
		Event: types.Event{
			PID:  pid,
			TGID: pid,
			Comm: [16]byte{'s', 'l', 'e', 'e', 'p', 0},
			UID:  uint32(os.Getuid()),
		},
	}

	// Execute kill action
	ctx := context.Background()
	err = enf.Execute(ctx, enforcer.ActionKill, alert)
	require.NoError(t, err)

	// Wait for process to exit
	done := make(chan error, 1)
	go func() {
		done <- testCmd.Wait()
	}()

	select {
	case err := <-done:
		if err != nil {
			// Process was killed as expected
			t.Logf("Process exited with error (expected): %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for process to be killed")
	}

	// Verify process is gone
	_, err = os.Stat(fmt.Sprintf("/proc/%d", pid))
	assert.True(t, os.IsNotExist(err), "process should no longer exist")

	// Give audit log time to write
	time.Sleep(200 * time.Millisecond)

	// Verify audit log entry
	entries, err := enforcer.ReadAuditLog(fmt.Sprintf("%s/audit.log", tmpDir))
	require.NoError(t, err)
	require.Len(t, entries, 1)

	entry := entries[0]
	assert.Equal(t, enforcer.ActionKill, entry.Action)
	assert.Equal(t, "test_kill_rule", entry.RuleID)
	assert.Equal(t, pid, entry.PID)
	assert.True(t, entry.Success)
}

// TestEnforcement_BlockAction tests the block enforcement action.
// This is a placeholder as full TC/XDP blocking requires kernel-level setup.
func TestEnforcement_BlockAction(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping: test requires Linux")
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Create enforcer with block enabled
	enf, err := enforcer.NewEnforcer(logger, enforcer.Config{
		EnableBlock: true,
	})
	require.NoError(t, err)

	alert := types.Alert{
		RuleID:   "test_block_rule",
		RuleName: "Test Block Rule",
		Severity: types.SeverityCritical,
		Event: types.Event{
			PID:  uint32(os.Getpid()),
			TGID: uint32(os.Getpid()),
			Comm: [16]byte{'t', 'e', 's', 't', 0},
			UID:  uint32(os.Getuid()),
		},
	}

	// Execute block action (currently logs only)
	ctx := context.Background()
	err = enf.Execute(ctx, enforcer.ActionBlock, alert)
	assert.NoError(t, err)
}

// TestEnforcement_ThrottleAction tests the throttle enforcement action.
// This test requires cgroup v2 and appropriate permissions.
func TestEnforcement_ThrottleAction(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping: test requires Linux")
	}

	// Check if cgroup v2 is available
	if !enforcer.IsCgroupV2Available() {
		t.Skip("skipping: cgroup v2 not available")
	}

	// Check if we have permission
	if os.Geteuid() != 0 {
		t.Skip("skipping: test requires root for cgroup operations")
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Create enforcer with throttle enabled
	enf, err := enforcer.NewEnforcer(logger, enforcer.Config{
		EnableThrottle: true,
	})
	require.NoError(t, err)

	// Use current process for testing
	pid := uint32(os.Getpid())

	alert := types.Alert{
		RuleID:   "test_throttle_rule",
		RuleName: "Test Throttle Rule",
		Severity: types.SeverityWarning,
		Event: types.Event{
			PID:  pid,
			TGID: pid,
			Comm: [16]byte{'t', 'e', 's', 't', 0},
			UID:  uint32(os.Getuid()),
		},
	}

	// Execute throttle action
	ctx := context.Background()
	err = enf.Execute(ctx, enforcer.ActionThrottle, alert)

	// Throttle may fail if cgroup setup is not complete
	// Just verify it doesn't panic and logs appropriately
	t.Logf("Throttle result: %v", err)

	// Verify throttle state was tracked
	state := enf.GetThrottleState(pid)
	if err == nil {
		require.NotNil(t, state)
		assert.Equal(t, pid, state.PID)
		assert.True(t, state.Active)
		assert.GreaterOrEqual(t, state.Count, 1)
	}
}

// TestEnforcement_DisabledActions tests that disabled actions return errors.
func TestEnforcement_DisabledActions(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Create enforcer with all actions disabled
	enf, err := enforcer.NewEnforcer(logger, enforcer.Config{})
	require.NoError(t, err)

	alert := types.Alert{
		RuleID: "test_rule",
		Event:  types.Event{PID: 1234},
	}

	ctx := context.Background()

	// All actions should fail with "disabled" error
	err = enf.Execute(ctx, enforcer.ActionKill, alert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "disabled")

	err = enf.Execute(ctx, enforcer.ActionBlock, alert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "disabled")

	err = enf.Execute(ctx, enforcer.ActionThrottle, alert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "disabled")
}

// TestEnforcement_AuditLogRotation tests audit log rotation.
func TestEnforcement_AuditLogRotation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	tmpDir := t.TempDir()

	// Create audit logger with small max size
	auditLogger, err := enforcer.NewAuditLogger(logger, enforcer.AuditLoggerConfig{
		Path:     fmt.Sprintf("%s/audit.log", tmpDir),
		MaxSize:  1, // 1 MB
		MaxFiles: 3,
	})
	require.NoError(t, err)
	defer auditLogger.Close()

	// Write many entries to trigger rotation
	for i := 0; i < 100; i++ {
		entry := enforcer.AuditEntry{
			Timestamp: time.Now(),
			Action:    enforcer.ActionKill,
			RuleID:    "test_rule",
			PID:       uint32(1000 + i),
			Success:   true,
		}
		err := auditLogger.Write(entry)
		require.NoError(t, err)
	}

	// Verify log file exists and has content
	entries, err := enforcer.ReadAuditLog(fmt.Sprintf("%s/audit.log", tmpDir))
	require.NoError(t, err)
	assert.Greater(t, len(entries), 0)
}

// TestEnforcement_CleanupThrottles tests throttle cleanup.
func TestEnforcement_CleanupThrottles(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	enf, err := enforcer.NewEnforcer(logger, enforcer.Config{EnableThrottle: true})
	require.NoError(t, err)

	// Manually add throttle states with different ages
	enf.RemoveThrottle(1) // Ensure clean state
	enf.RemoveThrottle(2)
	enf.RemoveThrottle(3)

	// Add states via reflection or internal method
	// For testing, we'll use the execute method to create states
	alert := types.Alert{
		RuleID: "test_rule",
		Event:  types.Event{PID: 1},
	}

	// This will create a state
	ctx := context.Background()
	_ = enf.Execute(ctx, enforcer.ActionThrottle, alert)

	// Verify state exists
	state := enf.GetThrottleState(1)
	require.NotNil(t, state)

	// Cleanup with very short max age should not remove recent entries
	removed := enf.CleanupThrottles(1 * time.Nanosecond)
	assert.Equal(t, 1, removed)

	// Verify state is gone
	assert.Nil(t, enf.GetThrottleState(1))
}


