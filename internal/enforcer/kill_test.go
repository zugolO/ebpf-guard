// Package enforcer provides tests for pidfd/proc-based process termination.
package enforcer

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// spawnChild starts a long-running child process and registers defensive
// cleanup so it is always reaped, even if the test fails midway.
func spawnChild(t *testing.T) (*exec.Cmd, uint32) {
	t.Helper()
	cmd := exec.Command("sleep", "60")
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return cmd, uint32(cmd.Process.Pid)
}

// isAlive reports whether the given PID is still a live (non-reaped) process.
// signal 0 performs existence/permission checking without delivering a signal.
func isAlive(pid uint32) bool {
	return syscall.Kill(int(pid), 0) == nil
}

// waitExit waits for cmd to terminate, up to timeout. Returns true if it exited.
func waitExit(cmd *exec.Cmd, timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

func TestKillViaProc(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}

	t.Run("empty comm sends SIGKILL without recheck", func(t *testing.T) {
		cmd, pid := spawnChild(t)

		err := killViaProc(pid, "")
		require.NoError(t, err)

		require.True(t, waitExit(cmd, 2*time.Second), "child should die after SIGKILL")
	})

	t.Run("matching comm kills the process", func(t *testing.T) {
		cmd, pid := spawnChild(t)

		// Read the real comm the kernel recorded for this child.
		data, err := os.ReadFile("/proc/" + itoa(pid) + "/comm")
		require.NoError(t, err)
		realComm := sanitizeComm(trimNL(string(data)))
		require.Equal(t, "sleep", realComm)

		err = killViaProc(pid, realComm)
		require.NoError(t, err)

		require.True(t, waitExit(cmd, 2*time.Second), "child should die after SIGKILL")
	})

	t.Run("wrong comm aborts and process survives", func(t *testing.T) {
		_, pid := spawnChild(t)

		err := killViaProc(pid, "definitely-not-sleep")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "pid reuse detected")

		// Security property: the process must NOT have received SIGKILL.
		// Prove the negative with a short bounded wait.
		time.Sleep(200 * time.Millisecond)
		assert.True(t, isAlive(pid), "process must still be alive after aborted kill")
	})
}

func TestKillViaPidfd(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	if !pidfdSupported {
		t.Skip("pidfd_open not supported on this kernel")
	}

	t.Run("success against real child", func(t *testing.T) {
		cmd, pid := spawnChild(t)

		err := killViaPidfd(pid)
		require.NoError(t, err)

		require.True(t, waitExit(cmd, 2*time.Second), "child should die after pidfd SIGKILL")
	})

	t.Run("stale reaped PID returns error", func(t *testing.T) {
		cmd := exec.Command("sleep", "60")
		require.NoError(t, cmd.Start())
		pid := uint32(cmd.Process.Pid)

		// Kill and fully reap so the PID is stale.
		require.NoError(t, cmd.Process.Kill())
		_ = cmd.Wait()

		err := killViaPidfd(pid)
		require.Error(t, err, "pidfd_open on a reaped PID must fail (ESRCH)")
		assert.Contains(t, err.Error(), "pidfd_open")
	})
}

// newKillEnforcer builds an enforcer with a buffered audit channel we read
// directly (no consumer goroutine) so tests can assert on audit entries.
func newKillEnforcer(t *testing.T) (*Enforcer, chan AuditEntry) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	auditCh := make(chan AuditEntry, 16)
	e, err := NewEnforcer(logger, Config{
		EnableKill:      true,
		AuditLogChannel: auditCh,
	})
	require.NoError(t, err)
	return e, auditCh
}

func readAudit(t *testing.T, ch chan AuditEntry) AuditEntry {
	t.Helper()
	select {
	case entry := <-ch:
		return entry
	case <-time.After(time.Second):
		t.Fatal("expected an audit entry but none arrived")
		return AuditEntry{}
	}
}

func killAlert(pid uint32, comm string) types.Alert {
	var commBytes [16]byte
	copy(commBytes[:], comm)
	return types.Alert{
		RuleID:   "test_kill_rule",
		Severity: types.SeverityCritical,
		Event: types.Event{
			PID:  pid,
			TGID: pid,
			Comm: commBytes,
			UID:  uint32(os.Getuid()),
			Type: types.EventSyscall,
		},
	}
}

func TestExecuteKill_ProcBranch(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}

	t.Run("successful proc kill", func(t *testing.T) {
		orig := pidfdSupported
		pidfdSupported = false
		defer func() { pidfdSupported = orig }()

		e, auditCh := newKillEnforcer(t)
		cmd, pid := spawnChild(t)

		err := e.executeKill(context.Background(), killAlert(pid, "sleep"))
		require.NoError(t, err)

		entry := readAudit(t, auditCh)
		assert.True(t, entry.Success)
		assert.Equal(t, pid, entry.PID)
		require.True(t, waitExit(cmd, 2*time.Second), "child should die")
	})

	t.Run("comm mismatch aborts, process survives, audit failure", func(t *testing.T) {
		orig := pidfdSupported
		pidfdSupported = false
		defer func() { pidfdSupported = orig }()

		e, auditCh := newKillEnforcer(t)
		_, pid := spawnChild(t)

		err := e.executeKill(context.Background(), killAlert(pid, "wrong-comm"))
		require.Error(t, err)

		entry := readAudit(t, auditCh)
		assert.False(t, entry.Success)
		assert.Contains(t, entry.Error, "proc kill:")

		time.Sleep(200 * time.Millisecond)
		assert.True(t, isAlive(pid), "process must survive an aborted kill")
	})

	t.Run("invalid event rejected before any kill", func(t *testing.T) {
		e, auditCh := newKillEnforcer(t)

		// UID above the allowed max makes validateEvent fail, so executeKill
		// must return early without emitting an audit entry.
		alert := killAlert(1234, "sleep")
		alert.Event.UID = 99999

		err := e.executeKill(context.Background(), alert)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidEvent)

		select {
		case entry := <-auditCh:
			t.Fatalf("no audit entry expected on validateEvent failure, got %+v", entry)
		case <-time.After(100 * time.Millisecond):
			// expected: nothing emitted
		}
	})

	t.Run("ValidatePID failure short-circuits", func(t *testing.T) {
		orig := pidfdSupported
		pidfdSupported = false
		defer func() { pidfdSupported = orig }()

		e, auditCh := newKillEnforcer(t)

		// PID is in valid range (passes validateEvent) but does not exist.
		const deadPID = 4000000
		require.Error(t, ValidatePID(deadPID), "test precondition: PID must not exist")

		err := e.executeKill(context.Background(), killAlert(deadPID, "ghost"))
		require.Error(t, err)

		entry := readAudit(t, auditCh)
		assert.False(t, entry.Success)
		assert.Contains(t, entry.Error, "not found")
	})
}

func TestExecuteKill_PidfdBranch(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	if !pidfdSupported {
		t.Skip("pidfd_open not supported on this kernel")
	}

	orig := pidfdSupported
	pidfdSupported = true // document intent explicitly
	defer func() { pidfdSupported = orig }()

	e, auditCh := newKillEnforcer(t)
	cmd, pid := spawnChild(t)

	before := testutil.ToFloat64(e.pidfdUsed)

	err := e.executeKill(context.Background(), killAlert(pid, "sleep"))
	require.NoError(t, err)

	after := testutil.ToFloat64(e.pidfdUsed)
	assert.Equal(t, before+1, after, "pidfd_used counter should increment by exactly 1")

	entry := readAudit(t, auditCh)
	assert.True(t, entry.Success)

	require.True(t, waitExit(cmd, 2*time.Second), "child should die after pidfd kill")
}

// itoa/trimNL: tiny local helpers to avoid importing strconv/strings just for
// two trivial conversions and to keep the test self-contained.
func itoa(n uint32) string {
	if n == 0 {
		return "0"
	}
	var buf [10]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func trimNL(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
