package enforcer

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// syscallAlert builds a non-file alert with a valid PID/UID.
func syscallAlert(ruleID string, pid, uid uint32) types.Alert {
	return types.Alert{
		RuleID: ruleID,
		Event: types.Event{
			PID:  pid,
			UID:  uid,
			Type: types.EventSyscall,
			Comm: [16]byte{'t', 'e', 's', 't'},
		},
	}
}

// ---------------------------------------------------------------------------
// RegisterMetrics
// ---------------------------------------------------------------------------

func TestRegisterMetrics_SuccessAndDuplicate(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()

	e1, err := NewEnforcer(testLogger(), Config{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = e1.Close() })
	require.NoError(t, e1.RegisterMetrics(reg), "first registration succeeds")

	// A second enforcer exposes metrics with identical names; registering into
	// the same registry must collide (real duplicate-collector error).
	e2, err := NewEnforcer(testLogger(), Config{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = e2.Close() })

	err = e2.RegisterMetrics(reg)
	require.Error(t, err, "duplicate metric registration must fail")
	var are prometheus.AlreadyRegisteredError
	assert.ErrorAs(t, err, &are, "expected AlreadyRegisteredError")
}

// ---------------------------------------------------------------------------
// ExecuteAction / Execute default branch
// ---------------------------------------------------------------------------

func TestExecuteAction_DispatchKill(t *testing.T) {
	t.Parallel()

	cmd := exec.Command("sleep", "30")
	require.NoError(t, cmd.Start())
	pid := uint32(cmd.Process.Pid)
	time.Sleep(50 * time.Millisecond)

	e, err := NewEnforcer(testLogger(), Config{EnableKill: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = e.Close() })

	alert := types.Alert{
		RuleID: "k",
		Event: types.Event{
			PID:  pid,
			TGID: pid,
			UID:  uint32(os.Getuid()),
			Comm: [16]byte{'s', 'l', 'e', 'e', 'p'},
		},
	}

	// ExecuteAction takes a plain string and must dispatch to the kill path.
	require.NoError(t, e.ExecuteAction(context.Background(), "kill", alert))

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("process not killed via ExecuteAction")
	}
}

func TestExecuteAction_GarbageIsDisabled(t *testing.T) {
	t.Parallel()
	e, err := NewEnforcer(testLogger(), Config{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = e.Close() })

	// An unknown action name is not in the enabled map, so Execute reports it
	// as disabled before reaching the switch.
	err = e.ExecuteAction(context.Background(), "garbage", syscallAlert("r", 100, 0))
	require.Error(t, err)
	assert.ErrorContains(t, err, "disabled")
}

func TestExecute_UnknownActionType(t *testing.T) {
	t.Parallel()
	e, err := NewEnforcer(testLogger(), Config{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = e.Close() })

	// Force the action to be "enabled" so we reach the switch's default arm.
	const bogus ActionType = "bogus"
	e.enabled[bogus] = true

	err = e.Execute(context.Background(), bogus, syscallAlert("r", 100, 0))
	require.Error(t, err)
	assert.ErrorContains(t, err, "unknown action type")
}

// ---------------------------------------------------------------------------
// executeBlock — real nftables / iptables backends
// ---------------------------------------------------------------------------

// NOTE: nftables uses a process-global "ebpf-guard" table (the table name is
// not parameterised), so nft-backed tests are intentionally NOT parallel.
func TestExecuteBlock_NFTablesReal(t *testing.T) {
	requireRoot(t)
	e, err := NewEnforcer(testLogger(), Config{
		EnableBlock:  true,
		BlockBackend: BlockBackendNFTables,
	})
	require.NoError(t, err)
	require.NotNil(t, e.nftablesMgr, "nftables manager must be initialised")
	t.Cleanup(func() {
		_ = e.Cleanup()
		_ = e.Close()
	})

	const uid = 40001
	require.NoError(t, e.Execute(context.Background(), ActionBlock, syscallAlert("blk", 100, uid)))

	assert.Contains(t, e.nftablesMgr.GetBlockedUIDs(), uint32(uid),
		"UID must be blocked in the real nftables manager")
}

func TestExecuteBlock_IPTablesReal(t *testing.T) {
	requireRoot(t)
	t.Parallel()

	e, err := NewEnforcer(testLogger(), Config{EnableBlock: true, BlockBackend: BlockBackendLog})
	require.NoError(t, err)
	t.Cleanup(func() { _ = e.Close() })

	// Attach an iptables manager with a unique chain so parallel tests never
	// collide on shared netfilter state.
	ipt := newTestIPTables(t)
	e.blockBackend = BlockBackendIPTables
	e.iptablesMgr = ipt

	const uid = 40002
	require.NoError(t, e.Execute(context.Background(), ActionBlock, syscallAlert("blk", 100, uid)))
	assert.Contains(t, ipt.GetBlockedUIDs(), uint32(uid),
		"UID must be blocked in the real iptables manager")
}

// newTestIPTables builds a real iptables manager with a unique chain name and
// registers cleanup that removes the chain.
func newTestIPTables(t *testing.T) *IPTablesManager {
	t.Helper()
	requireRoot(t)
	chain := "EGT-" + sanitizeChain(t.Name())
	ipt, err := NewIPTablesManager(testLogger(), IPTablesConfig{ChainName: chain})
	require.NoError(t, err)
	t.Cleanup(func() { _ = ipt.Cleanup() })
	return ipt
}

// sanitizeChain produces a short, iptables-safe chain suffix from a test name.
func sanitizeChain(name string) string {
	name = strings.NewReplacer("/", "-", " ", "-").Replace(name)
	if len(name) > 22 {
		name = name[len(name)-22:]
	}
	return strings.ToUpper(name)
}

// ---------------------------------------------------------------------------
// executeLSMBlock — all goto-driven branches
// ---------------------------------------------------------------------------

func TestExecuteLSMBlock_InvalidEvent(t *testing.T) {
	t.Parallel()
	e, err := NewEnforcer(testLogger(), Config{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = e.Close() })

	// UID out of range -> validateEvent rejects.
	err = e.Execute(context.Background(), ActionLSMBlock, syscallAlert("r", 100, 99999))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidEvent)
}

func TestExecuteLSMBlock_DryRunNonFile(t *testing.T) {
	t.Parallel()
	f := newFakeLSM(true)
	e, err := NewEnforcer(testLogger(), Config{DryRun: true, LSMManager: f})
	require.NoError(t, err)
	t.Cleanup(func() { _ = e.Close() })

	require.NoError(t, e.Execute(context.Background(), ActionLSMBlock, syscallAlert("r", 555, 0)))
	assert.False(t, f.hasPID(555), "dry-run must not add PID to LSM blocklist")
	assert.Empty(t, f.addPIDCalls)
}

func TestExecuteLSMBlock_LSMSuccess(t *testing.T) {
	t.Parallel()
	f := newFakeLSM(true)
	e, err := NewEnforcer(testLogger(), Config{LSMManager: f})
	require.NoError(t, err)
	t.Cleanup(func() { _ = e.Close() })

	require.NoError(t, e.Execute(context.Background(), ActionLSMBlock, syscallAlert("r", 777, 0)))
	assert.True(t, f.hasPID(777), "PID must be added to the LSM blocklist on success")
}

func TestExecuteLSMBlock_FileEventUsesPathBlocklist(t *testing.T) {
	t.Parallel()
	f := newFakeLSM(true)
	e, err := NewEnforcer(testLogger(), Config{LSMManager: f})
	require.NoError(t, err)
	t.Cleanup(func() { _ = e.Close() })

	alert := fileAlert("r", "/etc/shadow", 100, 0)
	require.NoError(t, e.Execute(context.Background(), ActionLSMBlock, alert))

	// Must use the PATH-based method, not the PID-based one.
	assert.True(t, f.hasPath("/etc/shadow"), "path must be blocked")
	assert.Empty(t, f.addPIDCalls, "file-access events must not touch PID blocklist")
}

func TestExecuteLSMBlock_FileEventNoManager(t *testing.T) {
	t.Parallel()
	// No LSM manager, not dry-run: file path block cannot proceed and returns
	// an error (there is no nftables fallback for file-access events).
	e, err := NewEnforcer(testLogger(), Config{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = e.Close() })

	alert := fileAlert("r", "/etc/shadow", 100, 0)
	err = e.Execute(context.Background(), ActionLSMBlock, alert)
	require.Error(t, err)
	assert.ErrorContains(t, err, "LSM not available")
}

// nft fallback: LSM available but AddToBlocklist fails -> nftables blocks UID.
func TestExecuteLSMBlock_NFTablesFallbackOnLSMError(t *testing.T) {
	requireRoot(t)
	f := newFakeLSM(true)
	f.addErr = fmt.Errorf("bpf map insert failed")

	e, err := NewEnforcer(testLogger(), Config{
		EnableBlock:  true,
		BlockBackend: BlockBackendNFTables,
		LSMManager:   f,
	})
	require.NoError(t, err)
	require.NotNil(t, e.nftablesMgr)
	t.Cleanup(func() {
		_ = e.Cleanup()
		_ = e.Close()
	})

	const uid = 40010
	require.NoError(t, e.Execute(context.Background(), ActionLSMBlock, syscallAlert("r", 100, uid)),
		"fallback to nftables must succeed")
	assert.Contains(t, f.addPIDCalls, uint32(100), "LSM add was attempted first")
	assert.Contains(t, e.nftablesMgr.GetBlockedUIDs(), uint32(uid),
		"UID must end up blocked in the real nftables manager via fallback")
}

// iptables fallback: LSM unavailable -> iptables blocks UID.
func TestExecuteLSMBlock_IPTablesFallbackWhenUnavailable(t *testing.T) {
	requireRoot(t)
	t.Parallel()
	f := newFakeLSM(false) // unavailable

	e, err := NewEnforcer(testLogger(), Config{LSMManager: f})
	require.NoError(t, err)
	t.Cleanup(func() { _ = e.Close() })

	ipt := newTestIPTables(t)
	e.iptablesMgr = ipt

	const uid = 40011
	require.NoError(t, e.Execute(context.Background(), ActionLSMBlock, syscallAlert("r", 100, uid)))
	assert.Empty(t, f.addPIDCalls, "unavailable LSM must be skipped entirely")
	assert.Contains(t, ipt.GetBlockedUIDs(), uint32(uid),
		"UID must be blocked via iptables fallback")
}

func TestExecuteLSMBlock_NoBackendAvailable(t *testing.T) {
	t.Parallel()
	// LSM nil/unavailable and no nftables/iptables managers.
	e, err := NewEnforcer(testLogger(), Config{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = e.Close() })

	err = e.Execute(context.Background(), ActionLSMBlock, syscallAlert("r", 100, 0))
	require.Error(t, err)
	assert.ErrorContains(t, err, "no blocking backend available")
}

// SetLSMManager wires a manager in after construction and must be honoured.
func TestSetLSMManager_Integration(t *testing.T) {
	t.Parallel()
	e, err := NewEnforcer(testLogger(), Config{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = e.Close() })

	// Before: no LSM, no fallback -> error.
	err = e.Execute(context.Background(), ActionLSMBlock, syscallAlert("r", 321, 0))
	require.Error(t, err)

	f := newFakeLSM(true)
	e.SetLSMManager(f)

	// After: LSM present -> PID blocked.
	require.NoError(t, e.Execute(context.Background(), ActionLSMBlock, syscallAlert("r", 321, 0)))
	assert.True(t, f.hasPID(321), "SetLSMManager-installed manager must be used")
}

// ---------------------------------------------------------------------------
// executeThrottle / cgroup helpers
// ---------------------------------------------------------------------------

func TestExecuteThrottle_InvalidEvent(t *testing.T) {
	t.Parallel()
	e, err := NewEnforcer(testLogger(), Config{EnableThrottle: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = e.Close() })

	err = e.Execute(context.Background(), ActionThrottle, syscallAlert("r", 0, 0)) // PID 0 invalid
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidEvent)
}

// cgroupWritePath returns the file applyCgroupThrottle would write to for the
// current process, and whether the enclosing directory is writable.
func cgroupWritePath(t *testing.T, e *Enforcer) string {
	t.Helper()
	p, err := e.findCgroupPath(uint32(os.Getpid()))
	require.NoError(t, err)
	return filepath.Join(p, "cpu.max")
}

// NOTE: applyCgroupThrottle writes to a process-global cgroup path
// (/sys/fs/cgroup/.../cpu.max). These tests are NOT parallel and clean up any
// file they may create so they never overlap or leak state.
func TestExecuteThrottle_WritesCgroupCPUMax(t *testing.T) {
	requireRoot(t)
	e, err := NewEnforcer(testLogger(), Config{EnableThrottle: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = e.Close() })

	pid := uint32(os.Getpid())
	target := cgroupWritePath(t, e)

	// In this container /sys/fs/cgroup is a tmpfs, so the write succeeds. Assert
	// the real resulting file content matches the throttle quota/period, then
	// remove the file we created.
	existedBefore := fileExists(target)
	t.Cleanup(func() {
		if !existedBefore {
			_ = os.Remove(target)
		}
	})

	require.NoError(t, e.Execute(context.Background(), ActionThrottle, syscallAlert("r", pid, 0)))

	st := e.GetThrottleState(pid)
	require.NotNil(t, st, "throttle state must be recorded")
	assert.Equal(t, 1, st.Count)
	assert.Equal(t, pid, st.PID)

	// Default ThrottleCPUPercent is 10 -> quota = 100000*10/100 = 10000.
	data, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, "10000 100000\n", string(data), "cpu.max content must match quota/period")
}

// TestExecuteThrottle_DryRun is the regression test for №52: dry_run must
// gate executeThrottle before the cgroup cpu.max write, the actual syscall.
func TestExecuteThrottle_DryRun(t *testing.T) {
	requireRoot(t)
	e, err := NewEnforcer(testLogger(), Config{EnableThrottle: true, DryRun: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = e.Close() })

	pid := uint32(os.Getpid())
	target := cgroupWritePath(t, e)
	existedBefore := fileExists(target)
	var mtimeBefore time.Time
	if existedBefore {
		info, statErr := os.Stat(target)
		require.NoError(t, statErr)
		mtimeBefore = info.ModTime()
	}

	before := testutil.ToFloat64(e.actionsTotal.WithLabelValues("throttle"))
	beforeDryrun := testutil.ToFloat64(e.dryrunTotal.WithLabelValues("throttle"))

	require.NoError(t, e.Execute(context.Background(), ActionThrottle, syscallAlert("r", pid, 0)))

	after := testutil.ToFloat64(e.actionsTotal.WithLabelValues("throttle"))
	afterDryrun := testutil.ToFloat64(e.dryrunTotal.WithLabelValues("throttle"))
	assert.Equal(t, before, after, "enforcement_actions_total{throttle} must not increase under dry_run")
	assert.Equal(t, beforeDryrun+1, afterDryrun, "enforcement_dryrun_total{throttle} must increase by exactly 1")

	// cpu.max must be untouched: either still absent, or unmodified.
	if existedBefore {
		info, statErr := os.Stat(target)
		require.NoError(t, statErr)
		assert.Equal(t, mtimeBefore, info.ModTime(), "cpu.max must not be rewritten under dry_run")
	} else {
		assert.False(t, fileExists(target), "cpu.max must not be created under dry_run")
	}
}

func TestFindCgroupPath(t *testing.T) {
	t.Parallel()
	e, err := NewEnforcer(testLogger(), Config{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = e.Close() })

	// Real PID (ourselves) resolves to a path under the cgroup mount.
	path, err := e.findCgroupPath(uint32(os.Getpid()))
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(path, "/sys/fs/cgroup"),
		"cgroup path must live under the cgroup mount, got %q", path)

	// Nonexistent PID -> read error.
	_, err = e.findCgroupPath(999999)
	require.Error(t, err)
	assert.ErrorContains(t, err, "read cgroup file")
}

func TestApplyCgroupThrottle(t *testing.T) {
	requireRoot(t)
	e, err := NewEnforcer(testLogger(), Config{ThrottleCPUPercent: 25})
	require.NoError(t, err)
	t.Cleanup(func() { _ = e.Close() })

	target := cgroupWritePath(t, e)
	existedBefore := fileExists(target)
	t.Cleanup(func() {
		if !existedBefore {
			_ = os.Remove(target)
		}
	})

	// Writable tmpfs path -> success; assert the quota reflects 25%.
	require.NoError(t, e.applyCgroupThrottle(uint32(os.Getpid())))
	data, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, "25000 100000\n", string(data), "quota must be 25%% of the period")

	// Nonexistent PID -> find-path error path.
	err = e.applyCgroupThrottle(999999)
	require.Error(t, err)
	assert.ErrorContains(t, err, "find cgroup path")
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func TestRemoveThrottle(t *testing.T) {
	t.Parallel()
	e, err := NewEnforcer(testLogger(), Config{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = e.Close() })

	e.mu.Lock()
	e.throttles[4242] = &ThrottleState{PID: 4242, LastThrottle: time.Now()}
	e.mu.Unlock()
	require.NotNil(t, e.GetThrottleState(4242))

	e.RemoveThrottle(4242)
	assert.Nil(t, e.GetThrottleState(4242))
}

// ---------------------------------------------------------------------------
// logAudit — success and dropped-entry branches
// ---------------------------------------------------------------------------

func TestLogAudit_DeliversEntry(t *testing.T) {
	t.Parallel()
	ch := make(chan AuditEntry, 1)
	e, err := NewEnforcer(testLogger(), Config{AuditLogChannel: ch})
	require.NoError(t, err)
	t.Cleanup(func() { _ = e.Close() })

	entry := AuditEntry{Action: ActionKill, PID: 9}
	e.logAudit(entry)

	select {
	case got := <-ch:
		assert.Equal(t, uint32(9), got.PID)
		assert.Equal(t, ActionKill, got.Action)
	default:
		t.Fatal("audit entry was not delivered to the channel")
	}
	assert.Equal(t, 0.0, testutil.ToFloat64(e.auditDropped), "no drop on successful send")
}

func TestLogAudit_DropsWhenChannelFull(t *testing.T) {
	t.Parallel()
	// Unbuffered channel with no reader -> the select's default arm fires.
	ch := make(chan AuditEntry)
	e, err := NewEnforcer(testLogger(), Config{AuditLogChannel: ch})
	require.NoError(t, err)
	t.Cleanup(func() { _ = e.Close() })

	before := testutil.ToFloat64(e.auditDropped)
	e.logAudit(AuditEntry{Action: ActionBlock, PID: 7}) // must not block/panic
	after := testutil.ToFloat64(e.auditDropped)
	assert.Equal(t, before+1, after, "auditDropped counter must increment by exactly 1")
}

// ---------------------------------------------------------------------------
// Cleanup / Close
// ---------------------------------------------------------------------------

func TestCleanup_ClearsBlockedState(t *testing.T) {
	requireRoot(t)
	t.Parallel()
	e, err := NewEnforcer(testLogger(), Config{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = e.Close() })

	ipt := newTestIPTables(t)
	e.iptablesMgr = ipt
	require.NoError(t, ipt.BlockUID(context.Background(), 40020))
	require.Contains(t, ipt.GetBlockedUIDs(), uint32(40020))

	require.NoError(t, e.Cleanup())
	assert.Empty(t, ipt.GetBlockedUIDs(), "Cleanup must empty the blocked-UID set")
}

func TestClose_StopsGoroutineAndClosesManagers(t *testing.T) {
	requireRoot(t)
	t.Parallel()
	e, err := NewEnforcer(testLogger(), Config{})
	require.NoError(t, err)

	ipt := newTestIPTables(t)
	e.iptablesMgr = ipt

	// Close must not hang (stops the cleanup goroutine) and returns nil.
	require.NoError(t, e.Close())
	// Second close is safe (stopCleanup cancel is idempotent).
	require.NoError(t, e.Close())
}

// ---------------------------------------------------------------------------
// Parsers / simple accessors
// ---------------------------------------------------------------------------

func TestParseBlockBackend(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in      string
		want    BlockBackend
		wantErr bool
	}{
		{"log", BlockBackendLog, false},
		{"nftables", BlockBackendNFTables, false},
		{"iptables", BlockBackendIPTables, false},
		{"xdp", BlockBackendXDP, false},
		{"bogus", "", true},
		{"", "", true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			got, err := ParseBlockBackend(tt.in)
			if tt.wantErr {
				require.Error(t, err)
				assert.ErrorContains(t, err, "unknown block backend")
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

// allDestructiveActionTypes lists every ActionType wired into Execute's
// switch (excluding ActionLog, which is never routed through Execute — the
// correlator handles "log" as a no-op locally). Any new ActionType constant
// that performs enforcement MUST be added here, or this sentinel fails
// closed via the "unknown action type" branch of Execute instead of
// silently reaching the stand as an unguarded destructive action (№52/№53).
var allDestructiveActionTypes = []ActionType{
	ActionBlock,
	ActionLSMBlock,
	ActionKill,
	ActionThrottle,
	ActionNetworkPolicy,
}

// actionsRequiringExplicitDryRunGate are the ActionTypes whose handler must
// itself account for dry_run: leave an AuditEntry with DryRun=true, count
// enforcement_dryrun_total, and never touch enforcement_actions_total, the
// counter that means "a real action happened".
//
// Originally (5.9.4a) this listed only kill and throttle — the two that reach
// a raw OS syscall — on the assumption that every other handler delegates to
// a manager constructed with the same Config.DryRun. Review of that wave found
// the assumption false for networkpolicy: NetworkPolicyCfg has no DryRun field
// at all, so in mode "apply" with an Applier set the handler would create a
// real NetworkPolicy in the cluster while enforcer.dry_run was true — #52 in a
// second location. All five are listed now, and the accounting requirement is
// the same for all of them regardless of who suppresses the side effect.
var actionsRequiringExplicitDryRunGate = []ActionType{
	ActionKill,
	ActionThrottle,
	ActionBlock,
	ActionLSMBlock,
	ActionNetworkPolicy,
}

// TestDryRunSentinel_AllActionTypesRouteThroughExecute guards against a new
// ActionType being added to the const block without being wired into
// Execute's switch — see №52/5.9.4a. If this fails after adding an action,
// add the missing `case` in Execute (enforcer.go) and, if the action
// reaches a syscall directly, add it to actionsRequiringExplicitDryRunGate
// below and give it a dry-run branch before the syscall.
func TestDryRunSentinel_AllActionTypesRouteThroughExecute(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only: ValidatePID/killViaPidfd read /proc")
	}
	f := newFakeLSM(true)
	e, err := NewEnforcer(testLogger(), Config{
		EnableBlock:    true,
		EnableKill:     true,
		EnableThrottle: true,
		BlockBackend:   BlockBackendLog, // no real network side effect
		DryRun:         true,
		LSMManager:     f,
		NetworkPolicy:  NetworkPolicyCfg{Enabled: true}, // default "suggest" mode: no apply side effect
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = e.Close() })

	// Use a disposable child, never the test process itself: if the dry-run
	// gate under test is broken, ActionKill would send a real SIGKILL.
	_, pid := spawnChild(t)

	for _, action := range allDestructiveActionTypes {
		t.Run(string(action), func(t *testing.T) {
			err := e.Execute(context.Background(), action, syscallAlert("sentinel", pid, 0))
			require.NoError(t, err, "action %s must be routed through Execute, not fall into the default branch", action)
		})
	}

	assert.Empty(t, f.addPIDCalls, "dry_run must never reach the LSM blocklist")
	assert.True(t, isAlive(pid), "dry_run must never actually kill the target process")
}

// TestDryRunSentinel_SyscallActionsGateBeforeEffect is the machine-checked
// version of the 5.9.4a requirement: every action in
// actionsRequiringExplicitDryRunGate must produce a DryRun=true audit entry
// and must not increment enforcement_actions_total under dry_run. A new
// syscall-reaching action added to that list without a dry-run branch fails
// here instead of on the live stand.
func TestDryRunSentinel_SyscallActionsGateBeforeEffect(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only: ValidatePID/killViaPidfd read /proc")
	}
	for _, action := range actionsRequiringExplicitDryRunGate {
		t.Run(string(action), func(t *testing.T) {
			auditCh := make(chan AuditEntry, 4)
			applier := &fakePolicyApplier{}
			lsm := newFakeLSM(true)
			e, err := NewEnforcer(testLogger(), Config{
				EnableKill:      true,
				EnableThrottle:  true,
				EnableBlock:     true,
				BlockBackend:    BlockBackendLog,
				LSMManager:      lsm,
				DryRun:          true,
				AuditLogChannel: auditCh,
				// Apply mode with a live applier: the only configuration in
				// which the networkpolicy handler has a real side effect to
				// suppress. Testing it in the default "suggest" mode would
				// pass with no gate at all — which is how the gap survived
				// wave 5.9.4a.
				NetworkPolicy: NetworkPolicyCfg{
					Enabled: true,
					Mode:    NetworkPolicyModeApply,
					Applier: applier,
				},
			})
			require.NoError(t, err)
			t.Cleanup(func() { _ = e.Close() })

			// Use a disposable child, never the test process itself: if the
			// dry-run gate under test is broken, ActionKill would send a
			// real SIGKILL.
			_, pid := spawnChild(t)

			label := string(action)
			before := testutil.ToFloat64(e.actionsTotal.WithLabelValues(label))
			dryBefore := testutil.ToFloat64(e.dryrunTotal.WithLabelValues(label))

			require.NoError(t, e.Execute(context.Background(), action, syscallAlert("sentinel", pid, 0)))

			after := testutil.ToFloat64(e.actionsTotal.WithLabelValues(label))
			assert.Equal(t, before, after, "enforcement_actions_total{%s} must not increase under dry_run", label)
			assert.Equal(t, float64(dryBefore+1), testutil.ToFloat64(e.dryrunTotal.WithLabelValues(label)),
				"enforcement_dryrun_total{%s} must record the suppressed action", label)

			select {
			case entry := <-auditCh:
				assert.True(t, entry.DryRun, "audit entry for %s under dry_run must have DryRun=true", label)
				assert.False(t, entry.Success, "a suppressed action must not be audited as successful (%s)", label)
			case <-time.After(time.Second):
				t.Fatalf("expected an audit entry for %s but none arrived", label)
			}

			assert.True(t, isAlive(pid), "dry_run must never actually act on the target process")
			assert.Empty(t, applier.applied, "dry_run must never apply a NetworkPolicy to the cluster")
			assert.Empty(t, lsm.addPIDCalls, "dry_run must never reach the LSM blocklist")
		})
	}
}

func TestIsDryRun(t *testing.T) {
	t.Parallel()
	dry, err := NewEnforcer(testLogger(), Config{DryRun: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = dry.Close() })
	assert.True(t, dry.IsDryRun())

	wet, err := NewEnforcer(testLogger(), Config{DryRun: false})
	require.NoError(t, err)
	t.Cleanup(func() { _ = wet.Close() })
	assert.False(t, wet.IsDryRun())
}

// ---------------------------------------------------------------------------
// verifyPIDComm / GetProcessStartTime
// ---------------------------------------------------------------------------

func TestVerifyPIDComm(t *testing.T) {
	t.Parallel()
	pid := uint32(os.Getpid())
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	require.NoError(t, err)
	comm := sanitizeComm(strings.TrimRight(string(raw), "\n"))

	// Match.
	assert.NoError(t, verifyPIDComm(pid, comm))

	// Mismatch (PID reuse detected).
	err = verifyPIDComm(pid, "definitely-not-the-comm")
	require.Error(t, err)
	assert.ErrorContains(t, err, "comm changed")

	// Vanished process.
	err = verifyPIDComm(999999, comm)
	require.Error(t, err)
	assert.ErrorContains(t, err, "vanished")
}

func TestGetProcessStartTime(t *testing.T) {
	t.Parallel()
	ts, err := GetProcessStartTime(uint32(os.Getpid()))
	require.NoError(t, err)
	assert.False(t, ts.IsZero(), "real process must have a non-zero start time")

	_, err = GetProcessStartTime(999999)
	require.Error(t, err)
}
