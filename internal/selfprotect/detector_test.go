package selfprotect

import (
	"os"
	"sync"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureAlertSink collects alerts sent to it for assertion in tests.
type captureAlertSink struct {
	mu     sync.Mutex
	alerts []types.Alert
}

func (c *captureAlertSink) SendAlert(a types.Alert) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.alerts = append(c.alerts, a)
}

func (c *captureAlertSink) Alerts() []types.Alert {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]types.Alert, len(c.alerts))
	copy(out, c.alerts)
	return out
}

func (c *captureAlertSink) Count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.alerts)
}

// mkBPFEvent constructs a minimal EventBPFProgram event for tests.
func mkBPFEvent(pid uint32, cmd uint32, ret int32) types.Event {
	var comm [16]byte
	copy(comm[:], "bpftool")
	return types.Event{
		Type:       types.EventBPFProgram,
		Timestamp:  uint64(time.Now().UnixNano()),
		PID:        pid,
		Comm:       comm,
		BPFProgram: &types.BPFProgramEvent{Cmd: cmd, Ret: ret},
	}
}

// ─── IsTamperingCmd ──────────────────────────────────────────────────────────

func TestIsTamperingCmd(t *testing.T) {
	cases := []struct {
		cmd     uint32
		wantDangerous bool
	}{
		{types.BPFCmdMapUpdate, true},
		{types.BPFCmdMapDelete, true},
		{types.BPFCmdProgDetach, true},
		{types.BPFCmdProgLoad, false},
		{types.BPFCmdMapCreate, false},
		{types.BPFCmdObjPin, false},
		{types.BPFCmdObjGet, false},
		{types.BPFCmdProgAttach, false},
		{99, false},
	}
	for _, tc := range cases {
		got := IsTamperingCmd(tc.cmd)
		assert.Equal(t, tc.wantDangerous, got, "cmd=%d", tc.cmd)
	}
}

func TestTamperingCmdName(t *testing.T) {
	assert.Equal(t, "BPF_MAP_UPDATE_ELEM", TamperingCmdName(types.BPFCmdMapUpdate))
	assert.Equal(t, "BPF_MAP_DELETE_ELEM", TamperingCmdName(types.BPFCmdMapDelete))
	assert.Equal(t, "BPF_PROG_DETACH", TamperingCmdName(types.BPFCmdProgDetach))
	assert.Equal(t, "", TamperingCmdName(types.BPFCmdProgLoad))
	assert.Equal(t, "", TamperingCmdName(99))
}

// ─── OwnedObjects ────────────────────────────────────────────────────────────

func TestOwnedObjects_ProgramIDs(t *testing.T) {
	o := NewOwnedObjects()
	assert.Equal(t, 0, o.ProgramCount())

	o.AddProgramID(10)
	o.AddProgramID(20)
	assert.Equal(t, 2, o.ProgramCount())
	assert.True(t, o.HasProgramID(10))
	assert.True(t, o.HasProgramID(20))
	assert.False(t, o.HasProgramID(99))

	o.RemoveProgramID(10)
	assert.False(t, o.HasProgramID(10))
	assert.Equal(t, 1, o.ProgramCount())
}

func TestOwnedObjects_MapIDs(t *testing.T) {
	o := NewOwnedObjects()
	assert.Equal(t, 0, o.MapCount())

	o.AddMapID(100)
	o.AddMapID(200)
	assert.Equal(t, 2, o.MapCount())
	assert.True(t, o.HasMapID(100))
	assert.False(t, o.HasMapID(99))

	o.RemoveMapID(100)
	assert.False(t, o.HasMapID(100))
	assert.Equal(t, 1, o.MapCount())
}

func TestOwnedObjects_PinPaths(t *testing.T) {
	o := NewOwnedObjects()

	o.AddPinPath("/sys/fs/bpf/ebpf-guard/syscall")
	o.AddPinPath("/sys/fs/bpf/ebpf-guard/network")

	assert.True(t, o.HasPinPath("/sys/fs/bpf/ebpf-guard/syscall"))
	assert.True(t, o.HasPinPath("/sys/fs/bpf/ebpf-guard/network"))
	assert.False(t, o.HasPinPath("/sys/fs/bpf/other/prog"))
}

func TestOwnedObjects_Concurrent(t *testing.T) {
	o := NewOwnedObjects()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id uint32) {
			defer wg.Done()
			o.AddProgramID(id)
			_ = o.HasProgramID(id)
			o.RemoveProgramID(id)
		}(uint32(i)) //nolint:gosec
	}
	wg.Wait()
}

// ─── AgentAllowlist ───────────────────────────────────────────────────────────

func TestAgentAllowlist_SelfPIDPreseeded(t *testing.T) {
	a := NewAgentAllowlist()
	selfPID := uint32(os.Getpid()) /* #nosec G115 -- Linux PIDs always fit in uint32 */
	assert.True(t, a.IsPIDAllowed(selfPID), "own PID must be pre-seeded")
	assert.Equal(t, 1, a.Count())
}

func TestAgentAllowlist_AddRemove(t *testing.T) {
	a := NewAgentAllowlist()
	a.AddPID(1234)
	assert.True(t, a.IsPIDAllowed(1234))
	assert.Equal(t, 2, a.Count())

	a.RemovePID(1234)
	assert.False(t, a.IsPIDAllowed(1234))
	assert.Equal(t, 1, a.Count())
}

func TestAgentAllowlist_UnknownPID(t *testing.T) {
	a := NewAgentAllowlist()
	assert.False(t, a.IsPIDAllowed(99999))
}

func TestAgentAllowlist_Concurrent(t *testing.T) {
	a := NewAgentAllowlist()
	var wg sync.WaitGroup
	for i := uint32(1); i <= 100; i++ {
		wg.Add(1)
		go func(pid uint32) {
			defer wg.Done()
			a.AddPID(pid)
			_ = a.IsPIDAllowed(pid)
			a.RemovePID(pid)
		}(i)
	}
	wg.Wait()
}

// ─── NewDetector ─────────────────────────────────────────────────────────────

func TestNewDetector_Defaults(t *testing.T) {
	d := NewDetector(Config{Enabled: true}, nil)
	assert.True(t, d.IsEnabled())
	assert.False(t, d.IsEnforceMode())
	assert.Equal(t, types.SeverityCritical, d.cfg.AlertSeverity)
	assert.NotNil(t, d.OwnedObjects())
	assert.NotNil(t, d.Allowlist())
}

func TestNewDetector_ExtraAgentPIDs(t *testing.T) {
	d := NewDetector(Config{
		Enabled:        true,
		ExtraAgentPIDs: []uint32{1111, 2222},
	}, nil)
	assert.True(t, d.Allowlist().IsPIDAllowed(1111))
	assert.True(t, d.Allowlist().IsPIDAllowed(2222))
	assert.False(t, d.Allowlist().IsPIDAllowed(9999))
}

func TestNewDetector_CustomSeverity(t *testing.T) {
	d := NewDetector(Config{Enabled: true, AlertSeverity: types.SeverityWarning}, nil)
	assert.Equal(t, types.SeverityWarning, d.cfg.AlertSeverity)
}

func TestNewDetector_EnforceMode(t *testing.T) {
	d := NewDetector(Config{Enabled: true, EnforceMode: true}, nil)
	assert.True(t, d.IsEnforceMode())
}

// ─── ProcessEvent — disabled detector ─────────────────────────────────────────

func TestDetector_ProcessEvent_WhenDisabled(t *testing.T) {
	sink := &captureAlertSink{}
	d := NewDetector(Config{Enabled: false}, sink)

	alert := d.ProcessEvent(mkBPFEvent(9999, types.BPFCmdProgDetach, -1))
	assert.Nil(t, alert, "disabled detector must return nil")
	assert.Equal(t, 0, sink.Count())
}

// ─── ProcessEvent — non-BPF events ──────────────────────────────────────────

func TestDetector_ProcessEvent_NonBPFEvent(t *testing.T) {
	sink := &captureAlertSink{}
	d := NewDetector(Config{Enabled: true}, sink)

	syscallEvt := types.Event{
		Type: types.EventSyscall,
		PID:  9999,
		BPFProgram: nil,
	}
	assert.Nil(t, d.ProcessEvent(syscallEvt))
	assert.Equal(t, 0, sink.Count())
}

func TestDetector_ProcessEvent_NilBPFProgram(t *testing.T) {
	sink := &captureAlertSink{}
	d := NewDetector(Config{Enabled: true}, sink)

	evt := types.Event{Type: types.EventBPFProgram, PID: 9999, BPFProgram: nil}
	assert.Nil(t, d.ProcessEvent(evt))
	assert.Equal(t, 0, sink.Count())
}

// ─── ProcessEvent — non-dangerous commands ───────────────────────────────────

func TestDetector_ProcessEvent_ProgLoad_NotDangerous(t *testing.T) {
	sink := &captureAlertSink{}
	d := NewDetector(Config{Enabled: true}, sink)

	// BPF_PROG_LOAD from an external PID should not fire (not a tamper command).
	alert := d.ProcessEvent(mkBPFEvent(9999, types.BPFCmdProgLoad, 5))
	assert.Nil(t, alert)
	assert.Equal(t, 0, sink.Count())
}

func TestDetector_ProcessEvent_MapCreate_NotDangerous(t *testing.T) {
	sink := &captureAlertSink{}
	d := NewDetector(Config{Enabled: true}, sink)

	alert := d.ProcessEvent(mkBPFEvent(9999, types.BPFCmdMapCreate, 5))
	assert.Nil(t, alert)
	assert.Equal(t, 0, sink.Count())
}

// ─── ProcessEvent — tamper detection ─────────────────────────────────────────

func TestDetector_ProcessEvent_ProgDetach_External(t *testing.T) {
	sink := &captureAlertSink{}
	d := NewDetector(Config{Enabled: true}, sink)

	alert := d.ProcessEvent(mkBPFEvent(9999, types.BPFCmdProgDetach, 0))

	require.NotNil(t, alert, "tamper attempt must generate an alert")
	assert.Equal(t, "self_protection_001", alert.RuleID)
	assert.Equal(t, types.SeverityCritical, alert.Severity)
	assert.Equal(t, uint32(9999), alert.PID)
	assert.Contains(t, alert.Message, "BPF_PROG_DETACH")
	assert.Contains(t, alert.Message, "9999")

	require.Equal(t, 1, sink.Count())
	sentAlert := sink.Alerts()[0]
	assert.Equal(t, alert.ID, sentAlert.ID)
}

func TestDetector_ProcessEvent_MapUpdate_External(t *testing.T) {
	sink := &captureAlertSink{}
	d := NewDetector(Config{Enabled: true}, sink)

	alert := d.ProcessEvent(mkBPFEvent(5555, types.BPFCmdMapUpdate, 0))

	require.NotNil(t, alert)
	assert.Equal(t, types.SeverityCritical, alert.Severity)
	assert.Contains(t, alert.Message, "BPF_MAP_UPDATE_ELEM")
	assert.Equal(t, 1, sink.Count())
}

func TestDetector_ProcessEvent_MapDelete_External(t *testing.T) {
	sink := &captureAlertSink{}
	d := NewDetector(Config{Enabled: true}, sink)

	alert := d.ProcessEvent(mkBPFEvent(7777, types.BPFCmdMapDelete, 0))

	require.NotNil(t, alert)
	assert.Contains(t, alert.Message, "BPF_MAP_DELETE_ELEM")
	assert.Equal(t, 1, sink.Count())
}

// ─── ProcessEvent — allowlist: agent's own operations must pass ───────────────

func TestDetector_ProcessEvent_OwnPID_Allowed(t *testing.T) {
	sink := &captureAlertSink{}
	d := NewDetector(Config{Enabled: true}, sink)

	// Use our own PID — should never be flagged as tampering.
	selfPID := uint32(os.Getpid()) /* #nosec G115 -- Linux PIDs always fit in uint32 */
	alert := d.ProcessEvent(mkBPFEvent(selfPID, types.BPFCmdProgDetach, 0))

	assert.Nil(t, alert, "agent's own PID must not generate a tamper alert")
	assert.Equal(t, 0, sink.Count())
}

func TestDetector_ProcessEvent_ExtraPID_Allowed(t *testing.T) {
	sink := &captureAlertSink{}
	d := NewDetector(Config{
		Enabled:        true,
		ExtraAgentPIDs: []uint32{42},
	}, sink)

	// PID 42 is allowed (e.g., a new agent process during upgrade).
	alert := d.ProcessEvent(mkBPFEvent(42, types.BPFCmdProgDetach, 0))
	assert.Nil(t, alert)
	assert.Equal(t, 0, sink.Count())
}

func TestDetector_ProcessEvent_DynamicAllowlist(t *testing.T) {
	sink := &captureAlertSink{}
	d := NewDetector(Config{Enabled: true}, sink)

	const upgradePID uint32 = 88888

	// Before adding: should be flagged.
	alert := d.ProcessEvent(mkBPFEvent(upgradePID, types.BPFCmdProgDetach, 0))
	require.NotNil(t, alert)

	// Add the upgrade PID to the allowlist (simulating upgrade start).
	d.Allowlist().AddPID(upgradePID)

	// Same PID now allowed.
	sink.mu.Lock()
	sink.alerts = nil
	sink.mu.Unlock()

	alert2 := d.ProcessEvent(mkBPFEvent(upgradePID, types.BPFCmdProgDetach, 0))
	assert.Nil(t, alert2)
	assert.Equal(t, 0, sink.Count())

	// After upgrade: remove from allowlist again.
	d.Allowlist().RemovePID(upgradePID)
	alert3 := d.ProcessEvent(mkBPFEvent(upgradePID, types.BPFCmdProgDetach, 0))
	require.NotNil(t, alert3)
}

// ─── ProcessEvent — alert contents ───────────────────────────────────────────

func TestDetector_Alert_Details(t *testing.T) {
	sink := &captureAlertSink{}
	d := NewDetector(Config{Enabled: true, EnforceMode: true}, sink)

	evt := mkBPFEvent(9999, types.BPFCmdProgDetach, -1)
	alert := d.ProcessEvent(evt)

	require.NotNil(t, alert)
	assert.Equal(t, "BPF_PROG_DETACH", alert.Details["bpf_cmd"])
	assert.Equal(t, types.BPFCmdProgDetach, alert.Details["cmd_number"])
	assert.Equal(t, true, alert.Details["enforce_mode"])
	assert.Equal(t, int32(-1), alert.Details["ret"])
	assert.NotEmpty(t, alert.ID)
	assert.WithinDuration(t, time.Now(), alert.Timestamp, 5*time.Second)
}

func TestDetector_Alert_CommField(t *testing.T) {
	sink := &captureAlertSink{}
	d := NewDetector(Config{Enabled: true}, sink)

	var comm [16]byte
	copy(comm[:], "bpftool\x00")
	evt := types.Event{
		Type:       types.EventBPFProgram,
		PID:        8888,
		Comm:       comm,
		Timestamp:  uint64(time.Now().UnixNano()),
		BPFProgram: &types.BPFProgramEvent{Cmd: types.BPFCmdProgDetach},
	}
	alert := d.ProcessEvent(evt)

	require.NotNil(t, alert)
	assert.Equal(t, "bpftool", alert.Comm)
	assert.Contains(t, alert.Message, "bpftool")
}

func TestDetector_Alert_WarningSeverity(t *testing.T) {
	sink := &captureAlertSink{}
	d := NewDetector(Config{
		Enabled:       true,
		AlertSeverity: types.SeverityWarning,
	}, sink)

	alert := d.ProcessEvent(mkBPFEvent(9999, types.BPFCmdProgDetach, 0))
	require.NotNil(t, alert)
	assert.Equal(t, types.SeverityWarning, alert.Severity)
}

func TestDetector_Alert_RuleName(t *testing.T) {
	sink := &captureAlertSink{}
	d := NewDetector(Config{Enabled: true}, sink)
	alert := d.ProcessEvent(mkBPFEvent(9999, types.BPFCmdProgDetach, 0))
	require.NotNil(t, alert)
	assert.Equal(t, "BPF Anti-Tampering", alert.RuleName)
}

// ─── ProcessEvent — nil sink ─────────────────────────────────────────────────

func TestDetector_NilSink_DoesNotPanic(t *testing.T) {
	d := NewDetector(Config{Enabled: true}, nil)
	alert := d.ProcessEvent(mkBPFEvent(9999, types.BPFCmdProgDetach, 0))
	assert.NotNil(t, alert, "alert returned even when sink is nil")
}

// ─── Unique alert IDs ─────────────────────────────────────────────────────────

func TestDetector_AlertIDs_AreUnique(t *testing.T) {
	sink := &captureAlertSink{}
	d := NewDetector(Config{Enabled: true}, sink)

	for i := 0; i < 5; i++ {
		evt := mkBPFEvent(uint32(9000+i), types.BPFCmdProgDetach, 0) //nolint:gosec
		d.ProcessEvent(evt)
	}

	ids := make(map[string]struct{})
	for _, a := range sink.Alerts() {
		ids[a.ID] = struct{}{}
	}
	assert.Equal(t, 5, len(ids), "each alert must have a unique ID")
}

// ─── commToString ─────────────────────────────────────────────────────────────

func TestCommToString(t *testing.T) {
	cases := []struct {
		input []byte
		want  string
	}{
		{[]byte("nginx\x00padding"), "nginx"},
		{[]byte("ebpf-guard\x00\x00\x00\x00\x00\x00"), "ebpf-guard"},
		{[]byte("toolong_name_trunc"), "toolong_name_trunc"},
		{[]byte("\x00"), ""},
		{[]byte{}, ""},
		{[]byte("bpftool"), "bpftool"},
	}
	for _, tc := range cases {
		got := commToString(tc.input)
		assert.Equal(t, tc.want, got, "input: %q", tc.input)
	}
}

// ─── OwnedObjects — idempotency ───────────────────────────────────────────────

func TestOwnedObjects_AddDuplicate_IsIdempotent(t *testing.T) {
	o := NewOwnedObjects()
	o.AddProgramID(42)
	o.AddProgramID(42)
	assert.Equal(t, 1, o.ProgramCount())
}

func TestOwnedObjects_RemoveNonExistent_IsNoop(t *testing.T) {
	o := NewOwnedObjects()
	// Should not panic or error.
	o.RemoveProgramID(999)
	o.RemoveMapID(999)
}

// ─── All three dangerous commands each fire an alert ─────────────────────────

func TestDetector_AllDangerousCommands(t *testing.T) {
	dangerous := []struct {
		cmd  uint32
		name string
	}{
		{types.BPFCmdProgDetach, "BPF_PROG_DETACH"},
		{types.BPFCmdMapUpdate, "BPF_MAP_UPDATE_ELEM"},
		{types.BPFCmdMapDelete, "BPF_MAP_DELETE_ELEM"},
	}

	for _, tc := range dangerous {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			sink := &captureAlertSink{}
			d := NewDetector(Config{Enabled: true}, sink)

			alert := d.ProcessEvent(mkBPFEvent(9999, tc.cmd, 0))
			require.NotNil(t, alert, "cmd %d must generate alert", tc.cmd)
			assert.Contains(t, alert.Message, tc.name)
			assert.Equal(t, 1, sink.Count())
		})
	}
}

// ─── Graceful operation with zero value ──────────────────────────────────────

func TestDetector_ZeroConfig_IsDisabled(t *testing.T) {
	d := NewDetector(Config{}, nil)
	assert.False(t, d.IsEnabled())
	// Should be a no-op — no panic.
	result := d.ProcessEvent(mkBPFEvent(9999, types.BPFCmdProgDetach, 0))
	assert.Nil(t, result)
}
