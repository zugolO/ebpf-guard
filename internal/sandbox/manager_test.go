package sandbox

import (
	"testing"

	"github.com/zugolO/ebpf-guard/internal/config"
)

func TestManager_AuditOnlyWithoutMaps(t *testing.T) {
	m, err := New(aiCfg("audit", config.AISandboxProfile{Name: "agent"}), nil)
	if err != nil {
		t.Fatal(err)
	}
	// No Load() → no maps → register records mapping but touches no kernel.
	if err := m.RegisterCgroup(12345, "agent"); err != nil {
		t.Fatalf("register: %v", err)
	}
	if m.registered[12345] != 1 {
		t.Errorf("registered profile id = %d, want 1", m.registered[12345])
	}
	if m.KernelEnforced() {
		t.Error("audit-only manager must not report kernel enforcement")
	}
	if err := m.UnregisterCgroup(12345); err != nil {
		t.Fatalf("unregister: %v", err)
	}
	if _, ok := m.registered[12345]; ok {
		t.Error("cgroup should be removed after unregister")
	}
}

func TestManager_RegisterUnknownProfile(t *testing.T) {
	m, _ := New(aiCfg("audit", config.AISandboxProfile{Name: "agent"}), nil)
	if err := m.RegisterCgroup(1, "nope"); err == nil {
		t.Fatal("registering an unknown profile should error")
	}
}

func TestManager_RegisterWritesMaps(t *testing.T) {
	m, err := New(aiCfg("enforce", config.AISandboxProfile{
		Name:               "agent",
		AllowedEgressPorts: []uint16{443},
	}), nil)
	if err != nil {
		t.Fatal(err)
	}
	// Inject fakes to exercise the kernel write path without a BPF host.
	cgroups := newFakeMap()
	state := newFakeMap()
	m.maps = &Maps{
		State:      state,
		Cgroups:    cgroups,
		PathPolicy: newFakeMap(),
		NetV4:      newFakeMap(),
		NetV6:      newFakeMap(),
		Ports:      newFakeMap(),
	}
	if err := m.RegisterCgroup(999, "agent"); err != nil {
		t.Fatalf("register: %v", err)
	}
	if len(cgroups.data) != 1 {
		t.Errorf("cgroups map rows = %d, want 1", len(cgroups.data))
	}
	if len(state.data) != 1 {
		t.Errorf("state map rows = %d, want 1", len(state.data))
	}
	if err := m.UnregisterCgroup(999); err != nil {
		t.Fatalf("unregister: %v", err)
	}
	if len(cgroups.data) != 0 {
		t.Errorf("cgroups map rows after unregister = %d, want 0", len(cgroups.data))
	}
}

func TestManager_GuardTargetDowngradesEnforce(t *testing.T) {
	m, err := New(aiCfg("enforce", config.AISandboxProfile{Name: "agent"}), nil)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a live kernel enforcement session so KernelEnforced would be true
	// were the target safe. Both the LSM programs and the exec-control hook are
	// attached (issue #267 item 2: exec hook is required for a full claim).
	m.kernelMode = true
	m.execHookAttached = true
	if !m.KernelEnforced() {
		t.Fatal("precondition: enforce+kernelMode+execHook should report enforced")
	}
	// A privileged target must latch enforcement-unsafe and flip KernelEnforced.
	safety := EnforcementSafety{Safe: false, Reasons: []string{"target holds CAP_BPF"}}
	m.applyGuard(safety) // test seam mirroring GuardTarget's decision
	if m.KernelEnforced() {
		t.Error("KernelEnforced must be false once a target is enforcement-unsafe")
	}
	unsafe, reasons := m.EnforcementUnsafe()
	if !unsafe || len(reasons) != 1 {
		t.Errorf("EnforcementUnsafe = (%v, %v), want (true, 1 reason)", unsafe, reasons)
	}
}

func TestManager_ExecHookDowngradesKernelEnforced(t *testing.T) {
	m, err := New(aiCfg("enforce", config.AISandboxProfile{Name: "agent"}), nil)
	if err != nil {
		t.Fatal(err)
	}
	// A live enforce session whose bprm_check exec hook failed to attach: the
	// operator must not be shown kernel_enforced=true while exec control is
	// backstopped only by file_open (issue #267 item 2).
	m.kernelMode = true
	m.execHookAttached = false
	if m.KernelEnforced() {
		t.Error("KernelEnforced must be false when the exec-control hook is unattached")
	}
	if m.ExecEnforced() {
		t.Error("ExecEnforced must be false when the exec-control hook is unattached")
	}
	// Once the exec hook attaches, both report enforced.
	m.execHookAttached = true
	if !m.KernelEnforced() {
		t.Error("KernelEnforced should be true once the exec-control hook attaches")
	}
	if !m.ExecEnforced() {
		t.Error("ExecEnforced should be true once the exec-control hook attaches")
	}
}

func TestManager_GuardTargetAuditNeverDowngrades(t *testing.T) {
	m, _ := New(aiCfg("audit", config.AISandboxProfile{Name: "agent"}), nil)
	m.applyGuard(EnforcementSafety{Safe: false, Reasons: []string{"target holds CAP_BPF"}})
	if unsafe, _ := m.EnforcementUnsafe(); unsafe {
		t.Error("audit mode has nothing to enforce; it must not latch unsafe")
	}
}

func TestManager_ProtectPIDWritesMap(t *testing.T) {
	m, err := New(aiCfg("enforce", config.AISandboxProfile{Name: "agent"}), nil)
	if err != nil {
		t.Fatal(err)
	}
	protected := newFakeMap()
	m.maps = &Maps{
		State:      newFakeMap(),
		Cgroups:    newFakeMap(),
		PathPolicy: newFakeMap(),
		NetV4:      newFakeMap(),
		NetV6:      newFakeMap(),
		Ports:      newFakeMap(),
		Protected:  protected,
	}

	if err := m.ProtectPID(4242); err != nil {
		t.Fatalf("protect: %v", err)
	}
	if len(protected.data) != 1 {
		t.Errorf("protected map rows = %d, want 1", len(protected.data))
	}
	if _, ok := m.protected[4242]; !ok {
		t.Error("pid 4242 should be tracked as protected")
	}

	// Idempotent: protecting again does not add a second row.
	if err := m.ProtectPID(4242); err != nil {
		t.Fatalf("re-protect: %v", err)
	}
	if len(protected.data) != 1 {
		t.Errorf("protected map rows after re-protect = %d, want 1", len(protected.data))
	}

	if err := m.UnprotectPID(4242); err != nil {
		t.Fatalf("unprotect: %v", err)
	}
	if len(protected.data) != 0 {
		t.Errorf("protected map rows after unprotect = %d, want 0", len(protected.data))
	}
	if _, ok := m.protected[4242]; ok {
		t.Error("pid 4242 should be untracked after unprotect")
	}
}

func TestManager_ProtectPIDAuditOnly(t *testing.T) {
	m, err := New(aiCfg("audit", config.AISandboxProfile{Name: "agent"}), nil)
	if err != nil {
		t.Fatal(err)
	}
	// No maps → records intent without touching the kernel.
	if err := m.ProtectPID(7); err != nil {
		t.Fatalf("protect (audit-only): %v", err)
	}
	if _, ok := m.protected[7]; !ok {
		t.Error("audit-only protect should still track intent")
	}
}

func TestManager_ProtectPIDRejectsZero(t *testing.T) {
	m, _ := New(aiCfg("enforce", config.AISandboxProfile{Name: "agent"}), nil)
	if err := m.ProtectPID(0); err == nil {
		t.Fatal("protecting pid 0 must error")
	}
}

func TestManager_UnprotectUnknownPIDNoop(t *testing.T) {
	m, _ := New(aiCfg("enforce", config.AISandboxProfile{Name: "agent"}), nil)
	if err := m.UnprotectPID(999); err != nil {
		t.Fatalf("unprotecting an unknown pid should be a no-op, got %v", err)
	}
}

func TestCgroupValuePacking(t *testing.T) {
	v := cgroupValue(3, flagPortsFilter, ModeEnforce)
	if got := uint32(v >> 32); got != 3 {
		t.Errorf("profile id = %d, want 3", got)
	}
	if got := uint8((v >> 8) & 0xFF); got != flagPortsFilter {
		t.Errorf("flags = %d, want %d", got, flagPortsFilter)
	}
	if got := uint8(v & 0xFF); got != ModeEnforce {
		t.Errorf("mode = %d, want %d", got, ModeEnforce)
	}
}
