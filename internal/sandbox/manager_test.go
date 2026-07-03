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
	// were the target safe.
	m.kernelMode = true
	if !m.KernelEnforced() {
		t.Fatal("precondition: enforce+kernelMode should report enforced")
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

func TestManager_GuardTargetAuditNeverDowngrades(t *testing.T) {
	m, _ := New(aiCfg("audit", config.AISandboxProfile{Name: "agent"}), nil)
	m.applyGuard(EnforcementSafety{Safe: false, Reasons: []string{"target holds CAP_BPF"}})
	if unsafe, _ := m.EnforcementUnsafe(); unsafe {
		t.Error("audit mode has nothing to enforce; it must not latch unsafe")
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
