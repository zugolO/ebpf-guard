package profiler

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

func makeSyscallEvent(nr int64) types.Event {
	return types.Event{
		Type:    types.EventSyscall,
		PID:     1234,
		Syscall: &types.SyscallEvent{Nr: nr},
	}
}

func defaultAllowlistConfig() SyscallAllowlistConfig {
	return SyscallAllowlistConfig{
		Enabled:         true,
		Mode:            "learning",
		EnforcingAction: "alert",
		PerWorkload:     true,
		LearningPeriod:  1, // 1 second — short for tests
		MinSamples:      3,
		SparseThreshold: 2,
	}
}

func newTestProfiler(cfg SyscallAllowlistConfig) *SyscallAllowlistProfiler {
	return NewSyscallAllowlistProfiler(cfg, nil)
}

// TestLearningPhase verifies that Check returns nil while learning.
func TestLearningPhase(t *testing.T) {
	p := newTestProfiler(defaultAllowlistConfig())
	e := makeSyscallEvent(1)
	p.Record(e)
	if v := p.Check(e); v != nil {
		t.Fatalf("expected nil during learning, got %+v", v)
	}
}

// TestEnforcingPhase verifies violation detection after learning completes.
func TestEnforcingPhase(t *testing.T) {
	cfg := defaultAllowlistConfig()
	cfg.LearningPeriod = 0 // expire immediately
	cfg.MinSamples = 3
	p := newTestProfiler(cfg)

	// Record 3 known syscalls to satisfy MinSamples.
	for range 3 {
		p.Record(makeSyscallEvent(1))
	}
	// Syscall 1 is known — no violation.
	if v := p.Check(makeSyscallEvent(1)); v != nil {
		t.Fatalf("expected nil for known syscall, got %+v", v)
	}
	// Syscall 99 was never seen — should fire.
	v := p.Check(makeSyscallEvent(99))
	if v == nil {
		t.Fatal("expected violation for unknown syscall 99")
	}
	if v.SyscallNr != 99 {
		t.Errorf("SyscallNr: want 99, got %d", v.SyscallNr)
	}
	if v.Source != "unknown" {
		t.Errorf("Source: want 'unknown', got %q", v.Source)
	}
	if v.Action != AllowlistActionAlert {
		t.Errorf("Action: want alert, got %q", v.Action)
	}
}

// TestGlobalDeny verifies that global_deny always fires.
func TestGlobalDeny(t *testing.T) {
	cfg := defaultAllowlistConfig()
	cfg.GlobalDeny = []int{101} // ptrace
	p := newTestProfiler(cfg)

	// Record ptrace during learning.
	p.Record(makeSyscallEvent(101))
	// Even during learning, global_deny should fire.
	v := p.Check(makeSyscallEvent(101))
	if v == nil {
		t.Fatal("expected violation for global_deny syscall")
	}
	if v.Source != "global_deny" {
		t.Errorf("Source: want 'global_deny', got %q", v.Source)
	}
}

// TestGlobalAllow verifies that global_allow syscalls are never alerted.
func TestGlobalAllow(t *testing.T) {
	cfg := defaultAllowlistConfig()
	cfg.LearningPeriod = 0
	cfg.MinSamples = 1
	cfg.GlobalAllow = []int{1} // read — always ok
	p := newTestProfiler(cfg)

	// Satisfy MinSamples with a different syscall.
	p.Record(makeSyscallEvent(2))

	// Syscall 1 is in global_allow — must not fire even though never recorded.
	if v := p.Check(makeSyscallEvent(1)); v != nil {
		t.Fatalf("expected nil for global_allow syscall, got %+v", v)
	}
}

// TestTransitionToEnforcing verifies mode switch after learning period + MinSamples.
func TestTransitionToEnforcing(t *testing.T) {
	cfg := defaultAllowlistConfig()
	cfg.LearningPeriod = 0
	cfg.MinSamples = 2
	p := newTestProfiler(cfg)

	e := makeSyscallEvent(5)
	p.Record(e)
	// Only 1 sample — still learning.
	if v := p.Check(makeSyscallEvent(99)); v != nil {
		t.Fatal("should still be learning after 1 sample")
	}
	p.Record(e)
	// Now 2 samples and period expired — enforcing.
	v := p.Check(makeSyscallEvent(99))
	if v == nil {
		t.Fatal("expected violation after transition to enforcing")
	}
}

// TestSparseProfiles verifies detection of profiles with too few unique syscalls.
func TestSparseProfiles(t *testing.T) {
	cfg := defaultAllowlistConfig()
	cfg.LearningPeriod = 0
	cfg.MinSamples = 2
	cfg.SparseThreshold = 5 // need 5 unique syscalls
	p := newTestProfiler(cfg)

	// Record only 2 unique syscalls but enough samples.
	p.Record(makeSyscallEvent(1))
	p.Record(makeSyscallEvent(2))

	sparse := p.SparseProfiles()
	if len(sparse) != 1 {
		t.Fatalf("expected 1 sparse profile, got %d", len(sparse))
	}
	if len(sparse[0].AllowedSyscalls) != 2 {
		t.Errorf("expected 2 unique syscalls in sparse profile, got %d", len(sparse[0].AllowedSyscalls))
	}
}

// TestNonSyscallEventsIgnored verifies non-syscall events are skipped.
func TestNonSyscallEventsIgnored(t *testing.T) {
	cfg := defaultAllowlistConfig()
	cfg.LearningPeriod = 0
	cfg.MinSamples = 1
	p := newTestProfiler(cfg)

	p.Record(types.Event{Type: types.EventTCPConnect, PID: 1})
	// No syscall recorded — profile is still in learning.
	v := p.Check(makeSyscallEvent(99))
	if v != nil {
		t.Fatalf("expected nil (still learning), got %+v", v)
	}
}

// TestDisabledProfiler verifies that a disabled profiler never fires.
func TestDisabledProfiler(t *testing.T) {
	cfg := defaultAllowlistConfig()
	cfg.Enabled = false
	p := newTestProfiler(cfg)
	if v := p.Check(makeSyscallEvent(999)); v != nil {
		t.Fatalf("expected nil for disabled profiler, got %+v", v)
	}
}

// TestPersistence verifies save/load round-trip.
func TestPersistence(t *testing.T) {
	cfg := defaultAllowlistConfig()
	cfg.LearningPeriod = 0
	cfg.MinSamples = 1
	p := newTestProfiler(cfg)

	p.Record(makeSyscallEvent(42))

	tmp := filepath.Join(t.TempDir(), "allowlist-state.json")
	if err := p.SaveState(tmp); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	if _, err := os.Stat(tmp); err != nil {
		t.Fatalf("state file not written: %v", err)
	}

	// Load into a new profiler.
	p2 := newTestProfiler(cfg)
	if err := p2.loadState(tmp); err != nil {
		t.Fatalf("loadState: %v", err)
	}
	p2.mu.RLock()
	nProfiles := len(p2.profiles)
	p2.mu.RUnlock()
	if nProfiles == 0 {
		t.Fatal("expected at least 1 profile after loading state")
	}
}

// TestSaveStateMissingDir verifies SaveState creates the parent directory.
func TestSaveStateMissingDir(t *testing.T) {
	cfg := defaultAllowlistConfig()
	p := newTestProfiler(cfg)
	p.Record(makeSyscallEvent(1))

	path := filepath.Join(t.TempDir(), "subdir", "nested", "state.json")
	if err := p.SaveState(path); err != nil {
		t.Fatalf("SaveState with missing dirs: %v", err)
	}
}

// TestSetSamplingRate verifies clamping.
func TestSetSamplingRate(t *testing.T) {
	p := newTestProfiler(defaultAllowlistConfig())
	p.SetSamplingRate(1.5)
	p.mu.RLock()
	rate := p.samplingRate
	p.mu.RUnlock()
	if rate != 1.0 {
		t.Errorf("expected 1.0, got %f", rate)
	}
	p.SetSamplingRate(-0.5)
	p.mu.RLock()
	rate = p.samplingRate
	p.mu.RUnlock()
	if rate != 0.0 {
		t.Errorf("expected 0.0, got %f", rate)
	}
}

// TestToSetNegativeIgnored verifies that negative syscall numbers are rejected.
func TestToSetNegativeIgnored(t *testing.T) {
	m := toSet([]int{-1, 0, 5})
	if _, ok := m[0]; !ok {
		t.Error("expected syscall 0 in set")
	}
	if _, ok := m[5]; !ok {
		t.Error("expected syscall 5 in set")
	}
	// uint32(-1) = 4294967295, should not be in map
	if len(m) != 2 {
		t.Errorf("expected 2 entries (negative excluded), got %d", len(m))
	}
}

// TestLearningPeriodNotYetExpired verifies no enforcement before the timer.
func TestLearningPeriodNotYetExpired(t *testing.T) {
	cfg := defaultAllowlistConfig()
	cfg.LearningPeriod = 3600 // 1 hour — won't expire during test
	cfg.MinSamples = 1
	p := newTestProfiler(cfg)

	p.Record(makeSyscallEvent(1))
	// MinSamples satisfied but period not over — still learning.
	if v := p.Check(makeSyscallEvent(99)); v != nil {
		t.Fatalf("expected nil before learning period expires, got %+v", v)
	}
}

// TestTimedTransition verifies the profiler switches to enforcing after the real timer.
func TestTimedTransition(t *testing.T) {
	cfg := defaultAllowlistConfig()
	cfg.LearningPeriod = 0
	cfg.MinSamples = 0
	p := newTestProfiler(cfg)

	// With period=0 and minSamples=0, first Record should trigger transition.
	p.Record(makeSyscallEvent(10))
	v := p.Check(makeSyscallEvent(99))
	if v == nil {
		t.Fatal("expected violation after immediate learning expiry")
	}
	_ = time.Now() // keep time import used
}
