package main

import (
	"runtime/debug"
	"testing"

	"github.com/zugolO/ebpf-guard/internal/config"
)

// TestApplyRuntimeTuning_LiteSetsGOMEMLIMITAndGOGC verifies the lite profile's
// GOMEMLIMIT/GOGC preset is actually applied to the Go runtime, restoring the
// previous settings afterward so this test doesn't leak into others.
func TestApplyRuntimeTuning_LiteSetsGOMEMLIMITAndGOGC(t *testing.T) {
	origLimit := debug.SetMemoryLimit(-1)
	origGC := debug.SetGCPercent(100) // 100 is a safe, real value; captures+restores the true prior setting
	t.Cleanup(func() {
		debug.SetMemoryLimit(origLimit)
		debug.SetGCPercent(origGC)
	})

	hw := config.HardwareProfileInfo{
		Hardware: config.HardwareInfo{CPUs: 1, MemTotalMB: 1024},
		Applied: config.ProfileDefaults{
			GOMEMLIMITRatio: 0.4,
			GOGCPercent:     50,
		},
	}
	applyRuntimeTuning(hw)

	memMB := float64(1024)
	wantLimit := int64(memMB * 0.4 * 1024 * 1024)
	if got := debug.SetMemoryLimit(-1); got != wantLimit {
		t.Errorf("GOMEMLIMIT = %d, want %d", got, wantLimit)
	}
	if got := debug.SetGCPercent(-1); got != 50 {
		t.Errorf("GOGC = %d, want 50", got)
	}
}

// TestApplyRuntimeTuning_BalancedIsNoOp verifies a profile with no
// GOMEMLIMIT/GOGC preset (ratio/percent both zero) leaves the Go runtime's
// existing settings untouched.
func TestApplyRuntimeTuning_BalancedIsNoOp(t *testing.T) {
	origLimit := debug.SetMemoryLimit(-1)
	origGC := debug.SetGCPercent(100) // 100 is a safe, real value; captures+restores the true prior setting
	t.Cleanup(func() {
		debug.SetMemoryLimit(origLimit)
		debug.SetGCPercent(origGC)
	})

	hw := config.HardwareProfileInfo{
		Hardware: config.HardwareInfo{CPUs: 4, MemTotalMB: 8192},
		Applied:  config.ProfileDefaults{},
	}
	applyRuntimeTuning(hw)

	if got := debug.SetMemoryLimit(-1); got != origLimit {
		t.Errorf("GOMEMLIMIT changed to %d, want unchanged %d", got, origLimit)
	}
	if got := debug.SetGCPercent(-1); got != origGC {
		t.Errorf("GOGC changed to %d, want unchanged %d", got, origGC)
	}
}

// TestApplyRuntimeTuning_ZeroMemTotalSkipsGOMEMLIMIT verifies that an
// undetectable MemTotalMB (0, e.g. /proc/meminfo unreadable) skips the
// GOMEMLIMIT computation rather than setting a bogus zero-byte limit, while
// GOGC (which doesn't depend on RAM) still applies.
func TestApplyRuntimeTuning_ZeroMemTotalSkipsGOMEMLIMIT(t *testing.T) {
	origLimit := debug.SetMemoryLimit(-1)
	origGC := debug.SetGCPercent(100) // 100 is a safe, real value; captures+restores the true prior setting
	t.Cleanup(func() {
		debug.SetMemoryLimit(origLimit)
		debug.SetGCPercent(origGC)
	})

	hw := config.HardwareProfileInfo{
		Hardware: config.HardwareInfo{CPUs: 1, MemTotalMB: 0},
		Applied: config.ProfileDefaults{
			GOMEMLIMITRatio: 0.4,
			GOGCPercent:     50,
		},
	}
	applyRuntimeTuning(hw)

	if got := debug.SetMemoryLimit(-1); got != origLimit {
		t.Errorf("GOMEMLIMIT changed to %d despite MemTotalMB=0, want unchanged %d", got, origLimit)
	}
	if got := debug.SetGCPercent(-1); got != 50 {
		t.Errorf("GOGC = %d, want 50", got)
	}
}
