package bpf

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeSamplingCtrl records SetSamplingRate calls for assertions.
type fakeSamplingCtrl struct {
	mu    sync.Mutex
	calls []samplingCall
}

type samplingCall struct {
	eventType string
	rate      float64
}

func (f *fakeSamplingCtrl) SetSamplingRate(eventType string, rate float64) error {
	f.mu.Lock()
	f.calls = append(f.calls, samplingCall{eventType, rate})
	f.mu.Unlock()
	return nil
}

func (f *fakeSamplingCtrl) getCalls() []samplingCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]samplingCall, len(f.calls))
	copy(out, f.calls)
	return out
}

// atomicDepth implements ChannelDepthProvider backed by an atomic value.
type atomicDepth struct{ v atomic.Value }

func (a *atomicDepth) set(fill float64) { a.v.Store(fill) }
func (a *atomicDepth) ChannelDepth() float64 {
	if v := a.v.Load(); v != nil {
		return v.(float64)
	}
	return 0.0
}

func TestClampRate(t *testing.T) {
	tests := []struct {
		rate, min, want float64
	}{
		{0.25, 0.05, 0.25},  // within range → unchanged
		{0.01, 0.05, 0.05},  // below min → clamped to min
		{1.5, 0.05, 1.0},    // above max → clamped to 1.0
		{0.0, 0.05, 0.05},   // zero → clamped to min
		{-0.1, 0.05, 0.05},  // negative → clamped to min (min floor wins)
		{0.5, 0.0, 0.5},     // zero min → no floor applied
	}
	for _, tt := range tests {
		got := clampRate(tt.rate, tt.min)
		if got != tt.want {
			t.Errorf("clampRate(%v, %v) = %v, want %v", tt.rate, tt.min, got, tt.want)
		}
	}
}

func TestDefaultRingBufLoadConfig(t *testing.T) {
	cfg := DefaultRingBufLoadConfig()
	if cfg.Enabled {
		t.Error("default should be disabled")
	}
	if cfg.DegradedThreshold >= cfg.CriticalThreshold {
		t.Errorf("DegradedThreshold (%v) must be < CriticalThreshold (%v)", cfg.DegradedThreshold, cfg.CriticalThreshold)
	}
	if cfg.RecoveryThreshold >= cfg.DegradedThreshold {
		t.Errorf("RecoveryThreshold (%v) must be < DegradedThreshold (%v) for hysteresis", cfg.RecoveryThreshold, cfg.DegradedThreshold)
	}
	if cfg.SyscallDegradedRate < cfg.SyscallCriticalRate {
		t.Errorf("SyscallDegradedRate should be >= SyscallCriticalRate")
	}
}

func TestRingBufLoadController_Normal(t *testing.T) {
	ctrl := &fakeSamplingCtrl{}
	depth := &atomicDepth{}
	depth.set(0.1)

	cfg := DefaultRingBufLoadConfig()
	cfg.Enabled = true

	c := NewRingBufLoadController(cfg, ctrl, depth, slog.Default())
	c.check()

	if c.Level() != int(loadLevelNormal) {
		t.Fatalf("expected normal level, got %d", c.Level())
	}
	rates := c.CurrentRates()
	for et, r := range rates {
		if r != 1.0 {
			t.Errorf("event type %q: expected rate 1.0, got %v", et, r)
		}
	}
}

func TestRingBufLoadController_DegradedTransition(t *testing.T) {
	ctrl := &fakeSamplingCtrl{}
	depth := &atomicDepth{}
	depth.set(0.6) // above DegradedThreshold (0.50)

	cfg := DefaultRingBufLoadConfig()
	cfg.Enabled = true

	c := NewRingBufLoadController(cfg, ctrl, depth, slog.Default())
	c.check()

	if c.Level() != int(loadLevelDegraded) {
		t.Fatalf("expected degraded level, got %d", c.Level())
	}

	rates := c.CurrentRates()
	if rates["syscall"] != cfg.SyscallDegradedRate {
		t.Errorf("syscall rate: want %v, got %v", cfg.SyscallDegradedRate, rates["syscall"])
	}
	if rates["file"] != cfg.FileDegradedRate {
		t.Errorf("file rate: want %v, got %v", cfg.FileDegradedRate, rates["file"])
	}
	if rates["network"] != 1.0 {
		t.Errorf("network should stay at 1.0 in degraded, got %v", rates["network"])
	}
}

func TestRingBufLoadController_CriticalTransition(t *testing.T) {
	ctrl := &fakeSamplingCtrl{}
	depth := &atomicDepth{}
	depth.set(0.85) // above CriticalThreshold (0.80)

	cfg := DefaultRingBufLoadConfig()
	cfg.Enabled = true

	c := NewRingBufLoadController(cfg, ctrl, depth, slog.Default())
	c.check()

	if c.Level() != int(loadLevelCritical) {
		t.Fatalf("expected critical level, got %d", c.Level())
	}

	rates := c.CurrentRates()
	if rates["syscall"] != cfg.SyscallCriticalRate {
		t.Errorf("syscall rate: want %v, got %v", cfg.SyscallCriticalRate, rates["syscall"])
	}
	if rates["file"] != cfg.FileCriticalRate {
		t.Errorf("file rate: want %v, got %v", cfg.FileCriticalRate, rates["file"])
	}
	if rates["network"] != cfg.NetworkCriticalRate {
		t.Errorf("network rate: want %v, got %v", cfg.NetworkCriticalRate, rates["network"])
	}
}

func TestRingBufLoadController_RecoveryHysteresis(t *testing.T) {
	ctrl := &fakeSamplingCtrl{}
	depth := &atomicDepth{}
	depth.set(0.6) // degraded

	cfg := DefaultRingBufLoadConfig()
	cfg.Enabled = true
	cfg.DegradedThreshold = 0.50
	cfg.RecoveryThreshold = 0.30

	c := NewRingBufLoadController(cfg, ctrl, depth, slog.Default())
	c.check()

	if c.Level() != int(loadLevelDegraded) {
		t.Fatal("should be degraded")
	}

	// Set fill between recovery (0.30) and degraded (0.50) — should not recover yet.
	depth.set(0.40)
	c.check()
	if c.Level() != int(loadLevelDegraded) {
		t.Error("should stay degraded (hysteresis): fill 0.40 is above recovery threshold 0.30")
	}

	// Drop below recovery threshold — should recover.
	depth.set(0.20)
	c.check()
	if c.Level() != int(loadLevelNormal) {
		t.Error("should recover to normal when fill drops below recovery threshold")
	}

	rates := c.CurrentRates()
	for et, r := range rates {
		if r != 1.0 {
			t.Errorf("after recovery, event type %q: expected 1.0, got %v", et, r)
		}
	}
}

func TestRingBufLoadController_MinRateFloor(t *testing.T) {
	ctrl := &fakeSamplingCtrl{}
	depth := &atomicDepth{}
	depth.set(0.99)

	cfg := DefaultRingBufLoadConfig()
	cfg.Enabled = true
	cfg.SyscallCriticalRate = 0.01 // below MinSyscallRate (0.05)
	cfg.MinSyscallRate = 0.05

	c := NewRingBufLoadController(cfg, ctrl, depth, slog.Default())
	c.check()

	rates := c.CurrentRates()
	if rates["syscall"] < 0.05 {
		t.Errorf("syscall rate %v below min rate 0.05", rates["syscall"])
	}
}

func TestRingBufLoadController_EWMAScaleFactor(t *testing.T) {
	ctrl := &fakeSamplingCtrl{}
	depth := &atomicDepth{}
	depth.set(0.85)

	cfg := DefaultRingBufLoadConfig()
	cfg.Enabled = true
	cfg.SyscallCriticalRate = 0.25

	c := NewRingBufLoadController(cfg, ctrl, depth, slog.Default())
	c.check()

	factor := c.EWMAScaleFactor("syscall")
	expectedFactor := 1.0 / cfg.SyscallCriticalRate
	if factor != expectedFactor {
		t.Errorf("EWMAScaleFactor: want %v, got %v", expectedFactor, factor)
	}

	// At normal rate, factor should be 1.0.
	if f := c.EWMAScaleFactor("unknown_type"); f != 1.0 {
		t.Errorf("unknown type factor should be 1.0, got %v", f)
	}
}

func TestRingBufLoadController_StartStop(t *testing.T) {
	ctrl := &fakeSamplingCtrl{}
	depth := &atomicDepth{}
	depth.set(0.6)

	cfg := DefaultRingBufLoadConfig()
	cfg.Enabled = true
	cfg.CheckInterval = 50 * time.Millisecond

	c := NewRingBufLoadController(cfg, ctrl, depth, slog.Default())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	c.StartWithDone(ctx, done)
	time.Sleep(150 * time.Millisecond) // allow at least one check

	if c.Level() != int(loadLevelDegraded) {
		t.Errorf("expected degraded level after start, got %d", c.Level())
	}

	// On cancel, controller should restore full rates.
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("goroutine did not exit within 2s")
	}

	// Verify the last calls restore to 1.0.
	calls := ctrl.getCalls()
	if len(calls) == 0 {
		t.Fatal("no BPF calls recorded")
	}
	lastByType := make(map[string]float64)
	for _, call := range calls {
		lastByType[call.eventType] = call.rate
	}
	for et, rate := range lastByType {
		if rate != 1.0 {
			t.Errorf("after shutdown, event type %q rate should be 1.0, got %v", et, rate)
		}
	}
}

func TestRingBufLoadController_NilCtrl(t *testing.T) {
	depth := &atomicDepth{}
	depth.set(0.9)

	cfg := DefaultRingBufLoadConfig()
	cfg.Enabled = true

	// Should not panic when ctrl is nil.
	c := NewRingBufLoadController(cfg, nil, depth, slog.Default())
	c.check()

	if c.Level() != int(loadLevelCritical) {
		t.Errorf("expected critical level, got %d", c.Level())
	}
}

func TestRingBufLoadController_NilDepth(t *testing.T) {
	ctrl := &fakeSamplingCtrl{}
	cfg := DefaultRingBufLoadConfig()
	cfg.Enabled = true

	// Nil depth → fill = 0 → stays Normal.
	c := NewRingBufLoadController(cfg, ctrl, nil, slog.Default())
	c.check()

	if c.Level() != int(loadLevelNormal) {
		t.Errorf("expected normal level with nil depth, got %d", c.Level())
	}
}

func TestApplyRingBufLoadDefaults(t *testing.T) {
	zero := RingBufLoadConfig{}
	got := applyRingBufLoadDefaults(zero)
	def := DefaultRingBufLoadConfig()

	if got.CheckInterval != def.CheckInterval {
		t.Errorf("CheckInterval: want %v, got %v", def.CheckInterval, got.CheckInterval)
	}
	if got.DegradedThreshold != def.DegradedThreshold {
		t.Errorf("DegradedThreshold: want %v, got %v", def.DegradedThreshold, got.DegradedThreshold)
	}
	if got.MinNetworkRate != def.MinNetworkRate {
		t.Errorf("MinNetworkRate: want %v, got %v", def.MinNetworkRate, got.MinNetworkRate)
	}
}
