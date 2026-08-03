// cpu_test.go — Tests for CPUPressureWatcher

package watchdog

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeClock drives the watcher's CPU sampler and wall clock deterministically.
// Each step advances wall time by one interval and adds cpuDelta CPU-seconds,
// so the resulting CPU% is fully under the test's control.
type fakeClock struct {
	now    time.Time
	cpu    float64
	numCPU int
}

func newFakeClock(numCPU int) *fakeClock {
	return &fakeClock{now: time.Unix(0, 0), numCPU: numCPU}
}

// stepFor advances the clock by interval and adds enough CPU time to produce
// the requested single-core CPU percentage over that interval.
func (f *fakeClock) stepFor(pct float64, interval time.Duration) {
	f.now = f.now.Add(interval)
	// pct = (cpuDelta / wallDelta) * 100 (percentage of a single core; not
	// normalized by numCPU).
	cpuDelta := pct / 100.0 * interval.Seconds()
	f.cpu += cpuDelta
}

// newTestWatcher wires a watcher to a fake clock with a fixed CPU count and a
// 1-sample window (no smoothing) unless overridden.
func newTestWatcher(t *testing.T, cfg CPUConfig, bpf BPFSamplingController) (*CPUPressureWatcher, *fakeClock) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	w := NewCPUPressureWatcher(cfg, logger, bpf)
	fc := newFakeClock(w.numCPU)
	w.cpuTimeFn = func() (float64, error) { return fc.cpu, nil }
	w.nowFn = func() time.Time { return fc.now }
	return w, fc
}

func TestDefaultCPUConfig(t *testing.T) {
	c := DefaultCPUConfig()
	assert.True(t, c.Enabled)
	assert.Equal(t, 5*time.Second, c.CheckInterval)
	assert.Equal(t, 40.0, c.CPULimitPercent)
	assert.Equal(t, 40.0, c.FileShedThreshold)
	assert.Equal(t, 70.0, c.AllShedThreshold)
	assert.Equal(t, 20.0, c.RecoveryThreshold)
	assert.Equal(t, 6, c.WindowSize)
	assert.Equal(t, 30*time.Second, c.MinDwell)
}

func TestCPUWatcher_ThresholdSeedingFromLimit(t *testing.T) {
	// Only cpu_limit_percent set; the rest should be derived.
	w := NewCPUPressureWatcher(CPUConfig{CPULimitPercent: 12.0, WindowSize: 1}, nil, nil)
	assert.Equal(t, 12.0, w.fileShedThreshold)
	assert.InDelta(t, 21.0, w.allShedThreshold, 0.001) // 12 * 7/4
	assert.InDelta(t, 6.0, w.recoveryThreshold, 0.001) // 12 * 0.5
}

func TestCPUWatcher_RegisterMetrics(t *testing.T) {
	w := NewCPUPressureWatcher(DefaultCPUConfig(), nil, nil)
	reg := prometheus.NewRegistry()
	require.NoError(t, w.RegisterMetrics(reg))

	families, err := reg.Gather()
	require.NoError(t, err)
	require.Len(t, families, 2)
	assert.Equal(t, "ebpf_guard_cpu_pressure_level", *families[0].Name)
	assert.Equal(t, "ebpf_guard_cpu_pressure_percent", *families[1].Name)
}

func TestCPUWatcher_FirstSamplePrimesOnly(t *testing.T) {
	cfg := CPUConfig{CheckInterval: time.Second, FileShedThreshold: 15, AllShedThreshold: 25, RecoveryThreshold: 9, WindowSize: 1}
	w, fc := newTestWatcher(t, cfg, nil)

	// Even at very high CPU, the first sample only establishes a baseline.
	fc.cpu = 1000
	w.checkCPU()
	assert.Equal(t, cpuLevelNormal, w.PressureLevel())
	assert.True(t, w.haveLast)
}

func TestCPUWatcher_EscalateAndRecover(t *testing.T) {
	bpf := newMockBPFController()
	cfg := CPUConfig{
		CheckInterval:     time.Second,
		FileShedThreshold: 15,
		AllShedThreshold:  25,
		RecoveryThreshold: 9,
		WindowSize:        1,
		MinDwell:          time.Nanosecond,
	}
	w, fc := newTestWatcher(t, cfg, bpf)
	interval := time.Second

	// Prime baseline at 0% CPU.
	w.checkCPU()
	assert.Equal(t, cpuLevelNormal, w.PressureLevel())

	// 18% CPU → level 1: file shed only.
	fc.stepFor(18, interval)
	w.checkCPU()
	assert.Equal(t, cpuLevelFileShed, w.PressureLevel())
	assert.True(t, w.IsThrottling())
	assert.Equal(t, 0.1, bpf.GetSamplingRate("file"))
	assert.Equal(t, 0.0, bpf.GetSamplingRate("syscall")) // untouched
	assert.Equal(t, 0.0, bpf.GetSamplingRate("network"))

	// 30% CPU → level 2: syscall + network shed too.
	fc.stepFor(30, interval)
	w.checkCPU()
	assert.Equal(t, cpuLevelAllShed, w.PressureLevel())
	assert.Equal(t, 0.1, bpf.GetSamplingRate("file"))
	assert.Equal(t, 0.1, bpf.GetSamplingRate("syscall"))
	assert.Equal(t, 0.1, bpf.GetSamplingRate("network"))

	// Still elevated (12%) but above recovery threshold → stay at level 2.
	fc.stepFor(12, interval)
	w.checkCPU()
	assert.Equal(t, cpuLevelAllShed, w.PressureLevel())

	// Drop below recovery threshold (5%) → recover fully, rates restored.
	fc.stepFor(5, interval)
	w.checkCPU()
	assert.Equal(t, cpuLevelNormal, w.PressureLevel())
	assert.False(t, w.IsThrottling())
	assert.Equal(t, 1.0, bpf.GetSamplingRate("file"))
	assert.Equal(t, 1.0, bpf.GetSamplingRate("syscall"))
	assert.Equal(t, 1.0, bpf.GetSamplingRate("network"))
}

func TestCPUWatcher_PressurePercent(t *testing.T) {
	cfg := CPUConfig{CheckInterval: time.Second, FileShedThreshold: 90, AllShedThreshold: 95, RecoveryThreshold: 10, WindowSize: 2}
	w, fc := newTestWatcher(t, cfg, nil)

	assert.Equal(t, 0.0, w.PressurePercent(), "no samples yet")

	w.checkCPU() // primes baseline only
	assert.Equal(t, 0.0, w.PressurePercent())

	fc.stepFor(20, time.Second)
	w.checkCPU()
	assert.InDelta(t, 20.0, w.PressurePercent(), 0.01)

	fc.stepFor(40, time.Second)
	w.checkCPU()
	assert.InDelta(t, 30.0, w.PressurePercent(), 0.01) // mean of last 2 samples (window=2)
}

func TestCPUWatcher_Hysteresis_NoFlapBetweenThresholds(t *testing.T) {
	bpf := newMockBPFController()
	cfg := CPUConfig{
		CheckInterval:     time.Second,
		FileShedThreshold: 15,
		AllShedThreshold:  25,
		RecoveryThreshold: 9,
		WindowSize:        1,
		MinDwell:          time.Nanosecond,
	}
	w, fc := newTestWatcher(t, cfg, bpf)
	interval := time.Second
	w.checkCPU()

	// Trip to level 1.
	fc.stepFor(16, interval)
	w.checkCPU()
	require.Equal(t, cpuLevelFileShed, w.PressureLevel())

	// CPU dips to 12% — below the L1 trip point but above recovery (9%).
	// Hysteresis must keep us at level 1, not flap back to normal.
	fc.stepFor(12, interval)
	w.checkCPU()
	assert.Equal(t, cpuLevelFileShed, w.PressureLevel())
}

func TestCPUWatcher_SlidingWindowSmoothsSpike(t *testing.T) {
	bpf := newMockBPFController()
	cfg := CPUConfig{
		CheckInterval:     time.Second,
		FileShedThreshold: 15,
		AllShedThreshold:  25,
		RecoveryThreshold: 9,
		WindowSize:        3,
		MinDwell:          time.Nanosecond,
	}
	w, fc := newTestWatcher(t, cfg, bpf)
	interval := time.Second
	w.checkCPU() // prime

	// Two quiet samples then one big spike. The 3-sample average stays under
	// the threshold, so a single transient spike must not trip shedding.
	fc.stepFor(2, interval)
	w.checkCPU()
	fc.stepFor(2, interval)
	w.checkCPU()
	fc.stepFor(30, interval) // avg = (2+2+30)/3 ≈ 11.3% < 15%
	w.checkCPU()
	assert.Equal(t, cpuLevelNormal, w.PressureLevel())

	// Sustained high load fills the window and trips shedding.
	fc.stepFor(30, interval) // avg = (2+30+30)/3 ≈ 20.7% ≥ 15%
	w.checkCPU()
	assert.Equal(t, cpuLevelFileShed, w.PressureLevel())
}

func TestCPUWatcher_NilControllerTracksStateOnly(t *testing.T) {
	cfg := CPUConfig{
		CheckInterval:     time.Second,
		FileShedThreshold: 15,
		AllShedThreshold:  25,
		RecoveryThreshold: 9,
		WindowSize:        1,
		MinDwell:          time.Nanosecond,
	}
	w, fc := newTestWatcher(t, cfg, nil)
	w.checkCPU()

	fc.stepFor(40, time.Second)
	w.checkCPU()
	// No controller, but state and metrics still advance.
	assert.Equal(t, cpuLevelAllShed, w.PressureLevel())
}

func TestCPUWatcher_StartStop(t *testing.T) {
	cfg := CPUConfig{CheckInterval: 20 * time.Millisecond, WindowSize: 1}
	w, _ := newTestWatcher(t, cfg, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		w.Start(ctx)
		close(done)
	}()
	<-done
}

func TestCPUWatcher_DirectRecoverFromL1(t *testing.T) {
	bpf := newMockBPFController()
	cfg := CPUConfig{
		CheckInterval:     time.Second,
		FileShedThreshold: 15,
		AllShedThreshold:  25,
		RecoveryThreshold: 9,
		WindowSize:        1,
		MinDwell:          time.Nanosecond,
	}
	w, fc := newTestWatcher(t, cfg, bpf)
	w.checkCPU()

	// Trip to level 1.
	fc.stepFor(16, time.Second)
	w.checkCPU()
	require.Equal(t, cpuLevelFileShed, w.PressureLevel())
	require.Equal(t, 0.1, bpf.GetSamplingRate("file"))

	// Drop straight below recovery from level 1 → back to normal, file restored.
	fc.stepFor(3, time.Second)
	w.checkCPU()
	assert.Equal(t, cpuLevelNormal, w.PressureLevel())
	assert.Equal(t, 1.0, bpf.GetSamplingRate("file"))
}

func TestCPUWatcher_SamplerErrorIsHandled(t *testing.T) {
	cfg := CPUConfig{CheckInterval: time.Second, WindowSize: 1}
	w, _ := newTestWatcher(t, cfg, nil)
	w.cpuTimeFn = func() (float64, error) { return 0, errors.New("read failed") }

	// Must not panic and must not establish a baseline on error.
	assert.NotPanics(t, w.checkCPU)
	assert.False(t, w.haveLast)
	assert.Equal(t, cpuLevelNormal, w.PressureLevel())
}

func TestCPUWatcher_NonPositiveWallDeltaSkipped(t *testing.T) {
	cfg := CPUConfig{CheckInterval: time.Second, FileShedThreshold: 15, AllShedThreshold: 25, RecoveryThreshold: 9, WindowSize: 1}
	w, fc := newTestWatcher(t, cfg, nil)
	w.checkCPU() // prime at t0

	// Advance CPU but not wall time: wallDelta == 0, sample is ignored.
	fc.cpu += 100
	w.checkCPU()
	assert.Equal(t, cpuLevelNormal, w.PressureLevel())
	assert.Nil(t, w.window)
}

func TestCPUWatcher_CounterResetClampedToZero(t *testing.T) {
	cfg := CPUConfig{CheckInterval: time.Second, FileShedThreshold: 15, AllShedThreshold: 25, RecoveryThreshold: 9, WindowSize: 1}
	w, fc := newTestWatcher(t, cfg, nil)
	w.checkCPU()

	// A decreasing CPU counter (should never happen, but guard against it)
	// must clamp to 0% rather than produce a negative reading.
	fc.now = fc.now.Add(time.Second)
	fc.cpu = -50
	w.checkCPU()
	assert.Equal(t, cpuLevelNormal, w.PressureLevel())
}

func TestCPUWatcher_RegisterMetricsDuplicateErrors(t *testing.T) {
	w := NewCPUPressureWatcher(DefaultCPUConfig(), nil, nil)
	reg := prometheus.NewRegistry()
	require.NoError(t, w.RegisterMetrics(reg))
	// Re-registering the same collectors must surface an error.
	assert.Error(t, w.RegisterMetrics(reg))
}

func TestReadProcSelfCPUSeconds(t *testing.T) {
	v, err := readProcSelfCPUSeconds()
	if err != nil {
		t.Skipf("/proc/self/stat not available: %v", err)
	}
	assert.GreaterOrEqual(t, v, 0.0)

	// Burn a little CPU and confirm the counter is monotonic non-decreasing.
	x := 0
	for i := 0; i < 5_000_000; i++ {
		x += i
	}
	_ = x
	v2, err := readProcSelfCPUSeconds()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, v2, v)
}

func TestCPUWatcher_DefaultSeedingFromZeroConfig(t *testing.T) {
	// An all-zero config must be filled in with safe defaults.
	w := NewCPUPressureWatcher(CPUConfig{}, nil, nil)
	assert.Equal(t, 5*time.Second, w.checkInterval)
	assert.Equal(t, 6, w.windowSize)
	assert.Equal(t, 40.0, w.fileShedThreshold)
	assert.InDelta(t, 70.0, w.allShedThreshold, 0.001)
	assert.InDelta(t, 20.0, w.recoveryThreshold, 0.001)
	assert.Equal(t, 30*time.Second, w.minDwell)
	assert.GreaterOrEqual(t, w.numCPU, 1)
}

func TestCPUWatcher_MinDwellPreventsPrematureRecovery(t *testing.T) {
	// A burst shorter than the smoothing window must not recover sampling
	// the instant CPU% dips, only to re-trip on the next burst: that would
	// cost the agent visibility right when an attack is in progress. With a
	// dwell floor, recovery must wait even though the instantaneous reading
	// is already below the recovery threshold.
	bpf := newMockBPFController()
	cfg := CPUConfig{
		CheckInterval:     time.Second,
		FileShedThreshold: 15,
		AllShedThreshold:  25,
		RecoveryThreshold: 9,
		WindowSize:        1,
		MinDwell:          10 * time.Second,
	}
	w, fc := newTestWatcher(t, cfg, bpf)
	interval := time.Second
	w.checkCPU()

	// Trip to level 1.
	fc.stepFor(16, interval)
	w.checkCPU()
	require.Equal(t, cpuLevelFileShed, w.PressureLevel())

	// CPU immediately drops below recovery, but only ~1s has elapsed in the
	// shed state — well short of the 10s dwell floor. Must stay shed.
	fc.stepFor(2, interval)
	w.checkCPU()
	assert.Equal(t, cpuLevelFileShed, w.PressureLevel())
	assert.Equal(t, 0.1, bpf.GetSamplingRate("file"))

	// Keep CPU low until the dwell floor has elapsed, then it should recover.
	for i := 0; i < 10; i++ {
		fc.stepFor(2, interval)
		w.checkCPU()
	}
	assert.Equal(t, cpuLevelNormal, w.PressureLevel())
	assert.Equal(t, 1.0, bpf.GetSamplingRate("file"))
}

func TestCPUWatcher_ShedIsIdempotent(t *testing.T) {
	bpf := newMockBPFController()
	w := NewCPUPressureWatcher(DefaultCPUConfig(), nil, bpf)

	w.shed("file")
	// A second shed of the same type must not overwrite the saved normal rate
	// nor re-issue the controller call with a stale value.
	bpf.SetSamplingRate("file", 0.5) // simulate external change
	w.shed("file")
	assert.Equal(t, 0.5, bpf.GetSamplingRate("file")) // untouched by the 2nd shed

	// Recovery still restores to the saved normal rate (1.0).
	w.recoverNormalMode()
	assert.Equal(t, 1.0, bpf.GetSamplingRate("file"))
}

func TestSetupCPUPressureWatcher_Disabled(t *testing.T) {
	cfg := DefaultCPUConfig()
	cfg.Enabled = false
	reg := prometheus.NewRegistry()
	w := SetupCPUPressureWatcher(context.Background(), cfg, nil, nil, reg)
	assert.Nil(t, w)
	// Nothing should have been registered.
	families, err := reg.Gather()
	require.NoError(t, err)
	assert.Empty(t, families)
}

func TestSetupCPUPressureWatcher_EnabledRegistersAndRuns(t *testing.T) {
	cfg := DefaultCPUConfig()
	cfg.CheckInterval = 20 * time.Millisecond
	reg := prometheus.NewRegistry()
	bpf := newMockBPFController()

	ctx, cancel := context.WithCancel(context.Background())
	w := SetupCPUPressureWatcher(ctx, cfg, nil, bpf, reg)
	require.NotNil(t, w)

	// Metrics registered.
	families, err := reg.Gather()
	require.NoError(t, err)
	assert.Len(t, families, 2)

	// Let the background goroutine tick at least once, then stop it cleanly.
	time.Sleep(50 * time.Millisecond)
	cancel()
}

func TestSetupCPUPressureWatcher_DuplicateRegistrationLogged(t *testing.T) {
	cfg := DefaultCPUConfig()
	reg := prometheus.NewRegistry()
	// Pre-register a colliding metric so RegisterMetrics fails inside Setup.
	clash := prometheus.NewGauge(prometheus.GaugeOpts{Name: "ebpf_guard_cpu_pressure_level"})
	require.NoError(t, reg.Register(clash))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Must not panic despite the registration error; watcher is still returned.
	w := SetupCPUPressureWatcher(ctx, cfg, nil, nil, reg)
	assert.NotNil(t, w)
}

func TestParseProcStatCPUSeconds(t *testing.T) {
	// Synthetic stat line. Fields 1–2 are pid and comm; the comm deliberately
	// contains spaces and a ')' to exercise the last-paren split. After the
	// comm: state(3)..stime(15). utime=200, stime=100 ticks → 3.0s at 100 Hz.
	line := "1234 (weird )name) S 1 1 1 0 -1 0 10 0 0 0 200 100 0 0 20 0 1 0 999 0 0\n"
	got, err := parseProcStatCPUSeconds(line)
	require.NoError(t, err)
	assert.InDelta(t, 3.0, got, 0.0001)
}

func TestParseProcStatCPUSeconds_Malformed(t *testing.T) {
	cases := map[string]string{
		"no closing paren":    "1234 (proc S 1 1",
		"nothing after paren": "1234 (proc)",
		"too few fields":      "1234 (proc) S 1 1 1",
		"non-numeric utime":   "1234 (proc) S 1 1 1 0 -1 0 10 0 0 0 xx 100 0 0 20 0 1 0 999 0 0",
		"non-numeric stime":   "1234 (proc) S 1 1 1 0 -1 0 10 0 0 0 200 yy 0 0 20 0 1 0 999 0 0",
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parseProcStatCPUSeconds(line)
			assert.Error(t, err)
		})
	}
}
