// cpu_test.go — Tests for CPUPressureWatcher

package watchdog

import (
	"context"
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
// the requested per-VPS CPU percentage over that interval.
func (f *fakeClock) stepFor(pct float64, interval time.Duration) {
	f.now = f.now.Add(interval)
	// pct = (cpuDelta / wallDelta) / numCPU * 100
	cpuDelta := pct / 100.0 * interval.Seconds() * float64(f.numCPU)
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
	assert.Equal(t, 15.0, c.CPULimitPercent)
	assert.Equal(t, 15.0, c.FileShedThreshold)
	assert.Equal(t, 25.0, c.AllShedThreshold)
	assert.Equal(t, 9.0, c.RecoveryThreshold)
	assert.Equal(t, 3, c.WindowSize)
}

func TestCPUWatcher_ThresholdSeedingFromLimit(t *testing.T) {
	// Only cpu_limit_percent set; the rest should be derived.
	w := NewCPUPressureWatcher(CPUConfig{CPULimitPercent: 12.0, WindowSize: 1}, nil, nil)
	assert.Equal(t, 12.0, w.fileShedThreshold)
	assert.InDelta(t, 20.0, w.allShedThreshold, 0.001) // 12 * 5/3
	assert.InDelta(t, 7.2, w.recoveryThreshold, 0.001) // 12 * 0.6
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

func TestCPUWatcher_Hysteresis_NoFlapBetweenThresholds(t *testing.T) {
	bpf := newMockBPFController()
	cfg := CPUConfig{
		CheckInterval:     time.Second,
		FileShedThreshold: 15,
		AllShedThreshold:  25,
		RecoveryThreshold: 9,
		WindowSize:        1,
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
