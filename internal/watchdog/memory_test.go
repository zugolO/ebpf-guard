// memory_test.go — Tests for MemoryPressureWatcher

package watchdog

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockControllableProfiler is a mock implementation of ControllableProfiler for testing.
type mockControllableProfiler struct {
	mu           sync.RWMutex
	enabled      bool
	samplingRate float64
}

func newMockProfiler() *mockControllableProfiler {
	return &mockControllableProfiler{
		enabled:      true,
		samplingRate: 1.0,
	}
}

func (m *mockControllableProfiler) Enable() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enabled = true
}

func (m *mockControllableProfiler) Disable() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enabled = false
}

func (m *mockControllableProfiler) IsEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.enabled
}

func (m *mockControllableProfiler) SetSamplingRate(rate float64) {
	// Mirror the real ControllableProfiler contract, which clamps to [0,1]
	// (see profiler.AnomalyDetector / SequenceProfiler.SetSamplingRate).
	if rate < 0.0 {
		rate = 0.0
	}
	if rate > 1.0 {
		rate = 1.0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.samplingRate = rate
}

func (m *mockControllableProfiler) GetSamplingRate() float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.samplingRate
}

// mockBPFController is a mock implementation of BPFSamplingController.
type mockBPFController struct {
	mu    sync.RWMutex
	rates map[string]float64
}

func newMockBPFController() *mockBPFController {
	return &mockBPFController{
		rates: make(map[string]float64),
	}
}

func (m *mockBPFController) SetSamplingRate(eventType string, rate float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rates[eventType] = rate
}

func (m *mockBPFController) GetSamplingRate(eventType string) float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.rates[eventType]
}

func TestMemoryPressureWatcher_DefaultConfig(t *testing.T) {
	config := DefaultMemoryConfig()
	assert.True(t, config.Enabled)
	assert.Equal(t, 5*time.Second, config.CheckInterval)
	assert.Equal(t, 10.0, config.LowMemoryThreshold)
	assert.Equal(t, 20.0, config.RecoveryThreshold)
}

func TestMemoryPressureWatcher_New(t *testing.T) {
	config := DefaultMemoryConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	profiler := newMockProfiler()
	bpfCtrl := newMockBPFController()

	watcher := NewMemoryPressureWatcher(config, logger, []ControllableProfiler{profiler}, bpfCtrl)
	require.NotNil(t, watcher)
	assert.NotNil(t, watcher.logger)
	assert.Equal(t, 10.0, watcher.lowMemoryThreshold)
	assert.Equal(t, 20.0, watcher.recoveryThreshold)
	assert.False(t, watcher.IsLowMemory())
}

func TestMemoryPressureWatcher_RegisterMetrics(t *testing.T) {
	config := DefaultMemoryConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	watcher := NewMemoryPressureWatcher(config, logger, nil, nil)

	reg := prometheus.NewRegistry()
	err := watcher.RegisterMetrics(reg)
	require.NoError(t, err)

	// Verify both metrics are registered. Gather() returns families sorted by
	// name, so "mode" precedes "ratio".
	families, err := reg.Gather()
	require.NoError(t, err)
	require.Len(t, families, 2)
	assert.Equal(t, "ebpf_guard_memory_pressure_mode", *families[0].Name)
	assert.Equal(t, "ebpf_guard_memory_pressure_ratio", *families[1].Name)
}

func TestMemoryPressureWatcher_LowMemoryMode(t *testing.T) {
	profiler := newMockProfiler()
	bpfCtrl := newMockBPFController()

	config := MemoryConfig{
		Enabled:            true,
		CheckInterval:      100 * time.Millisecond,
		LowMemoryThreshold: 50.0,
		RecoveryThreshold:  60.0,
	}

	watcher := NewMemoryPressureWatcher(config, nil, []ControllableProfiler{profiler}, bpfCtrl)

	// Initially not in low memory mode
	assert.False(t, watcher.IsLowMemory())
	assert.True(t, profiler.IsEnabled())
	assert.Equal(t, 1.0, profiler.GetSamplingRate())

	// Simulate entering low memory mode
	watcher.enterLowMemoryMode()

	// Profiler should be disabled and sampling rate reduced
	assert.False(t, profiler.IsEnabled())
	assert.Equal(t, 0.1, profiler.GetSamplingRate())

	// BPF sampling should be reduced
	assert.Equal(t, 0.1, bpfCtrl.GetSamplingRate("syscall"))
	assert.Equal(t, 0.1, bpfCtrl.GetSamplingRate("network"))
	assert.Equal(t, 0.1, bpfCtrl.GetSamplingRate("file"))
}

func TestMemoryPressureWatcher_RecoverNormalMode(t *testing.T) {
	profiler := newMockProfiler()
	bpfCtrl := newMockBPFController()

	config := DefaultMemoryConfig()
	watcher := NewMemoryPressureWatcher(config, nil, []ControllableProfiler{profiler}, bpfCtrl)

	// Enter low memory mode first
	watcher.enterLowMemoryMode()
	assert.False(t, profiler.IsEnabled())

	// Recover normal mode
	watcher.recoverNormalMode()

	// Profiler should be enabled and sampling rate restored
	assert.True(t, profiler.IsEnabled())
	assert.Equal(t, 1.0, profiler.GetSamplingRate())

	// BPF sampling should be restored
	assert.Equal(t, 1.0, bpfCtrl.GetSamplingRate("syscall"))
	assert.Equal(t, 1.0, bpfCtrl.GetSamplingRate("network"))
	assert.Equal(t, 1.0, bpfCtrl.GetSamplingRate("file"))
}

func TestMemoryPressureWatcher_MultipleProfilers(t *testing.T) {
	profiler1 := newMockProfiler()
	profiler2 := newMockProfiler()

	config := DefaultMemoryConfig()
	watcher := NewMemoryPressureWatcher(config, nil, []ControllableProfiler{profiler1, profiler2}, nil)

	// Enter low memory mode
	watcher.enterLowMemoryMode()

	// Both profilers should be disabled
	assert.False(t, profiler1.IsEnabled())
	assert.False(t, profiler2.IsEnabled())
	assert.Equal(t, 0.1, profiler1.GetSamplingRate())
	assert.Equal(t, 0.1, profiler2.GetSamplingRate())

	// Recover
	watcher.recoverNormalMode()

	// Both profilers should be enabled
	assert.True(t, profiler1.IsEnabled())
	assert.True(t, profiler2.IsEnabled())
}

func TestMockControllableProfiler(t *testing.T) {
	p := newMockProfiler()

	// Initial state
	assert.True(t, p.IsEnabled())
	assert.Equal(t, 1.0, p.GetSamplingRate())

	// Disable
	p.Disable()
	assert.False(t, p.IsEnabled())

	// Enable
	p.Enable()
	assert.True(t, p.IsEnabled())

	// Set sampling rate
	p.SetSamplingRate(0.5)
	assert.Equal(t, 0.5, p.GetSamplingRate())

	// Clamp to 0
	p.SetSamplingRate(-0.1)
	assert.Equal(t, 0.0, p.GetSamplingRate())

	// Clamp to 1
	p.SetSamplingRate(1.5)
	assert.Equal(t, 1.0, p.GetSamplingRate())
}

func TestMemoryPressureWatcher_StartStop(t *testing.T) {
	config := MemoryConfig{
		Enabled:       true,
		CheckInterval: 50 * time.Millisecond,
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	watcher := NewMemoryPressureWatcher(config, logger, nil, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	// Start should run until context is cancelled
	done := make(chan struct{})
	go func() {
		watcher.Start(ctx)
		close(done)
	}()

	// Wait for context timeout
	<-done
}

func BenchmarkMemoryPressureWatcher_ReadMemInfo(b *testing.B) {
	config := DefaultMemoryConfig()
	watcher := NewMemoryPressureWatcher(config, nil, nil, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := watcher.readMemInfo()
		if err != nil {
			b.Skip("/proc/meminfo not available")
		}
	}
}
