package watchdog

import (
	"io"
	"log/slog"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newDrivableWatcher() *MemoryPressureWatcher {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	seq := []ControllableProfiler{newMockProfiler()}
	all := []ControllableProfiler{newMockProfiler()}
	return NewMemoryPressureWatcherWithSequence(MemoryConfig{
		DisableSequenceThreshold: 10,
		DisableAllThreshold:      5,
		RecoveryThreshold:        20,
	}, logger, seq, all, newMockBPFController())
}

// TestMemoryPressure_StateMachine drives checkMemory through every transition by
// mutating the thresholds so the live /proc/meminfo reading lands in each band.
func TestMemoryPressure_StateMachine(t *testing.T) {
	w := newDrivableWatcher()
	assert.Equal(t, pressureLevelNormal, w.PressureLevel())
	assert.False(t, w.IsLowMemory())

	// Force "sequence disabled": availPct is below the sequence threshold but
	// above the all-disabled threshold.
	w.disableSequenceThreshold = 101
	w.disableAllThreshold = -1
	w.checkMemory()
	assert.Equal(t, pressureLevelSequenceDisabled, w.PressureLevel())
	assert.True(t, w.IsLowMemory())

	// Escalate to "all disabled".
	w.disableAllThreshold = 101
	w.checkMemory()
	assert.Equal(t, pressureLevelAllDisabled, w.PressureLevel())

	// Recover to normal: availPct above recovery threshold.
	w.disableAllThreshold = -1
	w.recoveryThreshold = -1
	w.checkMemory()
	assert.Equal(t, pressureLevelNormal, w.PressureLevel())

	// Normal → all-disabled directly (deep pressure).
	w.disableAllThreshold = 101
	w.checkMemory()
	assert.Equal(t, pressureLevelAllDisabled, w.PressureLevel())

	// Recover again from all-disabled.
	w.disableAllThreshold = -1
	w.checkMemory()
	assert.Equal(t, pressureLevelNormal, w.PressureLevel())

	// Sequence-disabled → recover path.
	w.disableSequenceThreshold = 101
	w.disableAllThreshold = -1
	w.checkMemory()
	assert.Equal(t, pressureLevelSequenceDisabled, w.PressureLevel())
	w.disableSequenceThreshold = -1
	w.checkMemory()
	assert.Equal(t, pressureLevelNormal, w.PressureLevel())
}

func TestMemoryPressureWatcher_RegisterMetricsExtra(t *testing.T) {
	w := newDrivableWatcher()
	require.NoError(t, w.RegisterMetrics(prometheus.NewRegistry()))
}

func TestMemoryPressureWatcher_ReadMemInfo(t *testing.T) {
	w := newDrivableWatcher()
	avail, total, err := w.readMemInfo()
	require.NoError(t, err)
	assert.Greater(t, total, uint64(0))
	assert.LessOrEqual(t, avail, total)
}
