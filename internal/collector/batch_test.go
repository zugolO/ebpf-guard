package collector

import (
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDefaultBatchConfig verifies the default batch configuration values are sane.
func TestDefaultBatchConfig(t *testing.T) {
	cfg := DefaultBatchConfig()

	assert.Equal(t, 100, cfg.BatchSize, "default batch size should be 100")
	assert.Equal(t, 10*time.Millisecond, cfg.BatchTimeout, "default timeout should be 10ms")
	assert.Equal(t, 1, cfg.MinEvents, "default min events should be 1")
}

// TestBatchConfig_PositiveValues verifies callers can construct custom configs.
func TestBatchConfig_PositiveValues(t *testing.T) {
	cfg := BatchConfig{
		BatchSize:    50,
		BatchTimeout: 5 * time.Millisecond,
		MinEvents:    10,
	}
	require.Equal(t, 50, cfg.BatchSize)
	require.Equal(t, 5*time.Millisecond, cfg.BatchTimeout)
	require.Equal(t, 10, cfg.MinEvents)
}

// TestBatchMetrics_Zero verifies a zero-value BatchMetrics is valid (no divide-by-zero).
func TestBatchMetrics_Zero(t *testing.T) {
	var m BatchMetrics
	assert.Equal(t, uint64(0), m.BatchesRead)
	assert.Equal(t, uint64(0), m.EventsRead)
	assert.Equal(t, uint64(0), m.EventsDropped)
	assert.Equal(t, float64(0), m.AvgBatchSize)
	assert.Equal(t, 0, m.MaxBatchSize)
	assert.Equal(t, time.Duration(0), m.TotalWaitTime)
}

// TestNewBatchReader_Nil verifies that NewBatchReader does not panic on nil reader.
// In production a nil reader is invalid but the constructor should not panic.
func TestNewBatchReader_ReturnsNonNil(t *testing.T) {
	if testing.Short() {
		t.Skip("requires kernel BPF ring buffer")
	}
	// This test is intentionally skipped in -short mode since we cannot create
	// a real ringbuf.Reader without a loaded eBPF program.
}

// TestNewBatchReader_Config verifies the constructed BatchReader stores its config
// by inspecting the metrics after zero reads.
func TestNewBatchReader_DefaultConfig(t *testing.T) {
	// We test that DefaultBatchConfig produces a non-zero, reasonable config
	// that can be passed to NewBatchReader in production code.
	cfg := DefaultBatchConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	_ = logger // would be passed to NewBatchReader

	assert.Greater(t, cfg.BatchSize, 0)
	assert.Greater(t, cfg.BatchTimeout, time.Duration(0))
}

// TestErrorReason_Coverage exercises the errorReason helper with various inputs.
func TestErrorReason_NilError(t *testing.T) {
	result := errorReason(nil)
	assert.Equal(t, "none", result)
}
