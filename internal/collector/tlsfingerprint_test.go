package collector

import (
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTLSFingerprintCollector_Name(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c, err := NewTLSFingerprintCollector(logger)
	require.NoError(t, err)
	assert.Equal(t, "tlsfingerprint", c.Name())
}

func TestTLSFingerprintCollector_InitialState(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c, err := NewTLSFingerprintCollector(logger)
	require.NoError(t, err)

	// Before Start, objs is nil → IsHealthy must be false.
	assert.False(t, c.IsHealthy())
	// No links attached yet.
	assert.False(t, c.IsAttached())
	// No lost events yet.
	assert.Equal(t, uint64(0), c.LostEvents())
	// No load error yet (constructor hasn't tried to load BPF objects).
	assert.NoError(t, c.LoadError())
}

func TestTLSFingerprintCollector_Close_NoObjs(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c, err := NewTLSFingerprintCollector(logger)
	require.NoError(t, err)

	// Close with objs == nil must not panic and must return nil.
	require.NotPanics(t, func() {
		err := c.Close()
		assert.NoError(t, err)
	})
}

func TestTLSFingerprintCollector_WithStatusReporter(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c, err := NewTLSFingerprintCollector(logger)
	require.NoError(t, err)

	var gotName string
	var gotUp bool
	sr := StatusReporterFunc(func(name string, up bool) {
		gotName = name
		gotUp = up
	})

	// WithStatusReporter returns the same collector (builder pattern).
	got := c.WithStatusReporter(sr)
	assert.Same(t, c, got)

	// Trigger a status update via the internal helper to verify wiring.
	c.status.SetUp("tlsfingerprint", true)
	assert.Equal(t, "tlsfingerprint", gotName)
	assert.True(t, gotUp)
}

func TestTLSFingerprintCollector_WithBackpressureStrategy(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c, err := NewTLSFingerprintCollector(logger)
	require.NoError(t, err)

	// WithBackpressureStrategy must return the same pointer (builder pattern).
	got := c.WithBackpressureStrategy(StrategyBlock)
	assert.Same(t, c, got)
	assert.Equal(t, StrategyBlock, c.strategy)
}
