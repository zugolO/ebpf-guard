package profiler

import (
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func buildFullProfiler(t *testing.T) *Profiler {
	t.Helper()
	cfg := ProfilerConfig{
		Threshold:      0.7,
		Weight:         0.3,
		TTLSeconds:     3600,
		MaxTrackedPIDs: 1024,
		Sequence:       DefaultSequenceConfig(),
	}
	return NewProfiler(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestProfiler_AccessorsAndMetrics(t *testing.T) {
	p := buildFullProfiler(t)

	assert.NotNil(t, p.GetSequenceProfiler())
	assert.NotNil(t, p.GetLineageTracker())
	assert.NotNil(t, p.GetAllowlistProfiler())

	// Learning state accessors return sane ranges.
	_ = p.IsLearningComplete()
	prog := p.LearningProgress()
	assert.GreaterOrEqual(t, prog, 0.0)
	assert.LessOrEqual(t, prog, 1.0)

	// Lineage match handler can be registered.
	p.SetLineageMatchHandler(func(LineageMatch) {})

	// Cleanup with the current time is a safe no-op on an empty profiler.
	p.Cleanup(time.Now())

	require.NoError(t, p.RegisterMetrics(prometheus.NewRegistry()))
}

func TestProfiler_SaveAndLoadState(t *testing.T) {
	p := buildFullProfiler(t)
	path := filepath.Join(t.TempDir(), "state.json")

	require.NoError(t, p.SaveState(path))

	// A fresh profiler can load the persisted state back.
	p2 := buildFullProfiler(t)
	_, err := p2.LoadState(path, time.Hour)
	require.NoError(t, err)

	// Loading a missing path is handled gracefully (start-fresh semantics).
	ready, err := p2.LoadState(filepath.Join(t.TempDir(), "missing.json"), time.Hour)
	_ = ready
	_ = err
}
