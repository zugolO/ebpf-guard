package profiler

import (
	"io"
	"log/slog"
	"os"
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

func TestProfiler_SaveAndLoadAllowlistState(t *testing.T) {
	p := buildFullProfiler(t)
	path := filepath.Join(t.TempDir(), "state.json")

	require.NoError(t, p.SaveAllowlistState(path))

	// A fresh profiler can load the persisted allowlist state back.
	p2 := buildFullProfiler(t)
	p2.LoadAllowlistState(path)

	// Loading a missing path is handled gracefully (start-fresh semantics).
	p2.LoadAllowlistState(filepath.Join(t.TempDir(), "missing.json"))
}

// TestDetectorsState_SaveAndLoad_LearningCompletePreserved is the P0-3
// acceptance test. It exercises SaveDetectorsState/LoadDetectorsState against
// a *pool* of detectors, the shape CorrelationEngine.SaveState/LoadState
// actually persists — a single *Profiler's own detector (p.detector) never
// receives events once anomaly detection is enabled, since IngestAsync routes
// exclusively through the engine's per-worker detector pool. A test that
// round-trips through p.detector alone (the pre-fix version of this test)
// would pass while the real restart path stayed broken.
func TestDetectorsState_SaveAndLoad_LearningCompletePreserved(t *testing.T) {
	learningPeriod := time.Hour
	pool := []*AnomalyDetector{
		NewAnomalyDetector(0.7, learningPeriod, 0.3),
		NewAnomalyDetector(0.7, learningPeriod, 0.3),
	}

	// Force learning to complete without waiting out the real learning period.
	pool[0].learner.mu.Lock()
	pool[0].learner.learningComplete = true
	pool[0].learner.mu.Unlock()
	pool[0].learningComplete.Store(true)
	require.True(t, pool[0].IsLearningComplete())

	path := filepath.Join(t.TempDir(), "state.json")
	require.NoError(t, SaveDetectorsState(pool, path))

	freshPool := []*AnomalyDetector{
		NewAnomalyDetector(0.7, learningPeriod, 0.3),
		NewAnomalyDetector(0.7, learningPeriod, 0.3),
	}
	require.False(t, freshPool[0].IsLearningComplete(), "sanity: fresh detector should not start as learning-complete")
	require.False(t, freshPool[1].IsLearningComplete(), "sanity: fresh detector should not start as learning-complete")

	ready, err := LoadDetectorsState(freshPool, path, learningPeriod)
	require.NoError(t, err)
	assert.True(t, ready, "LoadDetectorsState should report learning was already complete")
	assert.True(t, freshPool[0].IsLearningComplete(), "IsLearningComplete() must be preserved across save/load for every detector in the pool")
	assert.True(t, freshPool[1].IsLearningComplete(), "IsLearningComplete() must be preserved across save/load for every detector in the pool")
}

// TestSaveDetectorsState_NoDetectorsDoesNotTruncate covers the configuration
// where the profiler is disabled but state persistence is still switched on.
//
// CorrelationEngine.anomalyDetectors() returns nothing when EnableAnomaly is
// false, and gracefulShutdown calls engine.SaveState whenever
// state_persistence.Enabled — the prof != nil guard that used to sit there was
// dropped when persistence moved from *Profiler to the engine. Without a guard
// inside SaveDetectorsState, that combination overwrites a state file written
// by an earlier run with the profiler enabled, and P0-3 silently comes back on
// the next toggle.
func TestSaveDetectorsState_NoDetectorsDoesNotTruncate(t *testing.T) {
	learningPeriod := time.Hour
	path := filepath.Join(t.TempDir(), "state.json")

	// A previous run, with the profiler enabled, persisted completed learning.
	seeded := []*AnomalyDetector{NewAnomalyDetector(0.7, learningPeriod, 0.3)}
	seeded[0].learner.mu.Lock()
	seeded[0].learner.learningComplete = true
	seeded[0].learner.mu.Unlock()
	seeded[0].learningComplete.Store(true)
	require.NoError(t, SaveDetectorsState(seeded, path))

	original, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NotEmpty(t, original)

	// This run has the profiler disabled: no detectors at all, and a slice of
	// nils (the shape a partially-built pool would produce).
	require.NoError(t, SaveDetectorsState(nil, path))
	require.NoError(t, SaveDetectorsState([]*AnomalyDetector{nil, nil}, path))

	after, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, string(original), string(after),
		"saving with no live detectors must leave the existing state file untouched")

	// The preserved file must still restore learning-complete.
	fresh := []*AnomalyDetector{NewAnomalyDetector(0.7, learningPeriod, 0.3)}
	ready, err := LoadDetectorsState(fresh, path, learningPeriod)
	require.NoError(t, err)
	assert.True(t, ready, "the surviving state file must still restore completed learning")
}
