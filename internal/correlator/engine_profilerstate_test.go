package correlator

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// TestEngine_SaveLoadState_LearningCompleteSurvivesRestart is the 2.4 (P0-3)
// acceptance test. Prior to this fix, main.go called SaveState/LoadState on
// its standalone *profiler.Profiler — a detector that never receives events
// once anomaly detection is enabled, because IngestAsync routes exclusively
// through CorrelationEngine's per-worker detector pool
// (CorrelationEngine.anomalyDetectors()). Persistence therefore always saved
// an empty snapshot and restored into a detector nothing read from:
// ebpf_guard_profiler_state_restored reported success while every restart
// still reset the learning timer to zero (see plan.md волна 2, 2.4, and
// ISSUES-attack-run-2026-08-03.md P0-3).
//
// This test exercises the fixed path end-to-end: an engine's IngestWorkerCount
// pool feeding CorrelationEngine.SaveState/LoadState, matching what main.go
// now calls at startup and shutdown.
func TestEngine_SaveLoadState_LearningCompleteSurvivesRestart(t *testing.T) {
	cfg := DefaultCorrelationEngineConfig()
	cfg.EnableAnomaly = true
	// LearningPeriod must be long enough that LoadState's staleness check
	// (2×LearningPeriod) doesn't expire between SaveState and LoadState below.
	cfg.LearningPeriod = 200 * time.Millisecond
	cfg.MinLearningSamples = 10
	cfg.IngestWorkerCount = 4 // exercise the real multi-worker pool, not the solo detector

	ce := NewCorrelationEngineWithConfig(cfg)
	defer ce.Close()

	detectors := ce.anomalyDetectors()
	require.Len(t, detectors, 5, "solo detector + 4-worker pool")

	// Drive the solo-detector path (ce.Ingest) with enough samples to clear
	// MinLearningSamples, then poll the time gate — mirrors how a long-lived
	// agent completes learning organically before a save.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var comm [16]byte
	copy(comm[:], "sqlmap")
	for i := 0; i < 20; i++ {
		_ = ce.Ingest(ctx, types.Event{
			Type:    types.EventSyscall,
			PID:     4321,
			Comm:    comm,
			Syscall: &types.SyscallEvent{Nr: 1},
		})
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !ce.anomalyDetector.IsLearningComplete() {
		time.Sleep(time.Millisecond)
	}
	require.True(t, ce.anomalyDetector.IsLearningComplete())

	path := filepath.Join(t.TempDir(), "state.json")
	require.NoError(t, ce.SaveState(path))

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NotEmpty(t, data, "state file must not be empty")

	// Restore into a fresh engine with its own freshly constructed detector
	// pool and shared BaselineLearner — the same shape main.go builds on
	// every restart.
	ce2 := NewCorrelationEngineWithConfig(cfg)
	defer ce2.Close()

	for _, ad := range ce2.anomalyDetectors() {
		require.False(t, ad.IsLearningComplete(),
			"sanity: fresh engine's detectors must not start in completed state")
	}

	ready, err := ce2.LoadState(path, cfg.LearningPeriod)
	require.NoError(t, err)
	assert.True(t, ready, "LoadState must report learning was already complete")

	for i, ad := range ce2.anomalyDetectors() {
		assert.True(t, ad.IsLearningComplete(),
			"detector %d must report learning complete immediately after restart — "+
				"this is the P0-3 acceptance criterion: no 5-minute blind window after restart", i)
	}
}

// TestEngine_SaveLoadState_StatsSurviveRestartUnInflated guards the seam where
// 2.4 (persistence across the detector pool) meets 1.75b (/debug/state must
// agree with /metrics).
//
// LoadDetectorsState broadcasts the restored baseline into every detector,
// which is correct for EWMA statistics — each worker scores its own share of
// traffic against the same learned normal. But ProfilerStats aggregates over
// the same detectors, so anything both broadcast AND summed comes back
// multiplied by the detector count. With a 4-worker pool plus the solo
// detector that is a 5x inflation: a saved anomalies_total of 46 would restore
// as 230, reintroducing the exact /debug/state-vs-/metrics divergence 1.75b
// closed, and corrupting the замер №2 criterion that the two must match.
//
// The invariant asserted here is simply that a save/restore round-trip is
// identity for both reported figures.
func TestEngine_SaveLoadState_StatsSurviveRestartUnInflated(t *testing.T) {
	cfg := DefaultCorrelationEngineConfig()
	cfg.EnableAnomaly = true
	cfg.AnomalyThreshold = 0.0 // every scored event is anomalous
	cfg.LearningPeriod = 200 * time.Millisecond
	cfg.MinLearningSamples = 10
	cfg.EnableRateLimit = false
	cfg.EnableDedup = false
	cfg.IngestWorkerCount = 4

	ce := NewCorrelationEngineWithConfig(cfg)
	defer ce.Close()
	require.Len(t, ce.anomalyDetectors(), 5, "solo detector + 4-worker pool")

	ctx := context.Background()
	var comm [16]byte
	copy(comm[:], "sqlmap")

	for i := 0; i < 20; i++ {
		_ = ce.Ingest(ctx, types.Event{
			Type: types.EventSyscall, PID: 4321, Comm: comm,
			Syscall: &types.SyscallEvent{Nr: 1},
		})
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !ce.anomalyDetector.IsLearningComplete() {
		time.Sleep(time.Millisecond)
	}
	require.True(t, ce.anomalyDetector.IsLearningComplete())

	// Publish a few anomalies so AlertCount is non-zero and the inflation, if
	// present, is observable rather than 0*N == 0.
	const publishCount = 3
	for i := 0; i < publishCount; i++ {
		require.NotEmpty(t, ce.Ingest(ctx, types.Event{
			Type: types.EventSyscall, PID: 4321, Comm: comm,
			Syscall: &types.SyscallEvent{Nr: 1},
		}), "post-learning event must emit an anomaly alert under threshold=0")
	}

	before := ce.ProfilerStats()
	require.Equal(t, uint64(publishCount), before.AnomaliesTotal,
		"sanity: pre-save tally must equal what was published")
	require.Equal(t, 1, before.ProfilesActive, "sanity: one workload was exercised")

	path := filepath.Join(t.TempDir(), "state.json")
	require.NoError(t, ce.SaveState(path))

	ce2 := NewCorrelationEngineWithConfig(cfg)
	defer ce2.Close()
	_, err := ce2.LoadState(path, cfg.LearningPeriod)
	require.NoError(t, err)

	after := ce2.ProfilerStats()
	assert.Equal(t, before.AnomaliesTotal, after.AnomaliesTotal,
		"anomalies_total must survive a restart unchanged, not multiplied by the "+
			"detector count — /debug/state and /metrics diverge again otherwise (1.75b)")
	assert.Equal(t, before.ProfilesActive, after.ProfilesActive,
		"profiles_active counts distinct workloads; broadcasting one restored "+
			"workload into N detectors must not report it as N workloads")
}
