package correlator

import (
	"context"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/internal/policy"
	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEngineGettersAndLifecycle(t *testing.T) {
	cfg := DefaultCorrelationEngineConfig()
	cfg.EnableEventBuffer = true // exercise GetEvents/GetBuffer accessors
	ce := NewCorrelationEngineWithConfig(cfg)
	ctx := context.Background()

	// Accessors should return non-nil collaborators (or sensible defaults).
	assert.NotNil(t, ce.GetBuffer())
	assert.NotNil(t, ce.GetRateLimiter())
	assert.NotNil(t, ce.IncidentTracker())

	// Learning-state accessors are exercised regardless of whether an anomaly
	// detector is configured (the default config enables one).
	_ = ce.IsLearningComplete()
	prog := ce.LearningProgress()
	assert.GreaterOrEqual(t, prog, 0.0)
	assert.LessOrEqual(t, prog, 1.0)

	// Ingest a benign event so the engine counters advance.
	var comm [16]byte
	copy(comm[:], "proc")
	ce.Ingest(ctx, types.Event{Type: types.EventSyscall, PID: 1, Comm: comm, Syscall: &types.SyscallEvent{Nr: 1}})

	stats := ce.GetStats()
	assert.GreaterOrEqual(t, stats.ProcessedEvents, uint64(1))

	assert.NotNil(t, ce.GetEvents(1))

	// Queue-depth wiring.
	ce.SetQueueDepthFn(func() int { return 3 }, func() int { return 10 })
	assert.InDelta(t, 0.3, ce.QueueDepth(), 1e-9)

	// Optional hooks must accept callbacks without firing immediately.
	ce.SetSyscallFilterUpdater(func(nrs []uint32) {})
	ce.SetSamplingCorrections(map[string]float64{"syscall": 1.0})

	// Rate limiter reconfiguration and rule reload are safe no-panic operations.
	ce.UpdateRateLimiter(time.Minute, 100, true)
	ce.ReloadRules([]Rule{})

	// Draining the enforce queue with an empty queue returns promptly.
	ce.DrainEnforceQueue(ctx)

	// Metrics register cleanly against a fresh registry.
	require.NoError(t, ce.RegisterMetrics(prometheus.NewRegistry()))

	// Flush returns the pending alert slice and resets it.
	_ = ce.Flush()
	assert.Empty(t, ce.Flush())
}

func TestSelectMostSevereDecision(t *testing.T) {
	// Empty input yields the zero decision.
	assert.Equal(t, policy.PolicyDecision{}, selectMostSevereDecision(nil))

	// Single decision is returned as-is.
	single := policy.PolicyDecision{Severity: types.SeverityWarning}
	assert.Equal(t, single, selectMostSevereDecision([]policy.PolicyDecision{single}))

	// Critical wins over warning regardless of order.
	decisions := []policy.PolicyDecision{
		{Severity: types.SeverityWarning},
		{Severity: types.SeverityCritical},
	}
	assert.Equal(t, types.SeverityCritical, selectMostSevereDecision(decisions).Severity)
}

// TestProfilerStats_AggregatesAcrossIngestPool is the P1-10 acceptance test
// (question 7 in plan.md): /debug/state shipped
// `profiler_stats:{learning_complete:false,learning_progress:0,
// profiles_active:0,anomalies_total:0}` during run #4 while the live state
// lived in per-worker detectors the provider never walked. ProfilerStats() must
// sum ProfilesActive and AnomaliesTotal across the whole ingest pool, not just
// the solo detector wired in main.go.
func TestProfilerStats_AggregatesAcrossIngestPool(t *testing.T) {
	const workers = 4
	cfg := DefaultCorrelationEngineConfig()
	cfg.EnableAnomaly = true
	cfg.IngestWorkerCount = workers
	ce := NewCorrelationEngineWithConfig(cfg)
	defer ce.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Sanity: the aggregator sees solo + one detector per worker.
	dets := ce.anomalyDetectors()
	require.Len(t, dets, workers+1, "solo detector + one per ingest worker")

	// Drive profiles into every worker shard by hashing PIDs across all four
	// buckets (ingestMask = workers-1 = 3). Each comm produces a distinct
	// workload profile in whichever worker's profileManager the PID lands in.
	comms := []string{"alpha", "beta", "gamma", "delta", "epsilon", "zeta"}
	for i, name := range comms {
		var c [16]byte
		copy(c[:], name)
		pid := uint32(i * 4) // 0,4,8,16,20 → different hash buckets under mask 3
		ce.IngestAsync(ctx, types.Event{
			Type:    types.EventSyscall,
			PID:     pid,
			Comm:    c,
			Syscall: &types.SyscallEvent{Nr: 1},
		})
	}

	// IngestAsync is fire-and-forget; wait for the workers to drain the queue
	// and populate their profile managers before asserting.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ce.TrackedPIDCount() >= len(comms) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	assert.GreaterOrEqual(t, ce.TrackedPIDCount(), len(comms),
		"events did not reach the worker pool within timeout")

	stats := ce.ProfilerStats()

	// ProfilesActive is the headline P1-10 regression: run #4 read 0 because
	// only the solo (empty) detector was consulted. After aggregation across
	// the pool it must reflect the profiles the workers actually built.
	assert.GreaterOrEqual(t, stats.ProfilesActive, len(comms),
		"ProfilesActive must aggregate across the ingest pool, not read the empty solo detector")

	// Learning phase is gated by the shared learner (engine.go:801-806) that
	// every detector was switched onto at construction, so the engine-level
	// view matches the solo detector regardless of which worker saw events.
	assert.Equal(t, ce.IsLearningComplete(), stats.LearningComplete)
	assert.InDelta(t, ce.LearningProgress(), stats.LearningProgress, 1e-9)

	// Cross-check: sum per-detector ProfilesActive manually and confirm the
	// engine aggregator produces the same total — guards against future
	// refactors that silently drop the solo detector from the sum.
	var manualSum int
	for _, ad := range dets {
		if wpm := ad.GetProfileManager(); wpm != nil {
			manualSum += wpm.Len()
		}
	}
	assert.Equal(t, manualSum, stats.ProfilesActive,
		"ProfilerStats must equal the manual sum over anomalyDetectors()")
}
