package correlator

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// TestProfilerStats_ReflectsPublishedAnomalies is the 1.75b end-to-end
// acceptance test (plan.md волна 1.75b). The unit test in
// internal/profiler/anomaly_alertcount_test.go proves RecordPublishedAnomaly
// bumps profile.AlertCount; this test proves the engine calls it on the
// publish path (after dedup + rate-limit), so ProfilerStats().AnomaliesTotal
// — which sums AlertCount across the ingest pool — advances in lock-step with
// the anomaly alerts main.go dispatches to Prometheus.
//
// In замер №1 /debug/state shipped anomalies_total=0 while /metrics read 46
// because AlertCount was only ever written during persistence restore. After
// 1.75b the two views must converge by construction.
func TestProfilerStats_ReflectsPublishedAnomalies(t *testing.T) {
	cfg := DefaultCorrelationEngineConfig()
	cfg.EnableAnomaly = true
	cfg.AnomalyThreshold = 0.0 // any scored event is anomalous (0 >= 0)
	cfg.LearningPeriod = 1 * time.Millisecond
	cfg.MinLearningSamples = 10
	cfg.EWMAWeight = 0.5
	cfg.EnableRateLimit = false
	cfg.EnableDedup = false
	cfg.IngestWorkerCount = 0 // force solo detector path (no worker pool)

	ce := NewCorrelationEngineWithConfig(cfg)
	defer ce.Close()
	require.NotNil(t, ce.anomalyDetector, "solo AnomalyDetector must be wired when EnableAnomaly=true")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var comm [16]byte
	copy(comm[:], "sqlmap")

	// Drive enough samples to clear the MinLearningSamples gate on the solo
	// detector. The sample gate is hit well within this loop; the time gate
	// (LearningPeriod) is polled for below — without an explicit wait the
	// loop can complete in <LearningPeriod on a fast machine and the
	// post-loop assertion races the wall clock.
	for i := 0; i < 20; i++ {
		_ = ce.Ingest(ctx, types.Event{
			Type:    types.EventSyscall,
			PID:     4321,
			Comm:    comm,
			Syscall: &types.SyscallEvent{Nr: 1},
		})
	}
	// Poll IsLearningComplete rather than asserting once: the time gate is
	// 1ms but 20 synchronous ingests can complete faster on an idle CPU,
	// flipping the check into a wall-clock race.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !ce.anomalyDetector.IsLearningComplete() {
		time.Sleep(time.Millisecond)
	}
	require.True(t, ce.anomalyDetector.IsLearningComplete(),
		"learning must complete before anomaly scoring is reachable")

	before := ce.ProfilerStats().AnomaliesTotal

	// Send events after learning. Threshold=0 means every scored event emits
	// an anomaly alert; with dedup and rate-limit off, each one reaches the
	// publish path that calls ad.RecordPublishedAnomaly.
	const publishCount = 3
	for i := 0; i < publishCount; i++ {
		alerts := ce.Ingest(ctx, types.Event{
			Type:    types.EventSyscall,
			PID:     4321,
			Comm:    comm,
			Syscall: &types.SyscallEvent{Nr: 1},
		})
		require.NotEmpty(t, alerts,
			"post-learning event must emit an anomaly alert under threshold=0 — "+
				"if this fails, the rest of the test does not exercise the publish path")
		for _, a := range alerts {
			require.Equal(t, "anomaly_detection", a.RuleID,
				"only anomaly_detection alerts are expected in this scenario")
		}
	}

	after := ce.ProfilerStats().AnomaliesTotal
	assert.Equal(t, before+publishCount, after,
		"ProfilerStats().AnomaliesTotal must equal the number of published anomaly "+
			"alerts — this is the convergence between /debug/state and /metrics that 1.75b restores")
}
