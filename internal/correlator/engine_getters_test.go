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
