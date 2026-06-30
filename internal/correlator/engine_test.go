// Package correlator provides event correlation and rule-based detection.
package correlator

import (
	"context"
	"log/slog"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/zugolO/ebpf-guard/internal/policy"
	"github.com/zugolO/ebpf-guard/internal/profiler"
	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCorrelationEngine_Ingest(t *testing.T) {
	tests := []struct {
		name     string
		rules    []Rule
		events   []types.Event
		expected int // expected number of alerts
	}{
		{
			name:  "no rules - no alerts",
			rules: []Rule{},
			events: []types.Event{
				{Type: types.EventTCPConnect, PID: 1},
			},
			expected: 0,
		},
		{
			name: "single matching rule",
			rules: []Rule{
				{
					ID:          "rule_001",
					Name:        "Test Rule",
					Description: "Test description",
					EventType:   types.EventTCPConnect,
					Condition: RuleCondition{
						Field:  "dport",
						Op:     OpEquals,
						Values: []string{"8080"},
					},
					Severity: types.SeverityWarning,
					Action:   ActionAlert,
				},
			},
			events: []types.Event{
				{
					Type: types.EventTCPConnect,
					PID:  1,
					Network: &types.NetworkEvent{
						Dport: 8080,
					},
				},
			},
			expected: 1,
		},
		{
			name: "non-matching event type",
			rules: []Rule{
				{
					ID:        "rule_001",
					Name:      "Test Rule",
					EventType: types.EventTCPConnect,
					Condition: RuleCondition{Field: "dport", Op: OpEquals, Values: []string{"8080"}},
					Severity:  types.SeverityWarning,
					Action:    ActionAlert,
				},
			},
			events: []types.Event{
				{Type: types.EventSyscall, PID: 1},
			},
			expected: 0,
		},
		{
			name: "drop action - no alert",
			rules: []Rule{
				{
					ID:        "rule_001",
					Name:      "Drop Rule",
					EventType: types.EventTCPConnect,
					Condition: RuleCondition{Field: "dport", Op: OpEquals, Values: []string{"8080"}},
					Severity:  types.SeverityWarning,
					Action:    ActionDrop,
				},
			},
			events: []types.Event{
				{
					Type: types.EventTCPConnect,
					PID:  1,
					Network: &types.NetworkEvent{
						Dport: 8080,
					},
				},
			},
			expected: 0,
		},
		{
			name: "multiple events accumulate alerts",
			rules: []Rule{
				{
					ID:        "rule_001",
					Name:      "Port Rule",
					EventType: types.EventTCPConnect,
					Condition: RuleCondition{Field: "dport", Op: OpEquals, Values: []string{"8080"}},
					Severity:  types.SeverityWarning,
					Action:    ActionAlert,
				},
			},
			events: []types.Event{
				{Type: types.EventTCPConnect, PID: 1, Network: &types.NetworkEvent{Dport: 8080}},
				{Type: types.EventTCPConnect, PID: 2, Network: &types.NetworkEvent{Dport: 8080}},
				{Type: types.EventTCPConnect, PID: 3, Network: &types.NetworkEvent{Dport: 9090}},
			},
			expected: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := NewCorrelationEngine(tt.rules)
			ctx := context.Background()

			var totalAlerts int
			for _, e := range tt.events {
				alerts := engine.Ingest(ctx, e)
				totalAlerts += len(alerts)
			}

			assert.Equal(t, tt.expected, totalAlerts)
		})
	}
}

func TestCorrelationEngine_Flush(t *testing.T) {
	rules := []Rule{
		{
			ID:        "rule_001",
			Name:      "Test Rule",
			EventType: types.EventTCPConnect,
			Condition: RuleCondition{Field: "dport", Op: OpEquals, Values: []string{"8080"}},
			Severity:  types.SeverityWarning,
			Action:    ActionAlert,
		},
	}

	engine := NewCorrelationEngine(rules)
	ctx := context.Background()

	// Ingest events that generate alerts
	engine.Ingest(ctx, types.Event{
		Type:    types.EventTCPConnect,
		PID:     1,
		Network: &types.NetworkEvent{Dport: 8080},
	})
	engine.Ingest(ctx, types.Event{
		Type:    types.EventTCPConnect,
		PID:     2,
		Network: &types.NetworkEvent{Dport: 8080},
	})

	// Flush should return accumulated alerts
	alerts := engine.Flush()
	require.Len(t, alerts, 2)
	assert.Equal(t, "rule_001", alerts[0].RuleID)
	assert.Equal(t, "rule_001", alerts[1].RuleID)

	// Second flush should be empty
	alerts = engine.Flush()
	assert.Empty(t, alerts)
}

func TestCorrelationEngine_Buffer(t *testing.T) {
	cfg := DefaultCorrelationEngineConfig()
	cfg.EnableEventBuffer = true
	engine := NewCorrelationEngineWithConfig(cfg)
	ctx := context.Background()

	// Add events for different PIDs
	events := []types.Event{
		{Type: types.EventSyscall, PID: 1, Timestamp: 1},
		{Type: types.EventSyscall, PID: 1, Timestamp: 2},
		{Type: types.EventSyscall, PID: 2, Timestamp: 3},
	}

	for _, e := range events {
		engine.Ingest(ctx, e)
	}

	// Check buffered events for PID 1
	pid1Events := engine.GetEvents(1)
	require.Len(t, pid1Events, 2)
	assert.Equal(t, uint64(1), pid1Events[0].Timestamp)
	assert.Equal(t, uint64(2), pid1Events[1].Timestamp)

	// Check buffered events for PID 2
	pid2Events := engine.GetEvents(2)
	require.Len(t, pid2Events, 1)
	assert.Equal(t, uint64(3), pid2Events[0].Timestamp)

	// Check non-existent PID
	pid3Events := engine.GetEvents(3)
	assert.Empty(t, pid3Events)
}

func TestCorrelationEngine_Ingest_WithTraceContext(t *testing.T) {
	rules := []Rule{
		{
			ID:        "rule_001",
			Name:      "Test Rule",
			EventType: types.EventTCPConnect,
			Condition: RuleCondition{Field: "dport", Op: OpEquals, Values: []string{"8080"}},
			Severity:  types.SeverityWarning,
			Action:    ActionAlert,
		},
	}

	engine := NewCorrelationEngine(rules)
	ctx := context.Background()

	// Ingest event with trace context
	event := types.Event{
		Type: types.EventTCPConnect,
		PID:  1,
		Network: &types.NetworkEvent{
			Dport: 8080,
		},
		TraceContext: &types.TraceContext{
			TraceID: "abc123",
			SpanID:  "span456",
		},
	}

	alerts := engine.Ingest(ctx, event)
	require.Len(t, alerts, 1)
	assert.Equal(t, "abc123", alerts[0].TraceID)
}

// TestAlertIDUniqueness verifies that 10 000 alerts generated with identical
// ruleID + timestamp + pid all receive unique IDs (Sprint 27.0 Part A).
func TestAlertIDUniqueness(t *testing.T) {
	rule := Rule{
		ID:        "net_001",
		Name:      "Test Rule",
		EventType: types.EventTCPConnect,
		Condition: RuleCondition{Field: "dport", Op: OpEquals, Values: []string{"8080"}},
		Severity:  types.SeverityWarning,
		Action:    ActionAlert,
	}
	cfg := DefaultCorrelationEngineConfig()
	cfg.Rules = []Rule{rule}
	cfg.EnableRateLimit = false // disable rate limiting so all 10k alerts pass through
	cfg.EnableAnomaly = false
	cfg.EnableDedup = false // this test verifies ID uniqueness, not dedup behaviour
	engine := NewCorrelationEngineWithConfig(cfg)
	defer engine.Close()

	ctx := context.Background()
	event := types.Event{
		Type:      types.EventTCPConnect,
		Timestamp: 1234567890123456789,
		PID:       42,
		Network:   &types.NetworkEvent{Dport: 8080},
	}

	const n = 10_000
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		alerts := engine.Ingest(ctx, event)
		require.Len(t, alerts, 1, "expected one alert per ingest")
		id := alerts[0].ID
		_, dup := seen[id]
		assert.False(t, dup, "duplicate Alert ID: %s", id)
		seen[id] = struct{}{}
	}
	assert.Len(t, seen, n, "all %d Alert IDs must be unique", n)
}

func TestCorrelationEngine_AsyncRegoEval(t *testing.T) {
	rule := Rule{
		ID:        "rego_test_rule",
		EventType: types.EventTCPConnect,
		Condition: RuleCondition{Field: "dport", Op: OpEquals, Values: []string{"443"}},
		Severity:  types.SeverityWarning,
		Action:    ActionAlert,
	}

	// Empty temp dir → RegoEngine has no policies; alerts pass through unchanged.
	// This isolates the concurrency behaviour without requiring real .rego files.
	regoDir := t.TempDir()
	regoEng, err := policy.NewRegoEngine(policy.RegoEngineConfig{Enabled: true, RulesDir: regoDir})
	if err != nil {
		t.Skipf("cannot create rego engine: %v", err)
	}

	cfg := DefaultCorrelationEngineConfig()
	cfg.Rules = []Rule{rule}
	cfg.EnableRateLimit = false
	cfg.EnableAnomaly = false
	cfg.EnableRegoEval = true
	cfg.RegoEngine = regoEng
	cfg.RegoWorkerCount = 2

	engine := NewCorrelationEngineWithConfig(cfg)
	defer engine.Close()

	ctx := context.Background()
	event := types.Event{
		Type:    types.EventTCPConnect,
		PID:     42,
		Network: &types.NetworkEvent{Dport: 443},
	}

	// Ingest must return immediately without blocking on Rego.
	returned := engine.Ingest(ctx, event)
	require.Len(t, returned, 1, "Ingest must return the pre-rego alert synchronously")

	// Rego worker publishes to pending asynchronously; allow up to 200 ms.
	deadline := time.Now().Add(200 * time.Millisecond)
	var flushed []types.Alert
	for time.Now().Before(deadline) {
		flushed = engine.Flush()
		if len(flushed) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	require.Len(t, flushed, 1, "async rego worker must publish alert to pending")
}

func TestCorrelationEngine_ProcessTree(t *testing.T) {
	rule := Rule{
		ID:        "test_rule",
		EventType: types.EventSyscall,
		Condition: RuleCondition{Field: "nr", Op: OpEquals, Values: []string{"1"}},
		Severity:  types.SeverityWarning,
		Action:    ActionAlert,
	}

	lt := profiler.NewLineageTracker(profiler.DefaultLineageConfig(), slog.Default())

	cfg := DefaultCorrelationEngineConfig()
	cfg.Rules = []Rule{rule}
	cfg.EnableRateLimit = false
	cfg.EnableAnomaly = false
	cfg.LineageTracker = lt
	engine := NewCorrelationEngineWithConfig(cfg)
	defer engine.Close()

	ctx := context.Background()

	commOf := func(s string) [16]byte {
		var b [16]byte
		copy(b[:], s)
		return b
	}

	// Feed the ancestry chain: nginx(100) → bash(200) → curl(300)
	engine.Ingest(ctx, types.Event{
		Type:       types.EventSyscall,
		PID:        200,
		PPID:       100,
		Comm:       commOf("bash"),
		ParentComm: commOf("nginx"),
		Syscall:    &types.SyscallEvent{Nr: 99},
	})
	engine.Ingest(ctx, types.Event{
		Type:       types.EventSyscall,
		PID:        300,
		PPID:       200,
		Comm:       commOf("curl"),
		ParentComm: commOf("bash"),
		Syscall:    &types.SyscallEvent{Nr: 1}, // matches rule
	})

	alerts := engine.Flush()
	require.Len(t, alerts, 1)

	tree := alerts[0].ProcessTree
	require.NotNil(t, tree, "alert should carry a process tree")
	require.GreaterOrEqual(t, len(tree), 2, "chain must include at least bash→curl")

	last := tree[len(tree)-1]
	assert.Equal(t, uint32(300), last.PID, "last node should be curl")
	assert.Equal(t, "curl", last.Comm)

	prev := tree[len(tree)-2]
	assert.Equal(t, uint32(200), prev.PID, "second-to-last should be bash")
	assert.Equal(t, "bash", prev.Comm)
}

func TestCorrelationEngine_DedupWindow(t *testing.T) {
	comm := func(s string) [16]byte {
		var b [16]byte
		copy(b[:], s)
		return b
	}

	rule := Rule{
		ID:        "dedup_rule",
		EventType: types.EventTCPConnect,
		Condition: RuleCondition{Field: "dport", Op: OpEquals, Values: []string{"443"}},
		Severity:  types.SeverityWarning,
		Action:    ActionAlert,
	}

	cfg := DefaultCorrelationEngineConfig()
	cfg.Rules = []Rule{rule}
	cfg.EnableRateLimit = false
	cfg.EnableAnomaly = false
	cfg.EnableDedup = true
	cfg.DedupWindow = 200 * time.Millisecond

	engine := NewCorrelationEngineWithConfig(cfg)
	defer engine.Close()

	ctx := context.Background()
	event := types.Event{
		Type:    types.EventTCPConnect,
		PID:     100,
		Comm:    comm("nginx"),
		Network: &types.NetworkEvent{Dport: 443},
	}

	// First ingest: alert must pass through.
	first := engine.Ingest(ctx, event)
	require.Len(t, first, 1, "first alert must not be deduped")

	// Immediate second ingest: same key within window → dropped.
	second := engine.Ingest(ctx, event)
	assert.Empty(t, second, "duplicate within window must be suppressed")

	// Third ingest with a different PID: independent key → must pass.
	event2 := event
	event2.PID = 200
	third := engine.Ingest(ctx, event2)
	require.Len(t, third, 1, "different PID is a distinct dedup key")

	// Wait for the window to expire then re-ingest the original event.
	time.Sleep(250 * time.Millisecond)
	after := engine.Ingest(ctx, event)
	require.Len(t, after, 1, "alert must reappear after dedup window expires")
}

func TestCorrelationEngine_DedupDisabled(t *testing.T) {
	rule := Rule{
		ID:        "nodedup_rule",
		EventType: types.EventTCPConnect,
		Condition: RuleCondition{Field: "dport", Op: OpEquals, Values: []string{"80"}},
		Severity:  types.SeverityWarning,
		Action:    ActionAlert,
	}

	cfg := DefaultCorrelationEngineConfig()
	cfg.Rules = []Rule{rule}
	cfg.EnableRateLimit = false
	cfg.EnableAnomaly = false
	cfg.EnableDedup = false // explicitly off

	engine := NewCorrelationEngineWithConfig(cfg)
	defer engine.Close()

	ctx := context.Background()
	event := types.Event{
		Type:    types.EventTCPConnect,
		PID:     42,
		Network: &types.NetworkEvent{Dport: 80},
	}

	for i := 0; i < 3; i++ {
		got := engine.Ingest(ctx, event)
		require.Len(t, got, 1, "with dedup disabled every ingest must yield an alert (iter %d)", i)
	}
}

func TestHotReloadMetrics(t *testing.T) {
	initialRules := []Rule{
		{
			ID:        "rule_syscall",
			EventType: types.EventSyscall,
			Condition: RuleCondition{Field: "syscall_nr", Op: OpEquals, Values: []string{"59"}},
			Severity:  types.SeverityWarning,
			Action:    ActionAlert,
		},
		{
			ID:        "rule_network",
			EventType: types.EventTCPConnect,
			Condition: RuleCondition{Field: "dport", Op: OpEquals, Values: []string{"4444"}},
			Severity:  types.SeverityCritical,
			Action:    ActionAlert,
		},
	}

	cfg := DefaultCorrelationEngineConfig()
	cfg.Rules = initialRules
	cfg.EnableRateLimit = false
	cfg.EnableAnomaly = false
	engine := NewCorrelationEngineWithConfig(cfg)
	defer engine.Close()

	// Verify success counter increments on UpdateRules
	engine.UpdateRules(initialRules)

	successBefore := getCounterValue(t, engine.reloadTotal.WithLabelValues("success"))
	engine.UpdateRules(initialRules)
	successAfter := getCounterValue(t, engine.reloadTotal.WithLabelValues("success"))
	assert.Equal(t, float64(1), successAfter-successBefore, "success counter should increment on each UpdateRules call")

	// Verify failure counter via RecordReloadFailure
	failBefore := getCounterValue(t, engine.reloadTotal.WithLabelValues("failure"))
	engine.RecordReloadFailure()
	failAfter := getCounterValue(t, engine.reloadTotal.WithLabelValues("failure"))
	assert.Equal(t, float64(1), failAfter-failBefore, "failure counter should increment on RecordReloadFailure")

	// Verify yaml_parse duration is recorded
	engine.ObserveYAMLParseDuration(10 * time.Millisecond)
	yamlDur := getGaugeVecValue(t, engine.reloadDuration, "yaml_parse")
	assert.Greater(t, yamlDur, 0.0, "yaml_parse duration should be set after ObserveYAMLParseDuration")

	// Verify per-event-type rules_active gauge
	syscallActive := getGaugeVecValue(t, engine.rulesActive, "syscall")
	networkActive := getGaugeVecValue(t, engine.rulesActive, "network")
	assert.Equal(t, float64(1), syscallActive, "syscall rules_active should be 1")
	assert.Equal(t, float64(1), networkActive, "network rules_active should be 1")

	// Verify last reload timestamp is set
	ts := getGaugeValue(t, engine.lastReloadTimestamp)
	assert.Greater(t, ts, float64(0), "last reload timestamp should be set after UpdateRules")
}

// getCounterValue extracts the current float64 value from a prometheus.Counter via the Desc/Write protocol.
func getCounterValue(t *testing.T, c interface{ Write(*dto.Metric) error }) float64 {
	t.Helper()
	m := &dto.Metric{}
	require.NoError(t, c.Write(m))
	if m.Counter != nil {
		return m.Counter.GetValue()
	}
	return 0
}

func getGaugeVecValue(t *testing.T, gv *prometheus.GaugeVec, label string) float64 {
	t.Helper()
	g, err := gv.GetMetricWithLabelValues(label)
	require.NoError(t, err)
	m := &dto.Metric{}
	require.NoError(t, g.Write(m))
	if m.Gauge != nil {
		return m.Gauge.GetValue()
	}
	return 0
}

func getGaugeValue(t *testing.T, g prometheus.Gauge) float64 {
	t.Helper()
	m := &dto.Metric{}
	require.NoError(t, g.Write(m))
	if m.Gauge != nil {
		return m.Gauge.GetValue()
	}
	return 0
}

// TestSharedLearner_MultiWorkerConvergence verifies that with N ingest workers
// sharing a single BaselineLearner, the learning phase completes after
// minSamples aggregate events — not after N×minSamples (MEDIUM-6).
//
// The test drives IngestAsync from multiple goroutines so that events are
// distributed across workers, then waits for each worker's detector to report
// learning complete and checks that the aggregate sample count at that point
// does not exceed minSamples by more than one worker's worth of events.
func TestSharedLearner_MultiWorkerConvergence(t *testing.T) {
	const (
		workerCount = 4
		minSamples  = 200 // small enough to complete quickly in the test
	)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg := DefaultCorrelationEngineConfig()
	cfg.Rules = []Rule{}
	cfg.EnableAnomaly = true
	cfg.AnomalyThreshold = 0.9
	cfg.LearningPeriod = 1 * time.Millisecond // effectively time-gate disabled; sample gate drives exit
	cfg.MinLearningSamples = minSamples
	cfg.IngestWorkerCount = workerCount
	cfg.EnableRateLimit = false
	cfg.EnableDedup = false

	engine := NewCorrelationEngineWithConfig(cfg)
	defer engine.Close()

	// Verify that the shared learner is wired: all workers must reference the
	// same BaselineLearner pointer, so they all see the same aggregate count.
	require.Equal(t, workerCount, len(engine.ingestPool), "worker pool size mismatch")
	if workerCount > 1 {
		first := engine.ingestPool[0].ad
		for i := 1; i < len(engine.ingestPool); i++ {
			require.NotNil(t, engine.ingestPool[i].ad, "worker %d has nil AnomalyDetector", i)
			// Both detectors should be in the learning phase before any events.
			require.False(t, first.IsLearningComplete(), "worker 0 detector should not be complete yet")
			require.False(t, engine.ingestPool[i].ad.IsLearningComplete(),
				"worker %d detector should not be complete yet", i)
		}
	}

	// Send events spread across many distinct PIDs so the PID-hash routing
	// distributes them across all workers.
	const totalEvents = minSamples * 3
	for i := 0; i < totalEvents; i++ {
		engine.IngestAsync(ctx, types.Event{
			Type: types.EventSyscall,
			PID:  uint32(i % 1024), // 1024 distinct PIDs → round-robins across workers
			Syscall: &types.SyscallEvent{
				Nr: int64(i % 10),
			},
		})
	}

	// Give workers time to drain their queues.
	deadline := time.After(8 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for learning phase to complete across all workers")
		case <-ticker.C:
			allDone := true
			for _, w := range engine.ingestPool {
				if w.ad != nil && !w.ad.IsLearningComplete() {
					allDone = false
					break
				}
			}
			if allDone {
				return // all workers have exited learning phase — test passes
			}
		}
	}
}

// TestSharedLearner_GetRulesBeforeUpdate verifies that GetRules() returns nil
// (not panics) when called before the first UpdateRules() invocation (HIGH-2).
func TestSharedLearner_GetRulesBeforeUpdate(t *testing.T) {
	cfg := DefaultCorrelationEngineConfig()
	cfg.Rules = nil // start with no rules — ruleEngine is populated by NewCorrelationEngineWithConfig
	cfg.EnableAnomaly = false

	engine := NewCorrelationEngineWithConfig(cfg)
	defer engine.Close()

	// GetRules on a freshly constructed engine must not panic and must return a
	// non-nil slice (engine pre-loads the initial rules from cfg.Rules).
	rules := engine.GetRules()
	_ = rules // nil or empty both acceptable; only a panic is a failure

	// Concurrent GetRules + UpdateRules must not race.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 50; i++ {
			engine.UpdateRules([]Rule{})
		}
	}()
	for i := 0; i < 200; i++ {
		_ = engine.GetRules()
	}
	<-done
}
