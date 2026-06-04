// Package correlator provides event correlation and rule-based detection.
package correlator

import (
	"context"
	"log/slog"
	"testing"
	"time"

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
	engine := NewCorrelationEngine(nil)
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
