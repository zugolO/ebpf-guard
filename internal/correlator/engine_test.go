// Package correlator provides event correlation and rule-based detection.
package correlator

import (
	"context"
	"testing"

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
