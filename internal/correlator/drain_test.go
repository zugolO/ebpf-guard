package correlator

import (
	"context"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDrain_NoRegoQueue verifies that Drain returns immediately when no async
// Rego evaluation is configured (regoQueue is nil / disabled).
func TestDrain_NoRegoQueue(t *testing.T) {
	eng := NewCorrelationEngineWithConfig(DefaultCorrelationEngineConfig())
	defer eng.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := eng.Drain(ctx)
	require.NoError(t, err)
}

// TestDrain_FlushesAllAlerts verifies the full zero-loss path:
//  1. Send events that trigger alerts.
//  2. Call Drain (waits for all async evaluation).
//  3. Call Flush and confirm every expected alert is returned.
func TestDrain_FlushesAllAlerts(t *testing.T) {
	rules := []Rule{
		{
			ID:        "drain_rule",
			Name:      "Drain Test Rule",
			EventType: types.EventTCPConnect,
			Condition: RuleCondition{
				Field:  "dport",
				Op:     OpEquals,
				Values: []string{"9999"},
			},
			Severity: types.SeverityWarning,
			Action:   ActionAlert,
		},
	}

	cfg := DefaultCorrelationEngineConfig()
	cfg.Rules = rules
	cfg.EnableDedup = false
	cfg.EnableRateLimit = false

	eng := NewCorrelationEngineWithConfig(cfg)
	defer eng.Close()

	ctx := context.Background()

	// Ingest enough events to generate alerts, each with a unique PID.
	const count = 10
	for i := 0; i < count; i++ {
		eng.Ingest(ctx, types.Event{
			Type: types.EventTCPConnect,
			PID:  uint32(i + 1),
			Network: &types.NetworkEvent{Dport: 9999},
		})
	}

	// Drain waits for any async work (rego workers) to complete.
	drainCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err := eng.Drain(drainCtx)
	require.NoError(t, err)

	// All alerts must be available after Drain.
	alerts := eng.Flush()
	assert.Equal(t, count, len(alerts), "expected all alerts to be available after Drain+Flush")
}

// TestDrain_ContextCancellation verifies that Drain returns ctx.Err() when the
// deadline expires before the queue is empty.
func TestDrain_ContextCancellation(t *testing.T) {
	eng := NewCorrelationEngineWithConfig(DefaultCorrelationEngineConfig())
	defer eng.Close()

	// Cancel immediately.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := eng.Drain(ctx)
	assert.ErrorIs(t, err, context.Canceled)
}

// TestFlush_ReturnsAndClearsPending verifies that Flush returns buffered alerts
// and clears the pending slice so a second call returns zero alerts.
func TestFlush_ReturnsAndClearsPending(t *testing.T) {
	rules := []Rule{
		{
			ID:        "flush_rule",
			Name:      "Flush Test Rule",
			EventType: types.EventSyscall,
			Condition: RuleCondition{
				Field:  "nr",
				Op:     OpEquals,
				Values: []string{"59"}, // execve
			},
			Severity: types.SeverityWarning,
			Action:   ActionAlert,
		},
	}

	cfg := DefaultCorrelationEngineConfig()
	cfg.Rules = rules
	cfg.EnableDedup = false
	cfg.EnableRateLimit = false
	eng := NewCorrelationEngineWithConfig(cfg)
	defer eng.Close()

	ctx := context.Background()
	eng.Ingest(ctx, types.Event{
		Type:    types.EventSyscall,
		PID:     42,
		Syscall: &types.SyscallEvent{Nr: 59},
	})

	first := eng.Flush()
	require.Len(t, first, 1)

	second := eng.Flush()
	assert.Empty(t, second, "second Flush should return no alerts")
}

// TestGracefulShutdown_ZeroAlertLoss is an integration-style test that simulates
// the shutdown sequence: send events, stop feeding, drain+flush, confirm no loss.
func TestGracefulShutdown_ZeroAlertLoss(t *testing.T) {
	const alertCount = 50

	rules := []Rule{
		{
			ID:        "loss_rule",
			Name:      "Loss Test Rule",
			EventType: types.EventTCPConnect,
			Condition: RuleCondition{
				Field:  "dport",
				Op:     OpEquals,
				Values: []string{"4444"},
			},
			Severity: types.SeverityWarning,
			Action:   ActionAlert,
		},
	}

	cfg := DefaultCorrelationEngineConfig()
	cfg.Rules = rules
	cfg.EnableDedup = false
	cfg.EnableRateLimit = false
	eng := NewCorrelationEngineWithConfig(cfg)
	defer eng.Close()

	ctx := context.Background()

	// Ingest all events with unique PIDs to bypass dedup.
	for i := 0; i < alertCount; i++ {
		eng.Ingest(ctx, types.Event{
			Type:    types.EventTCPConnect,
			PID:     uint32(i + 1),
			Network: &types.NetworkEvent{Dport: 4444},
		})
	}

	// Simulate shutdown: drain then flush.
	shutCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	require.NoError(t, eng.Drain(shutCtx))

	alerts := eng.Flush()
	assert.Equal(t, alertCount, len(alerts),
		"zero alert loss: all %d alerts must be present after Drain+Flush", alertCount)
}
