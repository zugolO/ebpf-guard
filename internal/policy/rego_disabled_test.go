//go:build !rego

// Package policy tests the stub RegoEngine used when the rego build tag is
// not set. In this build configuration Rego/OPA support is not compiled in,
// so every method here is expected to behave as a documented no-op/zero-value
// implementation.
package policy

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

func TestDefaultRegoEngineConfig(t *testing.T) {
	cfg := DefaultRegoEngineConfig()
	assert.True(t, cfg.Enabled)
	assert.Equal(t, "rules/rego", cfg.RulesDir)
}

func TestNewRegoEngineStub_Enabled(t *testing.T) {
	engine, err := NewRegoEngine(RegoEngineConfig{Enabled: true, RulesDir: "unused"})
	require.NoError(t, err)
	require.NotNil(t, engine)
	assert.True(t, engine.IsEnabled())
}

func TestNewRegoEngineStub_Disabled(t *testing.T) {
	engine, err := NewRegoEngine(RegoEngineConfig{Enabled: false, RulesDir: "unused"})
	require.NoError(t, err)
	require.NotNil(t, engine)
	assert.False(t, engine.IsEnabled())
}

func TestRegoEngineStub_Evaluate_AlwaysNil(t *testing.T) {
	engine, err := NewRegoEngine(RegoEngineConfig{Enabled: true})
	require.NoError(t, err)

	alert := types.Alert{
		ID:       "test-1",
		RuleID:   "rule-1",
		Severity: types.SeverityCritical,
		PID:      42,
		Comm:     "bash",
		Event: types.Event{
			Type: types.EventSyscall,
		},
	}

	decisions, err := engine.Evaluate(context.Background(), alert)
	require.NoError(t, err)
	assert.Nil(t, decisions)

	// Evaluate is a no-op regardless of enabled state.
	engine.SetEnabled(false)
	decisions, err = engine.Evaluate(context.Background(), alert)
	require.NoError(t, err)
	assert.Nil(t, decisions)
}

func TestRegoEngineStub_Reload(t *testing.T) {
	engine, err := NewRegoEngine(RegoEngineConfig{Enabled: true})
	require.NoError(t, err)

	// Reload is a no-op and always succeeds.
	require.NoError(t, engine.Reload())

	// It also never touches the reload counter reported via GetStats.
	stats := engine.GetStats()
	assert.Equal(t, uint64(0), stats.ReloadCounter)
}

func TestRegoEngineStub_ReloadWithContext(t *testing.T) {
	engine, err := NewRegoEngine(RegoEngineConfig{Enabled: true})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already-cancelled context; stub ignores it entirely.

	require.NoError(t, engine.ReloadWithContext(ctx))
}

func TestRegoEngineStub_SetDurationObserver_NoEffect(t *testing.T) {
	engine, err := NewRegoEngine(RegoEngineConfig{Enabled: true})
	require.NoError(t, err)

	called := false
	engine.SetDurationObserver(func(d time.Duration) {
		called = true
	})

	_, err = engine.Evaluate(context.Background(), types.Alert{})
	require.NoError(t, err)

	// The stub never invokes the observer since Evaluate never runs any timing.
	assert.False(t, called)

	// Passing nil is also fine and a no-op.
	engine.SetDurationObserver(nil)
}

func TestRegoEngineStub_SetEnabled_IsEnabled(t *testing.T) {
	engine, err := NewRegoEngine(RegoEngineConfig{Enabled: false})
	require.NoError(t, err)
	assert.False(t, engine.IsEnabled())

	engine.SetEnabled(true)
	assert.True(t, engine.IsEnabled())

	engine.SetEnabled(false)
	assert.False(t, engine.IsEnabled())
}

func TestRegoEngineStub_GetStats_AlwaysZero(t *testing.T) {
	engine, err := NewRegoEngine(RegoEngineConfig{Enabled: true})
	require.NoError(t, err)

	stats := engine.GetStats()
	assert.Equal(t, uint64(0), stats.EvalTotal)
	assert.Equal(t, uint64(0), stats.EvalErrors)
	assert.Equal(t, uint64(0), stats.ReloadCounter)
	assert.Equal(t, 0, stats.PolicyCount)

	// Even after driving Evaluate/Reload calls, the stub's counters never move
	// because evalTotal/reloadCounter are never incremented in this build.
	for i := 0; i < 5; i++ {
		_, _ = engine.Evaluate(context.Background(), types.Alert{})
	}
	require.NoError(t, engine.Reload())

	stats = engine.GetStats()
	assert.Equal(t, uint64(0), stats.EvalTotal)
	assert.Equal(t, uint64(0), stats.ReloadCounter)
}

func TestPolicyDecisionStub_ZeroValue(t *testing.T) {
	var d PolicyDecision
	assert.False(t, d.Matched)
	assert.Empty(t, d.RuleID)
	assert.Empty(t, d.Message)
	assert.Empty(t, d.Action)
	assert.Empty(t, d.MitreTechnique)
	assert.Empty(t, string(d.Severity))
}
