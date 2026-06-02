package correlator

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// mockExecutor records ExecuteAction calls for verification.
type mockExecutor struct {
	mu      sync.Mutex
	calls   []enforceCall
	dryRun  bool
	failErr error // if non-nil, ExecuteAction returns this error
}

type enforceCall struct {
	Action string
	Alert  types.Alert
}

func (m *mockExecutor) ExecuteAction(_ context.Context, action string, alert types.Alert) error {
	if m.failErr != nil {
		return m.failErr
	}
	m.mu.Lock()
	m.calls = append(m.calls, enforceCall{Action: action, Alert: alert})
	m.mu.Unlock()
	return nil
}

func (m *mockExecutor) IsDryRun() bool { return m.dryRun }

func (m *mockExecutor) Calls() []enforceCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]enforceCall, len(m.calls))
	copy(out, m.calls)
	return out
}

func (m *mockExecutor) CallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.calls)
}

// ruleWithAction builds a minimal Rule that matches every syscall event.
func ruleWithAction(id string, action RuleAction) Rule {
	return Rule{
		ID:        id,
		Name:      "Test Rule " + id,
		EventType: types.EventSyscall,
		Condition: RuleCondition{
			Field:  "nr",
			Op:     "gt",
			Values: []string{"-1"}, // matches any syscall number ≥ 0
		},
		Severity: types.SeverityWarning,
		Action:   action,
	}
}

// syscallEvent builds a minimal syscall event.
func syscallEvent(pid uint32, nr int64) types.Event {
	return types.Event{
		Type:      types.EventSyscall,
		PID:       pid,
		Timestamp: uint64(time.Now().UnixNano()),
		Syscall: &types.SyscallEvent{
			Nr: nr,
		},
	}
}

// ---------------------------------------------------------------------------
// isEnforcedAction
// ---------------------------------------------------------------------------

func TestIsEnforcedAction(t *testing.T) {
	assert.True(t, isEnforcedAction("kill"))
	assert.True(t, isEnforcedAction("block"))
	assert.True(t, isEnforcedAction("throttle"))
	assert.False(t, isEnforcedAction("alert"))
	assert.False(t, isEnforcedAction("drop"))
	assert.False(t, isEnforcedAction(""))
	assert.False(t, isEnforcedAction("unknown"))
}

// ---------------------------------------------------------------------------
// Alert carries the rule action field
// ---------------------------------------------------------------------------

func TestRuleEngine_AlertCarriesAction(t *testing.T) {
	rules := []Rule{
		ruleWithAction("r_kill", ActionKill),
		ruleWithAction("r_alert", ActionAlert),
	}
	re := NewRuleEngine(rules)
	alerts := re.Evaluate(syscallEvent(1234, 1))

	require.Len(t, alerts, 2)
	actionByID := map[string]string{}
	for _, a := range alerts {
		actionByID[a.RuleID] = a.Action
	}
	assert.Equal(t, "kill", actionByID["r_kill"])
	assert.Equal(t, "alert", actionByID["r_alert"])
}

// ---------------------------------------------------------------------------
// Enforcement trigger in Ingest
// ---------------------------------------------------------------------------

func TestCorrelationEngine_EnforcementTriggeredForKill(t *testing.T) {
	exec := &mockExecutor{}
	cfg := DefaultCorrelationEngineConfig()
	cfg.Rules = []Rule{ruleWithAction("r_kill", ActionKill)}
	cfg.ActionExecutor = exec
	cfg.EnableAnomaly = false
	cfg.EnableRateLimit = false
	cfg.EnforcementCooldown = time.Hour // long cooldown so we get exactly one call

	ce := NewCorrelationEngineWithConfig(cfg)

	alerts := ce.Ingest(context.Background(), syscallEvent(1234, 99))
	require.Len(t, alerts, 1)
	assert.Equal(t, "kill", alerts[0].Action)
	assert.True(t, alerts[0].Enforced, "alert should be marked as enforced")

	// Wait for goroutine.
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, 1, exec.CallCount())
	calls := exec.Calls()
	assert.Equal(t, "kill", calls[0].Action)
	assert.Equal(t, uint32(1234), calls[0].Alert.PID)
}

func TestCorrelationEngine_EnforcementTriggeredForBlock(t *testing.T) {
	exec := &mockExecutor{}
	cfg := DefaultCorrelationEngineConfig()
	cfg.Rules = []Rule{ruleWithAction("r_block", ActionBlock)}
	cfg.ActionExecutor = exec
	cfg.EnableAnomaly = false
	cfg.EnableRateLimit = false

	ce := NewCorrelationEngineWithConfig(cfg)
	ce.Ingest(context.Background(), syscallEvent(2222, 1))
	time.Sleep(50 * time.Millisecond)

	assert.Equal(t, 1, exec.CallCount())
	assert.Equal(t, "block", exec.Calls()[0].Action)
}

func TestCorrelationEngine_EnforcementTriggeredForThrottle(t *testing.T) {
	exec := &mockExecutor{}
	cfg := DefaultCorrelationEngineConfig()
	cfg.Rules = []Rule{ruleWithAction("r_throttle", ActionThrottle)}
	cfg.ActionExecutor = exec
	cfg.EnableAnomaly = false
	cfg.EnableRateLimit = false

	ce := NewCorrelationEngineWithConfig(cfg)
	ce.Ingest(context.Background(), syscallEvent(3333, 1))
	time.Sleep(50 * time.Millisecond)

	assert.Equal(t, 1, exec.CallCount())
	assert.Equal(t, "throttle", exec.Calls()[0].Action)
}

func TestCorrelationEngine_AlertActionDoesNotTriggerEnforcer(t *testing.T) {
	exec := &mockExecutor{}
	cfg := DefaultCorrelationEngineConfig()
	cfg.Rules = []Rule{ruleWithAction("r_alert", ActionAlert)}
	cfg.ActionExecutor = exec
	cfg.EnableAnomaly = false
	cfg.EnableRateLimit = false

	ce := NewCorrelationEngineWithConfig(cfg)
	alerts := ce.Ingest(context.Background(), syscallEvent(1111, 1))
	time.Sleep(50 * time.Millisecond)

	assert.Len(t, alerts, 1)
	assert.False(t, alerts[0].Enforced)
	assert.Equal(t, 0, exec.CallCount(), "alert action must not trigger enforcer")
}

func TestCorrelationEngine_NoExecutorNoEnforcement(t *testing.T) {
	cfg := DefaultCorrelationEngineConfig()
	cfg.Rules = []Rule{ruleWithAction("r_kill", ActionKill)}
	cfg.ActionExecutor = nil // explicitly nil
	cfg.EnableAnomaly = false
	cfg.EnableRateLimit = false

	ce := NewCorrelationEngineWithConfig(cfg)
	alerts := ce.Ingest(context.Background(), syscallEvent(1234, 1))

	// Should still produce an alert, just not enforce.
	require.Len(t, alerts, 1)
	assert.False(t, alerts[0].Enforced)
}

// ---------------------------------------------------------------------------
// Enforcement cooldown
// ---------------------------------------------------------------------------

func TestCorrelationEngine_CooldownPreventsDuplicateEnforcement(t *testing.T) {
	exec := &mockExecutor{}
	cfg := DefaultCorrelationEngineConfig()
	cfg.Rules = []Rule{ruleWithAction("r_kill", ActionKill)}
	cfg.ActionExecutor = exec
	cfg.EnableAnomaly = false
	cfg.EnableRateLimit = false
	cfg.EnforcementCooldown = time.Hour // very long — second call must be suppressed

	ce := NewCorrelationEngineWithConfig(cfg)
	e := syscallEvent(1234, 99)

	ce.Ingest(context.Background(), e)
	ce.Ingest(context.Background(), e) // same rule + same PID = suppressed
	time.Sleep(100 * time.Millisecond)

	assert.Equal(t, 1, exec.CallCount(), "cooldown should prevent second enforcement")
}

func TestCorrelationEngine_CooldownExpiredAllowsReEnforcement(t *testing.T) {
	exec := &mockExecutor{}
	cfg := DefaultCorrelationEngineConfig()
	cfg.Rules = []Rule{ruleWithAction("r_kill", ActionKill)}
	cfg.ActionExecutor = exec
	cfg.EnableAnomaly = false
	cfg.EnableRateLimit = false
	cfg.EnforcementCooldown = 20 * time.Millisecond // short cooldown for test

	ce := NewCorrelationEngineWithConfig(cfg)
	e := syscallEvent(1234, 99)

	ce.Ingest(context.Background(), e)
	time.Sleep(50 * time.Millisecond) // wait for cooldown to expire
	ce.Ingest(context.Background(), e)
	time.Sleep(50 * time.Millisecond)

	assert.Equal(t, 2, exec.CallCount(), "should enforce again after cooldown expires")
}

func TestCorrelationEngine_DifferentPIDsEnforcedIndependently(t *testing.T) {
	exec := &mockExecutor{}
	cfg := DefaultCorrelationEngineConfig()
	cfg.Rules = []Rule{ruleWithAction("r_kill", ActionKill)}
	cfg.ActionExecutor = exec
	cfg.EnableAnomaly = false
	cfg.EnableRateLimit = false
	cfg.EnforcementCooldown = time.Hour

	ce := NewCorrelationEngineWithConfig(cfg)

	ce.Ingest(context.Background(), syscallEvent(1111, 1))
	ce.Ingest(context.Background(), syscallEvent(2222, 1)) // different PID
	time.Sleep(100 * time.Millisecond)

	assert.Equal(t, 2, exec.CallCount(), "different PIDs are independent cooldown keys")
}

// ---------------------------------------------------------------------------
// Enforcement failure doesn't affect alert emission
// ---------------------------------------------------------------------------

func TestCorrelationEngine_EnforcementFailureStillEmitsAlert(t *testing.T) {
	exec := &mockExecutor{failErr: assert.AnError}
	cfg := DefaultCorrelationEngineConfig()
	cfg.Rules = []Rule{ruleWithAction("r_kill", ActionKill)}
	cfg.ActionExecutor = exec
	cfg.EnableAnomaly = false
	cfg.EnableRateLimit = false

	ce := NewCorrelationEngineWithConfig(cfg)
	alerts := ce.Ingest(context.Background(), syscallEvent(1234, 1))
	time.Sleep(50 * time.Millisecond)

	require.Len(t, alerts, 1, "alert must be emitted even when enforcement fails")
	assert.True(t, alerts[0].Enforced, "alert should still be marked as enforced (attempt was made)")
}

// ---------------------------------------------------------------------------
// Concurrent enforcement — no race conditions
// ---------------------------------------------------------------------------

func TestCorrelationEngine_ConcurrentEnforcement(t *testing.T) {
	var callCount atomic.Int64
	exec := &mockExecutor{}

	cfg := DefaultCorrelationEngineConfig()
	cfg.Rules = []Rule{ruleWithAction("r_kill", ActionKill)}
	cfg.ActionExecutor = exec
	cfg.EnableAnomaly = false
	cfg.EnableRateLimit = false
	cfg.EnforcementCooldown = time.Millisecond // tiny cooldown to maximise goroutine churn

	ce := NewCorrelationEngineWithConfig(cfg)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(pid uint32) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				alerts := ce.Ingest(context.Background(), syscallEvent(pid, 1))
				callCount.Add(int64(len(alerts)))
				time.Sleep(2 * time.Millisecond)
			}
		}(uint32(i))
	}
	wg.Wait()
	time.Sleep(100 * time.Millisecond) // let goroutines settle

	// No assert on call count — just verify no race. The race detector will catch issues.
	assert.Greater(t, int(callCount.Load()), 0)
}

// ---------------------------------------------------------------------------
// ActionExecutor interface satisfaction (compile-time check)
// ---------------------------------------------------------------------------

// Verify *mockExecutor satisfies ActionExecutor at compile time.
var _ ActionExecutor = (*mockExecutor)(nil)
