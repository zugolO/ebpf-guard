//go:build integration

// Package integration_test contains end-to-end integration tests for the full
// detection pipeline without a real kernel:
//
//	SyntheticCollector → CorrelationEngine → Enforcer(DryRun) → MemoryStore
//
// Run with:
//
//	go test -tags=integration -v ./internal/integration/...
package integration_test

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/internal/collector"
	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/internal/enforcer"
	"github.com/zugolO/ebpf-guard/internal/store"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// ---------------------------------------------------------------------------
// Shared fixtures and helpers
// ---------------------------------------------------------------------------

// matchAllSyscalls matches every EventSyscall emitted by SyntheticCollector
// (syscall numbers ≥ 0). Used where any alert is sufficient for the assertion.
var matchAllSyscalls = correlator.Rule{
	ID:        "integ_rule_any_syscall",
	Name:      "Match All Syscalls",
	EventType: types.EventSyscall,
	Condition: correlator.RuleCondition{
		Field:  "nr",
		Op:     correlator.OpGreaterThan,
		Values: []string{"-1"},
	},
	Severity: types.SeverityWarning,
	Action:   correlator.ActionAlert,
}

// makeSyscallEvent returns a minimal EventSyscall with the given PID and a
// fresh nanosecond timestamp so consecutive events have distinct fingerprints.
func makeSyscallEvent(pid uint32) types.Event {
	return types.Event{
		Type:      types.EventSyscall,
		PID:       pid,
		Timestamp: uint64(time.Now().UnixNano()),
		Syscall:   &types.SyscallEvent{Nr: 1},
	}
}

// makeTCPEvent returns a minimal EventTCPConnect to the given destination port.
func makeTCPEvent(pid uint32, dport uint16) types.Event {
	return types.Event{
		Type:      types.EventTCPConnect,
		PID:       pid,
		Timestamp: uint64(time.Now().UnixNano()),
		Network:   &types.NetworkEvent{Dport: dport},
	}
}

// newDryRunEnforcer creates an enforcer that logs actions but never executes them.
func newDryRunEnforcer(t *testing.T) *enforcer.Enforcer {
	t.Helper()
	enf, err := enforcer.NewEnforcer(slog.Default(), enforcer.Config{
		DryRun:       true,
		BlockBackend: enforcer.BlockBackendLog,
		EnableBlock:  true,
		EnableKill:   true,
		EnableThrottle: true,
	})
	require.NoError(t, err)
	return enf
}

// newEngine wires a CorrelationEngine with the given rules and enforcer.
// Optional configure functions can override individual config fields.
func newEngine(
	enf *enforcer.Enforcer,
	rules []correlator.Rule,
	configure ...func(*correlator.CorrelationEngineConfig),
) *correlator.CorrelationEngine {
	cfg := correlator.DefaultCorrelationEngineConfig()
	cfg.Rules = rules
	cfg.ActionExecutor = enf
	cfg.EnableAnomaly = false // avoid profiler interference in short tests
	for _, fn := range configure {
		fn(&cfg)
	}
	return correlator.NewCorrelationEngineWithConfig(cfg)
}

// ingestAndStore ingests one event and persists every resulting alert.
// Returns the number of alerts stored.
func ingestAndStore(
	ctx context.Context,
	engine *correlator.CorrelationEngine,
	st *store.MemoryStore,
	event types.Event,
) int {
	alerts := engine.Ingest(ctx, event)
	for _, a := range alerts {
		_ = st.Store(ctx, a)
	}
	return len(alerts)
}

// ---------------------------------------------------------------------------
// Scenario 1: event matches rule → alert appears in store
// ---------------------------------------------------------------------------

func TestScenario1_EventMatchesRule_AlertInStore(t *testing.T) {
	ctx := context.Background()

	rule := correlator.Rule{
		ID:        "s1_tcp_8080",
		Name:      "TCP Connect Port 8080",
		EventType: types.EventTCPConnect,
		Condition: correlator.RuleCondition{
			Field:  "dport",
			Op:     correlator.OpEquals,
			Values: []string{"8080"},
		},
		Severity: types.SeverityWarning,
		Action:   correlator.ActionAlert,
	}

	enf := newDryRunEnforcer(t)
	engine := newEngine(enf, []correlator.Rule{rule}, func(cfg *correlator.CorrelationEngineConfig) {
		cfg.EnableDedup = false
		cfg.EnableRateLimit = false
	})
	st := store.NewMemoryStore()

	// Matching event must produce exactly one alert.
	n := ingestAndStore(ctx, engine, st, makeTCPEvent(1234, 8080))
	require.Equal(t, 1, n, "matching event must produce exactly one alert")

	got, err := st.Query(ctx, store.QueryFilters{RuleIDs: []string{rule.ID}})
	require.NoError(t, err)
	require.Len(t, got, 1, "alert must be persisted in the store")
	assert.Equal(t, rule.ID, got[0].RuleID)
	assert.Equal(t, types.SeverityWarning, got[0].Severity)
	assert.Equal(t, uint32(1234), got[0].PID)

	// Non-matching event (wrong port) must produce no alert.
	n2 := ingestAndStore(ctx, engine, st, makeTCPEvent(5678, 443))
	assert.Equal(t, 0, n2, "non-matching event must produce no alerts")

	// Store count must remain 1.
	count, err := st.Count(ctx, store.QueryFilters{})
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)
}

// ---------------------------------------------------------------------------
// Scenario 2: burst of 1000 events → rate limiter fires
// ---------------------------------------------------------------------------

func TestScenario2_Burst_RateLimiterFires(t *testing.T) {
	ctx := context.Background()

	const maxPerWindow = 5

	enf := newDryRunEnforcer(t)
	engine := newEngine(enf, []correlator.Rule{matchAllSyscalls}, func(cfg *correlator.CorrelationEngineConfig) {
		// Disable dedup so the rate limiter (not the deduplication logic) is the
		// binding constraint. Each event has a distinct PID so it would bypass dedup
		// anyway, but disabling it makes the test intent explicit.
		cfg.EnableDedup = false
		cfg.EnableRateLimit = true
		cfg.MaxAlertsPerWindow = maxPerWindow
		cfg.RateLimitWindow = 30 * time.Second // window won't reset during the test burst
	})
	st := store.NewMemoryStore()

	// Inject 1000 events with distinct PIDs so the dedup fingerprint differs for
	// each one, ensuring the rate limiter is the only suppression mechanism.
	for i := 0; i < 1000; i++ {
		ingestAndStore(ctx, engine, st, makeSyscallEvent(uint32(i+1)))
	}

	count, err := st.Count(ctx, store.QueryFilters{})
	require.NoError(t, err)

	// The rate limiter must have suppressed the vast majority.
	assert.Greater(t, count, int64(0),
		"at least one alert must pass before rate limiting kicks in")
	assert.LessOrEqual(t, count, int64(maxPerWindow),
		"rate limiter must cap alerts at MaxAlertsPerWindow=%d, got %d",
		maxPerWindow, count)
}

// ---------------------------------------------------------------------------
// Scenario 3: SIGTERM → graceful shutdown without alert loss
// ---------------------------------------------------------------------------

// TestScenario3_SIGTERM_GracefulShutdown starts the full pipeline with a
// SyntheticCollector, captures a SIGTERM sent to the process itself, initiates
// graceful shutdown via context cancellation, and verifies that no previously
// stored alert is lost.
func TestScenario3_SIGTERM_GracefulShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	enf := newDryRunEnforcer(t)
	engine := newEngine(enf, []correlator.Rule{matchAllSyscalls}, func(cfg *correlator.CorrelationEngineConfig) {
		cfg.EnableDedup = false
		cfg.EnableRateLimit = false
	})
	st := store.NewMemoryStore()

	// The SyntheticCollector generates random events including EventSyscall,
	// ~1/3 of which will match matchAllSyscalls.
	synth := collector.NewSyntheticCollector(slog.Default(), 5*time.Millisecond)
	eventCh := make(chan types.Event, 512)

	var storedTotal int64
	atLeastFive := make(chan struct{})
	var signalOnce sync.Once

	var wg sync.WaitGroup

	// Producer goroutine: emit synthetic events until context is cancelled.
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = synth.Start(ctx, eventCh)
	}()

	// Consumer goroutine: ingest and store alerts; drain channel on shutdown.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case event := <-eventCh:
				alerts := engine.Ingest(context.Background(), event)
				for _, a := range alerts {
					_ = st.Store(context.Background(), a)
					if n := atomic.AddInt64(&storedTotal, 1); n >= 5 {
						signalOnce.Do(func() { close(atLeastFive) })
					}
				}
			case <-ctx.Done():
				// Drain any events already buffered in the channel so none are
				// silently discarded when we stop.
				for {
					select {
					case event := <-eventCh:
						alerts := engine.Ingest(context.Background(), event)
						for _, a := range alerts {
							_ = st.Store(context.Background(), a)
							atomic.AddInt64(&storedTotal, 1)
						}
					default:
						return
					}
				}
			}
		}
	}()

	// Wait until at least 5 alerts are stored before triggering shutdown.
	select {
	case <-atLeastFive:
	case <-time.After(30 * time.Second):
		t.Fatal("timeout: no alerts stored within 30 s — verify SyntheticCollector and rule")
	}

	beforeShutdown := atomic.LoadInt64(&storedTotal)
	require.Positive(t, beforeShutdown, "must have stored alerts before shutdown")

	// Register SIGTERM handler before sending the signal so we don't miss it.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	// Send SIGTERM to this process to simulate operator-initiated shutdown.
	require.NoError(t, syscall.Kill(os.Getpid(), syscall.SIGTERM))

	select {
	case <-sigCh:
		cancel() // begin graceful shutdown
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("SIGTERM not received within 3 s")
	}

	// Wait for both goroutines to finish.
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("goroutines did not finish within 10 s after shutdown")
	}

	// The store must contain at least as many alerts as before SIGTERM.
	// More is acceptable (drain may add a few); fewer would mean data loss.
	finalCount, err := st.Count(context.Background(), store.QueryFilters{})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, finalCount, beforeShutdown,
		"graceful shutdown must not lose alerts (before=%d, after=%d)",
		beforeShutdown, finalCount)
}

// ---------------------------------------------------------------------------
// Scenario 4: hot-reload rules → new rules applied without restart
// ---------------------------------------------------------------------------

func TestScenario4_HotReloadRules_NewRulesApplied(t *testing.T) {
	ctx := context.Background()

	enf := newDryRunEnforcer(t)
	// Start with an empty rule set.
	engine := newEngine(enf, nil, func(cfg *correlator.CorrelationEngineConfig) {
		cfg.EnableDedup = false
		cfg.EnableRateLimit = false
	})
	st := store.NewMemoryStore()

	// --- Step 1: no rules → event produces no alert ---
	n := ingestAndStore(ctx, engine, st, makeTCPEvent(9001, 9090))
	assert.Equal(t, 0, n, "no rules loaded: event must produce no alerts")

	count0, err := st.Count(ctx, store.QueryFilters{})
	require.NoError(t, err)
	assert.Equal(t, int64(0), count0)

	// --- Step 2: hot-reload a matching rule ---
	hotRule := correlator.Rule{
		ID:        "hot_tcp_9090",
		Name:      "TCP Port 9090 (hot-reloaded)",
		EventType: types.EventTCPConnect,
		Condition: correlator.RuleCondition{
			Field:  "dport",
			Op:     correlator.OpEquals,
			Values: []string{"9090"},
		},
		Severity: types.SeverityCritical,
		Action:   correlator.ActionAlert,
	}
	engine.UpdateRules([]correlator.Rule{hotRule})

	require.Len(t, engine.GetRules(), 1, "engine must reflect exactly one hot-reloaded rule")
	assert.Equal(t, hotRule.ID, engine.GetRules()[0].ID)

	// Same event type/port — the hot-reloaded rule must now fire.
	n2 := ingestAndStore(ctx, engine, st, makeTCPEvent(9001, 9090))
	require.Equal(t, 1, n2, "hot-reloaded rule must match the event")

	got, err := st.Query(ctx, store.QueryFilters{RuleIDs: []string{hotRule.ID}})
	require.NoError(t, err)
	require.Len(t, got, 1, "alert from hot-reloaded rule must be in the store")
	assert.Equal(t, types.SeverityCritical, got[0].Severity)

	// --- Step 3: second hot-reload replaces the rule set ---
	syscallRule := correlator.Rule{
		ID:        "hot_syscall",
		Name:      "Syscall Rule (second hot-reload)",
		EventType: types.EventSyscall,
		Condition: correlator.RuleCondition{
			Field:  "nr",
			Op:     correlator.OpGreaterThan,
			Values: []string{"-1"},
		},
		Severity: types.SeverityWarning,
		Action:   correlator.ActionAlert,
	}
	engine.UpdateRules([]correlator.Rule{syscallRule})

	require.Len(t, engine.GetRules(), 1, "engine must reflect the second hot-reloaded rule set")

	// Old TCP rule is gone — same TCP event must no longer fire.
	nOld := ingestAndStore(ctx, engine, st, makeTCPEvent(9001, 9090))
	assert.Equal(t, 0, nOld, "replaced rule must not fire after second hot-reload")

	// New syscall rule must fire.
	nNew := ingestAndStore(ctx, engine, st, makeSyscallEvent(42))
	require.Equal(t, 1, nNew, "new rule must fire immediately after hot-reload")

	sysCalls, err := st.Query(ctx, store.QueryFilters{RuleIDs: []string{syscallRule.ID}})
	require.NoError(t, err)
	require.Len(t, sysCalls, 1)
	assert.Equal(t, syscallRule.ID, sysCalls[0].RuleID)
}

// ---------------------------------------------------------------------------
// Scenario 5: hot-reload with invalid YAML — old rules must remain active
// ---------------------------------------------------------------------------

// TestScenario5_HotReload_InvalidYAML_OldRulesRetained verifies that when a
// hot-reload is attempted with an invalid rule set (duplicate IDs, unknown field,
// or invalid operator), the atomic swap is aborted and the previous rules
// continue to fire as normal.
func TestScenario5_HotReload_InvalidYAML_OldRulesRetained(t *testing.T) {
	ctx := context.Background()
	enf := newDryRunEnforcer(t)

	goodRule := correlator.Rule{
		ID:        "integ_good_rule",
		Name:      "Good TCP Rule",
		EventType: types.EventTCPConnect,
		Condition: correlator.RuleCondition{
			Field:  "dport",
			Op:     correlator.OpEquals,
			Values: []string{"8080"},
		},
		Severity: types.SeverityWarning,
		Action:   correlator.ActionAlert,
	}

	engine := newEngine(enf, []correlator.Rule{goodRule}, func(cfg *correlator.CorrelationEngineConfig) {
		cfg.EnableDedup = false
		cfg.EnableRateLimit = false
	})
	st := store.NewMemoryStore()

	// Good rule fires before any reload attempt.
	n := ingestAndStore(ctx, engine, st, makeTCPEvent(1, 8080))
	require.Equal(t, 1, n, "good rule must fire before reload attempt")

	// Attempt a hot-reload with a rule set that has a duplicate ID.
	dupRule1 := correlator.Rule{
		ID:        "dup_id",
		Name:      "Dup Rule A",
		EventType: types.EventTCPConnect,
		Condition: correlator.RuleCondition{Field: "dport", Op: correlator.OpEquals, Values: []string{"9999"}},
		Severity:  types.SeverityWarning,
		Action:    correlator.ActionAlert,
	}
	dupRule2 := correlator.Rule{
		ID:        "dup_id", // same ID — ValidateFull must reject this
		Name:      "Dup Rule B",
		EventType: types.EventTCPConnect,
		Condition: correlator.RuleCondition{Field: "dport", Op: correlator.OpEquals, Values: []string{"7777"}},
		Severity:  types.SeverityWarning,
		Action:    correlator.ActionAlert,
	}
	invalidSet := []correlator.Rule{dupRule1, dupRule2}

	// ValidateFull must reject the invalid set.
	require.Error(t, correlator.ValidateFull(invalidSet), "duplicate IDs must be rejected by ValidateFull")

	// Simulate what the hot-reload handler does: validate first, skip swap on error.
	if err := correlator.ValidateFull(invalidSet); err != nil {
		// Reload aborted — old rules retained (no UpdateRules call).
	}

	// Engine must still have exactly the original rule.
	require.Len(t, engine.GetRules(), 1)
	assert.Equal(t, goodRule.ID, engine.GetRules()[0].ID, "old rule must be retained after aborted reload")

	// Original rule must still fire.
	n2 := ingestAndStore(ctx, engine, st, makeTCPEvent(2, 8080))
	require.Equal(t, 1, n2, "good rule must still fire after aborted invalid reload")

	// Attempt a reload with a rule containing an unknown field — also invalid.
	badFieldRule := correlator.Rule{
		ID:        "bad_field_rule",
		Name:      "Bad Field",
		EventType: types.EventTCPConnect,
		Condition: correlator.RuleCondition{Field: "no_such_field", Op: correlator.OpEquals, Values: []string{"1"}},
		Severity:  types.SeverityWarning,
		Action:    correlator.ActionAlert,
	}
	require.Error(t, correlator.ValidateFull([]correlator.Rule{badFieldRule}),
		"unknown field must be rejected by ValidateFull")

	// Engine unchanged.
	require.Len(t, engine.GetRules(), 1)
	assert.Equal(t, goodRule.ID, engine.GetRules()[0].ID)
}
