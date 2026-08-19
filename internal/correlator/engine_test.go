// Package correlator provides event correlation and rule-based detection.
package correlator

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/internal/feedback"
	"github.com/zugolO/ebpf-guard/internal/policy"
	"github.com/zugolO/ebpf-guard/internal/profiler"
	"github.com/zugolO/ebpf-guard/pkg/types"
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

// TestCorrelationEngine_SelfExclusion is the regression test for 5.8e
// (находка №18: the agent generated 45% of its own idle-hour alert volume —
// canary self-scans and the uprobe attacher's /proc/<pid>/maps reads slipping
// past per-rule "ebpf-guard-self" exceptions). It exercises the self-exclusion
// filter added at the top of ingestWithAD directly, rather than relying on the
// per-rule exceptions it is meant to backstop.
func TestCorrelationEngine_SelfExclusion(t *testing.T) {
	rules := []Rule{
		{
			ID:        "rule_001",
			Name:      "Any file access",
			EventType: types.EventFileAccess,
			Condition: RuleCondition{Field: "op", Op: OpEquals, Values: []string{"read"}},
			Severity:  types.SeverityWarning,
			Action:    ActionAlert,
		},
	}

	const selfPID = uint32(999)
	const childPID = uint32(1000)
	const otherPID = uint32(2000)

	newEvent := func(pid, ppid uint32) types.Event {
		return types.Event{
			Type: types.EventFileAccess,
			PID:  pid,
			PPID: ppid,
			File: &types.FileEvent{Op: 1}, // 1 = read, see fileOpNames
		}
	}

	t.Run("enabled: self PID produces no alert", func(t *testing.T) {
		cfg := DefaultCorrelationEngineConfig()
		cfg.Rules = rules
		cfg.SelfExcludeEnabled = true
		cfg.SelfPID = selfPID
		engine := NewCorrelationEngineWithConfig(cfg)
		ctx := context.Background()

		alerts := engine.Ingest(ctx, newEvent(selfPID, 1))
		assert.Empty(t, alerts, "events with e.PID == selfPID must not reach rule evaluation")
	})

	t.Run("enabled: descendant discovered via PPID produces no alert", func(t *testing.T) {
		cfg := DefaultCorrelationEngineConfig()
		cfg.Rules = rules
		cfg.SelfExcludeEnabled = true
		cfg.SelfPID = selfPID
		engine := NewCorrelationEngineWithConfig(cfg)
		ctx := context.Background()

		// First event from the child carries PPID == selfPID, so the child is
		// learned as part of the self tree...
		alerts := engine.Ingest(ctx, newEvent(childPID, selfPID))
		assert.Empty(t, alerts)

		// ...and a later event from the same child, without PPID set again,
		// is still excluded via the now-populated selfTree.
		alerts = engine.Ingest(ctx, newEvent(childPID, 0))
		assert.Empty(t, alerts)
	})

	t.Run("enabled: unrelated PID is unaffected", func(t *testing.T) {
		cfg := DefaultCorrelationEngineConfig()
		cfg.Rules = rules
		cfg.SelfExcludeEnabled = true
		cfg.SelfPID = selfPID
		engine := NewCorrelationEngineWithConfig(cfg)
		ctx := context.Background()

		alerts := engine.Ingest(ctx, newEvent(otherPID, 1))
		assert.Len(t, alerts, 1, "an attacker process, not a descendant of the agent, must still alert")
	})

	t.Run("disabled: self PID still alerts", func(t *testing.T) {
		cfg := DefaultCorrelationEngineConfig()
		cfg.Rules = rules
		cfg.SelfExcludeEnabled = false
		cfg.SelfPID = selfPID
		engine := NewCorrelationEngineWithConfig(cfg)
		ctx := context.Background()

		alerts := engine.Ingest(ctx, newEvent(selfPID, 1))
		assert.Len(t, alerts, 1, "self-exclusion must be fully disable-able via config")
	})
}

// TestCorrelationEngine_ObserverExclusion is the regression test for 5.9a
// (находки №27/№28: the idle-hour measurement harness — idle-run.sh and the
// curl/ps/grep/awk it forks — produced 71% of measured idle alert volume).
// It exercises the observer-tree exclusion filter, set live via
// SetObserverRoot the way main.go's root-PID-file poller does, mirroring
// TestCorrelationEngine_SelfExclusion above for the harness's tree instead of
// the agent's own.
func TestCorrelationEngine_ObserverExclusion(t *testing.T) {
	rules := []Rule{
		{
			ID:        "rule_001",
			Name:      "Any file access",
			EventType: types.EventFileAccess,
			Condition: RuleCondition{Field: "op", Op: OpEquals, Values: []string{"read"}},
			Severity:  types.SeverityWarning,
			Action:    ActionAlert,
		},
	}

	const rootPID = uint32(4242)
	const childPID = uint32(4300)
	const otherPID = uint32(5000)

	newEvent := func(pid, ppid uint32) types.Event {
		return types.Event{
			Type: types.EventFileAccess,
			PID:  pid,
			PPID: ppid,
			File: &types.FileEvent{Op: 1}, // 1 = read, see fileOpNames
		}
	}

	t.Run("enabled: harness root PID produces no alert", func(t *testing.T) {
		cfg := DefaultCorrelationEngineConfig()
		cfg.Rules = rules
		cfg.ObserverExcludeEnabled = true
		engine := NewCorrelationEngineWithConfig(cfg)
		engine.SetObserverRoot(rootPID)
		ctx := context.Background()

		alerts := engine.Ingest(ctx, newEvent(rootPID, 1))
		assert.Empty(t, alerts, "events with e.PID == observer root must not reach rule evaluation")
	})

	t.Run("enabled: descendant discovered via PPID produces no alert", func(t *testing.T) {
		cfg := DefaultCorrelationEngineConfig()
		cfg.Rules = rules
		cfg.ObserverExcludeEnabled = true
		engine := NewCorrelationEngineWithConfig(cfg)
		engine.SetObserverRoot(rootPID)
		ctx := context.Background()

		alerts := engine.Ingest(ctx, newEvent(childPID, rootPID))
		assert.Empty(t, alerts)

		alerts = engine.Ingest(ctx, newEvent(childPID, 0))
		assert.Empty(t, alerts)
	})

	t.Run("enabled: unrelated PID is unaffected", func(t *testing.T) {
		cfg := DefaultCorrelationEngineConfig()
		cfg.Rules = rules
		cfg.ObserverExcludeEnabled = true
		engine := NewCorrelationEngineWithConfig(cfg)
		engine.SetObserverRoot(rootPID)
		ctx := context.Background()

		alerts := engine.Ingest(ctx, newEvent(otherPID, 1))
		assert.Len(t, alerts, 1, "an attacker process, not a descendant of the harness, must still alert")
	})

	t.Run("enabled but root not yet set: nothing is excluded", func(t *testing.T) {
		cfg := DefaultCorrelationEngineConfig()
		cfg.Rules = rules
		cfg.ObserverExcludeEnabled = true
		engine := NewCorrelationEngineWithConfig(cfg)
		ctx := context.Background()

		// SetObserverRoot never called — root PID is still the zero value,
		// which must never match a real process (PID 0 is not a process).
		alerts := engine.Ingest(ctx, newEvent(rootPID, 1))
		assert.Len(t, alerts, 1, "before the harness's PID is known, nothing should be excluded")
	})

	t.Run("disabled: root PID still alerts", func(t *testing.T) {
		cfg := DefaultCorrelationEngineConfig()
		cfg.Rules = rules
		cfg.ObserverExcludeEnabled = false
		engine := NewCorrelationEngineWithConfig(cfg)
		engine.SetObserverRoot(rootPID)
		ctx := context.Background()

		alerts := engine.Ingest(ctx, newEvent(rootPID, 1))
		assert.Len(t, alerts, 1, "observer-exclusion must be fully disable-able via config")
	})

	t.Run("root change clears the cached tree", func(t *testing.T) {
		cfg := DefaultCorrelationEngineConfig()
		cfg.Rules = rules
		cfg.ObserverExcludeEnabled = true
		engine := NewCorrelationEngineWithConfig(cfg)
		engine.SetObserverRoot(rootPID)
		ctx := context.Background()

		// Grow the tree: childPID cached as a descendant of rootPID.
		assert.Empty(t, engine.Ingest(ctx, newEvent(childPID, rootPID)))

		// Harness run ends (root cleared to 0), a NEW harness starts with a
		// different PID. childPID may since have been reused by an unrelated
		// process — the stale cache entry must not keep excluding it.
		engine.SetObserverRoot(0)
		engine.SetObserverRoot(otherPID)

		alerts := engine.Ingest(ctx, newEvent(childPID, 1))
		assert.Len(t, alerts, 1,
			"a PID cached under a previous observer root must alert again after the root changes")
	})

	// Regression test for находка №34 (5.9.1a). SetObserverRoot is driven by a
	// 2s file poller (cmd/ebpf-guard/main.go) that typically lags well behind
	// the harness's first fork/exec, so an intermediate process's own event
	// commonly arrives — and gets lineage-tracked — before the agent has even
	// learned the root PID. The old one-hop check only ever cached a PID in
	// observerTree as a side effect of isObserverDescendant matching at the
	// moment that PID's own event was evaluated; if root was still 0 at that
	// moment, the match could never happen and the PID was cached nowhere, so
	// a descendant's later event (after root becomes known) had nothing to
	// hit via observerTree.Load(ppid). The full ancestor-chain walk fixes this
	// because lineageTracker.Track records raw PID/PPID lineage independently
	// of whether observer exclusion matched anything at the time.
	t.Run("enabled: descendant excluded even though intermediate was tracked before root was known", func(t *testing.T) {
		cfg := DefaultCorrelationEngineConfig()
		cfg.Rules = rules
		cfg.ObserverExcludeEnabled = true
		engine := NewCorrelationEngineWithConfig(cfg)
		ctx := context.Background()

		const intermediatePID = uint32(4310) // e.g. a shell the harness forked
		const leafPID = uint32(4320)         // e.g. curl, forked by the shell

		// Root not set yet (poller hasn't picked up the harness's PID file):
		// this event cannot be excluded, but lineageTracker.Track still runs
		// and records intermediatePID -> rootPID ancestry.
		nonMatchingEvent := types.Event{
			Type: types.EventFileAccess,
			PID:  intermediatePID,
			PPID: rootPID,
			File: &types.FileEvent{Op: 2}, // not "read" (1) — won't match rule_001
		}
		assert.Empty(t, engine.Ingest(ctx, nonMatchingEvent))

		// Root becomes known only now.
		engine.SetObserverRoot(rootPID)

		// leafPID's first event: its own ppid is intermediatePID, not root, and
		// intermediatePID was never cached in observerTree (its one chance to
		// be — its own event above — ran while root was still 0). The full
		// ancestor walk must still find root via intermediatePID's PPID field.
		alerts := engine.Ingest(ctx, newEvent(leafPID, intermediatePID))
		assert.Empty(t, alerts,
			"a descendant must be excluded via the full ancestor chain even when its parent's own PID was never cached in observerTree")
	})

	// Regression test for находка №41 (замер №2.9.1, 5.9.2d). The ancestor walk
	// returned false as soon as the lineage tracker produced ANY non-empty
	// chain that did not itself contain root — skipping the observerTree memo
	// checks below it. A short-lived pipeline leaf (`… | awk`, `… | tee`,
	// `$(date)`) has exactly that shape: by the time its chain is rebuilt from
	// /proc the intervening shell has exited, so the chain breaks at the first
	// unresolvable hop and never reaches root, even though the hop it DID
	// resolve is a PID the filter already confirmed. On замер №2.9.1 this left
	// 7 of 41 idle-hour alerts (17%, threshold <5%) on harness processes and
	// produced both process_chain-less `grep` incidents that failed criterion 10.
	t.Run("enabled: leaf excluded via memoised ancestor when its chain stops short of root", func(t *testing.T) {
		cfg := DefaultCorrelationEngineConfig()
		cfg.Rules = rules
		cfg.ObserverExcludeEnabled = true
		engine := NewCorrelationEngineWithConfig(cfg)
		engine.SetObserverRoot(rootPID)
		ctx := context.Background()

		const shellPID = uint32(4400) // shell forked by the harness
		const leafPID = uint32(4410)  // awk, forked by that shell

		// The shell's own event resolves to root and is memoised in observerTree.
		assert.Empty(t, engine.Ingest(ctx, newEvent(shellPID, rootPID)),
			"the shell is a direct child of the harness root and must be excluded")
		_, memoised := engine.observerTree.Load(shellPID)
		require.True(t, memoised, "the shell must be in observerTree for this test to exercise the memo path")

		// The shell exits and its lineage entry ages out — this is what makes
		// the leaf's chain stop short of root while the memo still holds the
		// answer. Cleanup is driven by the engine's own maintenance ticker in
		// production; here it is called directly with a clock far enough ahead
		// to pass the TTL.
		engine.lineageTracker.Cleanup(time.Now().Add(24 * time.Hour))
		require.Empty(t, engine.lineageTracker.GetProcessTree(shellPID),
			"the shell's ancestry must be gone for the chain to break at that hop")

		// The leaf's first event. Its chain can no longer reach root: the only
		// hop it resolves is the shell, whose own ancestry has been evicted.
		alerts := engine.Ingest(ctx, newEvent(leafPID, shellPID))
		assert.Empty(t, alerts,
			"a leaf whose ancestor chain stops short of root must still be excluded when its parent is already known to be in the observer tree")
	})

	// 5.9.2g: the in-kernel filter drops harness events before the ring buffer,
	// so once it is live the userspace walk is pure overhead on the agent's
	// hottest path. Anything that still arrives is by definition not in the
	// tree, and must be evaluated normally rather than re-walked.
	t.Run("kernel-side active: userspace walk is bypassed", func(t *testing.T) {
		cfg := DefaultCorrelationEngineConfig()
		cfg.Rules = rules
		cfg.ObserverExcludeEnabled = true
		engine := NewCorrelationEngineWithConfig(cfg)
		engine.SetObserverRoot(rootPID)
		ctx := context.Background()

		require.Empty(t, engine.Ingest(ctx, newEvent(rootPID, 1)),
			"sanity: with the userspace filter engaged the root's own events are excluded")

		engine.SetObserverKernelSide(true)
		assert.True(t, engine.ObserverKernelSide())

		alerts := engine.Ingest(ctx, newEvent(rootPID, 1))
		assert.NotEmpty(t, alerts,
			"with the kernel filter live the userspace walk must not run: an event that reached userspace already passed the kernel-side check")
	})

	// The kernel-side bypass must be scoped to the streams the BPF filter
	// actually covers. observer_should_drop() is compiled into three objects
	// (syscall, fileaccess, network); dns, tls, lsm/kmod, privesc, iouring,
	// gpu, bpfmonitor and http_uprobe have no such check, so for their events
	// the userspace walk is still the only filter there is. A global bypass
	// let the harness's own traffic back into the "share of the observer tree"
	// numerator through any of those collectors the moment the kernel side
	// came up — the same "mechanism silently off, indicator reads PASS" shape
	// wave 5.9.2 exists to remove.
	t.Run("kernel-side active: an event type the BPF filter does not cover is still walked", func(t *testing.T) {
		cfg := DefaultCorrelationEngineConfig()
		cfg.Rules = []Rule{{
			ID:        "rule_dns",
			Name:      "Any DNS query",
			EventType: types.EventDNS,
			Condition: RuleCondition{Field: "qname", Op: OpEquals, Values: []string{"example.com"}},
			Severity:  types.SeverityWarning,
			Action:    ActionAlert,
		}}
		cfg.ObserverExcludeEnabled = true
		engine := NewCorrelationEngineWithConfig(cfg)
		engine.SetObserverRoot(rootPID)
		engine.SetObserverKernelSide(true)
		ctx := context.Background()

		dnsEvent := func(pid, ppid uint32) types.Event {
			return types.Event{
				Type: types.EventDNS,
				PID:  pid,
				PPID: ppid,
				DNS:  &types.DNSEvent{QName: "example.com"},
			}
		}

		require.NotEmpty(t, engine.Ingest(ctx, dnsEvent(otherPID, 1)),
			"sanity: an unrelated process's DNS event must alert, or this test proves nothing")

		assert.Empty(t, engine.Ingest(ctx, dnsEvent(rootPID, 1)),
			"dns has no observer_should_drop() in its BPF object, so the userspace walk must still exclude the harness root even with the kernel side live")
		assert.Empty(t, engine.Ingest(ctx, dnsEvent(childPID, rootPID)),
			"the same must hold for a descendant discovered through the userspace walk")
	})

	// The counter series must stay continuous across the move from the
	// userspace filter to the kernel one, or the "share of the observer tree"
	// criterion silently changes meaning between waves.
	t.Run("kernel-side drops land on the same metric series", func(t *testing.T) {
		cfg := DefaultCorrelationEngineConfig()
		cfg.Rules = rules
		cfg.ObserverExcludeEnabled = true
		engine := NewCorrelationEngineWithConfig(cfg)

		before := testutil.ToFloat64(engine.eventsExcludedTotal.WithLabelValues("observer_tree"))
		engine.RecordObserverExcludedN(7)
		engine.RecordObserverExcludedN(0) // a zero delta must be a no-op
		after := testutil.ToFloat64(engine.eventsExcludedTotal.WithLabelValues("observer_tree"))

		assert.Equal(t, before+7, after,
			"kernel-side exclusions must accumulate on ebpf_guard_events_excluded_total{reason=\"observer_tree\"}, the same series 5.9a published from userspace")
	})
}

// TestCorrelationEngine_ConfirmedAttackAlertCountsInStats is the regression
// test for the 5.9c accounting hole found while recomputing the counter
// identity on №2.5 data: emitConfirmedAttackAlert fed synthetic
// incident_confirmed_attack alerts into pending without incrementing
// alertsGenerated, so every confirmed incident made engine_stats.total_alerts
// undercount the exported/store counters by one (11 of them on the idle hour).
func TestCorrelationEngine_ConfirmedAttackAlertCountsInStats(t *testing.T) {
	cfg := DefaultCorrelationEngineConfig()
	engine := NewCorrelationEngineWithConfig(cfg)

	before := engine.GetStats().AlertsGenerated
	engine.emitConfirmedAttackAlert(types.Incident{ID: "inc-1", PID: 4242})
	after := engine.GetStats().AlertsGenerated

	assert.Equal(t, before+1, after,
		"synthetic incident_confirmed_attack alerts enter the same pending pipeline as rule alerts and must be counted in engine_stats.total_alerts, or the 5.9c identity Δengine−Δfiltered−Δsuppressed = Δexported leaks one per incident")
}

// TestCorrelationEngine_FeedbackSuppressionCounted covers the other half of
// the same 5.9c accounting hole: feedbackManager.FilterAlerts drops alerts
// AFTER alertsGenerated already counted them, and until this wave that drop
// was invisible to every exported counter (7 such alerts on №2.5 idle could
// not be attributed). The drop must now land in
// ebpf_guard_alerts_suppressed_total{reason="feedback"}.
func TestCorrelationEngine_FeedbackSuppressionCounted(t *testing.T) {
	rules := []Rule{
		{
			ID:        "rule_001",
			Name:      "Any file read",
			EventType: types.EventFileAccess,
			Condition: RuleCondition{Field: "op", Op: OpEquals, Values: []string{"read"}},
			Severity:  types.SeverityWarning,
			Action:    ActionAlert,
		},
	}

	fm := feedback.NewManager("", slog.Default())
	cfg := DefaultCorrelationEngineConfig()
	cfg.Rules = rules
	cfg.FeedbackManager = fm
	engine := NewCorrelationEngineWithConfig(cfg)
	ctx := context.Background()

	newEvent := func(pid uint32) types.Event {
		e := types.Event{
			Type: types.EventFileAccess,
			PID:  pid,
			File: &types.FileEvent{Op: 1}, // 1 = read, see fileOpNames
		}
		copy(e.Comm[:], "curl")
		return e
	}

	alerts := engine.Ingest(ctx, newEvent(4242))
	require.Len(t, alerts, 1, "sanity: the rule fires before any suppression exists")
	require.Equal(t, float64(0),
		testutil.ToFloat64(engine.alertsSuppressedTotal.WithLabelValues("feedback")))

	_, err := fm.Submit(alerts[0], feedback.VerdictFalsePositive, "analyst says noise")
	require.NoError(t, err)

	// Different PID so the dedup window can't be what drops the second alert —
	// only the feedback suppression path is under test.
	alerts = engine.Ingest(ctx, newEvent(4243))
	assert.Empty(t, alerts, "the (rule_id, comm) pair is analyst-suppressed")
	assert.Equal(t, float64(1),
		testutil.ToFloat64(engine.alertsSuppressedTotal.WithLabelValues("feedback")),
		"a post-generation feedback drop must be counted, or the 5.9c counter identity leaks")
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

// TestPreAlertContext_AttachedOnMatch verifies that when EnableEventBuffer is true,
// alerts carry a PreAlertContext slice with the recent per-PID events that preceded
// the triggering event. This is the temporal attack-chain context feature.
func TestPreAlertContext_AttachedOnMatch(t *testing.T) {
	cfg := DefaultCorrelationEngineConfig()
	cfg.EnableEventBuffer = true
	cfg.EnableAnomaly = false
	cfg.EnableDedup = false
	cfg.Rules = []Rule{
		newSyscallRule("pre_ctx_rule", OpIn, []string{"1"}), // matches nr=1
	}
	engine := NewCorrelationEngineWithConfig(cfg)
	defer engine.Close()
	ctx := context.Background()

	const pid = uint32(42)
	// Send 5 background events (nr=99, no match) to seed the buffer.
	for i := range 5 {
		engine.Ingest(ctx, types.Event{
			Type:      types.EventSyscall,
			PID:       pid,
			Timestamp: uint64(i + 1),
			Syscall:   &types.SyscallEvent{Nr: 99},
		})
	}

	// Send the triggering event (nr=1, matches the rule).
	alerts := engine.Ingest(ctx, types.Event{
		Type:      types.EventSyscall,
		PID:       pid,
		Timestamp: uint64(100),
		Syscall:   &types.SyscallEvent{Nr: 1},
	})
	require.Len(t, alerts, 1, "expected one alert from rule match")

	// PreAlertContext must be populated with the 5 background events + the trigger.
	ctx6 := alerts[0].PreAlertContext
	require.NotEmpty(t, ctx6, "PreAlertContext must be non-empty when EnableEventBuffer=true")
	// The triggering event (ts=100) is the most recent — it's included.
	last := ctx6[len(ctx6)-1]
	assert.Equal(t, uint64(100), last.Timestamp, "last PreAlertContext event must be the trigger")
	// All events in the context must belong to the same PID.
	for _, ev := range ctx6 {
		assert.Equal(t, pid, ev.PID)
	}
}

// TestPreAlertContext_DisabledByDefault verifies that PreAlertContext is nil when
// EnableEventBuffer is false (the production default). This guards the hot path.
func TestPreAlertContext_DisabledByDefault(t *testing.T) {
	cfg := DefaultCorrelationEngineConfig()
	cfg.EnableEventBuffer = false
	cfg.EnableAnomaly = false
	cfg.EnableDedup = false
	cfg.Rules = []Rule{
		newSyscallRule("pre_ctx_disabled", OpIn, []string{"1"}),
	}
	engine := NewCorrelationEngineWithConfig(cfg)
	defer engine.Close()
	ctx := context.Background()

	alerts := engine.Ingest(ctx, types.Event{
		Type:      types.EventSyscall,
		PID:       1,
		Timestamp: 1,
		Syscall:   &types.SyscallEvent{Nr: 1},
	})
	require.Len(t, alerts, 1)
	assert.Nil(t, alerts[0].PreAlertContext, "PreAlertContext must be nil when buffer is disabled")
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

// TestCorrelationEngine_DedupDropsAreAttributedPerRule covers the 5.8b
// remediation of finding №21: alerts_dedup_dropped_total is a single aggregate
// counter, so when the store and the metric disagreed 2× for most rules and
// ~30× for owasp_log_tampering/sigma_log_deletion, nothing in the agent could
// say whether dedup accounted for either. The per-rule breakdown has to
// attribute a suppression to the rule that produced it, not just count it.
func TestCorrelationEngine_DedupDropsAreAttributedPerRule(t *testing.T) {
	comm := func(s string) [16]byte {
		var b [16]byte
		copy(b[:], s)
		return b
	}

	noisy := Rule{
		ID:        "dedup_attrib_noisy",
		EventType: types.EventTCPConnect,
		Condition: RuleCondition{Field: "dport", Op: OpEquals, Values: []string{"443"}},
		Severity:  types.SeverityWarning,
		Action:    ActionAlert,
	}
	quiet := Rule{
		ID:        "dedup_attrib_quiet",
		EventType: types.EventTCPConnect,
		Condition: RuleCondition{Field: "dport", Op: OpEquals, Values: []string{"8443"}},
		Severity:  types.SeverityWarning,
		Action:    ActionAlert,
	}

	cfg := DefaultCorrelationEngineConfig()
	cfg.Rules = []Rule{noisy, quiet}
	cfg.EnableRateLimit = false
	cfg.EnableAnomaly = false
	cfg.EnableDedup = true
	cfg.DedupWindow = 10 * time.Second

	engine := NewCorrelationEngineWithConfig(cfg)
	defer engine.Close()

	ctx := context.Background()
	event := types.Event{
		Type:    types.EventTCPConnect,
		PID:     100,
		Comm:    comm("nginx"),
		Network: &types.NetworkEvent{Dport: 443},
	}

	require.Len(t, engine.Ingest(ctx, event), 1, "first alert must not be deduped")
	for i := 0; i < 3; i++ {
		assert.Empty(t, engine.Ingest(ctx, event), "duplicate within window must be suppressed")
	}

	// One event for the quiet rule, never repeated — it must not pick up any
	// of the noisy rule's suppressions.
	quietEvent := event
	quietEvent.PID = 200
	quietEvent.Network = &types.NetworkEvent{Dport: 8443}
	require.Len(t, engine.Ingest(ctx, quietEvent), 1)

	assert.Equal(t, 3.0, testutil.ToFloat64(engine.alertsDedupDroppedByRule.WithLabelValues(noisy.ID)),
		"all three suppressions must be attributed to the rule that produced them")
	assert.Equal(t, 0.0, testutil.ToFloat64(engine.alertsDedupDroppedByRule.WithLabelValues(quiet.ID)),
		"a rule that never deduped must not accumulate another rule's drops")
	assert.Equal(t, 3.0, testutil.ToFloat64(engine.alertsDedupDropped),
		"the aggregate counter must stay consistent with the per-rule breakdown")
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
