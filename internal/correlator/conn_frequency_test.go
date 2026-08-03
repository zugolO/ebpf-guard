package correlator

import (
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// A single connection must count once no matter how many rules reference
// conn_rate_1m. Regression test: the field used to call Record() from
// getFieldValue, which the rule engine invokes once per rule (and once per
// condition inside a condition group), so the observed rate scaled with the
// size of the ruleset instead of with actual traffic — a 2-rule ruleset
// reached a "30 connections/min" threshold after 15 real connections.
func TestConnRate_RecordedOncePerEventNotPerRule(t *testing.T) {
	globalConnFrequency = NewConnFrequencyTracker()
	defer func() { globalConnFrequency = NewConnFrequencyTracker() }()

	cond := RuleCondition{Field: "conn_rate_1m", Op: OpGreaterThan, Values: []string{"1000000"}}
	engine := NewRuleEngine([]Rule{
		{ID: "r1", EventType: types.EventTCPConnect, Condition: cond, Severity: types.SeverityWarning},
		{ID: "r2", EventType: types.EventTCPConnect, Condition: cond, Severity: types.SeverityWarning},
		{ID: "r3", EventType: types.EventTCPConnect, Condition: cond, Severity: types.SeverityWarning},
	})

	now := time.Now()
	e := types.Event{
		Type:      types.EventTCPConnect,
		PID:       42,
		Timestamp: uint64(now.UnixNano()),
		Network:   &types.NetworkEvent{Dport: 443},
	}
	globalConnFrequency.Record(e.PID, e.Network.Dport, eventTime(e)) // as the engine does, once
	engine.Evaluate(e)

	if got := globalConnFrequency.Rate(42, 443, now); got != 1 {
		t.Fatalf("one connection evaluated against 3 rules produced rate %d, want 1", got)
	}
}

// Events without a populated BPF timestamp must still be counted. time.Unix(0,0)
// is 1970, which falls outside every sliding window, so treating a zero
// timestamp literally pinned the rate at 1 and silently disabled frequency
// rules on paths that don't set it (synthetic collector, replay, tests).
func TestConnRate_ZeroTimestampFallsBackToNow(t *testing.T) {
	tr := NewConnFrequencyTracker()
	e := types.Event{Type: types.EventTCPConnect, PID: 9, Timestamp: 0, Network: &types.NetworkEvent{Dport: 22}}
	for i := 0; i < 40; i++ {
		tr.Record(e.PID, e.Network.Dport, eventTime(e))
	}
	if got := tr.Rate(9, 22, time.Now()); got != 40 {
		t.Fatalf("rate with zero timestamps = %d, want 40", got)
	}
}

// Rate must not mutate the window: repeated reads report the same value.
func TestConnRate_RateIsReadOnly(t *testing.T) {
	tr := NewConnFrequencyTracker()
	now := time.Now()
	tr.Record(1, 80, now)
	tr.Record(1, 80, now)
	for i := 0; i < 5; i++ {
		if got := tr.Rate(1, 80, now); got != 2 {
			t.Fatalf("Rate call %d returned %d, want 2 (Rate must not record)", i, got)
		}
	}
	if got := tr.Rate(7, 7, now); got != 0 {
		t.Fatalf("Rate for unknown key = %d, want 0", got)
	}
}

func TestConnFrequencyTracker_CountsWithinWindow(t *testing.T) {
	tr := NewConnFrequencyTracker()
	base := time.Now()

	for i := 0; i < 5; i++ {
		count := tr.Record(1234, 443, base.Add(time.Duration(i)*time.Second))
		if count != i+1 {
			t.Fatalf("attempt %d: got count %d, want %d", i, count, i+1)
		}
	}
}

func TestConnFrequencyTracker_WindowSlides(t *testing.T) {
	tr := NewConnFrequencyTracker()
	base := time.Now()

	tr.Record(1, 80, base)
	tr.Record(1, 80, base.Add(10*time.Second))

	// 90s later: cutoff is 30s after base, so both prior samples have expired
	// and only this new one remains.
	count := tr.Record(1, 80, base.Add(90*time.Second))
	if count != 1 {
		t.Fatalf("expected only the most recent attempt to remain in window, got %d", count)
	}
}

func TestConnFrequencyTracker_SeparateKeysDoNotCollide(t *testing.T) {
	tr := NewConnFrequencyTracker()
	base := time.Now()

	tr.Record(1, 443, base)
	tr.Record(2, 443, base)
	count := tr.Record(1, 22, base)

	if count != 1 {
		t.Fatalf("different pid/port keys must not share counts, got %d", count)
	}
}

func TestConnFrequencyTracker_Cleanup(t *testing.T) {
	tr := NewConnFrequencyTracker()
	past := time.Now().Add(-time.Hour)
	tr.Record(1, 80, past)

	removed := tr.Cleanup(10 * time.Minute)
	if removed != 1 {
		t.Fatalf("expected 1 stale key removed, got %d", removed)
	}
}

// TestNetHighFrequencyConnectionsRule verifies the brute-force behavioral
// signal added for P3-9: repeated connections from one PID to the same port
// within the window trip net_high_frequency_connections, even though no
// syscall or file event was ever generated (the SQLi/brute-force attacks
// this rule targets are pure L7 HTTP traffic).
func TestNetHighFrequencyConnectionsRule(t *testing.T) {
	rules := []Rule{
		{
			ID:        "net_high_frequency_connections",
			EventType: types.EventTCPConnect,
			ConditionGroup: &RuleConditionGroup{
				Operator: "and",
				Conditions: []RuleCondition{
					{Field: "conn_rate_1m", Op: OpGreaterThan, Values: []string{"30"}},
				},
			},
			Severity: types.SeverityWarning,
			Action:   ActionAlert,
		},
	}
	engine := NewRuleEngine(rules)

	globalConnFrequency = NewConnFrequencyTracker()
	defer func() { globalConnFrequency = NewConnFrequencyTracker() }()

	makeEvent := func(pid uint32, ts time.Time) types.Event {
		return types.Event{
			Type:      types.EventTCPConnect,
			PID:       pid,
			Timestamp: uint64(ts.UnixNano()),
			Network:   &types.NetworkEvent{Dport: 3000},
		}
	}

	base := time.Now()
	var lastAlerts []types.Alert
	for i := 0; i < 31; i++ {
		e := makeEvent(999, base.Add(time.Duration(i)*time.Second))
		// The engine records each connection exactly once per event before rule
		// evaluation (see ingestWithAD); Evaluate itself only reads the rate, so
		// the count can't depend on how many rules reference conn_rate_1m.
		globalConnFrequency.Record(e.PID, e.Network.Dport, eventTime(e))
		lastAlerts = engine.Evaluate(e)
	}

	if len(lastAlerts) == 0 {
		t.Fatal("expected high-frequency connection alert after 31 rapid connections, got none")
	}
	if lastAlerts[0].RuleID != "net_high_frequency_connections" {
		t.Fatalf("unexpected rule fired: %s", lastAlerts[0].RuleID)
	}
}
