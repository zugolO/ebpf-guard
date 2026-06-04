package correlator

import (
	"context"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

func TestReplay_NoEvents(t *testing.T) {
	engine := NewRuleEngine([]Rule{})
	result := Replay(context.Background(), engine, nil, time.Hour, "/fake/path", 10)
	if result.TotalEvents != 0 {
		t.Errorf("expected 0 total events, got %d", result.TotalEvents)
	}
	if result.MatchedAlerts != 0 {
		t.Errorf("expected 0 matched alerts, got %d", result.MatchedAlerts)
	}
	summary := result.PrintSummary()
	if summary == "" {
		t.Error("PrintSummary returned empty string")
	}
}

func TestReplay_MatchesRule(t *testing.T) {
	rules := []Rule{
		{
			ID:        "test_file",
			Name:      "Test file access",
			EventType: types.EventFileAccess,
			Condition: RuleCondition{
				Field:  "filename",
				Op:     OpEquals,
				Values: []string{"/etc/shadow.canary"},
			},
			Severity: "critical",
			Action:   ActionAlert,
		},
	}
	engine := NewRuleEngine(rules)

	events := []types.Event{
		{
			Type: types.EventFileAccess,
			PID:  1234,
			File: &types.FileEvent{Filename: [256]byte{}},
		},
		{
			Type: types.EventFileAccess,
			PID:  5678,
			File: &types.FileEvent{},
		},
	}
	// Set canary filename on first event.
	copy(events[0].File.Filename[:], "/etc/shadow.canary")

	result := Replay(context.Background(), engine, events, time.Hour, "/fake", 20)
	if result.TotalEvents != 2 {
		t.Errorf("expected 2 total events, got %d", result.TotalEvents)
	}
	if result.MatchedAlerts != 1 {
		t.Errorf("expected 1 matched alert, got %d", result.MatchedAlerts)
	}
	if result.AlertsByRule["test_file"] != 1 {
		t.Errorf("expected 1 alert for test_file, got %d", result.AlertsByRule["test_file"])
	}
	if len(result.SampleAlerts) != 1 {
		t.Errorf("expected 1 sample alert, got %d", len(result.SampleAlerts))
	}
}

func TestReplay_SampleLimit(t *testing.T) {
	rules := []Rule{
		{
			ID:        "r1",
			EventType: types.EventFileAccess,
			Condition: RuleCondition{
				Field:  "filename",
				Op:     OpEquals,
				Values: []string{"/etc/shadow.canary"},
			},
			Severity: "critical",
			Action:   ActionAlert,
		},
	}
	engine := NewRuleEngine(rules)

	events := make([]types.Event, 30)
	for i := range events {
		fe := &types.FileEvent{}
		copy(fe.Filename[:], "/etc/shadow.canary")
		events[i] = types.Event{Type: types.EventFileAccess, PID: uint32(i), File: fe}
	}

	result := Replay(context.Background(), engine, events, time.Hour, "/fake", 5)
	if result.MatchedAlerts != 30 {
		t.Errorf("expected 30 matched alerts, got %d", result.MatchedAlerts)
	}
	if len(result.SampleAlerts) != 5 {
		t.Errorf("expected sample limit of 5, got %d", len(result.SampleAlerts))
	}
}

func TestReplayResult_PrintSummary_WithAlerts(t *testing.T) {
	r := &ReplayResult{
		TotalEvents:   100,
		MatchedAlerts: 3,
		AlertsByRule:  map[string]int{"canary_001": 3},
		RuleNames:     map[string]string{"canary_001": "Canary Trap"},
		SampleAlerts: []types.Alert{
			{RuleID: "canary_001", Severity: "critical", PID: 42, Comm: "curl"},
		},
		SampleLimit:  20,
		Window:       24 * time.Hour,
		EventLogPath: "/var/lib/ebpf-guard/events.jsonl",
	}
	s := r.PrintSummary()
	if s == "" {
		t.Fatal("PrintSummary returned empty string")
	}
	for _, want := range []string{"100", "3", "canary_001", "Canary Trap"} {
		if !containsStr(s, want) {
			t.Errorf("PrintSummary missing %q; got:\n%s", want, s)
		}
	}
}

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsByte(s, substr))
}

func containsByte(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
