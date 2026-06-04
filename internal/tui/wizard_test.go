package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

func TestBuildYAML(t *testing.T) {
	m := NewWizardModel()
	// Populate step 1 field choices for event_type=network
	m.steps[1].choices = fieldChoices("network")
	// Simulate answering all steps
	answers := []string{
		"network",        // event_type
		"dport",          // field
		"eq",             // operator
		"4444",           // values
		"critical",       // severity
		"block",          // action
		"detect c2 port", // name
		"",               // description (blank)
	}
	for i, ans := range answers {
		m.steps[i].answer = ans
		if m.steps[i].kind == stepText {
			m.steps[i].input = ans
		}
	}
	yaml := m.buildYAML()

	for _, want := range []string{
		"event_type: network",
		`field: "dport"`,
		"op: eq",
		`"4444"`,
		"severity: critical",
		"action: block",
		"detect_c2_port",
	} {
		if !strings.Contains(yaml, want) {
			t.Errorf("generated YAML missing %q:\n%s", want, yaml)
		}
	}
}

func TestFieldChoices(t *testing.T) {
	tests := []struct {
		eventType string
		wantField string
	}{
		{"syscall", "syscall_nr"},
		{"network", "dport"},
		{"file", "filename"},
		{"dns", "qname"},
		{"tls", "data"},
		{"privesc", "caps_gained"},
		{"kmod", "module_name"},
	}
	for _, tt := range tests {
		choices := fieldChoices(tt.eventType)
		found := false
		for _, c := range choices {
			if c.value == tt.wantField {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("fieldChoices(%q) missing field %q", tt.eventType, tt.wantField)
		}
	}
}

func TestFeedPushSnapshot(t *testing.T) {
	f := NewFeed()

	a := types.Alert{
		ID:        "test-1",
		RuleID:    "rule_001",
		Comm:      "nginx",
		Severity:  types.SeverityCritical,
		Timestamp: time.Now(),
	}
	for i := 0; i < 5; i++ {
		f.PushAlert(a)
	}

	alerts, _, stats := f.Snapshot(3, 10)
	if len(alerts) != 3 {
		t.Errorf("expected 3 alerts from snapshot(max=3), got %d", len(alerts))
	}
	if stats.TotalAlerts != 5 {
		t.Errorf("expected TotalAlerts=5, got %d", stats.TotalAlerts)
	}
	if stats.Critical != 5 {
		t.Errorf("expected Critical=5, got %d", stats.Critical)
	}
}

func TestFeedRuleHits(t *testing.T) {
	f := NewFeed()
	for i := 0; i < 3; i++ {
		f.PushAlert(types.Alert{RuleID: "rule_a", Severity: types.SeverityWarning})
	}
	f.PushAlert(types.Alert{RuleID: "rule_b", Severity: types.SeverityCritical})

	_, _, stats := f.Snapshot(10, 10)
	if stats.RuleHits["rule_a"] != 3 {
		t.Errorf("expected rule_a hits=3, got %d", stats.RuleHits["rule_a"])
	}
	if stats.RuleHits["rule_b"] != 1 {
		t.Errorf("expected rule_b hits=1, got %d", stats.RuleHits["rule_b"])
	}
}
