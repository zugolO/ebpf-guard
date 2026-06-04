package simulate

import (
	"bytes"
	"strings"
	"testing"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

func TestCollector_Empty(t *testing.T) {
	c := NewCollector()
	var buf bytes.Buffer
	c.PrintReport(&buf)
	out := buf.String()
	if !strings.Contains(out, "No alerts") {
		t.Errorf("expected 'No alerts' in output, got:\n%s", out)
	}
}

func TestCollector_Record(t *testing.T) {
	c := NewCollector()

	c.Record(types.Alert{RuleID: "rule_001", Comm: "nginx", Severity: types.SeverityCritical, Action: "kill"})
	c.Record(types.Alert{RuleID: "rule_001", Comm: "nginx", Severity: types.SeverityWarning, Action: "block"})
	c.Record(types.Alert{RuleID: "rule_002", Comm: "curl", Severity: types.SeverityWarning, Action: "throttle"})
	c.Record(types.Alert{RuleID: "rule_003", Comm: "curl", Severity: types.SeverityWarning, Action: ""})

	counts := c.actionCounts()
	if counts["kill"] != 1 {
		t.Errorf("expected 1 kill, got %d", counts["kill"])
	}
	if counts["block"] != 1 {
		t.Errorf("expected 1 block, got %d", counts["block"])
	}
	if counts["throttle"] != 1 {
		t.Errorf("expected 1 throttle, got %d", counts["throttle"])
	}
	if counts["alert"] != 1 {
		t.Errorf("expected 1 alert (empty action), got %d", counts["alert"])
	}

	ruleCounts := c.ruleCounts()
	if ruleCounts["rule_001"] != 2 {
		t.Errorf("expected rule_001 count=2, got %d", ruleCounts["rule_001"])
	}
}

func TestCollector_PrintReport(t *testing.T) {
	c := NewCollector()
	for i := 0; i < 5; i++ {
		c.Record(types.Alert{RuleID: "rule_kill", Comm: "attacker", Severity: types.SeverityCritical, Action: "kill"})
	}
	for i := 0; i < 3; i++ {
		c.Record(types.Alert{RuleID: "rule_block", Comm: "scanner", Severity: types.SeverityWarning, Action: "block"})
	}

	var buf bytes.Buffer
	c.PrintReport(&buf)
	out := buf.String()

	for _, want := range []string{"kill", "block", "rule_kill", "rule_block", "8"} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q:\n%s", want, out)
		}
	}
}

func TestTopN(t *testing.T) {
	m := map[string]int{"a": 10, "b": 5, "c": 20, "d": 1}
	top := topN(m, 2)
	if len(top) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(top))
	}
	if top[0].key != "c" || top[0].val != 20 {
		t.Errorf("expected top[0]=(c,20), got (%s,%d)", top[0].key, top[0].val)
	}
	if top[1].key != "a" || top[1].val != 10 {
		t.Errorf("expected top[1]=(a,10), got (%s,%d)", top[1].key, top[1].val)
	}
}
