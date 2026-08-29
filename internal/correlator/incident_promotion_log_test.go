package correlator

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// capturingHandler is a minimal slog.Handler that records every "incident
// promoted" record's verdict attribute, so tests can assert on how many
// times — and with which verdict — 5.9.9.F.5b's promotion log fired.
type capturingHandler struct {
	mu       sync.Mutex
	verdicts []string
}

func (h *capturingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *capturingHandler) Handle(_ context.Context, r slog.Record) error {
	if r.Message != "correlator: incident promoted" {
		return nil
	}
	var verdict string
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "verdict" {
			verdict = a.Value.String()
		}
		return true
	})
	h.mu.Lock()
	h.verdicts = append(h.verdicts, verdict)
	h.mu.Unlock()
	return nil
}

func (h *capturingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *capturingHandler) WithGroup(string) slog.Handler      { return h }

func (h *capturingHandler) snapshot() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]string, len(h.verdicts))
	copy(out, h.verdicts)
	return out
}

// TestIncidentTracker_PromotionLoggedOnceOnTransition is the 5.9.9.F.5b
// (находка №153) regression test: before this wave the agent's journal
// carried no trace of an incident being promoted to "suspicious"/"attack" at
// all, so an incident promoted and then evicted within the idle-hour window
// left nothing behind but the counter. It checks both required properties:
// the record fires exactly once per verdict transition (not once per alert
// that arrives after the transition already happened), and a de-escalation
// attempt does not duplicate it (recalculateScore never lets Verdict drop
// back out of "attack", so re-promotion of the same incident/verdict pair is
// not possible — this test pins that invariant from the logging side).
func TestIncidentTracker_PromotionLoggedOnceOnTransition(t *testing.T) {
	handler := &capturingHandler{}
	prev := slog.Default()
	slog.SetDefault(slog.New(handler))
	defer slog.SetDefault(prev)

	rules := []Rule{
		{ID: "rule1", Tags: []string{"execution", "persistence"}},
		{ID: "rule2", Tags: []string{"execution"}},
		{ID: "rule3", Tags: []string{"persistence"}},
		{ID: "rule4", Tags: []string{"execution"}},
		{ID: "rule5", Tags: []string{"privilege_escalation", "execution"}},
		{ID: "rule6", Tags: []string{"privilege_escalation"}},
		{ID: "rule7", Tags: []string{"defense_evasion"}},
		{ID: "rule8", Tags: []string{"defense_evasion"}},
	}
	tr := newIncidentTracker(60*time.Second, nil, rules)
	now := time.Now()

	// A single warning-severity alert already scores above zero
	// (cfg.WeightSeverity), so it crosses straight into VerdictSuspicious —
	// exactly one "suspicious" record expected, and repeating the same alert
	// must not duplicate it.
	tr.Add(makeAlert("rule1", 100, "prod", types.SeverityWarning, now))
	got := handler.snapshot()
	if len(got) != 1 || got[0] != string(types.VerdictSuspicious) {
		t.Fatalf("expected exactly one 'suspicious' promotion log, got %v", got)
	}
	tr.Add(makeAlert("rule2", 100, "prod", types.SeverityWarning, now.Add(time.Second)))
	got = handler.snapshot()
	if len(got) != 1 {
		t.Fatalf("expected the 'suspicious' promotion log to stay at 1 record while incident remains suspicious, got %d: %v", len(got), got)
	}

	// Remaining alerts push the incident up to VerdictAttack — one more
	// record, this time "attack", and the "suspicious" one must not repeat.
	for i := 2; i < 8; i++ {
		ruleID := fmt.Sprintf("rule%d", i+1)
		tr.Add(makeAlert(ruleID, 100, "prod", types.SeverityWarning, now.Add(time.Duration(i)*time.Second)))
	}
	got = handler.snapshot()
	if len(got) != 2 {
		t.Fatalf("expected exactly 2 promotion log records (suspicious, then attack), got %d: %v", len(got), got)
	}
	if got[0] != string(types.VerdictSuspicious) || got[1] != string(types.VerdictAttack) {
		t.Fatalf("expected [suspicious, attack] in order, got %v", got)
	}

	// Incident is already at VerdictAttack and stays there by construction
	// (recalculateScore never de-escalates out of attack) — further alerts on
	// the same incident must not re-fire the promotion log.
	tr.Add(makeAlert("rule1", 100, "prod", types.SeverityWarning, now.Add(20*time.Second)))
	tr.Add(makeAlert("rule2", 100, "prod", types.SeverityWarning, now.Add(21*time.Second)))
	got = handler.snapshot()
	if len(got) != 2 {
		t.Fatalf("expected promotion log to stay at 2 records after further alerts on an already-attack incident, got %d: %v", len(got), got)
	}
}
