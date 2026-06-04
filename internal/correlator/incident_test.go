package correlator

import (
	"fmt"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

func makeAlert(ruleID string, pid uint32, namespace string, sev types.Severity, ts time.Time) types.Alert {
	return types.Alert{
		ID:        fmt.Sprintf("alert-%s-%d-%d", ruleID, pid, ts.UnixNano()),
		RuleID:    ruleID,
		PID:       pid,
		Severity:  sev,
		Timestamp: ts,
		Enrichment: types.EnrichmentInfo{
			Namespace: namespace,
		},
	}
}

func TestIncidentTracker_GroupsSamePIDNamespace(t *testing.T) {
	tr := newIncidentTracker(60 * time.Second)
	now := time.Now()

	tr.Add(makeAlert("rule1", 100, "prod", types.SeverityWarning, now))
	tr.Add(makeAlert("rule2", 100, "prod", types.SeverityCritical, now.Add(5*time.Second)))
	tr.Add(makeAlert("rule1", 100, "prod", types.SeverityWarning, now.Add(10*time.Second)))

	incidents := tr.GetAll("", "", 0)
	if len(incidents) != 1 {
		t.Fatalf("expected 1 incident, got %d", len(incidents))
	}
	inc := incidents[0]
	if inc.AlertCount != 3 {
		t.Errorf("expected 3 alerts in incident, got %d", inc.AlertCount)
	}
	if inc.Severity != types.SeverityCritical {
		t.Errorf("expected critical severity (max), got %q", inc.Severity)
	}
	if len(inc.RuleIDs) != 2 {
		t.Errorf("expected 2 distinct rule IDs, got %d: %v", len(inc.RuleIDs), inc.RuleIDs)
	}
	if inc.Status != "open" {
		t.Errorf("expected status=open, got %q", inc.Status)
	}
}

func TestIncidentTracker_SeparatesOnWindowExpiry(t *testing.T) {
	tr := newIncidentTracker(60 * time.Second)
	now := time.Now()

	// First alert creates incident A
	tr.Add(makeAlert("rule1", 200, "dev", types.SeverityWarning, now))
	// Alert arriving after the window starts a NEW incident
	tr.Add(makeAlert("rule1", 200, "dev", types.SeverityWarning, now.Add(90*time.Second)))

	incidents := tr.GetAll("", "", 0)
	if len(incidents) != 2 {
		t.Fatalf("expected 2 separate incidents, got %d", len(incidents))
	}
}

func TestIncidentTracker_SeparatesByNamespace(t *testing.T) {
	tr := newIncidentTracker(60 * time.Second)
	now := time.Now()

	tr.Add(makeAlert("rule1", 300, "ns-a", types.SeverityWarning, now))
	tr.Add(makeAlert("rule1", 300, "ns-b", types.SeverityWarning, now.Add(time.Second)))

	allInc := tr.GetAll("", "", 0)
	if len(allInc) != 2 {
		t.Fatalf("expected 2 incidents (one per namespace), got %d", len(allInc))
	}

	nsA := tr.GetAll("ns-a", "", 0)
	if len(nsA) != 1 {
		t.Errorf("expected 1 incident for ns-a, got %d", len(nsA))
	}
}

func TestIncidentTracker_GetByID(t *testing.T) {
	tr := newIncidentTracker(60 * time.Second)
	now := time.Now()
	tr.Add(makeAlert("rule1", 400, "prod", types.SeverityWarning, now))

	all := tr.GetAll("", "", 0)
	if len(all) != 1 {
		t.Fatal("expected 1 incident")
	}
	id := all[0].ID

	inc, ok := tr.GetByID(id)
	if !ok {
		t.Fatalf("GetByID(%q) returned not found", id)
	}
	if inc.ID != id {
		t.Errorf("GetByID returned wrong ID: got %q, want %q", inc.ID, id)
	}

	_, ok = tr.GetByID("inc-nonexistent")
	if ok {
		t.Error("GetByID should return false for unknown ID")
	}
}

func TestIncidentTracker_StatusFilter(t *testing.T) {
	tr := newIncidentTracker(60 * time.Second)
	past := time.Now().Add(-120 * time.Second) // older than window → closed
	recent := time.Now()

	tr.Add(makeAlert("rule1", 500, "ns", types.SeverityWarning, past))
	tr.Add(makeAlert("rule1", 501, "ns", types.SeverityWarning, recent))

	open := tr.GetAll("", "open", 0)
	if len(open) != 1 {
		t.Errorf("expected 1 open incident, got %d", len(open))
	}

	closed := tr.GetAll("", "closed", 0)
	if len(closed) != 1 {
		t.Errorf("expected 1 closed incident, got %d", len(closed))
	}
}

func TestIncidentTracker_Cleanup(t *testing.T) {
	tr := newIncidentTracker(60 * time.Second)
	ancient := time.Now().Add(-400 * time.Second) // beyond retention (60s * 5 = 300s)

	tr.Add(makeAlert("rule1", 600, "ns", types.SeverityWarning, ancient))

	if tr.Count() != 1 {
		t.Fatal("expected 1 incident before cleanup")
	}

	tr.Cleanup(time.Now())

	if tr.Count() != 0 {
		t.Errorf("expected incident to be evicted after cleanup, got %d", tr.Count())
	}
}

func TestIncidentTracker_Limit(t *testing.T) {
	tr := newIncidentTracker(60 * time.Second)
	now := time.Now()

	for i := 0; i < 10; i++ {
		tr.Add(makeAlert("rule1", uint32(700+i), "ns", types.SeverityWarning, now))
	}

	limited := tr.GetAll("", "", 3)
	if len(limited) != 3 {
		t.Errorf("expected limit=3 results, got %d", len(limited))
	}
}

func TestIncidentTracker_MaxSeverity(t *testing.T) {
	tests := []struct {
		a, b types.Severity
		want types.Severity
	}{
		{types.SeverityWarning, types.SeverityCritical, types.SeverityCritical},
		{types.SeverityCritical, types.SeverityWarning, types.SeverityCritical},
		{types.SeverityWarning, types.SeverityWarning, types.SeverityWarning},
		{"", types.SeverityWarning, types.SeverityWarning},
	}
	for _, tt := range tests {
		got := maxIncidentSeverity(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("maxIncidentSeverity(%q, %q) = %q, want %q", tt.a, tt.b, got, tt.want)
		}
	}
}
