package correlator

import (
	"fmt"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/internal/profiler"
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

// makeAlertWithComm is the P1-27 companion to makeAlert: incidents must carry
// the triggering process name, so attack-burst helpers need a way to attach a
// comm without touching every existing caller of makeAlert.
func makeAlertWithComm(ruleID string, pid uint32, namespace string, sev types.Severity, ts time.Time, comm string) types.Alert {
	a := makeAlert(ruleID, pid, namespace, sev, ts)
	a.Comm = comm
	return a
}

func TestIncidentTracker_AttackScoring(t *testing.T) {
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

	for i := 0; i < 8; i++ {
		ruleID := fmt.Sprintf("rule%d", i+1)
		tr.Add(makeAlert(ruleID, 100, "prod", types.SeverityWarning, now.Add(time.Duration(i)*time.Second)))
	}

	incidents := tr.GetAll("", "", 0)
	if len(incidents) != 1 {
		t.Fatalf("expected 1 incident, got %d", len(incidents))
	}

	inc := incidents[0]
	if inc.Verdict != types.VerdictAttack {
		t.Errorf("expected verdict %s, got %s", types.VerdictAttack, inc.Verdict)
	}

	if inc.Score < attackScoreThreshold {
		t.Errorf("expected score >= %f, got %f", attackScoreThreshold, inc.Score)
	}
}

func TestIncidentTracker_GroupsSamePIDNamespace(t *testing.T) {
	tr := newIncidentTracker(60*time.Second, nil, []Rule{})
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
	tr := newIncidentTracker(60*time.Second, nil, []Rule{})
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
	tr := newIncidentTracker(60*time.Second, nil, []Rule{})
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
	tr := newIncidentTracker(60*time.Second, nil, []Rule{})
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
	tr := newIncidentTracker(60*time.Second, nil, []Rule{})
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
	tr := newIncidentTracker(60*time.Second, nil, []Rule{})
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
	tr := newIncidentTracker(60*time.Second, nil, []Rule{})
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

// TestIncidentTracker_ProcessTreeCorrelation tests P0-1 acceptance criteria:
// parent-shell → child-download → child-exec from one process-tree gives ONE incident.
func TestIncidentTracker_ProcessTreeCorrelation(t *testing.T) {
	lt := profiler.NewLineageTracker(profiler.DefaultLineageConfig(), nil)
	tr := newIncidentTracker(60*time.Second, lt, []Rule{})
	now := time.Now()

	// Build process tree: systemd(1) → bash(100) → curl(200) → xmrig(300)
	// Use Track to populate lineage information
	lt.Track(types.Event{
		PID:        100,
		PPID:       1,
		Comm:       [16]byte{'b', 'a', 's', 'h'},
		ParentComm: [16]byte{'s', 'y', 's', 't', 'e', 'm', 'd'},
	})
	lt.Track(types.Event{
		PID:        200,
		PPID:       100,
		Comm:       [16]byte{'c', 'u', 'r', 'l'},
		ParentComm: [16]byte{'b', 'a', 's', 'h'},
	})
	lt.Track(types.Event{
		PID:        300,
		PPID:       200,
		Comm:       [16]byte{'x', 'm', 'r', 'i', 'g'},
		ParentComm: [16]byte{'c', 'u', 'r', 'l'},
	})

	// Create alerts for each process in the chain
	alerts := []types.Alert{
		makeAlert("shell_network_tool", 100, "prod", types.SeverityCritical, now),
		makeAlert("network_egress", 200, "prod", types.SeverityWarning, now.Add(5*time.Second)),
		makeAlert("crypto_miner", 300, "prod", types.SeverityCritical, now.Add(10*time.Second)),
	}

	// Add process tree to each alert
	for i := range alerts {
		alerts[i].ProcessTree = lt.GetProcessTree(alerts[i].PID)
		tr.Add(alerts[i])
	}

	// All three alerts should be grouped into a SINGLE incident
	incidents := tr.GetAll("", "", 0)
	if len(incidents) != 1 {
		t.Fatalf("expected 1 incident for entire attack chain, got %d", len(incidents))
	}

	inc := incidents[0]
	if inc.AlertCount != 3 {
		t.Errorf("expected 3 alerts in incident, got %d", inc.AlertCount)
	}
	if inc.Severity != types.SeverityCritical {
		t.Errorf("expected critical severity, got %q", inc.Severity)
	}
	if len(inc.RuleIDs) != 3 {
		t.Errorf("expected 3 distinct rule IDs, got %d: %v", len(inc.RuleIDs), inc.RuleIDs)
	}

	// Verify the incident has a root PID (it may be 100 if PID 1 wasn't seen by BPF)
	if inc.RootPID == 0 {
		t.Error("expected RootPID to be set")
	}
	if len(inc.ProcessChain) == 0 {
		t.Error("expected ProcessChain to be populated")
	}
	if len(inc.ProcessChain) < 3 {
		t.Errorf("expected at least 3 entries in ProcessChain, got %d", len(inc.ProcessChain))
	}

	// Verify the chain contains the expected process names
	expectedComms := []string{"bash", "curl", "xmrig"}
	for _, expected := range expectedComms {
		found := false
		for _, actual := range inc.ProcessChain {
			if actual == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected process chain to contain %q, got %v", expected, inc.ProcessChain)
		}
	}
}
