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

// TestIncidentTracker_ScoringAlertCountDedupsBySourceEvent is the regression
// test for 5.8f (находка №19): a single /proc read fans out into multiple
// rule matches, and prior to the fix each one incremented ScoringAlertCount
// independently, inflating the time-density score term as if that many
// distinct events had arrived in the same instant. sourceEventKey is derived
// from (PID, Timestamp), which the correlator always sets identically for
// every rule that fires off the same triggering event — makeAlert with a
// shared ts reproduces that here without needing a real event.
func TestIncidentTracker_ScoringAlertCountDedupsBySourceEvent(t *testing.T) {
	rules := []Rule{
		{ID: "r1", Tags: []string{"execution"}},
		{ID: "r2", Tags: []string{"execution"}},
		{ID: "r3", Tags: []string{"execution"}},
	}
	tr := newIncidentTracker(60*time.Second, nil, rules)
	ts := time.Now()

	tr.Add(makeAlert("r1", 100, "prod", types.SeverityWarning, ts))
	tr.Add(makeAlert("r2", 100, "prod", types.SeverityWarning, ts))
	tr.Add(makeAlert("r3", 100, "prod", types.SeverityWarning, ts))

	incidents := tr.GetAll("", "", 0)
	if len(incidents) != 1 {
		t.Fatalf("expected 1 incident, got %d", len(incidents))
	}
	inc := incidents[0]
	if inc.AlertCount != 3 {
		t.Errorf("AlertCount (observability, unaffected by the fix) = %d, want 3", inc.AlertCount)
	}
	if inc.ScoringAlertCount != 1 {
		t.Errorf("ScoringAlertCount = %d, want 1 (one source event, not one per fanned-out rule)", inc.ScoringAlertCount)
	}
	if len(inc.ScoringSourceEvents) != 1 {
		t.Errorf("ScoringSourceEvents has %d entries, want 1", len(inc.ScoringSourceEvents))
	}
}

// TestIncidentTracker_ProcReconClusterCollapsesToOneSignal is the regression
// test for 5.8f point 2 (находка №19): container_escape_init_proc,
// mitre_sandbox_detect_proc_read and sigma_cpu_info_access all detect the
// same underlying /proc read from three angles and share procReconClusterTag.
// Before collapsing, one such read firing all three counted as three
// independent rules and — since the three rules here carry three distinct
// tactics — three independent tactics, both of which push the score up on
// their own. After collapsing they must count as exactly one signal.
func TestIncidentTracker_ProcReconClusterCollapsesToOneSignal(t *testing.T) {
	rules := []Rule{
		{ID: "cluster_a", Tags: []string{"execution", procReconClusterTag}},
		{ID: "cluster_b", Tags: []string{"persistence", procReconClusterTag}},
		{ID: "cluster_c", Tags: []string{"privilege_escalation", procReconClusterTag}},
	}
	tr := newIncidentTracker(60*time.Second, nil, rules)
	ts := time.Now()

	// One /proc read, same PID + timestamp, fanning out across the cluster.
	tr.Add(makeAlert("cluster_a", 100, "prod", types.SeverityWarning, ts))
	tr.Add(makeAlert("cluster_b", 100, "prod", types.SeverityWarning, ts))
	tr.Add(makeAlert("cluster_c", 100, "prod", types.SeverityWarning, ts))

	incidents := tr.GetAll("", "", 0)
	if len(incidents) != 1 {
		t.Fatalf("expected 1 incident, got %d", len(incidents))
	}
	inc := incidents[0]

	// RuleIDs stays fully observable — nothing disappears from the record.
	if len(inc.RuleIDs) != 3 {
		t.Errorf("RuleIDs (observability) = %d, want 3: %v", len(inc.RuleIDs), inc.RuleIDs)
	}
	// Tactics is observable too and keeps reporting everything actually seen —
	// collapsing it would both hide evidence and (since the collapse picks one
	// cluster member) make the reported tactic depend on map iteration order.
	if len(inc.Tactics) != 3 {
		t.Errorf("Tactics (observability) = %d, want 3: %v", len(inc.Tactics), inc.Tactics)
	}
	// The collapse shows up in the score instead. Measured against the same
	// three alerts on three *untagged* rules: there the three distinct tactics
	// clear minTacticsForScore and add 3 × WeightTacticsDiversity, here the
	// cluster contributes one tactic and the term must not fire at all.
	untagged := []Rule{
		{ID: "cluster_a", Tags: []string{"execution"}},
		{ID: "cluster_b", Tags: []string{"persistence"}},
		{ID: "cluster_c", Tags: []string{"privilege_escalation"}},
	}
	tu := newIncidentTracker(60*time.Second, nil, untagged)
	tu.Add(makeAlert("cluster_a", 100, "prod", types.SeverityWarning, ts))
	tu.Add(makeAlert("cluster_b", 100, "prod", types.SeverityWarning, ts))
	tu.Add(makeAlert("cluster_c", 100, "prod", types.SeverityWarning, ts))
	uncollapsed := tu.GetAll("", "", 0)[0].Score
	wantDelta := 3 * DefaultIncidentScoringConfig().WeightTacticsDiversity
	if uncollapsed-inc.Score != wantDelta {
		t.Errorf("collapse saved %f score points, want exactly %f (3 tactics × WeightTacticsDiversity); collapsed=%f uncollapsed=%f",
			uncollapsed-inc.Score, wantDelta, inc.Score, uncollapsed)
	}
	if inc.Verdict == types.VerdictAttack {
		t.Errorf("a single fanned-out /proc read must not alone promote to attack; score=%f", inc.Score)
	}
}

// TestIncidentTracker_ClusterCollapseIsDeterministic pins the collapse to a
// stable representative. Cluster members carry different tactics, so choosing
// the representative by Go map iteration order made the score (and the
// reported Tactics) differ between runs on byte-identical input — a scoring
// formula that is not a function of its inputs cannot be reasoned about across
// two measurement runs, which is exactly what wave 5.8 is being accepted on.
func TestIncidentTracker_ClusterCollapseIsDeterministic(t *testing.T) {
	// Tagged exactly like the three real cluster members, whose tactic sets
	// differ in *size*: container_escape_init_proc's tags map to no MITRE
	// tactic at all, the other two map to one each. Whichever member the
	// collapse keeps therefore decides whether the incident shows 1 or 2
	// tactics — i.e. whether it clears minTacticsForScore.
	rules := []Rule{
		{ID: "cluster_a", Tags: []string{"container-escape", "init-process", "pid-1", procReconClusterTag}},
		{ID: "cluster_b", Tags: []string{"mitre:T1497.001", "sandbox-evasion", procReconClusterTag}},
		{ID: "cluster_c", Tags: []string{"mitre:T1082", "sigma", procReconClusterTag}},
		{ID: "solo_d", Tags: []string{"mitre:T1543", "persistence"}},
	}

	var first float64
	for i := 0; i < 50; i++ {
		tr := newIncidentTracker(60*time.Second, nil, rules)
		ts := time.Now()
		for j, id := range []string{"cluster_a", "cluster_b", "cluster_c", "solo_d"} {
			tr.Add(makeAlert(id, 100, "prod", types.SeverityWarning, ts.Add(time.Duration(j)*time.Second)))
		}
		score := tr.GetAll("", "", 0)[0].Score
		if i == 0 {
			first = score
			continue
		}
		if score != first {
			t.Fatalf("iteration %d scored %f, first iteration scored %f — collapse representative depends on map order", i, score, first)
		}
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
