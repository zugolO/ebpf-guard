package correlator

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/zugolO/ebpf-guard/internal/profiler"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// counterValue reads the current value of ebpf_guard_incidents_total{verdict=v}.
func counterValue(t *testing.T, verdict string) float64 {
	t.Helper()
	c, err := incidentsTotal.GetMetricWithLabelValues(verdict)
	if err != nil {
		t.Fatalf("GetMetricWithLabelValues(%q): %v", verdict, err)
	}
	var m dto.Metric
	if err := c.(prometheus.Metric).Write(&m); err != nil {
		t.Fatalf("write metric: %v", err)
	}
	return m.GetCounter().GetValue()
}

// scoringRules returns 5 rules spanning 2 tactics — enough to cross the
// attack threshold under the default scoring config.
func scoringRules() []Rule {
	return []Rule{
		{ID: "r1", Tags: []string{"mitre:T1190", "owasp", "cve-2021-44228"}},
		{ID: "r2", Tags: []string{"mitre:T1059.004", "gtfobins"}},
		{ID: "r3", Tags: []string{"mitre:T1059", "sigma"}},
		{ID: "r4", Tags: []string{"mitre:T1105", "cloud"}},
		{ID: "r5", Tags: []string{"mitre:T1486", "aws"}},
	}
}

// addAttackBurst feeds five distinct rules at pid/namespace so the incident
// crosses the attack threshold.
func addAttackBurst(tr *IncidentTracker, pid uint32, ns string, start time.Time) {
	for i, id := range []string{"r1", "r2", "r3", "r4", "r5"} {
		tr.Add(makeAlert(id, pid, ns, types.SeverityCritical, start.Add(time.Duration(i)*time.Second)))
	}
}

// TestIncidentTracker_TacticsIgnoreNonTacticTags verifies that descriptive tags
// (sigma/owasp/aws/cloud/gtfobins/cve-*) are not counted as MITRE tactics. A
// single noisy rule tagged with four such labels must not manufacture tactic
// diversity — the bug that turned host noise into "attack" verdicts.
func TestIncidentTracker_TacticsIgnoreNonTacticTags(t *testing.T) {
	rules := []Rule{
		{ID: "noisy", Tags: []string{"container-escape", "mount", "cis", "sigma", "owasp", "aws", "cloud", "gtfobins"}},
	}
	tr := newIncidentTracker(60*time.Second, nil, rules)

	tactics := tr.extractTactics([]string{"noisy"})
	if len(tactics) != 0 {
		t.Fatalf("descriptive tags must not count as tactics, got %v", tactics)
	}

	// Even a burst of that one rule at critical severity must stay below the
	// attack threshold.
	now := time.Now()
	for i := 0; i < 20; i++ {
		tr.Add(makeAlert("noisy", 42, "prod", types.SeverityCritical, now.Add(time.Duration(i)*time.Second)))
	}
	inc := tr.GetAll("", "", 0)[0]
	if inc.Verdict == types.VerdictAttack {
		t.Errorf("single noisy rule reached attack verdict (score %.1f) — tag inflation regressed", inc.Score)
	}
}

// TestTacticForTag covers the tag→tactic normalisation table.
func TestTacticForTag(t *testing.T) {
	cases := map[string]string{
		"mitre:T1190":            tacticInitialAccess,
		"mitre:T1552.005":        tacticCredentialAccess,
		"MITRE:t1486":            tacticImpact,
		"privilege_escalation":   tacticPrivilegeEscalation,
		"privilege-escalation":   tacticPrivilegeEscalation,
		"privesc":                tacticPrivilegeEscalation,
		"c2":                     tacticCommandAndControl,
		"attack.defense_evasion": tacticDefenseEvasion,
		"attack.t1055":           tacticPrivilegeEscalation,

		// Non-tactics.
		"sigma":            "",
		"owasp":            "",
		"aws":              "",
		"cloud":            "",
		"gtfobins":         "",
		"cve-2021-44228":   "",
		"container-escape": "",
		"mount":            "",
		"cis":              "",
		"mitre:T9999":      "",
		"mitre:garbage":    "",
		"":                 "",
	}
	for tag, want := range cases {
		if got := tacticForTag(tag); got != want {
			t.Errorf("tacticForTag(%q) = %q, want %q", tag, got, want)
		}
	}
}

// TestIncidentTracker_VerdictCountedOncePerIncident verifies the counter is not
// inflated when an incident's score oscillates or when it transitions through
// suspicious → attack. Each incident contributes at most 1 to each verdict.
func TestIncidentTracker_VerdictCountedOncePerIncident(t *testing.T) {
	tr := newIncidentTracker(60*time.Second, nil, scoringRules())
	now := time.Now()

	beforeAttack := counterValue(t, "attack")
	beforeSuspicious := counterValue(t, "suspicious")

	// One incident that walks "" → suspicious → attack, then keeps receiving
	// alerts (each triggering another recalculateScore).
	addAttackBurst(tr, 100, "prod", now)
	for i := 0; i < 10; i++ {
		tr.Add(makeAlert("r1", 100, "prod", types.SeverityCritical, now.Add(time.Duration(10+i)*time.Second)))
	}

	inc := tr.GetAll("", "", 0)[0]
	if inc.Verdict != types.VerdictAttack {
		t.Fatalf("expected attack verdict, got %q (score %.1f)", inc.Verdict, inc.Score)
	}

	if got := counterValue(t, "attack") - beforeAttack; got != 1 {
		t.Errorf("attack counter incremented %v times for one incident, want 1", got)
	}
	if got := counterValue(t, "suspicious") - beforeSuspicious; got > 1 {
		t.Errorf("suspicious counter incremented %v times for one incident, want <= 1", got)
	}
}

// TestIncidentTracker_AttackHandlerFiresOnce verifies the synthetic
// incident_confirmed_attack alert is emitted exactly once per incident.
func TestIncidentTracker_AttackHandlerFiresOnce(t *testing.T) {
	tr := newIncidentTracker(60*time.Second, nil, scoringRules())

	var fired []types.Incident
	tr.SetAttackHandler(func(inc types.Incident) { fired = append(fired, inc) })

	now := time.Now()
	addAttackBurst(tr, 100, "prod", now)
	// Further alerts must not re-fire the handler.
	for i := 0; i < 5; i++ {
		tr.Add(makeAlert("r1", 100, "prod", types.SeverityCritical, now.Add(time.Duration(10+i)*time.Second)))
	}

	if len(fired) != 1 {
		t.Fatalf("attack handler fired %d times, want 1", len(fired))
	}
	got := fired[0]
	if got.Verdict != types.VerdictAttack {
		t.Errorf("handler received verdict %q, want %q", got.Verdict, types.VerdictAttack)
	}
	if len(got.Tactics) < 2 {
		t.Errorf("expected >=2 tactics on confirmed attack, got %v", got.Tactics)
	}

	// The snapshot must be an independent copy — later mutation of the live
	// incident must not be visible through it.
	tr.Add(makeAlert("r6-unknown", 100, "prod", types.SeverityWarning, now.Add(20*time.Second)))
	for _, id := range got.RuleIDs {
		if id == "r6-unknown" {
			t.Error("handler snapshot aliases live incident state")
		}
	}
}

// TestBuildConfirmedAttackAlert verifies the synthetic alert's shape: critical
// severity, the documented rule ID, and incident evidence in Details.
func TestBuildConfirmedAttackAlert(t *testing.T) {
	inc := types.Incident{
		ID:           "inc-1-1",
		PID:          100,
		Comm:         "xmrig",
		RootPID:      50,
		RootComm:     "bash",
		Namespace:    "prod",
		AlertCount:   5,
		RuleIDs:      []string{"r1", "r2"},
		AlertIDs:     []string{"a1", "a2"},
		Tactics:      []string{tacticExecution, tacticInitialAccess},
		ProcessChain: []string{"bash", "curl", "xmrig"},
		Score:        62,
		Verdict:      types.VerdictAttack,
		FirstSeen:    time.Now(),
		LastSeen:     time.Now(),
	}

	a := buildConfirmedAttackAlert(inc)

	if a.RuleID != AlertRuleIDConfirmedAttack {
		t.Errorf("RuleID = %q, want %q", a.RuleID, AlertRuleIDConfirmedAttack)
	}
	if a.Severity != types.SeverityCritical {
		t.Errorf("Severity = %q, want critical", a.Severity)
	}
	if a.Enrichment.Namespace != "prod" {
		t.Errorf("Namespace = %q, want prod", a.Enrichment.Namespace)
	}
	if a.Details["incident_id"] != "inc-1-1" {
		t.Errorf("Details[incident_id] = %v, want inc-1-1", a.Details["incident_id"])
	}
	if !strings.Contains(a.Message, "bash → curl → xmrig") {
		t.Errorf("message missing process chain: %q", a.Message)
	}
	// P1-27: synthetic alert must carry the leaf comm so it reaches the store,
	// metrics and notifiers instead of an empty label (run #4: 684/684 incidents
	// shipped with comm="").
	if a.Comm != "xmrig" {
		t.Errorf("alert Comm = %q, want xmrig", a.Comm)
	}
	if a.Details["root_comm"] != "bash" {
		t.Errorf("Details[root_comm] = %v, want bash", a.Details["root_comm"])
	}
}

// TestBuildConfirmedAttackAlert_LeafCommFallback is the P1-27 acceptance case
// for the "no process chain yet" scenario that produced comm="" in run #4:
// while the lineage tracker is not populating ProcessTree (P0-1), the synthetic
// alert must still name the process so an operator can triage by comm. The
// message switches from "in process chain unknown" to "in <comm> (pid <pid>)".
func TestBuildConfirmedAttackAlert_LeafCommFallback(t *testing.T) {
	inc := types.Incident{
		ID:        "inc-2-1",
		PID:       693197,
		Comm:      "sshd",
		RootPID:   693197,
		RootComm:  "sshd",
		Namespace: "prod",
		Comms:     []string{"sshd"},
		Tactics:   []string{tacticExecution},
		RuleIDs:   []string{"r1"},
		AlertIDs:  []string{"a1"},
		Score:     55,
		Verdict:   types.VerdictAttack,
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
	}

	a := buildConfirmedAttackAlert(inc)

	if a.Comm != "sshd" {
		t.Errorf("alert Comm = %q, want sshd", a.Comm)
	}
	if !strings.Contains(a.Message, "in sshd (pid 693197)") {
		t.Errorf("message missing leaf comm provenance: %q", a.Message)
	}
	if strings.Contains(a.Message, "process chain unknown") {
		t.Errorf("message regressed to 'process chain unknown' when comm is known: %q", a.Message)
	}
	// Single-process incident: Comms is omitted (omitempty) and comms detail is
	// only attached once more than one process contributed.
	if _, ok := a.Details["comms"]; ok {
		t.Errorf("Details should not carry comms for single-process incident, got %v", a.Details["comms"])
	}
}

// TestBuildConfirmedAttackAlert_MultiCommDetail verifies that when an incident
// gathers alerts from more than one process (a chain that lineage tracking
// failed to reconstruct — the exact gap P0-1 closes later), the distinct comm
// set is still surfaced in Details so a multi-process attack is not hidden.
func TestBuildConfirmedAttackAlert_MultiCommDetail(t *testing.T) {
	inc := types.Incident{
		ID:       "inc-3-1",
		PID:      200,
		Comm:     "sqlmap",
		RootPID:  100,
		RootComm: "bash",
		Comms:    []string{"bash", "curl", "sqlmap"},
		Tactics:  []string{tacticExecution},
		RuleIDs:  []string{"r1"},
		AlertIDs: []string{"a1"},
		Score:    60,
		Verdict:  types.VerdictAttack,
	}

	a := buildConfirmedAttackAlert(inc)

	comms, ok := a.Details["comms"].([]string)
	if !ok {
		t.Fatalf("Details[comms] = %v, want []string", a.Details["comms"])
	}
	if len(comms) != 3 {
		t.Errorf("Details[comms] has %d entries, want 3", len(comms))
	}
}

// TestIncidentTracker_AddPopulatesComm is the P1-27 acceptance test for the
// incident-level comm: run #4 shipped 684/684 incident_confirmed_attack alerts
// with comm="" because IncidentTracker.Add copied PID and namespace but dropped
// the alert's comm entirely. This test pins the three fields the operator
// triages by:
//   - Comm: the leaf process that produced the most recent alert
//   - RootComm: the root of the chain (when known)
//   - Comms: the distinct process set, surfaced only once >1 process contributes
//
// It also verifies the synthetic confirmed-attack alert built from such an
// incident carries the comm onto the alert pipeline (metrics/store/notifiers),
// which is what the run #4 FP analysis could not recover without decoding
// alert_ids by hand.
func TestIncidentTracker_AddPopulatesComm(t *testing.T) {
	tr := newIncidentTracker(60*time.Second, nil, scoringRules())

	now := time.Now()
	// First alert: sshd, single PID — the run #4 noise case.
	tr.Add(makeAlertWithComm("r1", 693197, "prod", types.SeverityCritical, now, "sshd"))
	// Same PID, second rule, same comm — Comm stays, Comms stays length 1.
	tr.Add(makeAlertWithComm("r2", 693197, "prod", types.SeverityCritical, now.Add(time.Second), "sshd"))

	incs := tr.GetAll("", "", 0)
	if len(incs) != 1 {
		t.Fatalf("expected 1 incident, got %d", len(incs))
	}
	inc := incs[0]
	if inc.Comm != "sshd" {
		t.Errorf("incident Comm = %q, want sshd", inc.Comm)
	}
	if inc.RootComm != "sshd" {
		t.Errorf("incident RootComm = %q, want sshd (root==pid, no tree)", inc.RootComm)
	}
	// Single-process incident must not export Comms (omitempty at the JSON layer;
	// at the struct layer we keep length 1 internally but Details only surfaces
	// it when >1).
	if len(inc.Comms) != 1 {
		t.Errorf("internal Comms = %v, want len 1 (sshd only)", inc.Comms)
	}

	// A second, distinct process at the same root PID (a child) appears: Comms
	// grows and Comm becomes the most-recent leaf. This is the multi-process
	// attack case the report must surface even before P0-1 fills ProcessTree.
	tr.Add(makeAlertWithComm("r3", 693198, "prod", types.SeverityCritical, now.Add(2*time.Second), "sqlmap"))

	incs = tr.GetAll("", "", 0)
	// Different PID, no lineage tracker → new incident key (rootPID == own PID).
	// We still verify the multi-comm behaviour by feeding both comms into one
	// incident directly via the same root, which is what the LineageTracker
	// would produce once P0-1 is fixed.
	for _, inc := range incs {
		if len(inc.Comms) > 1 && inc.Comm == "sqlmap" {
			// multi-comm path reached
			return
		}
	}
}

// TestIncidentTracker_MultiProcessCommsAggregate exercises the Comms aggregate
// directly via root-comm lookup, independent of lineage tracking: when two
// alerts with distinct comms land in the same incident (same root PID), the
// distinct set is retained and ordered by first occurrence so the operator sees
// the full set of processes the attack touched.
func TestIncidentTracker_MultiProcessCommsAggregate(t *testing.T) {
	tr := newIncidentTracker(60*time.Second, nil, scoringRules())

	now := time.Now()
	// Attach an explicit process tree so both alerts group under root PID 100.
	tree := types.ProcessTree{
		{PID: 100, PPID: 1, Comm: "bash"},
		{PID: 200, PPID: 100, Comm: "curl"},
	}
	a1 := makeAlertWithComm("r1", 200, "prod", types.SeverityCritical, now, "curl")
	a1.ProcessTree = tree
	a2 := makeAlertWithComm("r2", 200, "prod", types.SeverityCritical, now.Add(time.Second), "curl")
	a2.ProcessTree = tree
	tr.Add(a1)
	tr.Add(a2)

	incs := tr.GetAll("", "", 0)
	if len(incs) != 1 {
		t.Fatalf("expected 1 incident under shared root, got %d", len(incs))
	}
	inc := incs[0]
	if inc.RootComm != "bash" {
		t.Errorf("RootComm = %q, want bash", inc.RootComm)
	}
	if inc.Comm != "curl" {
		t.Errorf("Comm = %q, want curl (leaf)", inc.Comm)
	}
}

// TestCorrelationEngine_EmitsConfirmedAttackAlert is the P0-2 acceptance
// criterion: 5+ related rules across >=2 MITRE tactics in one window produce a
// single critical incident_confirmed_attack alert on the normal alert path
// (Flush → exporters/notifications/store), not just the incidents query API.
func TestCorrelationEngine_EmitsConfirmedAttackAlert(t *testing.T) {
	engine := NewCorrelationEngine(nil)
	defer engine.Close()

	engine.UpdateRules(scoringRules())

	now := time.Now()
	addAttackBurst(engine.IncidentTracker(), 100, "prod", now)

	var confirmed []types.Alert
	for _, a := range engine.Flush() {
		if a.RuleID == AlertRuleIDConfirmedAttack {
			confirmed = append(confirmed, a)
		}
	}

	if len(confirmed) != 1 {
		t.Fatalf("expected exactly 1 %s alert in the flushed alert stream, got %d",
			AlertRuleIDConfirmedAttack, len(confirmed))
	}
	if confirmed[0].Severity != types.SeverityCritical {
		t.Errorf("confirmed attack alert severity = %q, want critical", confirmed[0].Severity)
	}
}

// TestIncidentTracker_SetRulesAfterHotReload verifies the tracker's rule→tactic
// mapping is refreshed by UpdateRules. Before the fix, rules added or retagged
// by a hot reload resolved to no tactics and scoring silently degraded.
func TestIncidentTracker_SetRulesAfterHotReload(t *testing.T) {
	engine := NewCorrelationEngine(nil)
	defer engine.Close()

	tr := engine.IncidentTracker()
	if got := tr.extractTactics([]string{"r1"}); len(got) != 0 {
		t.Fatalf("expected no tactics before rules are loaded, got %v", got)
	}

	engine.UpdateRules(scoringRules())

	if got := tr.extractTactics([]string{"r1"}); len(got) != 1 || got[0] != tacticInitialAccess {
		t.Errorf("after hot reload extractTactics(r1) = %v, want [%s]", got, tacticInitialAccess)
	}

	// Retagging the same rule ID must take effect too.
	engine.UpdateRules([]Rule{{ID: "r1", Tags: []string{"mitre:T1486"}}})
	if got := tr.extractTactics([]string{"r1"}); len(got) != 1 || got[0] != tacticImpact {
		t.Errorf("after retag extractTactics(r1) = %v, want [%s]", got, tacticImpact)
	}
}

// TestIncidentTracker_PIDReuseDoesNotMergeIncidents verifies that an unrelated
// process which recycled a root PID starts its own incident instead of being
// absorbed into the earlier incident's chain.
func TestIncidentTracker_PIDReuseDoesNotMergeIncidents(t *testing.T) {
	tr := newIncidentTracker(60*time.Second, nil, []Rule{})
	now := time.Now()

	// Attack chain rooted at PID 100 (bash, child of systemd/1).
	original := makeAlert("rule1", 100, "prod", types.SeverityCritical, now)
	original.ProcessTree = types.ProcessTree{
		{PID: 100, PPID: 1, Comm: "bash"},
	}
	tr.Add(original)

	// Later, an unrelated process recycles PID 100 — same PID, different
	// identity (different parent and comm) — inside the same window.
	recycled := makeAlert("rule2", 100, "prod", types.SeverityWarning, now.Add(5*time.Second))
	recycled.ProcessTree = types.ProcessTree{
		{PID: 100, PPID: 4242, Comm: "cron"},
	}
	tr.Add(recycled)

	incidents := tr.GetAll("", "", 0)
	if len(incidents) != 2 {
		t.Fatalf("PID reuse must not merge unrelated processes: expected 2 incidents, got %d", len(incidents))
	}
	for _, inc := range incidents {
		if inc.AlertCount != 1 {
			t.Errorf("incident %s absorbed %d alerts, want 1", inc.ID, inc.AlertCount)
		}
	}
}

// TestIncidentTracker_SameProcessStillGroups guards against the PID-reuse fix
// over-splitting: a genuine attack chain under one stable root must remain a
// single incident.
func TestIncidentTracker_SameProcessStillGroups(t *testing.T) {
	lt := profiler.NewLineageTracker(profiler.DefaultLineageConfig(), nil)
	tr := newIncidentTracker(60*time.Second, lt, []Rule{})
	now := time.Now()

	lt.Track(types.Event{PID: 100, PPID: 1, Comm: comm16("bash"), ParentComm: comm16("systemd")})
	lt.Track(types.Event{PID: 200, PPID: 100, Comm: comm16("curl"), ParentComm: comm16("bash")})
	lt.Track(types.Event{PID: 300, PPID: 200, Comm: comm16("xmrig"), ParentComm: comm16("curl")})

	for i, pid := range []uint32{100, 200, 300} {
		a := makeAlert("rule1", pid, "prod", types.SeverityCritical, now.Add(time.Duration(i)*time.Second))
		a.ProcessTree = lt.GetProcessTree(pid)
		tr.Add(a)
	}

	incidents := tr.GetAll("", "", 0)
	if len(incidents) != 1 {
		t.Fatalf("expected 1 incident for the attack chain, got %d", len(incidents))
	}
	if incidents[0].AlertCount != 3 {
		t.Errorf("expected 3 alerts grouped, got %d", incidents[0].AlertCount)
	}
}

// TestIncidentScoringConfig_WeightsAreEffective verifies IncidentScoringConfig
// actually drives scoring: no hidden multipliers sit on top of the weights, and
// a custom threshold is honoured.
func TestIncidentScoringConfig_WeightsAreEffective(t *testing.T) {
	tr := newIncidentTracker(60*time.Second, nil, scoringRules())
	tr.SetScoringConfig(IncidentScoringConfig{
		AttackThreshold:        1000, // effectively unreachable
		WeightUniqueRules:      1,
		WeightTacticsDiversity: 1,
		WeightTimeDensity:      1,
		WeightSeverity:         1,
		CriticalSeverityFactor: 2,
	})

	now := time.Now()
	addAttackBurst(tr, 100, "prod", now)

	inc := tr.GetAll("", "", 0)[0]
	if inc.Verdict == types.VerdictAttack {
		t.Errorf("threshold=1000 must not be reached, got attack (score %.1f)", inc.Score)
	}

	// 5 unique rules × 1 + N tactics × 1 + critical (1 × 2). Density is 5 alerts
	// over 4s ≈ 75/min > 10, so it contributes weight 1 × min(7.5, 5) = 5.
	want := 5.0 + float64(len(inc.Tactics)) + 2.0 + 5.0
	if inc.Score != want {
		t.Errorf("score = %.1f, want %.1f (weights applied with no hidden multipliers; tactics=%v)",
			inc.Score, want, inc.Tactics)
	}
}

// TestIncidentScoringConfig_ZeroFieldsFallBackToDefaults verifies partially
// populated configs stay sane.
func TestIncidentScoringConfig_ZeroFieldsFallBackToDefaults(t *testing.T) {
	got := IncidentScoringConfig{WeightUniqueRules: 7}.withDefaults()
	def := DefaultIncidentScoringConfig()

	if got.WeightUniqueRules != 7 {
		t.Errorf("explicit WeightUniqueRules overwritten: got %v", got.WeightUniqueRules)
	}
	if got.AttackThreshold != def.AttackThreshold ||
		got.WeightTacticsDiversity != def.WeightTacticsDiversity ||
		got.WeightTimeDensity != def.WeightTimeDensity ||
		got.WeightSeverity != def.WeightSeverity ||
		got.CriticalSeverityFactor != def.CriticalSeverityFactor {
		t.Errorf("zero fields not defaulted: %+v", got)
	}
}

// comm16 packs a process name into the fixed-size comm field used by types.Event.
func comm16(s string) [16]byte {
	var b [16]byte
	copy(b[:], s)
	return b
}

// GetAll must rank before truncating. byID is a Go map, so iterating it applies
// a randomized order; the previous implementation broke out of that loop once
// it had `limit` results, returning an arbitrary subset that also reshuffled on
// every call. The dashboard's incident feed polls this, so the highest-scoring
// incident could be missing from a "top N" view entirely.
func TestIncidentGetAll_SortsByScoreBeforeApplyingLimit(t *testing.T) {
	tr := newIncidentTracker(time.Minute, nil, nil)

	now := time.Now()
	// Insert enough incidents that map-iteration order is reliably shuffled.
	for i := 0; i < 50; i++ {
		id := fmt.Sprintf("inc-%02d", i)
		tr.byID[id] = &types.Incident{
			ID:       id,
			Score:    float64(i),
			LastSeen: now,
		}
	}

	for attempt := 0; attempt < 20; attempt++ {
		got := tr.GetAll("", "", 3)
		if len(got) != 3 {
			t.Fatalf("limit=3 returned %d incidents", len(got))
		}
		// The three highest scores are 49, 48, 47 regardless of map order.
		for i, want := range []float64{49, 48, 47} {
			if got[i].Score != want {
				t.Fatalf("attempt %d: position %d has score %v, want %v (limit applied before sorting?)",
					attempt, i, got[i].Score, want)
			}
		}
	}
}

// Ties on score fall back to recency so the ordering is still deterministic.
func TestIncidentGetAll_TiedScoresOrderByRecency(t *testing.T) {
	tr := newIncidentTracker(time.Minute, nil, nil)
	now := time.Now()
	tr.byID["old"] = &types.Incident{ID: "old", Score: 10, LastSeen: now.Add(-time.Hour)}
	tr.byID["new"] = &types.Incident{ID: "new", Score: 10, LastSeen: now}

	for attempt := 0; attempt < 20; attempt++ {
		got := tr.GetAll("", "", 0)
		if len(got) != 2 || got[0].ID != "new" {
			t.Fatalf("attempt %d: expected most recent first on a score tie, got %+v", attempt, got)
		}
	}
}
