package correlator

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/zugolO/ebpf-guard/internal/profiler"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

var (
	incidentsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_guard_incidents_total",
			Help: "Total number of incidents by verdict (attack/suspicious). Each incident is counted at most once per verdict.",
		},
		[]string{"verdict"},
	)

	// incidentsEmptyChainTotal counts incidents promoted to a verdict without a
	// populated process chain. Together with incidents_total it gives the ratio
	// empty/total — the operational signal for P0-1 health: a non-zero value
	// here means the lineage pipeline is silently broken (events arriving with
	// PPID=0 and /proc enrichment not recovering them). The problem persisted
	// across four attack runs precisely because no metric surfaced it.
	incidentsEmptyChainTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_guard_incidents_empty_chain_total",
			Help: "Incidents promoted to a verdict without a populated process chain. Compare with ebpf_guard_incidents_total to track P0-1 lineage health.",
		},
		[]string{"verdict"},
	)

	// incidentsTrustedRootTotal counts incidents whose root process is a trusted
	// system daemon (sshd, cron — see defaultTrustedComms). Divided by
	// incidents_total it is the "share of incidents on system daemons" that the
	// wave 2 gate puts at < 20%; in run #4 it was 100% (114/114 on sshd) and in
	// замер №1 still 37.4%.
	//
	// This is the counterpart to incidents_empty_chain_total: that metric covers
	// the gate's second criterion, this one its first. Without it the share is
	// only computable by post-hoc analysis of an incidents snapshot, which is
	// exactly how P0-1 survived four runs unnoticed — a criterion nobody
	// computes is a criterion that quietly weakens (пункт 4 «Порядка работы»).
	incidentsTrustedRootTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_guard_incidents_trusted_root_total",
			Help: "Incidents promoted to a verdict whose root process is a trusted system daemon. Divide by ebpf_guard_incidents_total for the daemon share (wave 2 gate: < 20%).",
		},
		[]string{"verdict"},
	)
)

const (
	attackScoreThreshold = 50.0

	// Per-unit score weights. Each is the full contribution of one unit of the
	// corresponding signal — no additional multipliers are applied on top, so
	// tuning IncidentScoringConfig has the effect its field names imply.
	weightUniqueRules      = 2.0
	weightTacticsDiversity = 9.0
	weightTimeDensity      = 1.0
	// weightSeverity is the contribution of a warning-severity incident; a
	// critical incident contributes criticalSeverityFactor times as much.
	weightSeverity         = 4.0
	criticalSeverityFactor = 2.0

	// Signals below these thresholds are treated as background noise and score
	// zero, so a single noisy rule cannot manufacture an "attack" verdict.
	minUniqueRulesForScore = 5
	minTacticsForScore     = 2
	minDensityForScore     = 10.0
	maxDensityScoreUnits   = 5.0

	// backgroundReopenWindow extends the grouping window for a *periodic
	// background* incident: one rooted at a trusted daemon that has never
	// carried an untrusted-comm or network signal, and never assembled a
	// scoring-qualifying cluster.
	//
	// 5.5d (находка №9). The tracker's window is 60s and a cron minute tick is
	// exactly 60s apart, so `ts.Sub(LastSeen) > window` fired on every single
	// tick: the same long-lived daemon (root_pid 160579 throughout замер №2.1)
	// minted a brand-new incident once a minute, each one lasting <1s. With a
	// 5-minute retention that is a standing population of exactly five cron
	// incidents in every snapshot — the daemon share of /api/v1/incidents is a
	// structural constant, not a detection outcome, and no amount of scoring
	// work moves it. On idle without attacks the snapshot is 11/11 background
	// daemons.
	//
	// Rather than suppress the verdict (which would hide the activity and
	// break P1-13's deliberate "held at suspicious" behaviour), the periodic
	// background case simply stays *one* incident: a longer reopen window lets
	// the next tick land in the existing entry instead of creating a sibling.
	// The alerts, rules and counts all still accrue — nothing disappears
	// (пункт 8), it is one row instead of N identical ones.
	//
	// Chosen as 5×window so a strictly-once-a-minute source coalesces with
	// margin, while anything genuinely idle for five minutes still starts a
	// fresh incident. Only ever applied to incidents that qualify as periodic
	// background on *every* dimension — see isPeriodicBackground.
	backgroundReopenWindow = 5

	// AlertRuleIDConfirmedAttack is the synthetic rule ID carried by the alert
	// emitted when an incident crosses the attack threshold.
	AlertRuleIDConfirmedAttack = "incident_confirmed_attack"
)

// defaultTrustedComms lists processes whose file/config-read alerts are
// legitimate background activity (auth reading /etc/passwd, cron reading its
// spool) rather than attacker behaviour. P1-13: 102 of 114 "attack" incidents
// in attack-run telemetry were sshd reading /etc/passwd at login, matched by
// five rules that key on filename alone. Wave 3 (closed question 9) has since
// added the missing comm dimension to the web-framed rules
// (owasp-web.yaml/application-exploits.yaml/webshell-detection.yaml), which
// removes most of that fan-out at the source — this gate stays as the
// correlation-level defence, because rule specificity is per-rule work that
// can regress, while the trust gate is one place that cannot.
//
// Alerts from these comms still reach the incident and its process_chain, they
// just cannot supply the score that promotes a verdict — see
// hasUntrustedOrNetworkSignal. Override per deployment via
// correlator.trusted_comms (see IncidentTrustedComms).
var defaultTrustedComms = map[string]struct{}{
	"sshd": {},
	"cron": {},
}

// IncidentScoringConfig tunes how incidents are scored and when they are
// promoted to an "attack" verdict. Weights are per-unit contributions; the
// scorer applies no hidden multipliers on top of them.
type IncidentScoringConfig struct {
	// AttackThreshold is the score at or above which an incident is judged an attack.
	AttackThreshold float64
	// WeightUniqueRules scores each distinct rule that fired in the incident,
	// once at least minUniqueRulesForScore distinct rules are present.
	WeightUniqueRules float64
	// WeightTacticsDiversity scores each distinct MITRE tactic represented in
	// the incident (killchain progress), once at least two tactics are present.
	WeightTacticsDiversity float64
	// WeightTimeDensity scores alert burst density, capped at
	// maxDensityScoreUnits units.
	WeightTimeDensity float64
	// WeightSeverity is added for a warning-severity incident; a critical
	// incident is worth CriticalSeverityFactor times this.
	WeightSeverity float64
	// CriticalSeverityFactor multiplies WeightSeverity for critical incidents.
	CriticalSeverityFactor float64
}

// DefaultIncidentScoringConfig returns the built-in scoring configuration.
func DefaultIncidentScoringConfig() IncidentScoringConfig {
	return IncidentScoringConfig{
		AttackThreshold:        attackScoreThreshold,
		WeightUniqueRules:      weightUniqueRules,
		WeightTacticsDiversity: weightTacticsDiversity,
		WeightTimeDensity:      weightTimeDensity,
		WeightSeverity:         weightSeverity,
		CriticalSeverityFactor: criticalSeverityFactor,
	}
}

// withDefaults fills zero-valued fields from the built-in defaults so partially
// populated configs (e.g. one supplied from YAML) stay sane.
func (c IncidentScoringConfig) withDefaults() IncidentScoringConfig {
	d := DefaultIncidentScoringConfig()
	if c.AttackThreshold <= 0 {
		c.AttackThreshold = d.AttackThreshold
	}
	if c.WeightUniqueRules <= 0 {
		c.WeightUniqueRules = d.WeightUniqueRules
	}
	if c.WeightTacticsDiversity <= 0 {
		c.WeightTacticsDiversity = d.WeightTacticsDiversity
	}
	if c.WeightTimeDensity <= 0 {
		c.WeightTimeDensity = d.WeightTimeDensity
	}
	if c.WeightSeverity <= 0 {
		c.WeightSeverity = d.WeightSeverity
	}
	if c.CriticalSeverityFactor <= 0 {
		c.CriticalSeverityFactor = d.CriticalSeverityFactor
	}
	return c
}

// incidentRetentionMultiplier controls how long closed incidents remain
// visible after their last alert: retention = window * multiplier.
const incidentRetentionMultiplier = 5

// incidentKey is the grouping key: same root process inside the same Kubernetes
// namespace. Empty namespace covers bare-metal workloads.
//
// Root PID is the oldest ancestor in the process tree, allowing attack chains
// like bash→curl→xmrig to be grouped into a single incident.
//
// rootGen disambiguates PID reuse. Linux recycles PIDs, and lineage entries
// expire after LineageConfig.TTL, so a later unrelated process can present the
// same root PID. rootGen carries a cheap identity token for the root process
// (its parent PID and comm as last observed); when that identity changes the
// key changes too, so the new process starts a fresh incident instead of
// absorbing the stale one's chain.
type incidentKey struct {
	rootPID   uint32
	rootGen   string
	namespace string
}

// IncidentTracker groups consecutive alerts from the same process/namespace
// into Incident records using a sliding time window.
//
// The tracker is embedded in CorrelationEngine and its periodic Cleanup is
// driven by the engine's existing maintenance goroutine — no extra goroutine
// is required.
type IncidentTracker struct {
	window         time.Duration
	lineageTracker *profiler.LineageTracker
	scoringConfig  IncidentScoringConfig
	// trustedComms lists process names whose alerts cannot by themselves
	// promote an incident to "attack" — see defaultTrustedComms and
	// hasUntrustedOrNetworkSignal.
	trustedComms map[string]struct{}

	// onAttack is invoked (outside the tracker lock) the first time an incident
	// is promoted to the "attack" verdict, so the engine can emit a synthetic
	// incident_confirmed_attack alert into the normal alert pipeline.
	onAttack func(types.Incident)

	mu sync.RWMutex
	// rules maps ruleID → tactic set, rebuilt on every rule hot-reload via
	// SetRules. Only the derived tactics are retained, so the tracker never
	// aliases a []Rule the engine may mutate elsewhere.
	ruleTactics map[string][]string
	open        map[incidentKey]*types.Incident // active incidents (last alert within window)
	byID        map[string]*types.Incident      // all incidents for ID-based lookups
	seq         atomic.Uint64
}

// newIncidentTracker creates an IncidentTracker with the given sliding window.
// A zero or negative window defaults to 60 seconds.
// The lineageTracker is used to find the root ancestor PID for grouping
// attack chains across multiple processes.
func newIncidentTracker(window time.Duration, lineageTracker *profiler.LineageTracker, rules []Rule) *IncidentTracker {
	if window <= 0 {
		window = 60 * time.Second
	}
	t := &IncidentTracker{
		window:         window,
		lineageTracker: lineageTracker,
		scoringConfig:  DefaultIncidentScoringConfig(),
		trustedComms:   defaultTrustedComms,
		ruleTactics:    buildRuleTactics(rules),
		open:           make(map[incidentKey]*types.Incident),
		byID:           make(map[string]*types.Incident),
	}
	return t
}

// buildRuleTactics derives the per-rule tactic set from rule tags. Tags that do
// not resolve to a MITRE tactic are dropped — see tacticForTag.
func buildRuleTactics(rules []Rule) map[string][]string {
	m := make(map[string][]string, len(rules))
	for i := range rules {
		m[rules[i].ID] = TacticsForTags(rules[i].Tags)
	}
	return m
}

// SetRules refreshes the tracker's rule→tactic mapping after a rule hot-reload.
// Without this, rules added or retagged by a reload resolve to no tactics and
// incident scoring silently degrades.
func (t *IncidentTracker) SetRules(rules []Rule) {
	next := buildRuleTactics(rules)
	t.mu.Lock()
	t.ruleTactics = next
	t.mu.Unlock()
}

// SetScoringConfig replaces the scoring configuration. Zero-valued fields fall
// back to the built-in defaults.
func (t *IncidentTracker) SetScoringConfig(cfg IncidentScoringConfig) {
	cfg = cfg.withDefaults()
	t.mu.Lock()
	t.scoringConfig = cfg
	t.mu.Unlock()
}

// SetTrustedComms replaces the set of process names whose alerts cannot alone
// promote an incident to "attack" (see defaultTrustedComms). An empty or nil
// slice clears the allowlist entirely, i.e. every comm counts as untrusted.
func (t *IncidentTracker) SetTrustedComms(comms []string) {
	next := make(map[string]struct{}, len(comms))
	for _, c := range comms {
		next[c] = struct{}{}
	}
	t.mu.Lock()
	t.trustedComms = next
	t.mu.Unlock()
}

// SetAttackHandler registers a callback invoked once per incident, at the moment
// it is first promoted to the "attack" verdict. The callback runs outside the
// tracker lock and must not call back into the tracker.
func (t *IncidentTracker) SetAttackHandler(fn func(types.Incident)) {
	t.mu.Lock()
	t.onAttack = fn
	t.mu.Unlock()
}

// rootIdentity returns the root ancestor PID for the alert's process together
// with a generation token that distinguishes distinct processes that happen to
// share the same PID (PID reuse).
//
// When no lineage is available the alert's own PID is the root, and the token
// falls back to the alert's comm — still enough to keep an unrelated process
// that recycled the PID out of the earlier incident in the common case.
func (t *IncidentTracker) rootIdentity(alert types.Alert) (uint32, string) {
	// Prefer the tree already attached to the alert: it was captured when the
	// alert fired, so it is not subject to lineage expiry between then and now.
	tree := alert.ProcessTree
	if len(tree) == 0 && t.lineageTracker != nil {
		tree = t.lineageTracker.GetProcessTree(alert.PID)
	}
	if len(tree) == 0 {
		return alert.PID, alert.Comm
	}
	root := tree[0]
	// PPID+comm is a stable identity for a live process and changes when the PID
	// is recycled by an unrelated process.
	return root.PID, fmt.Sprintf("%d/%s", root.PPID, root.Comm)
}

// sourceEventKey identifies the kernel event that produced alert, so that
// multiple rules firing on the same event (same PID, same nanosecond-precision
// alert timestamp) count as one source event rather than N independent
// signals. Uses Alert.Timestamp because the engine always populates it — it is
// derived from the triggering event's clock, so every rule that fires on one
// event carries the identical value, which is exactly the equality this dedup
// needs. The embedded Event.Timestamp is left zero on synthetic and
// engine-internal alerts, which would collapse unrelated alerts into one key.
// Packing PID into the high bits keeps the key collision-free across
// concurrently active PIDs sharing a timestamp; a raw timestamp key would
// conflate unrelated processes sampled in the same tick.
func sourceEventKey(alert types.Alert) uint64 {
	return uint64(alert.PID)<<32 ^ uint64(alert.Timestamp.UnixNano())
}

// isTrustedComm reports whether comm is in the tracker's trusted-process
// allowlist (see defaultTrustedComms). Caller must hold at least the read lock,
// or call before any lock is taken (trustedComms is only replaced wholesale by
// SetTrustedComms, never mutated in place).
func (t *IncidentTracker) isTrustedComm(comm string) bool {
	if comm == "" {
		return false
	}
	_, ok := t.trustedComms[comm]
	return ok
}

// isPeriodicBackground reports whether inc is recurring trusted-daemon
// background rather than a developing incident: rooted at a trusted comm, with
// no untrusted-comm and no network signal anywhere in it, and never having
// assembled a scoring-qualifying cluster of non-info rules.
//
// 5.5d (находка №9): such an incident is what a cron minute tick produces, and
// it gets a longer reopen window so consecutive ticks coalesce into one entry
// — see backgroundReopenWindow. The three conditions are deliberately
// conjunctive and all are load-bearing:
//
//   - trusted root: the P1-13 allowlist (sshd, cron), the same notion of
//     "background" already used for verdict promotion. RootComm, not the leaf
//     comm, so an incident rooted at cron that later sprouts an attacker child
//     is judged on its origin.
//   - no untrusted/network signal: the moment either appears the incident stops
//     being background and reverts to the normal window on the next alert, so
//     an attack that starts inside a daemon is not swallowed by a 5-minute
//     grouping.
//   - sub-threshold scoring cluster: uses the 5.5a scoring mirrors, so a daemon
//     that genuinely trips minUniqueRulesForScore distinct non-info rules is
//     never treated as background regardless of the other two.
//
// Caller must hold at least the read lock.
func (t *IncidentTracker) isPeriodicBackground(inc *types.Incident) bool {
	if inc == nil {
		return false
	}
	if inc.HasUntrustedSignal || inc.HasNetworkSignal {
		return false
	}
	if !t.isTrustedComm(inc.RootComm) {
		return false
	}
	return len(inc.ScoringRuleIDs) < minUniqueRulesForScore
}

// isNetworkSignal reports whether et is a network-observable event type
// (TCP connect/close, DNS, TLS) as opposed to a purely local
// syscall/file/privesc event. Attacker traffic (sqlmap, curl, C2 beacons) is
// exactly the traffic run #4 failed to flag — a real attack chain should
// eventually surface one of these types even when individual hops are
// local syscalls.
func isNetworkSignal(et types.EventType) bool {
	switch et { //nolint:exhaustive // only the network-observable types are meaningful here; every other type falls through to false.
	case types.EventTCPConnect, types.EventNetClose, types.EventDNS, types.EventTLS:
		return true
	default:
		return false
	}
}

// getProcessChain extracts the process chain from an alert's ProcessTree.
// Returns a slice of process names from root to leaf.
func (t *IncidentTracker) getProcessChain(alert types.Alert) []string {
	if len(alert.ProcessTree) == 0 {
		return nil
	}
	chain := make([]string, 0, len(alert.ProcessTree))
	for _, node := range alert.ProcessTree {
		if node.Comm != "" {
			chain = append(chain, node.Comm)
		}
	}
	return chain
}

// rootComm returns the root ancestor's comm for the alert. Prefers the attached
// ProcessTree's root node; falls back to the alert's own comm when no lineage is
// available (single-process incident). Used to populate Incident.RootComm so an
// operator can triage the origin process without rebuilding the tree.
func (t *IncidentTracker) rootComm(alert types.Alert, rootPID uint32) string {
	if len(alert.ProcessTree) > 0 && alert.ProcessTree[0].Comm != "" {
		return alert.ProcessTree[0].Comm
	}
	if rootPID == alert.PID || rootPID == 0 {
		return alert.Comm
	}
	// Root is a different PID but no tree was attached: ask the lineage tracker
	// for the root's comm as a best-effort, otherwise leave it to the alert comm.
	if t.lineageTracker != nil {
		if tree := t.lineageTracker.GetProcessTree(alert.PID); len(tree) > 0 && tree[0].Comm != "" {
			return tree[0].Comm
		}
	}
	return alert.Comm
}

// Add associates alert with the appropriate incident.
// A new incident is created when no open incident exists for the root process
// identity + namespace, or the most recent alert in the open incident arrived
// more than window ago. Alerts from processes in the same process tree are
// grouped together, enabling attack chain correlation across parent-child
// relationships.
//
// If adding the alert promotes the incident to the "attack" verdict for the
// first time, the registered attack handler is invoked after the lock is
// released.
func (t *IncidentTracker) Add(alert types.Alert) {
	rootPID, rootGen := t.rootIdentity(alert)
	key := incidentKey{rootPID: rootPID, rootGen: rootGen, namespace: alert.Enrichment.Namespace}
	ts := alert.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}

	t.mu.Lock()

	inc, exists := t.open[key]
	// 5.5d: periodic daemon background coalesces into one incident instead of
	// one per tick — see backgroundReopenWindow.
	window := t.window
	if exists && t.isPeriodicBackground(inc) {
		window = t.window * backgroundReopenWindow
	}
	if !exists || ts.Sub(inc.LastSeen) > window {
		id := t.nextID(ts)
		inc = &types.Incident{
			ID:           id,
			FirstSeen:    ts,
			PID:          alert.PID,
			Comm:         alert.Comm,
			Namespace:    alert.Enrichment.Namespace,
			AlertIDs:     make([]string, 0, 4),
			RuleIDs:      make([]string, 0, 4),
			RootPID:      rootPID,
			RootComm:     t.rootComm(alert, rootPID),
			ProcessChain: t.getProcessChain(alert),
			SourceEvents: make(map[uint64]struct{}, 4),
		}
		// Seed the distinct-comm set with the creating alert's comm. Kept only
		// when more than one process contributes — exposing multi-process
		// attacks even when lineage tracking failed to build a tree (P0-1).
		if alert.Comm != "" {
			inc.Comms = []string{alert.Comm}
		}
		t.open[key] = inc
		t.byID[id] = inc
	} else {
		// Update process chain if this alert provides a longer chain
		if chain := t.getProcessChain(alert); len(chain) > len(inc.ProcessChain) {
			inc.ProcessChain = chain
		}
		// The most recent alert's comm is the actionable leaf process.
		if alert.Comm != "" {
			inc.Comm = alert.Comm
		}
		// Track distinct comms across the incident. Only retained in the
		// exported field once a second comm appears, so the common single-process
		// case stays absent from JSON (omitempty).
		if alert.Comm != "" {
			found := false
			for _, c := range inc.Comms {
				if c == alert.Comm {
					found = true
					break
				}
			}
			if !found {
				inc.Comms = append(inc.Comms, alert.Comm)
			}
		}
	}

	// P1-13: record the source event this alert came from, and whether it
	// carries an untrusted-comm or network signal. recalculateScore uses these
	// to reject incidents built entirely from one kernel event fanned out
	// across rules that key only on filename (sshd + /etc/passwd), or entirely
	// from allowlisted daemons with no network corroboration.
	if inc.SourceEvents == nil {
		inc.SourceEvents = make(map[uint64]struct{}, 4)
	}
	inc.SourceEvents[sourceEventKey(alert)] = struct{}{}
	if !t.isTrustedComm(alert.Comm) {
		inc.HasUntrustedSignal = true
	}
	if isNetworkSignal(alert.Event.Type) {
		inc.HasNetworkSignal = true
	}

	// 5.5a: info-severity alerts stay in RuleIDs/AlertIDs/SourceEvents above
	// (still visible, still in filtered_total) but are kept out of the
	// scoring-only mirrors, so a cron/sshd burst of pure info alerts cannot
	// reach minUniqueRulesForScore and manufacture a "suspicious"/"attack"
	// verdict on its own — see находка №8.
	if alert.Severity != types.SeverityInfo {
		if inc.ScoringRuleIDs == nil {
			inc.ScoringRuleIDs = make(map[string]struct{}, 4)
		}
		inc.ScoringRuleIDs[alert.RuleID] = struct{}{}
		if inc.ScoringSourceEvents == nil {
			inc.ScoringSourceEvents = make(map[uint64]struct{}, 4)
		}
		inc.ScoringSourceEvents[sourceEventKey(alert)] = struct{}{}
		inc.ScoringAlertCount++
	}

	inc.LastSeen = ts
	inc.AlertIDs = append(inc.AlertIDs, alert.ID)
	inc.AlertCount = len(inc.AlertIDs)
	inc.Severity = maxIncidentSeverity(inc.Severity, alert.Severity)

	// Append ruleID only if not already present (linear scan is fine for short lists).
	ruleNew := true
	for _, r := range inc.RuleIDs {
		if r == alert.RuleID {
			ruleNew = false
			break
		}
	}
	if ruleNew {
		inc.RuleIDs = append(inc.RuleIDs, alert.RuleID)
	}

	promoted := t.recalculateScore(inc)
	var snapshot types.Incident
	handler := t.onAttack
	if promoted && handler != nil {
		snapshot = *inc
		snapshot.Status = "open"
		snapshot.AlertIDs = append([]string(nil), inc.AlertIDs...)
		snapshot.RuleIDs = append([]string(nil), inc.RuleIDs...)
		snapshot.ProcessChain = append([]string(nil), inc.ProcessChain...)
		if inc.Comms != nil {
			snapshot.Comms = append([]string(nil), inc.Comms...)
		}
	}
	t.mu.Unlock()

	// Dispatch outside the lock: the handler feeds the alert pipeline.
	if promoted && handler != nil {
		handler(snapshot)
	}
}

// recalculateScore recomputes inc.Score and inc.Verdict.
// It reports whether this call promoted the incident to the "attack" verdict
// for the first time. Verdict counters are incremented at most once per
// incident per verdict, so an incident whose score oscillates around the
// threshold is not counted repeatedly.
//
// Caller must hold the write lock.
func (t *IncidentTracker) recalculateScore(inc *types.Incident) bool {
	if inc == nil {
		return false
	}

	cfg := t.scoringConfig
	score := 0.0
	dur := inc.LastSeen.Sub(inc.FirstSeen)
	if dur.Seconds() < 1 {
		dur = time.Second
	}

	// 5.5a: score from the scoring-only rule set, which excludes rules that
	// only ever fired at info severity — see the ScoringRuleIDs doc comment.
	scoringRuleIDs := make([]string, 0, len(inc.ScoringRuleIDs))
	for id := range inc.ScoringRuleIDs {
		scoringRuleIDs = append(scoringRuleIDs, id)
	}

	// P1-13: cap the unique-rules signal at the number of distinct source
	// events. Without this, one kernel event that trips five filename-keyed
	// rules (sshd + /etc/passwd) scores as if five independent attack signals
	// had been observed — the exact shape of the 102/114 false "confirmed
	// attacks" in attack-run telemetry. A real multi-rule incident has more
	// than one source event backing it; this only clamps the degenerate case.
	uniqueRules := len(scoringRuleIDs)
	if sourceEvents := len(inc.ScoringSourceEvents); sourceEvents > 0 && sourceEvents < uniqueRules {
		uniqueRules = sourceEvents
	}
	if uniqueRules >= minUniqueRulesForScore {
		score += float64(uniqueRules) * cfg.WeightUniqueRules
	}

	tactics := t.extractTactics(scoringRuleIDs)
	if len(tactics) >= minTacticsForScore {
		score += float64(len(tactics)) * cfg.WeightTacticsDiversity
	}
	inc.Tactics = tactics

	// 5.5a: density from the scoring-only alert count — an info-only burst
	// (cron reading its spool) should not be able to inflate density either.
	density := float64(inc.ScoringAlertCount) / dur.Minutes()
	if density > minDensityForScore {
		score += cfg.WeightTimeDensity * math.Min(density/minDensityForScore, maxDensityScoreUnits)
	}

	switch inc.Severity {
	case types.SeverityCritical:
		score += cfg.WeightSeverity * cfg.CriticalSeverityFactor
	case types.SeverityWarning:
		score += cfg.WeightSeverity
	}

	inc.Score = score

	// P1-13: a high score alone is not enough to confirm an attack when every
	// contributing alert came from a trusted daemon (sshd, cron) with no
	// network corroboration — that combination is background noise dressed up
	// as five rules, not evidence of compromise. Score-qualifying incidents
	// that fail this check are held at "suspicious" instead of promoted.
	hasQualifyingSignal := inc.HasUntrustedSignal || inc.HasNetworkSignal

	verdict := types.IncidentVerdict("")
	if score >= cfg.AttackThreshold && hasQualifyingSignal {
		verdict = types.VerdictAttack
	} else if score > 0 {
		verdict = types.VerdictSuspicious
	}

	// An incident never de-escalates out of "attack": the evidence that
	// triggered it does not stop having happened, and letting the verdict drop
	// back would re-fire the promotion (and its counter) on the next alert.
	if inc.Verdict == types.VerdictAttack {
		verdict = types.VerdictAttack
	}
	inc.Verdict = verdict

	// Count each incident at most once per verdict. The empty-chain counter
	// fires alongside the total so an operator can compute the ratio directly
	// from the metrics: empty_chain{verdict} / incidents_total{verdict}. The
	// chain snapshot is taken at promotion time, so a later alert that extends
	// the chain does not retract the counter — this is intentional, the
	// incident was *promoted* without a chain, which is the failure signal.
	promoted := false
	emptyChain := len(inc.ProcessChain) == 0
	// Root comm, not the comm of any single alert: an incident rooted at sshd
	// that also contains alerts from an attacker child is not a daemon FP, and
	// counting it as one would understate the gate.
	trustedRoot := t.isTrustedComm(inc.RootComm)
	switch verdict {
	case types.VerdictAttack:
		if !inc.CountedAttack {
			inc.CountedAttack = true
			incidentsTotal.WithLabelValues("attack").Inc()
			if emptyChain {
				incidentsEmptyChainTotal.WithLabelValues("attack").Inc()
			}
			if trustedRoot {
				incidentsTrustedRootTotal.WithLabelValues("attack").Inc()
			}
			promoted = true
		}
	case types.VerdictSuspicious:
		if !inc.CountedSuspicious {
			inc.CountedSuspicious = true
			incidentsTotal.WithLabelValues("suspicious").Inc()
			if emptyChain {
				incidentsEmptyChainTotal.WithLabelValues("suspicious").Inc()
			}
			if trustedRoot {
				incidentsTrustedRootTotal.WithLabelValues("suspicious").Inc()
			}
		}
	}

	return promoted
}

// extractTactics returns the sorted set of distinct MITRE tactics represented by
// the incident's rules. Descriptive rule tags (sigma, owasp, cve-*, cloud, …)
// are not tactics and do not appear here — see tacticForTag.
//
// Caller must hold at least the read lock.
func (t *IncidentTracker) extractTactics(ruleIDs []string) []string {
	seen := make(map[string]struct{})
	for _, ruleID := range ruleIDs {
		for _, tactic := range t.ruleTactics[ruleID] {
			seen[tactic] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for tactic := range seen {
		out = append(out, tactic)
	}
	sort.Strings(out)
	return out
}

// GetAll returns a snapshot of all known incidents, applying optional filters.
//   - namespace: if non-empty, only incidents from that namespace are returned.
//   - status: "open", "closed", or "" for both.
//   - limit: maximum number of results; ≤0 returns all matches.
func (t *IncidentTracker) GetAll(namespace, status string, limit int) []types.Incident {
	now := time.Now()
	t.mu.RLock()
	defer t.mu.RUnlock()

	out := make([]types.Incident, 0, len(t.byID))
	for _, inc := range t.byID {
		s := t.incStatusFor(inc, now)
		if namespace != "" && inc.Namespace != namespace {
			continue
		}
		if status != "" && s != status {
			continue
		}
		snap := *inc
		snap.Status = s
		out = append(out, snap)
	}

	// Rank before truncating. byID is a map, so iteration order is randomized:
	// applying limit inside the loop returned an arbitrary subset and reordered
	// the list on every poll, which made the dashboard's incident feed shuffle
	// between refreshes and could hide the highest-scoring incident entirely.
	// Highest score first, then most recent, so a "top N" query returns the
	// incidents an operator actually needs to triage.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].LastSeen.After(out[j].LastSeen)
	})

	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// GetByID returns a copy of the incident with id, or (nil, false) if unknown.
func (t *IncidentTracker) GetByID(id string) (*types.Incident, bool) {
	now := time.Now()
	t.mu.RLock()
	defer t.mu.RUnlock()

	inc, ok := t.byID[id]
	if !ok {
		return nil, false
	}
	snap := *inc
	snap.Status = t.incStatusFor(inc, now)
	return &snap, true
}

// Cleanup evicts stale entries. Should be called periodically by the caller
// (e.g. the engine's maintenance goroutine).
//
// An open entry is moved to closed (removed from the open map) once its last
// alert is older than window — or window * backgroundReopenWindow for periodic
// daemon background, matching the window Add uses to reopen it (5.5d). Entries
// in byID are evicted once older than window * incidentRetentionMultiplier to
// bound memory growth.
func (t *IncidentTracker) Cleanup(now time.Time) {
	retention := t.window * incidentRetentionMultiplier

	t.mu.Lock()
	defer t.mu.Unlock()

	for k, inc := range t.open {
		// 5.5d: a periodic background incident is held open for the same
		// extended window Add uses to reopen it. Evicting it at t.window would
		// undo the coalescing — the next tick would find no open entry and mint
		// a sibling anyway, which is the exact behaviour находка №9 removes.
		closeAfter := t.window
		if t.isPeriodicBackground(inc) {
			closeAfter = t.window * backgroundReopenWindow
		}
		if now.Sub(inc.LastSeen) > closeAfter {
			delete(t.open, k)
		}
	}
	for id, inc := range t.byID {
		if now.Sub(inc.LastSeen) > retention {
			delete(t.byID, id)
		}
	}
}

// Count returns the total number of tracked incidents (open + recently closed).
func (t *IncidentTracker) Count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.byID)
}

// nextID generates a time-sortable, unique incident ID.
// Caller must hold the write lock.
func (t *IncidentTracker) nextID(ts time.Time) string {
	return fmt.Sprintf("inc-%d-%d", ts.UnixMilli(), t.seq.Add(1))
}

// incStatus computes the current status of an incident at read time.
func incStatus(inc *types.Incident, now time.Time, window time.Duration) string {
	if now.Sub(inc.LastSeen) <= window {
		return "open"
	}
	return "closed"
}

// incStatusFor is incStatus with the 5.5d extended window applied to periodic
// daemon background, so the reported status matches the window that actually
// governs grouping — otherwise a coalescing cron incident reads "closed"
// between ticks while still accepting alerts into the same entry.
//
// Caller must hold at least the read lock.
func (t *IncidentTracker) incStatusFor(inc *types.Incident, now time.Time) string {
	window := t.window
	if t.isPeriodicBackground(inc) {
		window = t.window * backgroundReopenWindow
	}
	return incStatus(inc, now, window)
}

// maxIncidentSeverity returns the higher-ranked of two Severity values.
func maxIncidentSeverity(a, b types.Severity) types.Severity {
	if incidentSeverityRank(a) >= incidentSeverityRank(b) {
		return a
	}
	return b
}

func incidentSeverityRank(s types.Severity) int {
	switch s {
	case types.SeverityCritical:
		return 2
	case types.SeverityWarning:
		return 1
	default:
		return 0
	}
}

// buildConfirmedAttackAlert renders the synthetic critical alert emitted when an
// incident is first judged an attack. It carries the incident's evidence
// (rules, tactics, process chain) so downstream notifiers and the alert store
// can present the correlated attack rather than N isolated signals.
func buildConfirmedAttackAlert(inc types.Incident) types.Alert {
	// Message provenance (P1-27): name the process so an operator can triage
	// without decoding alert_ids. Prefer the explicit process chain when the
	// lineage tracker populated it; otherwise fall back to "<comm> (pid <pid>)"
	// using the leaf comm — the common case while P0-1 (chain population) is
	// still open. "unknown" is kept only as the last resort so the message is
	// never empty.
	var where string
	switch {
	case len(inc.ProcessChain) > 0:
		where = "process chain " + strings.Join(inc.ProcessChain, " → ")
	case inc.Comm != "":
		where = fmt.Sprintf("%s (pid %d)", inc.Comm, inc.PID)
	default:
		where = "process chain unknown"
	}
	tactics := inc.Tactics
	msg := fmt.Sprintf(
		"Confirmed attack: %d alerts from %d rules across %d MITRE tactics (%s) in %s (score %.1f)",
		inc.AlertCount, len(inc.RuleIDs), len(tactics), strings.Join(tactics, ", "), where, inc.Score,
	)

	// comms carries the distinct process set when more than one process
	// contributed to the incident — surfaces multi-process attacks even when
	// ProcessChain is empty (lineage tracking gap, see P0-1).
	details := map[string]interface{}{
		"incident_id":   inc.ID,
		"root_pid":      inc.RootPID,
		"score":         inc.Score,
		"verdict":       string(types.VerdictAttack),
		"alert_count":   inc.AlertCount,
		"rule_ids":      inc.RuleIDs,
		"alert_ids":     inc.AlertIDs,
		"tactics":       tactics,
		"process_chain": inc.ProcessChain,
		"first_seen":    inc.FirstSeen,
		"last_seen":     inc.LastSeen,
	}
	if len(inc.Comms) > 1 {
		details["comms"] = inc.Comms
	}
	if inc.RootComm != "" {
		details["root_comm"] = inc.RootComm
	}

	return types.Alert{
		ID:        "alert-" + inc.ID + "-attack",
		Timestamp: inc.LastSeen,
		RuleID:    AlertRuleIDConfirmedAttack,
		RuleName:  "Correlated incident confirmed as attack",
		Severity:  types.SeverityCritical,
		PID:       inc.PID,
		Comm:      inc.Comm,
		Message:   msg,
		Details:   details,
		Enrichment: types.EnrichmentInfo{
			Namespace: inc.Namespace,
		},
	}
}
