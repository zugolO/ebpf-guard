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

	// AlertRuleIDConfirmedAttack is the synthetic rule ID carried by the alert
	// emitted when an incident crosses the attack threshold.
	AlertRuleIDConfirmedAttack = "incident_confirmed_attack"
)

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
	if !exists || ts.Sub(inc.LastSeen) > t.window {
		id := t.nextID(ts)
		inc = &types.Incident{
			ID:           id,
			FirstSeen:    ts,
			PID:          alert.PID,
			Namespace:    alert.Enrichment.Namespace,
			AlertIDs:     make([]string, 0, 4),
			RuleIDs:      make([]string, 0, 4),
			RootPID:      rootPID,
			ProcessChain: t.getProcessChain(alert),
		}
		t.open[key] = inc
		t.byID[id] = inc
	} else {
		// Update process chain if this alert provides a longer chain
		if chain := t.getProcessChain(alert); len(chain) > len(inc.ProcessChain) {
			inc.ProcessChain = chain
		}
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

	uniqueRules := len(inc.RuleIDs)
	if uniqueRules >= minUniqueRulesForScore {
		score += float64(uniqueRules) * cfg.WeightUniqueRules
	}

	tactics := t.extractTactics(inc.RuleIDs)
	if len(tactics) >= minTacticsForScore {
		score += float64(len(tactics)) * cfg.WeightTacticsDiversity
	}
	inc.Tactics = tactics

	density := float64(inc.AlertCount) / dur.Minutes()
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

	verdict := types.IncidentVerdict("")
	if score >= cfg.AttackThreshold {
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

	// Count each incident at most once per verdict.
	promoted := false
	switch verdict {
	case types.VerdictAttack:
		if !inc.CountedAttack {
			inc.CountedAttack = true
			incidentsTotal.WithLabelValues("attack").Inc()
			promoted = true
		}
	case types.VerdictSuspicious:
		if !inc.CountedSuspicious {
			inc.CountedSuspicious = true
			incidentsTotal.WithLabelValues("suspicious").Inc()
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
		s := incStatus(inc, now, t.window)
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
	snap.Status = incStatus(inc, now, t.window)
	return &snap, true
}

// Cleanup evicts stale entries. Should be called periodically by the caller
// (e.g. the engine's maintenance goroutine).
//
// An open entry is moved to closed (removed from the open map) once its last
// alert is older than window. Entries in byID are evicted once older than
// window * incidentRetentionMultiplier to bound memory growth.
func (t *IncidentTracker) Cleanup(now time.Time) {
	retention := t.window * incidentRetentionMultiplier

	t.mu.Lock()
	defer t.mu.Unlock()

	for k, inc := range t.open {
		if now.Sub(inc.LastSeen) > t.window {
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
	chain := "unknown"
	if len(inc.ProcessChain) > 0 {
		chain = strings.Join(inc.ProcessChain, " → ")
	}
	tactics := inc.Tactics
	msg := fmt.Sprintf(
		"Confirmed attack: %d alerts from %d rules across %d MITRE tactics (%s) in process chain %s (score %.1f)",
		inc.AlertCount, len(inc.RuleIDs), len(tactics), strings.Join(tactics, ", "), chain, inc.Score,
	)

	return types.Alert{
		ID:        "alert-" + inc.ID + "-attack",
		Timestamp: inc.LastSeen,
		RuleID:    AlertRuleIDConfirmedAttack,
		RuleName:  "Correlated incident confirmed as attack",
		Severity:  types.SeverityCritical,
		PID:       inc.PID,
		Message:   msg,
		Details: map[string]interface{}{
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
		},
		Enrichment: types.EnrichmentInfo{
			Namespace: inc.Namespace,
		},
	}
}
