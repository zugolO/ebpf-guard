package profiler

import (
	"container/heap"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/zugolO/ebpf-guard/internal/util"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// DriftBaselineConfig configures the drift/FIM observe-mode profiler.
//
// Rules tagged `class: drift` (container/library/config drift, FIM-style
// monitoring — as opposed to `class: threat`, a genuine attack signature)
// are noisy on a live system: legitimate systemd/ldconfig/package-manager
// activity matches the same conditions as real container escapes. Rather
// than alerting on every match, the profiler spends a learning window
// building a per-workload baseline of the (rule, target) signatures it
// observes, then only alerts on signatures that were NOT seen during
// learning — i.e. genuine deviation from this host's own normal behavior.
type DriftBaselineConfig struct {
	// Enabled activates drift-class alert suppression. When false, rules
	// with class: drift alert exactly as class: threat rules do (no change
	// in behavior from before this profiler existed).
	Enabled bool `mapstructure:"enabled"`
	// LearningPeriod is the duration to observe drift-class matches before a
	// workload's baseline is considered complete, in seconds.
	LearningPeriod int `mapstructure:"learning_period"`
	// MinSamples is the minimum number of drift-class matches that must be
	// observed for a workload before its baseline can complete, in addition
	// to LearningPeriod elapsing.
	MinSamples int `mapstructure:"min_samples"`
	// PerWorkload separates baselines per (comm, namespace, app_label) tuple.
	// When false a single global baseline is maintained across all workloads.
	PerWorkload bool `mapstructure:"per_workload"`
	// MaxWorkloads caps the number of per-workload profiles held in memory.
	// Once the cap is reached, the least-recently-active profile is evicted
	// before a new one is created. comm cardinality is attacker-controlled
	// (prctl(PR_SET_NAME), random binary names), so without a cap the profile
	// map grows unbounded — a slow but guaranteed memory leak, felt most on
	// the lite profile's tight GOMEMLIMIT. Default: 1000. Zero or negative
	// means unbounded (not recommended).
	MaxWorkloads int `mapstructure:"max_workloads"`
	// MaxSignaturesPerWorkload caps how many distinct (rule, target) signatures
	// a single workload's baseline may hold. Signature targets include file
	// paths and argv[0], both attacker-controlled, so the set needs a bound of
	// its own — the MaxWorkloads cap only bounds the number of profiles, not
	// the size of each. Once a profile is at the cap its baseline is frozen:
	// further novel signatures are not learned, and after promotion they are
	// reported as anomalies like any other unknown signature. That is a
	// deliberate bias toward noise over blindness, and it is visible in
	// ebpf_guard_drift_baseline_saturated_profiles. Default: 256. Zero or
	// negative means unbounded (not recommended).
	MaxSignaturesPerWorkload int `mapstructure:"max_signatures_per_workload"`
	// EnforceDeadlinePeriods forces a workload into enforcing after this many
	// LearningPeriods have elapsed, regardless of whether MinSamples was ever
	// reached. Without it, a workload generating drift events more rarely than
	// MinSamples per LearningPeriod stays in learning forever — and while
	// learning, every match is suppressed, so drift rules never fire on that
	// workload. Low traffic means a baseline is reached quickly and
	// confidently, not that the workload should be a permanent blind spot.
	// Default: 3. Zero or negative disables deadline-based forcing.
	EnforceDeadlinePeriods int `mapstructure:"enforce_deadline_periods"`
}

// DefaultDriftBaselineConfig returns safe defaults. Disabled by default so
// installing a `class: drift`-tagged rule set never changes alert volume
// until an operator opts in.
func DefaultDriftBaselineConfig() DriftBaselineConfig {
	return DriftBaselineConfig{
		Enabled:                  false,
		LearningPeriod:           3600,
		MinSamples:               20,
		PerWorkload:              true,
		MaxWorkloads:             1000,
		MaxSignaturesPerWorkload: 256,
		EnforceDeadlinePeriods:   3,
	}
}

// defaultDriftMaxWorkloads is the fallback profile cap applied when the config
// leaves MaxWorkloads unset.
const defaultDriftMaxWorkloads = 1000

// defaultDriftEnforceDeadlinePeriods is the fallback deadline multiplier applied
// when the config leaves EnforceDeadlinePeriods unset.
const defaultDriftEnforceDeadlinePeriods = 3

// defaultDriftMaxSignaturesPerWorkload is the fallback per-profile signature cap
// applied when the config leaves MaxSignaturesPerWorkload unset.
const defaultDriftMaxSignaturesPerWorkload = 256

// driftGlobalProfileLabel is the synthetic "comm" used to label the global
// fallback baseline (see the `global` field doc) in logs and /debug/state,
// distinguishing it from any real per-workload profile.
const driftGlobalProfileLabel = "*global*"

// driftWorkloadProfile holds the drift-signature baseline learned for one workload.
type driftWorkloadProfile struct {
	// signatures is the set of (rule_id, normalized target) pairs observed
	// during the learning window.
	signatures  map[string]struct{}
	startedAt   time.Time
	lastSeen    time.Time
	sampleCount int
	enforcing   bool
	// saturated records that the signature set hit MaxSignaturesPerWorkload
	// during learning, so the baseline is frozen and known to be incomplete.
	saturated bool
	// reported holds the signatures already reported as anomalies for this
	// workload, so a drift is alerted once rather than on every recurrence.
	// Allocated lazily: most profiles never report anything.
	reported map[string]struct{}
}

// DriftBaselineProfiler learns, per workload, which drift-class rule matches
// are normal for this host during a learning window, then flags only the
// signatures that were never observed during learning as anomalies.
type DriftBaselineProfiler struct {
	config DriftBaselineConfig
	mu     sync.RWMutex
	// profiles is keyed by WorkloadKey.String().
	profiles map[string]*driftWorkloadProfile
	// lruHeap/lruIndex order profile keys by last activity so the cap can
	// evict the least-recently-active profile in O(log n).
	lruHeap  lruStringHeap
	lruIndex lruStringIndex

	// global accumulates drift signatures across ALL workloads, in parallel
	// with the per-workload profiles above, whenever PerWorkload is true (when
	// it is false, resolveKey already returns the single shared WorkloadKey{}
	// profile, so there is nothing extra to maintain). It exists to close
	// finding №193: without it, a workload in its own learning phase
	// unconditionally suppresses every drift-class match, so an attacker who
	// arrives as (or spawns) a workload the profiler has never seen before —
	// which is exactly what an attack looks like — gets a free pass on the
	// primitives these rules exist to catch. A signature unknown to every
	// OTHER workload on the host is not "normal for this host" just because
	// the workload making it happens to be new; it alerts even during that
	// workload's own learning window. global is exempt from the MaxWorkloads
	// LRU cap: it is one profile, not attacker-controlled cardinality. Guarded
	// by the same p.mu as profiles; there is no separate lock for it.
	global *driftWorkloadProfile

	// maxWorkloads is the resolved profile cap (0 = unbounded).
	maxWorkloads int
	// maxSignatures is the resolved per-profile signature cap (0 = unbounded).
	maxSignatures int
	// enforceDeadline is the resolved wall-clock duration after which a
	// still-learning workload is forced into enforcing (0 = disabled).
	enforceDeadline time.Duration

	// nowFn is injectable so tests can drive the learning deadline
	// deterministically; defaults to time.Now.
	nowFn func() time.Time

	suppressedTotal *prometheus.CounterVec
	anomaliesTotal  *prometheus.CounterVec
	learningGauge   prometheus.Gauge
	profilesGauge   prometheus.Gauge
	stuckGauge      prometheus.Gauge
	overdueGauge    prometheus.Gauge
	saturatedGauge  prometheus.Gauge
	evictionsTotal  prometheus.Counter
	log             *slog.Logger
}

// NewDriftBaselineProfiler creates a new profiler with the given config.
func NewDriftBaselineProfiler(cfg DriftBaselineConfig, log *slog.Logger) *DriftBaselineProfiler {
	if log == nil {
		log = slog.Default()
	}

	maxWorkloads := cfg.MaxWorkloads
	if maxWorkloads == 0 {
		maxWorkloads = defaultDriftMaxWorkloads
	}
	if maxWorkloads < 0 {
		maxWorkloads = 0 // explicit "unbounded"
	}
	maxSignatures := cfg.MaxSignaturesPerWorkload
	if maxSignatures == 0 {
		maxSignatures = defaultDriftMaxSignaturesPerWorkload
	}
	if maxSignatures < 0 {
		maxSignatures = 0 // explicit "unbounded"
	}
	deadlinePeriods := cfg.EnforceDeadlinePeriods
	if deadlinePeriods == 0 {
		deadlinePeriods = defaultDriftEnforceDeadlinePeriods
	}
	var enforceDeadline time.Duration
	if deadlinePeriods > 0 && cfg.LearningPeriod > 0 {
		enforceDeadline = time.Duration(deadlinePeriods) * time.Duration(cfg.LearningPeriod) * time.Second
	}

	return &DriftBaselineProfiler{
		config:          cfg,
		profiles:        make(map[string]*driftWorkloadProfile),
		lruIndex:        make(lruStringIndex),
		maxWorkloads:    maxWorkloads,
		maxSignatures:   maxSignatures,
		enforceDeadline: enforceDeadline,
		nowFn:           time.Now,
		log:             log,
		suppressedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ebpf_guard_drift_baseline_suppressed_total",
			Help: "Drift-class rule matches suppressed because they were still learning or matched the workload's known baseline.",
		}, []string{"rule_id", "reason"}),
		anomaliesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ebpf_guard_drift_baseline_anomalies_total",
			Help: "Drift-class rule matches that deviated from the learned baseline and were allowed through as alerts.",
		}, []string{"rule_id"}),
		learningGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ebpf_guard_drift_baseline_learning_workloads",
			Help: "Number of workloads currently in the drift-baseline learning phase.",
		}),
		profilesGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ebpf_guard_drift_baseline_profiles",
			Help: "Number of per-workload drift baseline profiles currently held in memory.",
		}),
		stuckGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ebpf_guard_drift_baseline_stuck_learning_workloads",
			Help: "Number of workloads learning longer than one LearningPeriod whose enforcement deadline has not yet elapsed — genuine drift-rule blind spots right now (wave 6.0d, finding №198; see learning_overdue_workloads for the deadline-agnostic count this replaced).",
		}),
		overdueGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ebpf_guard_drift_baseline_learning_overdue_workloads",
			Help: "Number of workloads that have been learning longer than one LearningPeriod, regardless of deadline state (the pre-6.0d definition of stuck_learning_workloads).",
		}),
		saturatedGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ebpf_guard_drift_baseline_saturated_profiles",
			Help: "Number of workload profiles whose signature set hit MaxSignaturesPerWorkload — their baseline is frozen and incomplete.",
		}),
		evictionsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ebpf_guard_drift_baseline_evictions_total",
			Help: "Total drift baseline profiles evicted because the workload cap was reached.",
		}),
	}
}

// RegisterMetrics registers Prometheus metrics with reg.
func (p *DriftBaselineProfiler) RegisterMetrics(reg prometheus.Registerer) error {
	for _, c := range []prometheus.Collector{
		p.suppressedTotal, p.anomaliesTotal, p.learningGauge,
		p.profilesGauge, p.stuckGauge, p.overdueGauge, p.saturatedGauge, p.evictionsTotal,
	} {
		if err := reg.Register(c); err != nil {
			return err
		}
	}
	return nil
}

// Observe records a drift-class rule match and reports whether it should be
// emitted as an alert. Equivalent to ObserveRule(ruleID, e, false) — see there
// for the full semantics. Kept as the zero-flag entry point so the large
// majority of class: drift rules (and every existing caller/test) are
// unaffected by the DriftNovelWorkload flag added in wave 6.0d.
func (p *DriftBaselineProfiler) Observe(ruleID string, e types.Event) bool {
	return p.ObserveRule(ruleID, e, false)
}

// ObserveRule records a drift-class rule match and reports whether it should
// be emitted as an alert. Returns true when the profiler is disabled
// (fail-open to unchanged behavior), when the workload's baseline learning
// has just completed and the signature is genuinely novel, or immediately
// whenever the given ruleID's signature was never observed during learning.
//
// Returns false while the workload is still learning AND the signature is
// covered by one of the two exceptions below, when the signature matches a
// baseline entry learned for this workload (both are treated as "normal for
// this host"), or when this workload already reported the same novel
// signature once — see the report-once note further down.
//
// novelWorkloadAlert (Rule.DriftNovelWorkload == "alert", wave 6.0d, finding
// №193) removes ALL of a new workload's learning-phase suppression for this
// rule: matches are evaluated exactly as they would be for an
// already-enforcing workload, so container/namespace-escape primitives never
// get a free pass just because the process making them is new. Independent
// of that flag, the SAME free pass is also closed by the global fallback
// baseline (see the `global` field doc): a signature unknown to every OTHER
// workload the profiler has ever seen is not "normal for this host" merely
// because the workload producing it is new, so it alerts too — even for
// rules that never set the flag. The flag exists because the global baseline
// is itself vulnerable to the same attack it defends against everywhere else
// (an attack that starts before the learning window opens teaches the global
// baseline its own primitives, e.g. the container-escape pipeline's own
// unshare/mount prologue); DriftNovelWorkload:alert is for the subset of
// rules where that residual blind spot is unacceptable regardless of cost.
func (p *DriftBaselineProfiler) ObserveRule(ruleID string, e types.Event, novelWorkloadAlert bool) bool {
	if !p.config.Enabled {
		return true
	}

	sig := ruleID + "|" + driftSignatureTarget(e)
	key := p.resolveKey(e)
	keyStr := key.String()
	now := p.nowFn()

	p.mu.Lock()
	defer p.mu.Unlock()

	prof, ok := p.profiles[keyStr]
	if !ok {
		// Enforce the profile cap before inserting a new workload so that
		// attacker-driven comm cardinality cannot grow the map without bound.
		p.evictIfOverCapacityLocked()
		prof = &driftWorkloadProfile{
			signatures: make(map[string]struct{}),
			startedAt:  now,
			lastSeen:   now,
		}
		p.profiles[keyStr] = prof
		p.lruIndex.push(&p.lruHeap, keyStr)
	} else {
		prof.lastSeen = now
		p.lruIndex.touch(&p.lruHeap, keyStr)
	}

	// Global fallback baseline (№193a). Maintained whenever PerWorkload
	// separates baselines per workload; when it doesn't, prof above IS
	// already the single shared profile and global would just be a second
	// copy of the same state under a different key. Learns from every
	// drift-class match on the host regardless of which workload made it, and
	// is never subject to the MaxWorkloads eviction that bounds attacker-
	// controlled comm cardinality — it is exactly one profile.
	var globalKnownBefore bool
	if p.config.PerWorkload {
		if p.global == nil {
			p.global = &driftWorkloadProfile{
				signatures: make(map[string]struct{}),
				startedAt:  now,
				lastSeen:   now,
			}
		}
		p.global.lastSeen = now
		p.global.sampleCount++
		_, globalKnownBefore = p.global.signatures[sig]
		p.learnSignatureLocked(p.global, sig, WorkloadKey{Comm: driftGlobalProfileLabel})
	}

	if !prof.enforcing {
		p.learnSignatureLocked(prof, sig, key)
		prof.sampleCount++

		learningPeriod := time.Duration(p.config.LearningPeriod) * time.Second
		elapsed := now.Sub(prof.startedAt)
		switch {
		case elapsed >= learningPeriod && prof.sampleCount >= p.config.MinSamples:
			prof.enforcing = true
			p.log.Info("drift-baseline: workload baseline learned, switching to enforcing",
				"workload", key.Comm, "namespace", key.Namespace, "unique_signatures", len(prof.signatures))
		case p.enforceDeadline > 0 && elapsed >= p.enforceDeadline:
			// Deadline reached without ever meeting MinSamples: a low-traffic
			// workload must not stay a permanent blind spot. Freeze whatever
			// baseline was learned and start enforcing against it.
			prof.enforcing = true
			p.log.Info("drift-baseline: learning deadline reached, forcing enforcing despite low sample count",
				"workload", key.Comm, "namespace", key.Namespace,
				"samples", prof.sampleCount, "min_samples", p.config.MinSamples,
				"unique_signatures", len(prof.signatures))
		}

		// Two exceptions fall through to the report-once/alert logic below
		// instead of the unconditional learning suppression: the rule opted
		// out of the presumption of innocence entirely (novelWorkloadAlert),
		// or the signature was unknown to every OTHER workload on the host
		// before this call (globalKnownBefore is false and a global baseline
		// is actually being kept). Neither check considers prof.signatures —
		// a workload's own in-progress learning never excuses it here, only
		// the global view of "has anyone on this host ever done this before".
		switch {
		case novelWorkloadAlert:
		case p.config.PerWorkload && !globalKnownBefore:
		default:
			p.suppressedTotal.WithLabelValues(ruleID, "learning").Inc()
			return false
		}
	} else if _, known := prof.signatures[sig]; known {
		p.suppressedTotal.WithLabelValues(ruleID, "baseline_known").Inc()
		return false
	}

	// anomaliesTotal counts EVERY match of a novel signature, including the
	// repeats suppressed just below. It is the raw drift volume, and keeping it
	// raw is the point: a run can then show both what the host actually did and
	// what the operator was actually paged about, instead of only the latter.
	p.anomaliesTotal.WithLabelValues(ruleID).Inc()

	// Report-once. A drift-class rule reports a CHANGE OF STATE — a binary that
	// was not there before, a mount that this workload never made — and a state
	// change is worth one alert, not one per recurrence. Without this the alert
	// volume tracks how often the new thing runs, which is a property of the
	// workload rather than of the drift, and measurement №6.0's ceiling
	// criterion (<=100 drift alerts/hour) becomes a lottery on cron frequency.
	// With it, volume tracks the number of DISTINCT new signatures per hour,
	// which is what the criterion was always meant to bound.
	//
	// The cost is real and deliberate: an operator who misses the first alert
	// gets no repeat. anomaliesTotal above and the alert store both still hold
	// the evidence. There is no re-arm TTL yet.
	if _, seen := prof.reported[sig]; seen {
		p.suppressedTotal.WithLabelValues(ruleID, "already_reported").Inc()
		return false
	}
	if p.maxSignatures <= 0 || len(prof.reported) < p.maxSignatures {
		if prof.reported == nil {
			prof.reported = make(map[string]struct{})
		}
		prof.reported[sig] = struct{}{}
	}
	// When the reported set is at its cap the signature is not recorded and the
	// next occurrence alerts again — noise over blindness, same bias as the
	// learning-side cap. The per-rule rate limiter is the backstop.
	return true
}

// learnSignatureLocked adds sig to prof's signature set, respecting
// p.maxSignatures. Once the cap is hit the baseline is frozen: the signature
// is not learned, so it is reported as an anomaly on any future comparison
// against this profile — noise over blindness, same bias for the per-workload
// and global profiles alike. Caller must hold p.mu.
func (p *DriftBaselineProfiler) learnSignatureLocked(prof *driftWorkloadProfile, sig string, key WorkloadKey) {
	if _, known := prof.signatures[sig]; known {
		return
	}
	if p.maxSignatures > 0 && len(prof.signatures) >= p.maxSignatures {
		if !prof.saturated {
			prof.saturated = true
			p.log.Warn("drift-baseline: workload signature cap reached, baseline frozen incomplete",
				"workload", key.Comm, "namespace", key.Namespace,
				"max_signatures", p.maxSignatures)
		}
		return
	}
	prof.signatures[sig] = struct{}{}
}

// LearningWorkloads returns the number of workloads still in the learning
// phase. Exposed for the learning-progress gauge.
func (p *DriftBaselineProfiler) LearningWorkloads() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	n := 0
	for _, prof := range p.profiles {
		if !prof.enforcing {
			n++
		}
	}
	return n
}

// StuckLearningWorkloads returns the number of workloads that have been in the
// learning phase for longer than one LearningPeriod AND whose enforcement
// deadline has not yet elapsed — i.e. workloads that are a genuine drift-rule
// blind spot right now.
//
// Wave 6.0d, finding №198: before PromoteExpiredWorkloads existed, nothing
// promoted a past-deadline workload except the next lucky Observe() call, so
// "past one LearningPeriod" and "past the deadline, still waiting for a match
// to notice" were the same population in practice — this gauge conflated
// "still blind" with "would stay blind forever at this traffic rate", and an
// operator reading it during idle silence had no way to tell which. With the
// periodic sweep in place, a workload whose deadline has elapsed is promoted
// on the next sweep regardless of traffic, so it is excluded here even if the
// sweep has not run yet this instant. See LearningOverdueWorkloads for the
// deadline-agnostic count this definition replaced.
func (p *DriftBaselineProfiler) StuckLearningWorkloads() int {
	learningPeriod := time.Duration(p.config.LearningPeriod) * time.Second
	if learningPeriod <= 0 {
		return 0
	}
	now := p.nowFn()
	p.mu.RLock()
	defer p.mu.RUnlock()
	n := 0
	for _, prof := range p.profiles {
		if prof.enforcing || now.Sub(prof.startedAt) <= learningPeriod {
			continue
		}
		if p.enforceDeadline > 0 && now.Sub(prof.startedAt) >= p.enforceDeadline {
			continue // deadline already elapsed; the periodic sweep clears this workload
		}
		n++
	}
	return n
}

// LearningOverdueWorkloads returns the number of workloads that have been in
// the learning phase for longer than one LearningPeriod, regardless of
// deadline state. This is the definition StuckLearningWorkloads held before
// wave 6.0d; kept as its own series so redefining "stuck" does not erase this
// cut of the data (finding №198).
func (p *DriftBaselineProfiler) LearningOverdueWorkloads() int {
	learningPeriod := time.Duration(p.config.LearningPeriod) * time.Second
	if learningPeriod <= 0 {
		return 0
	}
	now := p.nowFn()
	p.mu.RLock()
	defer p.mu.RUnlock()
	n := 0
	for _, prof := range p.profiles {
		if !prof.enforcing && now.Sub(prof.startedAt) > learningPeriod {
			n++
		}
	}
	return n
}

// PromoteExpiredWorkloads forces every still-learning workload whose
// enforcement deadline has elapsed into enforcing, using whatever baseline it
// accumulated so far — the same forcing Observe() already did inline, but run
// proactively instead of waiting for that workload's next match.
//
// Wave 6.0d, finding №198: before this existed, promotion was entirely lazy —
// checked only inside Observe(), which means a workload that stopped
// producing drift-class events right after its deadline passed stayed
// "learning" (and therefore a silent blind spot for every OTHER rule sharing
// its baseline) indefinitely, since nothing else ever asked the question
// again. Intended to be called from the same periodic loop that already
// drives UpdateLearningGauge, so the deadline is enforced on a bounded delay
// instead of on the next coincidental event. Returns the number of workloads
// promoted, for logging/testing.
func (p *DriftBaselineProfiler) PromoteExpiredWorkloads() int {
	if p.enforceDeadline <= 0 {
		return 0
	}
	now := p.nowFn()
	p.mu.Lock()
	defer p.mu.Unlock()
	promoted := 0
	for key, prof := range p.profiles {
		if prof.enforcing || now.Sub(prof.startedAt) < p.enforceDeadline {
			continue
		}
		prof.enforcing = true
		promoted++
		comm := key
		if i := strings.IndexByte(comm, '|'); i >= 0 {
			comm = comm[:i]
		}
		p.log.Info("drift-baseline: learning deadline reached, forcing enforcing despite low sample count",
			"workload", comm, "samples", prof.sampleCount, "min_samples", p.config.MinSamples,
			"unique_signatures", len(prof.signatures))
	}
	return promoted
}

// ProfileCount returns the number of per-workload profiles currently held.
func (p *DriftBaselineProfiler) ProfileCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.profiles)
}

// UpdateLearningGauge promotes any workload whose enforcement deadline has
// elapsed (finding №198 — see PromoteExpiredWorkloads), then refreshes the
// learning-progress, profile-count, stuck-learning and overdue-learning
// gauges. Intended to be called periodically (e.g. by the same background
// loop that persists other profiler state); promotion runs first so the
// gauges below reflect its effect within the same tick rather than one tick
// later.
func (p *DriftBaselineProfiler) UpdateLearningGauge() {
	p.PromoteExpiredWorkloads()
	p.learningGauge.Set(float64(p.LearningWorkloads()))
	p.profilesGauge.Set(float64(p.ProfileCount()))
	p.stuckGauge.Set(float64(p.StuckLearningWorkloads()))
	p.overdueGauge.Set(float64(p.LearningOverdueWorkloads()))
	p.saturatedGauge.Set(float64(p.SaturatedWorkloads()))
}

// DriftWorkloadState is a per-workload view of the drift baseline, exposed on
// GET /debug/state.
//
// Wave 6.0 shipped only three aggregate numbers (profiles / learning / stuck).
// That was enough to say "some profile is enforcing" and not enough to say
// which — so the 6.0.4 pipeline guard printed "our drift-pc seed is enforcing"
// while actually asserting `profiles > learning`, and when the 6.0.3 positive
// control came back silent 70 minutes later there was no way to tell a
// collapsed signature from a workload that never promoted. This is that
// missing bit.
type DriftWorkloadState struct {
	// Workload is the resolved (comm, namespace, app_label) key.
	Workload string `json:"workload"`
	Comm     string `json:"comm"`
	// State is one of:
	//   "learning"  — inside the first LearningPeriod;
	//   "stuck"     — learning past one LearningPeriod, deadline NOT yet
	//                 elapsed, i.e. a drift-rule blind spot right now;
	//   "overdue"   — learning past the enforcement deadline, awaiting the
	//                 next PromoteExpiredWorkloads sweep (wave 6.0d, finding
	//                 №198 — the pre-6.0d definition of "stuck" covered both
	//                 this and the case above);
	//   "enforcing" — baseline frozen, drift reported against it;
	//   "global"    — the single global fallback baseline (finding №193a),
	//                 which has no promotion lifecycle at all.
	// The first three all mean "still learning". "stuck" here matches
	// StuckLearningWorkloads() and "overdue" matches LearningOverdueWorkloads()
	// minus "stuck", so /debug/state and /metrics cannot disagree.
	State string `json:"state"`
	// Signatures is how many distinct signatures the baseline holds.
	Signatures int `json:"signatures"`
	// Samples is how many drift-class matches were observed during learning.
	Samples int `json:"samples"`
	// Saturated is true when the signature cap froze this baseline incomplete.
	Saturated bool `json:"saturated"`
	// Reported is how many distinct signatures this workload has already
	// alerted on. Its growth rate is the drift alert volume for this workload.
	Reported int `json:"reported"`
	// StartedAt is when the profile was created (first observed match), which
	// is what the learning deadline is measured from — NOT agent start.
	StartedAt time.Time `json:"started_at"`
	LastSeen  time.Time `json:"last_seen"`
}

// WorkloadStates returns a per-workload snapshot of the drift baseline.
func (p *DriftBaselineProfiler) WorkloadStates() []DriftWorkloadState {
	learningPeriod := time.Duration(p.config.LearningPeriod) * time.Second
	now := p.nowFn()

	p.mu.RLock()
	defer p.mu.RUnlock()

	out := make([]DriftWorkloadState, 0, len(p.profiles))
	for key, prof := range p.profiles {
		state := "learning"
		switch {
		case prof.enforcing:
			state = "enforcing"
		case p.enforceDeadline > 0 && now.Sub(prof.startedAt) >= p.enforceDeadline:
			// Past the deadline: the periodic sweep promotes it regardless of
			// traffic, so it is not a standing blind spot (finding №198).
			state = "overdue"
		case learningPeriod > 0 && now.Sub(prof.startedAt) > learningPeriod:
			state = "stuck"
		}
		// WorkloadKey.String() is "comm|namespace|app_label"; surface comm on
		// its own so a guard can grep for the workload it seeded by name.
		comm := key
		if i := strings.IndexByte(comm, '|'); i >= 0 {
			comm = comm[:i]
		}
		out = append(out, DriftWorkloadState{
			Workload:   key,
			Comm:       comm,
			State:      state,
			Signatures: len(prof.signatures),
			Samples:    prof.sampleCount,
			Saturated:  prof.saturated,
			Reported:   len(prof.reported),
			StartedAt:  prof.startedAt,
			LastSeen:   prof.lastSeen,
		})
	}
	if p.global != nil {
		// The global fallback baseline (№193a) never enforces/learns in the
		// per-workload sense — it has no promotion deadline, only a growing
		// signature set — so it gets its own state label rather than being
		// forced into learning/stuck/enforcing. It is included here (and in
		// SaturatedWorkloads below) precisely so an operator can tell "the
		// global baseline saturated" apart from any specific workload doing
		// so: it sees every workload's signatures at once and so hits
		// MaxSignaturesPerWorkload sooner than any of them individually — a
		// measurement, not a fault (plan.md, 6.0d).
		out = append(out, DriftWorkloadState{
			Workload:   driftGlobalProfileLabel,
			Comm:       driftGlobalProfileLabel,
			State:      "global",
			Signatures: len(p.global.signatures),
			Samples:    p.global.sampleCount,
			Saturated:  p.global.saturated,
			StartedAt:  p.global.startedAt,
			LastSeen:   p.global.lastSeen,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Workload < out[j].Workload })
	return out
}

// SaturatedWorkloads returns the number of profiles whose signature set hit
// MaxSignaturesPerWorkload during learning. Their baseline is frozen and known
// to be incomplete, so they may report anomalies for signatures that are in
// fact normal — the operator needs to be able to see that. Includes the
// global fallback baseline (№193a) alongside per-workload profiles: it is
// exactly as capable of saturating, and typically saturates first.
func (p *DriftBaselineProfiler) SaturatedWorkloads() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	n := 0
	for _, prof := range p.profiles {
		if prof.saturated {
			n++
		}
	}
	if p.global != nil && p.global.saturated {
		n++
	}
	return n
}

// evictIfOverCapacityLocked drops the least-recently-active profile when the
// map is at the configured cap, so a new workload can be inserted without
// growing memory past the bound. Caller must hold p.mu. No-op when the cap is
// disabled (maxWorkloads <= 0) or the map is below the cap.
func (p *DriftBaselineProfiler) evictIfOverCapacityLocked() {
	if p.maxWorkloads <= 0 || len(p.profiles) < p.maxWorkloads {
		return
	}
	if p.lruHeap.Len() == 0 {
		return
	}
	e := heap.Pop(&p.lruHeap).(*lruEntry)
	delete(p.lruIndex, e.key)
	delete(p.profiles, e.key)
	p.profilesGauge.Set(float64(len(p.profiles)))
	p.evictionsTotal.Inc()
}

func (p *DriftBaselineProfiler) resolveKey(e types.Event) WorkloadKey {
	if p.config.PerWorkload {
		return WorkloadKeyFromEvent(e)
	}
	return WorkloadKey{}
}

// driftSignatureTarget extracts a normalized, PID/inode-independent
// description of what a drift-class rule matched, so that repeated matches
// against the same class of target (e.g. any file under /etc, any
// connection to the same port) collapse into a single baseline signature.
//
//nolint:exhaustive // only file/network/syscall events are meaningful drift-class targets; other event types fall through to the zero-value signature.
func driftSignatureTarget(e types.Event) string {
	switch e.Type {
	case types.EventFileAccess:
		if e.File != nil {
			path := e.File.FDPath
			if path == "" {
				path = util.BytesToString(e.File.Filename[:])
			}
			return normalizeDriftPath(path)
		}
	case types.EventTCPConnect:
		if e.Network != nil {
			return strconv.Itoa(int(e.Network.Dport))
		}
	case types.EventSyscall:
		if e.Syscall != nil {
			sig := strconv.Itoa(int(e.Syscall.Nr))
			// Fold the syscall's semantic scalar argument into the signature
			// when it has one. Wave 6.0 left drift_dangerous_syscall matching
			// on nr alone (ptrace/mount/unshare/... carry no proc.args), so a
			// workload that made ONE bpf() call during learning had every
			// later bpf() call suppressed — including BPF_PROG_LOAD, the whole
			// reason the rule exists. The register arguments are already
			// carried end-to-end (bpf/syscall.bpf.c copies ctx->args on
			// sys_enter and restores them from syscall_args on sys_exit;
			// they are the rule fields arg0..arg5), they were simply never
			// read here.
			if spec, ok := driftSyscallArgSpecs[e.Syscall.Nr]; ok {
				sig += "|" + spec.name + "=" + driftFormatSyscallArgs(spec, e.Syscall.Args)
			}
			// A bare syscall number collapses every exec of a given
			// workload into one signature after the first sample — e.g.
			// drift_exec_from_system_bin matches on proc.args (which binary
			// path ran), but without this, "sshd execve'd once" would
			// permanently suppress every later exec of any OTHER binary by
			// a comm=sshd workload too, since they all share the same
			// execve syscall number. When proc.args is available (as it is
			// for any rule that conditions on it, by construction), fold
			// its argv[0] into the signature so distinct binaries under the
			// same syscall number stay distinguishable. Since 6.0 that is
			// literally true: normalizeDriftPath no longer truncates the path,
			// so /usr/bin/curl and /usr/bin/python3 are two signatures, not
			// one. Syscalls that carry no proc.args at all (ptrace, mount,
			// unshare, ...) are handled by the argument fold above, not here.
			if e.ProcArgs != "" {
				argv0 := e.ProcArgs
				if sp := strings.IndexByte(argv0, ' '); sp >= 0 {
					argv0 = argv0[:sp]
				}
				sig += "|" + normalizeDriftPath(argv0)
			}
			return sig
		}
	}
	return ""
}

// normalizeDriftPath reduces a file path to a PID/inode-independent form by
// replacing purely numeric path segments with "*" (e.g. "/proc/12345/mem" ->
// "/proc/*/mem"). Every other segment is kept verbatim.
//
// Wave 6.0 removed the depth truncation that used to sit here
// (driftPathPrefixMaxDepth = 2, kept only the first two segments). It made the
// baseline exactly as coarse as the drift rules' own prefix lists — "/usr/bin",
// "/usr/sbin", "/usr/local", "/usr/lib", "/etc" — so once a workload had
// exec'd or opened ANY path under such a directory during learning, every
// other path under it was "known" forever. Measurement №6.0 proved it live:
// the 6.0.3 positive control exec'd a brand-new binary under /usr/local/bin
// with an already-enforcing workload and got zero alerts, because
// "/usr/local/bin/drift-pc" and "/usr/local/bin/drift-pc-attack-window/drift-pc"
// both collapsed to "/usr/local". Rules whose whole purpose is the word "new"
// (drift_new_library_in_system_dir, drift_new_file_dir_sensitive,
// drift_exec_from_system_bin) cannot work at directory granularity. Unbounded
// signature cardinality is now bounded by MaxSignaturesPerWorkload instead,
// which caps the cost directly rather than by throwing away the distinction
// the rules are built on.
func normalizeDriftPath(path string) string {
	if path == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(path))
	start := 0
	for i := 0; i <= len(path); i++ {
		if i == len(path) || path[i] == '/' {
			if i > start {
				seg := path[start:i]
				if isNumericSegment(seg) {
					seg = "*"
				}
				b.WriteByte('/')
				b.WriteString(seg)
			}
			start = i + 1
		}
	}
	if b.Len() == 0 {
		return "/"
	}
	return b.String()
}

// isNumericSegment reports whether s consists entirely of ASCII digits (non-empty).
func isNumericSegment(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
