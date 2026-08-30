// Package correlator provides event correlation and rule-based detection.
package correlator

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"log/slog"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/zugolO/ebpf-guard/internal/feedback"
	"github.com/zugolO/ebpf-guard/internal/policy"
	"github.com/zugolO/ebpf-guard/internal/profiler"
	"github.com/zugolO/ebpf-guard/internal/util"
	"github.com/zugolO/ebpf-guard/pkg/types"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/time/rate"
)

// tracer is the OpenTelemetry tracer for the correlator package.
var tracer = otel.Tracer("github.com/zugolO/ebpf-guard/internal/correlator")

// Engine defines the interface for event correlation engines.
type Engine interface {
	// Ingest processes a single event synchronously and returns any alerts it
	// produced. Suitable for tests and tools; production ingestion should use
	// IngestAsync + periodic Flush instead (see CorrelationEngine.IngestAsync).
	Ingest(ctx context.Context, e types.Event) []types.Alert
	// Flush returns and resets pending alerts accumulated via IngestAsync (and
	// via the async Rego evaluation path). Production callers must poll this
	// periodically to drain alerts and dispatch them to storage/notifiers —
	// pending is otherwise unbounded for the life of the engine.
	Flush() []types.Alert
}

// WasmEvaluator is the interface for the WASM plugin engine.
// Implemented by *wasm.Engine; defined here to avoid an import cycle.
type WasmEvaluator interface {
	// Evaluate runs all loaded WASM plugins against the event.
	Evaluate(ctx context.Context, e types.Event) []types.Alert
}

// IOCMatcher allows the correlation engine to check events against cluster-wide
// IOC intelligence provided by the gossip sub-system.
// Implemented by gossip.Manager; decoupled here to avoid an import cycle.
type IOCMatcher interface {
	MatchIP(ip string) bool
	MatchDNS(domain string) bool
	MatchFingerprint(fp string) bool
}

// ActionExecutor triggers active enforcement when a rule specifies a
// non-alert action (kill, block, throttle).
// Implemented by *enforcer.Enforcer; decoupled to avoid an import cycle.
type ActionExecutor interface {
	ExecuteAction(ctx context.Context, action string, alert types.Alert) error
	IsDryRun() bool
}

// SensitivityAdjuster allows the gossip sub-system to signal cross-node alert
// amplification: when a peer node fires a critical alert in namespace N, the
// local engine lowers its anomaly detection threshold for that namespace so
// related lateral-movement activity is caught even at lower anomaly scores.
// Implemented by gossip.Manager; decoupled here to avoid an import cycle.
type SensitivityAdjuster interface {
	// GetThresholdMultiplier returns a multiplier in (0,1] for the given
	// namespace. Values below 1.0 lower the effective anomaly threshold,
	// increasing detection sensitivity. Returns 1.0 (no change) when no
	// amplification signal is active for the namespace.
	GetThresholdMultiplier(namespace string) float64
}

// CorrelationEngine correlates events and applies detection rules.
type CorrelationEngine struct {
	ruleEngine atomic.Pointer[RuleEngine]
	buffer     *ShardedEventBuffer // Uses sharded locks for better concurrency
	// enableEventBuffer gates the per-event buffer.Add on the hot path. When
	// false (default) events are not copied into the per-PID ring buffer.
	enableEventBuffer bool
	pending           []types.Alert
	pendingMu         sync.Mutex // Protects pending alerts slice

	// Anomaly detection
	anomalyDetector *profiler.AnomalyDetector
	enableAnomaly   bool

	// Rate limiting
	rateLimiter   *RateLimiter
	rlStatesGauge prometheus.Gauge // ebpf_guard_ratelimiter_states_total
	cancelCleanup context.CancelFunc

	// Global token-bucket rate limit — caps total alerts/sec across all rules.
	globalLimiter        *rate.Limiter
	globalLimiterEnabled bool
	alertsDroppedGlobal  prometheus.Counter // ebpf_guard_alerts_dropped_total{reason="global_rate_limit"}

	// Rego policy engine (post-YAML filter, Sprint 23.0)
	regoEngine       *policy.RegoEngine
	enableRegoEval   bool
	regoQueue        chan regoTask
	regoQueueDropped prometheus.Counter
	regoQueueGauge   prometheus.Gauge // ebpf_guard_rego_queue_occupancy
	// regoWg tracks in-flight rego evaluation tasks for clean Drain.
	regoWg sync.WaitGroup

	// dnsPrefilter short-circuits Rego evaluation for benign DNS events.
	// Initialised to DefaultDNSPrefilter() by NewCorrelationEngine.
	dnsPrefilter *DNSPrefilter

	// Monotonic counter for unique Alert IDs — prevents collision when
	// two alerts share the same ruleID+timestamp+pid (e.g. bursts in <1ns resolution).
	alertSeq atomic.Uint64

	// queueDepthFn returns the current fill level (len) of the shared event channel.
	// Wired via SetQueueDepthFn after the channel is created in main.
	queueDepthFn func() int
	// queueCapFn returns the capacity of the shared event channel.
	queueCapFn func() int

	// Metrics
	processedEvents atomic.Uint64
	alertsGenerated atomic.Uint64
	alertsDropped   atomic.Uint64

	// Sprint 34.0 Prometheus metrics
	queueDepthGauge  prometheus.Gauge     // ebpf_guard_event_queue_fill_ratio
	latencyHistogram prometheus.Histogram // ebpf_guard_correlation_latency_seconds (internal histogram)
	activeRulesGauge prometheus.Gauge     // ebpf_guard_active_rules_total

	// Map size metrics — updated by updateRLGaugeLoop.
	cooldownEntriesGauge prometheus.Gauge // ebpf_guard_cooldown_entries_total
	dedupEntriesGauge    prometheus.Gauge // ebpf_guard_dedup_entries_total

	// Hot-reload metrics
	reloadTotal         *prometheus.CounterVec // ebpf_guard_rule_reload_total{status}
	reloadDuration      *prometheus.GaugeVec   // ebpf_guard_rule_reload_duration_seconds{phase}
	rulesActive         *prometheus.GaugeVec   // ebpf_guard_rules_active{event_type}
	lastReloadTimestamp prometheus.Gauge       // ebpf_guard_rule_last_reload_timestamp_seconds

	// Metrics callback
	onCorrelate MetricsCallback

	// lineageTracker maintains per-PID ancestor chains used to enrich alerts
	// with a full process tree. Created automatically if not provided via config.
	lineageTracker *profiler.LineageTracker

	// feedbackManager suppresses alerts whose (ruleID, comm) pair has been
	// marked as a false positive by an analyst. Optional — nil disables suppression.
	feedbackManager *feedback.Manager

	// IOC matcher (gossip integration — optional)
	iocMatcher IOCMatcher

	// sensitivityAdjuster provides cross-node alert amplification signals
	// so the engine temporarily lowers its anomaly threshold for namespaces
	// under active attack on a peer node (Feature F).
	sensitivityAdjuster  SensitivityAdjuster
	baseAnomalyThreshold float64

	// WASM plugin engine for custom detection logic (optional).
	// When set, all loaded .wasm plugins are evaluated on every event.
	wasmEngine WasmEvaluator

	// Alert deduplication — sliding window keyed on (ruleID, pid, comm).
	// Sharded across mapShardCount buckets to reduce lock contention on the hot path.
	enableDedup        bool
	dedupWindow        time.Duration
	dedup              *shardedDedup
	alertsDedupDropped prometheus.Counter
	// alertsDedupDroppedByRule breaks the same suppression down per rule.
	// 5.8b (находка №21): the aggregate counter above cannot say WHICH rules
	// the ~2× store/metric gap comes from, and it could neither confirm nor
	// rule out dedup as the cause of the ~30× outliers on owasp_log_tampering
	// and sigma_log_deletion — the whole reason that finding stayed open.
	alertsDedupDroppedByRule *prometheus.CounterVec

	// alertsRateLimitedByRule breaks down per-rule rate-limiter drops (5.9.9.F.5n,
	// №164): before this, per-rule drops were folded into the un-labelled
	// alertsDropped counter alongside dedup and global-limiter drops, so a rule
	// pinned at the 10/60s ceiling was indistinguishable from a rule that simply
	// stopped firing.
	alertsRateLimitedByRule *prometheus.CounterVec

	// Rule-based enforcement (optional)
	actionExecutor  ActionExecutor
	enforceCooldown time.Duration
	// cooldowns is sharded across mapShardCount buckets; pid selects the shard.
	// This reduces lock contention under enforcement bursts vs. a single mutex.
	cooldowns           *shardedCooldowns
	enforcedCounter     prometheus.Counter
	enforceQueue        chan enforceTask
	enforceQueueDropped prometheus.Counter
	enforceQueueGauge   prometheus.Gauge // ebpf_guard_enforcement_queue_occupancy
	// enforceWg tracks in-flight enforcement tasks for clean DrainEnforceQueue.
	enforceWg sync.WaitGroup

	// ingestWg tracks in-flight ingest worker tasks for clean shutdown.
	// Incremented before queueing to ingestPool, decremented after processing.
	ingestWg sync.WaitGroup

	// allowlistProfiler detects unknown syscalls after the learning phase.
	// nil disables allowlist enforcement.
	allowlistProfiler *profiler.SyscallAllowlistProfiler

	// driftBaselineProfiler suppresses class: drift rule matches during a
	// per-workload learning window and thereafter alerts only on matches that
	// deviate from the learned baseline (issue #286). nil disables it, in
	// which case drift-class rules alert exactly like threat-class rules.
	driftBaselineProfiler *profiler.DriftBaselineProfiler

	// regoEvalErrors counts Rego evaluation failures so degraded-enrichment
	// is observable via Prometheus rather than silently swallowed.
	regoEvalErrors prometheus.Counter

	// scoreReporter is called after every anomaly score update so an external
	// cardinality-guarded Prometheus gauge can be kept in sync without importing
	// the exporter package (which would create a circular dependency).
	scoreReporter func(pid, comm string, score float64)

	// incidentTracker groups alerts from the same (pid, namespace) within a
	// sliding window into Incident records for higher-level attack correlation.
	incidentTracker *IncidentTracker

	// PID-partitioned ingest worker pool.  Each worker holds an isolated
	// AnomalyDetector so ProcessEvent is always called from a single goroutine
	// per instance.  IngestAsync routes events here; Ingest bypasses the pool.
	ingestPool []*workerState
	ingestMask uint32
	// closeIngestOnce guards closing the ingest worker channels so both
	// DrainIngestPool (called during graceful shutdown, before the final
	// Flush) and Close (final cleanup) can safely request the close without
	// a double-close panic.
	closeIngestOnce sync.Once

	// traceCtxCache memoises /proc/<pid>/environ trace-context lookups (including
	// negative results) so the alert path does not re-read /proc on every alert.
	traceCtxCache *traceContextCache

	// syscallFilterFn is called with the updated syscall allowlist whenever rules
	// are loaded or hot-reloaded.  Set via SetSyscallFilterUpdater so the
	// correlator stays decoupled from the bpf package.  nil disables the hook.
	syscallFilterFn func(nrs []uint32)

	// selfExcludeEnabled gates the 5.8e self-exclusion filter (находка №18):
	// events generated by the agent's own process tree are dropped before
	// rule evaluation instead of relying on a per-rule "ebpf-guard-self"
	// exception. Kernel-side BPF self-exclusion (wave 0.5) only suppresses
	// events *about* the agent's own files; this suppresses events
	// *produced by* the agent's own process (and any child it forks),
	// which the canary verification loop and the uprobe attacher's own
	// /proc/<pid>/maps reads both are. Must stay operator-toggleable and
	// logged at startup — see the config wiring in main.go — because a
	// compromised binary named "ebpf-guard" would otherwise get a blind
	// spot for free.
	selfExcludeEnabled bool
	// selfPID is the agent's own PID, captured once at construction.
	selfPID uint32
	// selfTree records PIDs known to be the agent's own process or a
	// descendant of it, grown incrementally from each event's PPID as
	// children are observed (no /proc walk needed). Never shrinks — the
	// agent's own tree stays small and long-lived for the process lifetime.
	selfTree sync.Map // map[uint32]struct{}
	// selfExcludedEvents counts events dropped by the self-exclusion filter.
	selfExcludedEvents prometheus.Counter // ebpf_guard_self_excluded_events_total

	// observerExcludeEnabled gates the 5.9a observer-tree exclusion filter
	// (находки №27/№28): events generated by the *measurement harness*
	// (idle-run.sh and the curl/ps/grep/awk processes it forks) are dropped
	// before rule evaluation, the same way 5.8e drops the agent's own tree.
	// Test-only — must stay false in production, because the root PID is
	// whatever the test harness tells it via observerRootPID, and trusting an
	// operator-supplied PID as "not an attacker" would be a blind spot by
	// construction outside a controlled test stand.
	observerExcludeEnabled bool
	// observerRootPID is the PID of the harness process tree to exclude, set
	// live via SetObserverRoot (main.go polls a file the harness writes its
	// own $$ into, since the harness starts after the agent is already
	// running as a service). 0 means "not yet known" — nothing is excluded.
	observerRootPID atomic.Uint32
	// observerTree records PIDs known to be the observer root or a descendant
	// of it, grown the same incremental way as selfTree.
	observerTree sync.Map // map[uint32]struct{}
	// observerKernelSide is set once the in-kernel filter (5.9.2g) has the
	// harness root published to at least one collector's observer_root_pid
	// map. From that point the userspace walk below is dead weight: BPF drops
	// harness events before bpf_ringbuf_reserve, so anything reaching here is
	// by definition not in the tree. Kept as a runtime switch rather than a
	// config flag because the BPF program may fail to load (verifier, missing
	// BTF, stub build) — in that case this stays false and the userspace path
	// remains the filter, which is the whole reason it is not simply deleted.
	observerKernelSide atomic.Bool
	// eventsExcludedTotal counts events dropped by reason (currently only
	// "observer_tree"), separate from selfExcludedEvents so existing 5.8e
	// dashboards built on ebpf_guard_self_excluded_events_total stay
	// unaffected.
	eventsExcludedTotal *prometheus.CounterVec // ebpf_guard_events_excluded_total{reason}
	// alertsSuppressedTotal counts alerts dropped AFTER alertsGenerated has
	// already counted them (currently only reason="feedback" — analyst
	// false-positive suppression via feedbackManager.FilterAlerts). Without
	// this the 5.9c counter identity (Δengine − Δfiltered = Δexported =
	// Δstore) has an invisible leak: №2.5 idle data showed 7 alerts generated
	// but never exported, unattributable to any exported counter.
	alertsSuppressedTotal *prometheus.CounterVec // ebpf_guard_alerts_suppressed_total{reason}
}

// MetricsCallback is a function called to record metrics.
type MetricsCallback func(duration float64)

// cooldownKey is the zero-allocation composite key for enforcement cooldown tracking.
type cooldownKey struct {
	ruleID string
	pid    uint32
}

// dedupKey is the composite key for the sliding-window alert deduplication map.
type dedupKey struct {
	ruleID string
	pid    uint32
	comm   string
}

// enforceTask is a unit of work dispatched to the enforcement worker pool.
type enforceTask struct {
	ctx    context.Context
	cancel context.CancelFunc
	action string
	alert  types.Alert
}

// regoTask is a unit of work dispatched to the async Rego evaluation pool.
type regoTask struct {
	ctx    context.Context
	cancel context.CancelFunc
	alerts []types.Alert
}

// workerTask is an event dispatched to a PID-partitioned ingest worker.
type workerTask struct {
	ctx   context.Context
	event types.Event
}

// workerTaskPool reduces per-event allocations on the ingest hot path by
// recycling workerTask structs rather than allocating a new one each time.
var workerTaskPool = sync.Pool{New: func() any { return new(workerTask) }}

// workerState is one slot in the parallel ingest pool.  Each worker holds an
// isolated AnomalyDetector so ProcessEvent is always called from a single
// goroutine per instance, satisfying the detector's thread-safety invariant.
type workerState struct {
	ch chan *workerTask
	ad *profiler.AnomalyDetector // nil when anomaly detection is disabled
}

// CorrelationEngineConfig holds configuration for the correlation engine.
type CorrelationEngineConfig struct {
	// Rule engine configuration
	Rules []Rule

	// Buffer configuration
	BufferSize int

	// EnableEventBuffer controls whether every ingested event is copied into the
	// per-PID ShardedEventBuffer. The buffer is only read back via GetEvents /
	// GetBuffer, which have no production consumer today, so it defaults to false
	// to keep the per-event hot path free of a shard-lock + Event-struct copy.
	// Set to true if an external consumer (e.g. an event-replay API) needs the
	// recent per-PID event history.
	EnableEventBuffer bool

	// Anomaly detection configuration
	EnableAnomaly    bool
	AnomalyThreshold float64
	LearningPeriod   time.Duration
	EWMAWeight       float64
	// MinLearningSamples is the minimum number of events that must be observed
	// before the learning phase can complete (in addition to LearningPeriod
	// elapsing). Zero falls back to the detector default (100).
	MinLearningSamples uint64

	// ProfilerMaxPIDs is the maximum number of workload profiles retained by the
	// anomaly detector's LRU cache. Each profile consumes ~2 KB; the default of
	// 8192 caps memory at ~16 MB and is appropriate for Kubernetes DaemonSets with
	// typical per-node pod density. Zero falls back to the detector default (65536).
	ProfilerMaxPIDs int

	// Rate limiting configuration
	EnableRateLimit    bool
	RateLimitWindow    time.Duration
	MaxAlertsPerWindow int

	// Rego policy engine configuration (Sprint 23.0)
	EnableRegoEval bool
	RegoEngine     *policy.RegoEngine

	// RegoWorkerCount is the number of goroutines draining the async Rego
	// evaluation queue. Zero → max(2, runtime.NumCPU()/2).
	RegoWorkerCount int

	// RegoQueueSize is the capacity of the async Rego evaluation channel.
	// When the queue is full Ingest falls back to synchronous OPA evaluation,
	// adding latency to the hot path. Increase if regoQueueDropped rises.
	// Zero → 4096.
	RegoQueueSize int

	// Global alert rate limit — maximum alerts per second across all rules.
	// Zero means unlimited. Default: 10000.
	MaxAlertsPerSecond int

	// BufferTTL is the idle TTL for per-PID event buffers. PIDs that have not
	// produced an event within this duration are evicted. Default: 10 minutes.
	BufferTTL time.Duration

	// Metrics callback (optional)
	OnCorrelate MetricsCallback

	// LineageTracker enables process-tree enrichment on every alert.
	// When nil, a new tracker with DefaultLineageConfig is created automatically.
	// Pass the Profiler's LineageTracker to share ancestry state.
	LineageTracker *profiler.LineageTracker

	// FeedbackManager drops alerts whose (ruleID, comm) pair has been marked as a
	// false positive. Optional — nil disables analyst-driven suppression.
	FeedbackManager *feedback.Manager

	// IOCMatcher integrates gossip-based cluster-wide IOC intelligence.
	// When set, events are checked against known IOCs and produce alerts.
	// Optional — nil disables this check entirely.
	IOCMatcher IOCMatcher

	// SensitivityAdjuster enables cross-node alert amplification (Feature F).
	// When set, namespaces with active peer alerts get a temporarily lowered
	// anomaly detection threshold.  Optional — nil disables amplification.
	SensitivityAdjuster SensitivityAdjuster

	// ActionExecutor is the enforcement backend (optional).
	// When set, rules with action: kill|block|throttle call ExecuteAction
	// asynchronously while the alert is still emitted for auditing.
	ActionExecutor ActionExecutor

	// EnforcementCooldown is the minimum interval between enforcement
	// executions for the same (rule, PID) pair. Zero → 5 seconds.
	EnforcementCooldown time.Duration

	// EnforceWorkerCount is the number of goroutines that drain the
	// enforcement queue. Zero → max(2, runtime.NumCPU()).
	EnforceWorkerCount int

	// EnforceQueueSize is the capacity of the async enforcement action channel.
	// When the queue is full enforcement actions are dropped.
	// Zero → 4096.
	EnforceQueueSize int

	// WasmEngine evaluates custom WASM detection plugins on every event.
	// When nil, WASM plugin evaluation is skipped.
	WasmEngine WasmEvaluator

	// IngestWorkerCount controls the size of the parallel ingest worker pool.
	// Zero → max(runtime.NumCPU(), 4) rounded up to the next power of 2, capped at 64.
	// Workers are PID-partitioned so each AnomalyDetector instance is always
	// accessed from a single goroutine, satisfying its thread-safety invariant.
	IngestWorkerCount int

	// IngestWorkerBufferSize controls the capacity of each per-worker ingest
	// channel. Default 1024. Increase when a single hot PID saturates its
	// dedicated worker under burst load (P1-6 in AUDIT-PERF-2026-06-13).
	// Zero uses the default of 1024.
	IngestWorkerBufferSize int

	// AnomalyScoreReporter is called after every anomaly ProcessEvent so an
	// external cardinality-guarded metric (e.g. exporter.SetAnomalyScoreWithGuard)
	// can track scores without creating a circular import.  Optional — nil disables.
	AnomalyScoreReporter func(pid, comm string, score float64)

	// EnableDedup enables sliding-window alert deduplication.
	// Duplicate (ruleID, pid, comm) alerts within DedupWindow are dropped.
	// Default: true.
	EnableDedup bool

	// DedupWindow is the deduplication suppression window.
	// Zero → 5 seconds.
	DedupWindow time.Duration

	// IncidentWindow is the sliding time window for grouping alerts from the
	// same (pid, namespace) into an Incident. Zero → 60 seconds.
	IncidentWindow time.Duration

	// IncidentTrustedComms overrides the set of process names whose alerts
	// cannot alone promote an incident to an "attack" verdict. Empty → the
	// built-in default (see defaultTrustedComms).
	IncidentTrustedComms []string

	// AllowlistProfiler enables deny-unknown syscall enforcement.
	// When set, every syscall event is checked against the learned allowlist
	// and generates an alert (or enforced action) when unknown.
	// Created externally (e.g. in main) so the learning phase can start
	// before the correlation engine is fully initialised.
	AllowlistProfiler *profiler.SyscallAllowlistProfiler

	// DriftBaselineProfiler suppresses class: drift rule matches until they
	// deviate from a learned per-workload baseline (issue #286).
	// Created externally (e.g. in main) so the learning phase can start
	// before the correlation engine is fully initialised.
	// Optional — nil means class: drift rules alert exactly like class: threat.
	DriftBaselineProfiler *profiler.DriftBaselineProfiler

	// SelfExcludeEnabled activates the 5.8e self-exclusion filter: events from
	// the agent's own PID (and any process forked from it) are dropped before
	// rule evaluation. Default: true. Set false to keep the agent fully
	// visible to its own rules — e.g. when verifying a suspected
	// impersonating binary, or when reproducing pre-5.8e detection baselines.
	SelfExcludeEnabled bool

	// SelfPID overrides the PID considered "self" by the self-exclusion
	// filter. Zero uses os.Getpid() (the normal case — this only exists so
	// tests can exercise the filter without depending on the test binary's
	// own PID).
	SelfPID uint32

	// ObserverExcludeEnabled activates the 5.9a observer-tree exclusion
	// filter: events from the measurement harness's process tree (root PID
	// set live via SetObserverRoot) are dropped before rule evaluation.
	// Default: false — test-only, wired from correlator.observer_exclude in
	// config-test.yaml, never from the production config.
	ObserverExcludeEnabled bool
}

// DefaultCorrelationEngineConfig returns a default configuration.
func DefaultCorrelationEngineConfig() CorrelationEngineConfig {
	return CorrelationEngineConfig{
		Rules:              []Rule{},
		BufferSize:         100,
		EnableAnomaly:      true,
		AnomalyThreshold:   0.8,
		LearningPeriod:     time.Hour,
		EWMAWeight:         0.3,
		ProfilerMaxPIDs:    8192,
		EnableRateLimit:    true,
		RateLimitWindow:    time.Minute,
		MaxAlertsPerWindow: 10,
		MaxAlertsPerSecond: 10000,
		BufferTTL:          2 * time.Minute,
		EnableDedup:        true,
		DedupWindow:        5 * time.Second,
		IncidentWindow:     60 * time.Second,
		RegoQueueSize:      4096,
		EnforceQueueSize:   4096,
		SelfExcludeEnabled: true,
	}
}

// NewCorrelationEngine creates a new correlation engine.
func NewCorrelationEngine(rules []Rule) *CorrelationEngine {
	config := DefaultCorrelationEngineConfig()
	config.Rules = rules
	return NewCorrelationEngineWithConfig(config)
}

// NewCorrelationEngineWithConfig creates a new correlation engine with full configuration.
func NewCorrelationEngineWithConfig(config CorrelationEngineConfig) *CorrelationEngine {
	ctx, cancel := context.WithCancel(context.Background())

	rlStatesGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ebpf_guard_ratelimiter_states_total",
		Help: "Current number of per-rule state entries in the rate limiter.",
	})

	alertsDroppedGlobal := prometheus.NewCounter(prometheus.CounterOpts{
		Name:        "ebpf_guard_alerts_dropped_total",
		Help:        "Total alerts dropped by the global rate limiter.",
		ConstLabels: prometheus.Labels{"reason": "global_rate_limit"},
	})

	queueDepthGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ebpf_guard_event_queue_fill_ratio",
		Help: "Current event channel fill level as a fraction [0,1]. Distinct from ebpf_guard_event_queue_depth (raw count).",
	})

	latencyHistogram := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "ebpf_guard_correlation_latency_seconds",
		Help:    "Latency of a single event through the correlation engine.",
		Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0},
	})

	activeRulesGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ebpf_guard_active_rules_total",
		Help: "Number of detection rules currently loaded in the rule engine.",
	})

	cooldownEntriesGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ebpf_guard_cooldown_entries_total",
		Help: "Current number of entries in the enforcement cooldown map.",
	})

	dedupEntriesGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ebpf_guard_dedup_entries_total",
		Help: "Current number of entries in the alert deduplication map.",
	})

	reloadTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ebpf_guard_rule_reload_total",
		Help: "Total number of rule hot-reloads attempted.",
	}, []string{"status"})

	reloadDuration := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ebpf_guard_rule_reload_duration_seconds",
		Help: "Time taken for each phase of the last rule hot-reload.",
	}, []string{"phase"})

	rulesActive := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ebpf_guard_rules_active",
		Help: "Current number of active detection rules by event type.",
	}, []string{"event_type"})

	lastReloadTimestamp := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ebpf_guard_rule_last_reload_timestamp_seconds",
		Help: "Unix timestamp of the last successful rule hot-reload.",
	})

	maxRPS := config.MaxAlertsPerSecond
	if maxRPS <= 0 {
		maxRPS = 10000
	}
	var globalLimiter *rate.Limiter
	globalLimiterEnabled := true
	globalLimiter = rate.NewLimiter(rate.Limit(maxRPS), maxRPS)

	enforceCooldown := config.EnforcementCooldown
	if enforceCooldown <= 0 {
		enforceCooldown = 5 * time.Second
	}

	enforcedCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ebpf_guard_enforcement_triggered_total",
		Help: "Number of rule-based enforcement actions triggered by the correlation engine.",
	})

	enforceQueueDropped := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ebpf_guard_enforcement_queue_dropped_total",
		Help: "Enforcement actions dropped because the enforcement queue was full.",
	})
	enforceQueueGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ebpf_guard_enforcement_queue_occupancy",
		Help: "Current number of enforcement tasks waiting in the worker queue.",
	})

	selfExcludedEvents := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ebpf_guard_self_excluded_events_total",
		Help: "Events dropped before rule evaluation because they originated from the agent's own process tree (5.8e self-exclusion filter).",
	})
	selfPID := config.SelfPID
	if selfPID == 0 {
		selfPID = uint32(os.Getpid()) /* #nosec G115 -- Linux PIDs always fit in uint32 (max 4194304) */
	}
	slog.Info("correlator: self-exclusion filter",
		slog.Bool("enabled", config.SelfExcludeEnabled),
		slog.Uint64("self_pid", uint64(selfPID)))

	eventsExcludedTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ebpf_guard_events_excluded_total",
		Help: "Events dropped before rule evaluation, by reason (5.9a: reason=\"observer_tree\" is the measurement harness's own process tree in test runs).",
	}, []string{"reason"})
	slog.Info("correlator: observer-tree exclusion filter (5.9a, test-only)",
		slog.Bool("enabled", config.ObserverExcludeEnabled))

	alertsSuppressedTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ebpf_guard_alerts_suppressed_total",
		Help: "Alerts dropped after generation was already counted in engine_stats.total_alerts, by reason (feedback = analyst false-positive suppression). Needed for the 5.9c counter identity to balance.",
	}, []string{"reason"})

	lt := config.LineageTracker
	if lt == nil {
		lt = profiler.NewLineageTracker(profiler.DefaultLineageConfig(), slog.Default())
	}

	enforceWorkers := config.EnforceWorkerCount
	if enforceWorkers <= 0 {
		enforceWorkers = runtime.NumCPU()
		if enforceWorkers < 2 {
			enforceWorkers = 2
		}
	}
	// Queue depth: default 4096 gives ~400ms burst capacity for enforcement spikes.
	// Each task is ~200 bytes.
	enforceQueueSize := config.EnforceQueueSize
	if enforceQueueSize <= 0 {
		enforceQueueSize = 4096
	}
	enforceQueue := make(chan enforceTask, enforceQueueSize)

	dedupWindow := config.DedupWindow
	if dedupWindow <= 0 {
		dedupWindow = 5 * time.Second
	}

	alertsDedupDropped := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ebpf_guard_alerts_dedup_dropped_total",
		Help: "Alerts suppressed by the sliding-window deduplication filter.",
	})
	// Per-rule breakdown of the same suppression (5.8b). Kept as a separate
	// metric rather than a label on the counter above so existing dashboards
	// and the №2.1…№2.4 series stay comparable. Cardinality is bounded by the
	// rule count (600 in-tree) and only rules that actually dedup get a series.
	alertsDedupDroppedByRule := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ebpf_guard_alerts_dedup_dropped_by_rule_total",
		Help: "Alerts suppressed by the sliding-window deduplication filter, broken down by rule_id (5.8b).",
	}, []string{"rule_id"})

	// Per-rule rate-limiter drop counter (5.9.9.F.5n, №164). Same rationale and
	// cardinality bound as alertsDedupDroppedByRule above: only rules that
	// actually hit their 10/60s ceiling get a series.
	alertsRateLimitedByRule := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ebpf_guard_alerts_ratelimited_by_rule_total",
		Help: "Alerts suppressed by the per-rule rate limiter, broken down by rule_id (5.9.9.F.5n).",
	}, []string{"rule_id"})

	var regoQueue chan regoTask
	var regoQueueDropped prometheus.Counter
	var regoQueueGauge prometheus.Gauge
	var regoEvalErrors prometheus.Counter
	if config.EnableRegoEval && config.RegoEngine != nil {
		regoQueueDropped = prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ebpf_guard_rego_queue_dropped_total",
			Help: "Rego evaluation tasks dropped because the async worker queue was full.",
		})
		regoQueueGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ebpf_guard_rego_queue_occupancy",
			Help: "Current number of Rego evaluation tasks waiting in the async worker queue.",
		})
		regoEvalErrors = prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ebpf_guard_rego_eval_errors_total",
			Help: "Rego policy evaluation errors; affected alerts pass through without MITRE enrichment.",
		})
		regoQueueSize := config.RegoQueueSize
		if regoQueueSize <= 0 {
			regoQueueSize = 4096
		}
		regoQueue = make(chan regoTask, regoQueueSize)
	}

	ce := &CorrelationEngine{
		buffer:                   NewShardedEventBuffer(config.BufferSize),
		enableEventBuffer:        config.EnableEventBuffer,
		traceCtxCache:            newTraceContextCache(),
		pending:                  make([]types.Alert, 0),
		enableAnomaly:            config.EnableAnomaly,
		rateLimiter:              NewRateLimiterWithContext(ctx, config.RateLimitWindow, config.MaxAlertsPerWindow, config.EnableRateLimit),
		rlStatesGauge:            rlStatesGauge,
		cancelCleanup:            cancel,
		enableRegoEval:           config.EnableRegoEval,
		regoEngine:               config.RegoEngine,
		dnsPrefilter:             DefaultDNSPrefilter(),
		regoQueue:                regoQueue,
		regoQueueDropped:         regoQueueDropped,
		regoQueueGauge:           regoQueueGauge,
		onCorrelate:              config.OnCorrelate,
		lineageTracker:           lt,
		feedbackManager:          config.FeedbackManager,
		iocMatcher:               config.IOCMatcher,
		sensitivityAdjuster:      config.SensitivityAdjuster,
		baseAnomalyThreshold:     config.AnomalyThreshold,
		wasmEngine:               config.WasmEngine,
		enableDedup:              config.EnableDedup,
		dedupWindow:              dedupWindow,
		dedup:                    newShardedDedup(dedupWindow),
		alertsDedupDropped:       alertsDedupDropped,
		alertsDedupDroppedByRule: alertsDedupDroppedByRule,
		alertsRateLimitedByRule:  alertsRateLimitedByRule,
		actionExecutor:           config.ActionExecutor,
		enforceCooldown:          enforceCooldown,
		cooldowns:                newShardedCooldowns(),
		enforcedCounter:          enforcedCounter,
		enforceQueue:             enforceQueue,
		enforceQueueDropped:      enforceQueueDropped,
		enforceQueueGauge:        enforceQueueGauge,
		globalLimiter:            globalLimiter,
		globalLimiterEnabled:     globalLimiterEnabled,
		alertsDroppedGlobal:      alertsDroppedGlobal,
		queueDepthGauge:          queueDepthGauge,
		latencyHistogram:         latencyHistogram,
		activeRulesGauge:         activeRulesGauge,
		cooldownEntriesGauge:     cooldownEntriesGauge,
		dedupEntriesGauge:        dedupEntriesGauge,
		reloadTotal:              reloadTotal,
		reloadDuration:           reloadDuration,
		rulesActive:              rulesActive,
		lastReloadTimestamp:      lastReloadTimestamp,
		incidentTracker:          newIncidentTracker(config.IncidentWindow, lt, config.Rules),
		regoEvalErrors:           regoEvalErrors,
		allowlistProfiler:        config.AllowlistProfiler,
		driftBaselineProfiler:    config.DriftBaselineProfiler,
		selfExcludeEnabled:       config.SelfExcludeEnabled,
		selfPID:                  selfPID,
		selfExcludedEvents:       selfExcludedEvents,
		observerExcludeEnabled:   config.ObserverExcludeEnabled,
		eventsExcludedTotal:      eventsExcludedTotal,
		alertsSuppressedTotal:    alertsSuppressedTotal,
	}

	initialRuleEngine := NewRuleEngine(config.Rules)
	initialRuleEngine.SetChainGroupResolver(ce.chainGroup)
	ce.ruleEngine.Store(initialRuleEngine)

	// Which daemons are background noise is deployment-specific, so the trust
	// gate's allowlist is tunable without a rebuild. Empty keeps the default.
	if len(config.IncidentTrustedComms) > 0 {
		ce.incidentTracker.SetTrustedComms(config.IncidentTrustedComms)
	}

	// Emit a synthetic critical alert the first time an incident is judged an
	// attack, so correlated attacks reach exporters, notifications and the alert
	// store instead of only the incidents query API (P0-2).
	ce.incidentTracker.SetAttackHandler(ce.emitConfirmedAttackAlert)

	// Seed active rules gauge
	activeRulesGauge.Set(float64(len(config.Rules)))

	// Background goroutine that evicts stale per-PID event buffers.
	bufferTTL := config.BufferTTL
	if bufferTTL <= 0 {
		bufferTTL = 2 * time.Minute
	}
	// Sweep at half the TTL so idle PID buffers are reclaimed promptly without
	// excessive cleanup churn. Clamped to a 30s floor.
	bufferSweep := bufferTTL / 2
	if bufferSweep < 30*time.Second {
		bufferSweep = 30 * time.Second
	}
	// Only run the eviction sweep when the per-PID event buffer is actually
	// populated; with EnableEventBuffer=false the buffer stays empty so the
	// goroutine would just wake up to do nothing.
	if config.EnableEventBuffer {
		go func() {
			ticker := time.NewTicker(bufferSweep)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					ce.buffer.CleanupExpired(bufferTTL)
				}
			}
		}()
	}

	// Background goroutine that evicts expired enforcement cooldown and dedup entries.
	// Without this the maps grow unbounded with unique (ruleID,PID) pairs.
	go func() {
		// Check every 5× the cooldown window so entries live long enough to
		// block repeated enforcement, but dead PIDs don't accumulate forever.
		interval := enforceCooldown * 5
		if interval < time.Minute {
			interval = time.Minute
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now := time.Now()
				ce.cooldowns.cleanup(now.Add(-enforceCooldown))
				ce.dedup.cleanup(now.Add(-ce.dedupWindow))
				ce.incidentTracker.Cleanup(now)
				ce.lineageTracker.Cleanup(now)
				ce.traceCtxCache.cleanup(now)
				// Evict (pid, dport) keys with no connections in the last
				// 10 minutes. Each live key holds a fixed 1024-entry ring
				// buffer, so without this short-lived PIDs leak ~24 KB each
				// for the lifetime of the process.
				globalConnFrequency.Cleanup(10 * time.Minute)
				// Evict (ruleID, pid) burst-tracker keys with no matches in
				// the last 10 minutes — same rationale as globalConnFrequency
				// above, for rule.Threshold's per-PID ring buffers.
				globalBurstTracker.Cleanup(10 * time.Minute)
			}
		}
	}()

	// Initialize anomaly detector if enabled
	if config.EnableAnomaly {
		ce.anomalyDetector = profiler.NewAnomalyDetectorWithSamples(
			ctx,
			config.AnomalyThreshold,
			config.LearningPeriod,
			config.EWMAWeight,
			config.MinLearningSamples,
			config.ProfilerMaxPIDs,
		)
		ce.scoreReporter = config.AnomalyScoreReporter
	}

	// Start bounded enforcement worker pool. Workers drain enforceQueue and call
	// ExecuteAction; the pool size is capped so enforcement can never create an
	// unbounded number of goroutines under a burst of matching events.
	if config.ActionExecutor != nil {
		for i := 0; i < enforceWorkers; i++ {
			go ce.enforceWorker(ctx)
		}
	}

	// Start async Rego evaluation worker pool. Pool size is max(2, NumCPU/2)
	// to avoid blocking the Ingest hot path while still bounding goroutine growth.
	if config.EnableRegoEval && config.RegoEngine != nil {
		regoWorkers := config.RegoWorkerCount
		if regoWorkers <= 0 {
			regoWorkers = runtime.NumCPU() / 2
			if regoWorkers < 2 {
				regoWorkers = 2
			}
		}
		for i := 0; i < regoWorkers; i++ {
			go ce.regoWorker(ctx)
		}
	}

	// Start PID-partitioned ingest worker pool.  Each worker gets an isolated
	// AnomalyDetector so ProcessEvent is never called concurrently for the same
	// detector instance.  Pool size is a power of 2 for O(1) bitmask routing.
	{
		n := config.IngestWorkerCount
		if n <= 0 {
			n = runtime.NumCPU()
			if n < 4 {
				n = 4
			}
			p := 1
			for p < n {
				p <<= 1
			}
			n = p
		}
		if n > 64 {
			n = 64
		}
		ce.ingestMask = uint32(n - 1)
		ce.ingestPool = make([]*workerState, n)

		// One shared BaselineLearner across all workers so the learning phase gates
		// on the aggregate event rate (total across all workers) rather than each
		// worker independently needing minSamples. With N workers and PID hashing,
		// each worker sees ~1/N of traffic; without sharing, N workers each need
		// minSamples before transitioning — effectively requiring N×minSamples total
		// events to exit the learning phase.
		//
		// ce.anomalyDetector (used by the single-goroutine Ingest path) is also
		// switched onto this same learner so learning-phase behavior is identical
		// regardless of whether a caller uses Ingest or IngestAsync — otherwise the
		// two paths would silently diverge (Ingest gating on its own solo sample
		// count instead of the aggregate).
		var sharedLearner *profiler.BaselineLearner
		if config.EnableAnomaly {
			sharedLearner = profiler.NewBaselineLearner(config.LearningPeriod, config.MinLearningSamples)
			if ce.anomalyDetector != nil {
				ce.anomalyDetector.SetSharedLearner(sharedLearner)
			}
		}

		ingestBufSize := config.IngestWorkerBufferSize
		if ingestBufSize <= 0 {
			ingestBufSize = 1024
		}

		for i := range ce.ingestPool {
			var workerAD *profiler.AnomalyDetector
			if config.EnableAnomaly {
				workerAD = profiler.NewAnomalyDetectorWithSamples(
					ctx,
					config.AnomalyThreshold,
					config.LearningPeriod,
					config.EWMAWeight,
					config.MinLearningSamples,
					config.ProfilerMaxPIDs,
				)
				workerAD.SetSharedLearner(sharedLearner)
			}
			ce.ingestPool[i] = &workerState{
				ch: make(chan *workerTask, ingestBufSize),
				ad: workerAD,
			}
		}
		for _, w := range ce.ingestPool {
			ce.ingestWg.Add(1)
			go ce.runIngestWorker(ctx, w)
		}
	}

	// Update the gauge periodically so it reflects the live state count.
	go ce.updateRLGaugeLoop(ctx)

	return ce
}

// updateRLGaugeLoop refreshes the ratelimiter states gauge, queue depth gauge,
// rego/enforce queue occupancy gauges, and cooldown/dedup entry gauges every
// 30 seconds. Triggers early eviction of expired cooldown and dedup entries at
// 80% capacity to prevent the maps from growing to the hard cap between ticks.
func (ce *CorrelationEngine) updateRLGaugeLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ce.rlStatesGauge.Set(float64(ce.rateLimiter.StateCount()))
			ce.queueDepthGauge.Set(ce.QueueDepth())

			cooldownSize := ce.cooldowns.Size()
			ce.cooldownEntriesGauge.Set(float64(cooldownSize))
			// High-water-mark early eviction at 80%: trigger cleanup immediately
			// instead of waiting for the next tick. Prevents the map from growing
			// to the hard cap between interval-based cleanup cycles.
			if cooldownSize >= int64(MaxCooldownEntries*4/5) {
				go ce.cooldowns.cleanup(time.Now().Add(-ce.enforceCooldown))
			}
			if cooldownSize >= int64(MaxCooldownEntries*9/10) {
				slog.Warn("correlator: cooldown map near capacity",
					"entries", cooldownSize, "limit", MaxCooldownEntries)
			}

			dedupSize := ce.dedup.Size()
			ce.dedupEntriesGauge.Set(float64(dedupSize))
			if dedupSize >= int64(MaxDedupEntries*4/5) {
				go ce.dedup.cleanup(time.Now().Add(-ce.dedupWindow))
			}
			if dedupSize >= int64(MaxDedupEntries*9/10) {
				slog.Warn("correlator: dedup map near capacity",
					"entries", dedupSize, "limit", MaxDedupEntries)
			}

			if ce.regoQueue != nil && ce.regoQueueGauge != nil {
				qLen := len(ce.regoQueue)
				qCap := cap(ce.regoQueue)
				ce.regoQueueGauge.Set(float64(qLen))
				if qCap > 0 && qLen >= qCap*9/10 {
					slog.Warn("correlator: rego queue near capacity",
						"occupancy", qLen, "capacity", qCap,
					)
				}
			}

			if ce.enforceQueue != nil && ce.enforceQueueGauge != nil {
				eLen := len(ce.enforceQueue)
				ce.enforceQueueGauge.Set(float64(eLen))
			}
		}
	}
}

// enforceWorker drains the enforcement queue and calls ExecuteAction for each task.
// It exits when ctx is cancelled and the queue is drained.
func (ce *CorrelationEngine) enforceWorker(ctx context.Context) {
	for {
		select {
		case task, ok := <-ce.enforceQueue:
			if !ok {
				return
			}
			if err := ce.actionExecutor.ExecuteAction(task.ctx, task.action, task.alert); err != nil {
				slog.Warn("correlator: rule enforcement failed",
					slog.String("rule_id", task.alert.RuleID),
					slog.String("action", task.action),
					slog.Uint64("pid", uint64(task.alert.PID)),
					slog.Any("err", err),
				)
			}
			task.cancel()
			ce.enforceWg.Done()
		case <-ctx.Done():
			return
		}
	}
}

// localFlushBatch is the per-worker buffer threshold before flushing to ce.pending.
// Small enough to bound memory, large enough to amortize the pendingMu lock cost
// across ~64 events rather than acquiring it per-event (P1-4).
const localFlushBatch = 64

// preAlertContextWindow is the number of recent per-PID events attached to each
// alert as PreAlertContext when EnableEventBuffer is true. 20 events covers roughly
// a 5–30 second attack window at typical event rates and is enough to reconstruct
// a kill chain (DNS→TCP→file write→execve) without blowing up alert size.
const preAlertContextWindow = 20

// localFlushInterval is the maximum time a worker holds alerts before flushing.
const localFlushInterval = 100 * time.Millisecond

// flushPending appends buf's contents to ce.pending under the central lock and
// resets buf. Must be called when len(*buf) > 0.
func (ce *CorrelationEngine) flushPending(buf *[]types.Alert) {
	if len(*buf) == 0 {
		return
	}
	ce.pendingMu.Lock()
	ce.pending = append(ce.pending, *buf...)
	ce.pendingMu.Unlock()
	*buf = (*buf)[:0]
}

// chainGroup resolves pid to the identity of the process chain it belongs to,
// for threshold rules with group_by: chain (5.8g). The identity is the root of
// the ancestry chain — the same anchor IncidentTracker.rootIdentity uses, so a
// burst counted here and an incident grouped there agree on what "one chain"
// means. Root PPID and comm are folded in for the same reason rootIdentity
// includes them: a recycled root PID must not silently continue an older
// chain's burst window.
//
// Returns false when no chain is known, which makes the caller fall back to
// the PID. Only rules that actually declare group_by: chain reach this, so the
// GetProcessTree lookup (a shard RLock plus a copy of the chain) stays off the
// path of every other rule.
func (ce *CorrelationEngine) chainGroup(pid uint32) (uint64, bool) {
	if ce.lineageTracker == nil {
		return 0, false
	}
	tree := ce.lineageTracker.GetProcessTree(pid)
	if len(tree) == 0 {
		return 0, false
	}
	root := tree[0]
	h := fnv.New64a()
	var buf [8]byte
	binary.LittleEndian.PutUint32(buf[0:4], root.PID)
	binary.LittleEndian.PutUint32(buf[4:8], root.PPID)
	_, _ = h.Write(buf[:])
	_, _ = h.Write([]byte(root.Comm))
	return h.Sum64(), true
}

// isSelfOrDescendant reports whether pid is the agent's own PID or a process
// forked from it, tracked via a growing set seeded from observed PPID values
// rather than a /proc ancestry walk (5.8e) — the agent rarely forks children,
// so the common case (pid == selfPID, e.g. the canary loop or the uprobe
// attacher reading /proc/<pid>/maps in-process) is a single map-free
// comparison, and the rare case (an actual child, e.g. during a self-upgrade)
// is discovered the first time that child's own PPID-carrying event arrives.
// Concurrency: called from multiple ingest workers; selfTree is a sync.Map so
// no external lock is needed, and a benign race where two workers both
// observe the same new child and both Store it is harmless (idempotent).
func (ce *CorrelationEngine) isSelfOrDescendant(pid, ppid uint32) bool {
	if pid == ce.selfPID {
		return true
	}
	if _, ok := ce.selfTree.Load(pid); ok {
		return true
	}
	if ppid == ce.selfPID {
		ce.selfTree.Store(pid, struct{}{})
		return true
	}
	if _, ok := ce.selfTree.Load(ppid); ok {
		ce.selfTree.Store(pid, struct{}{})
		return true
	}
	return false
}

// SetObserverRoot sets the PID of the measurement harness's process tree for
// the 5.9a observer-tree exclusion filter. Called live (not just at startup)
// because the harness (idle-run.sh) is launched separately from — and
// typically well after — the agent's own systemd service, so its PID isn't
// known at engine construction time. Passing 0 disables exclusion (nothing
// matches PID 0). Safe to call from any goroutine; ce.observerRootPID is an
// atomic.
func (ce *CorrelationEngine) SetObserverRoot(pid uint32) {
	if old := ce.observerRootPID.Swap(pid); old != pid {
		// The tree cache is only valid for the root it was grown from: PIDs
		// descended from a previous harness run must not stay excluded after
		// the root changes (or is cleared to 0) — a new unrelated process
		// reusing one of those PIDs would silently vanish from correlation.
		ce.observerTree.Range(func(k, _ any) bool {
			ce.observerTree.Delete(k)
			return true
		})
	}
}

// observerKernelFilteredType reports whether the in-kernel observer filter
// (5.9.2g) runs for events of this type, i.e. whether the BPF object that
// emits them calls observer_should_drop() before reserving the record.
//
// Kept next to SetObserverKernelSide so the two are read together: the flag
// says "the kernel side is live", this says "for which streams" — and only
// their conjunction may skip the userspace walk. Extend this list in the same
// commit that adds observer_should_drop() to another .bpf.c, never before.
func observerKernelFilteredType(t types.EventType) bool {
	switch t {
	case types.EventSyscall, // bpf/syscall.bpf.c (sys_enter, sys_exit)
		types.EventFileAccess,                      // bpf/fileaccess.bpf.c (open, read, write)
		types.EventTCPConnect, types.EventNetClose: // bpf/network.bpf.c (tcp_connect, tcp_close)
		return true
	default:
		return false
	}
}

// SetObserverKernelSide records whether the in-kernel observer filter (5.9.2g)
// is live. When it is, ProcessEvent skips the userspace ancestry walk entirely:
// the events that walk existed to discard never leave the kernel.
//
// Callers must only pass true after a successful write to observer_root_pid —
// not merely because the feature is enabled in config. Setting it optimistically
// would disable both filters at once if the BPF side failed to load, which is
// the silent-blindness failure mode this wave exists to remove.
func (ce *CorrelationEngine) SetObserverKernelSide(active bool) {
	if ce.observerKernelSide.Swap(active) != active {
		slog.Info("correlator: observer-tree exclusion moved",
			slog.String("filter", map[bool]string{true: "kernel (5.9.2g)", false: "userspace (5.9a)"}[active]))
	}
}

// RecordObserverExcludedN adds n to
// ebpf_guard_events_excluded_total{reason="observer_tree"} on behalf of the
// in-kernel filter, which counts its own drops in a BPF per-CPU array that
// userspace drains periodically.
//
// Callers pass the DELTA since their last read, never the cumulative BPF total:
// this is a Prometheus counter, and adding a cumulative value each tick would
// make the series grow quadratically.
func (ce *CorrelationEngine) RecordObserverExcludedN(n uint64) {
	if n == 0 {
		return
	}
	ce.eventsExcludedTotal.WithLabelValues("observer_tree").Add(float64(n))
}

// ObserverKernelSide reports whether the in-kernel observer filter is live, so
// /debug/state can show which of the two filters actually ran for a given run.
func (ce *CorrelationEngine) ObserverKernelSide() bool {
	return ce.observerKernelSide.Load()
}

// ObserverRoot returns the harness root PID currently set via SetObserverRoot
// (0 if unset), so callers like /debug/state (5.9.1a) can confirm the agent's
// 2s file poller has actually picked up a registration before the harness
// proceeds to generate events of its own.
func (ce *CorrelationEngine) ObserverRoot() uint32 {
	return ce.observerRootPID.Load()
}

// isObserverDescendant mirrors isSelfOrDescendant, but against the harness
// root PID set via SetObserverRoot instead of the agent's own PID, and (5.9.1a,
// находка №34) walks the full ancestor chain instead of one ppid hop. A
// one-hop check only catches a leaf whose immediate parent already had an
// event of its own tracked; it misses a leaf that fires its first event
// before that parent does, which is exactly the pattern short-lived processes
// forked straight off the harness (or off a shell the harness just forked)
// produce. Root 0 (not yet set) never matches, since PID 0 is not a real
// process PID.
func (ce *CorrelationEngine) isObserverDescendant(e types.Event) bool {
	root := ce.observerRootPID.Load()
	if root == 0 {
		return false
	}
	pid, ppid := e.PID, e.PPID
	if pid == root {
		return true
	}
	if _, ok := ce.observerTree.Load(pid); ok {
		return true
	}
	if ce.lineageTracker != nil {
		if tree := ce.lineageTracker.GetProcessTree(pid); len(tree) > 0 {
			for _, node := range tree {
				// node.PID == root fires when the chain was bootstrapped from
				// /proc far enough to include the root process itself.
				// node.PPID == root fires for the (common) case where the
				// oldest *tracked* ancestor's parent is root but root's own
				// PID never appears as a chain entry — the harness process
				// forks children without necessarily emitting BPF events of
				// its own, so it may never get a node in anyone's chain.
				if node.PID == root || node.PPID == root {
					ce.observerTree.Store(pid, struct{}{})
					return true
				}
				// 5.9.2d (находка №41): a chain that does not itself reach
				// root can still hang off a PID already known to be in the
				// tree. This used to `return false` here, skipping the memo
				// checks below entirely — so a short-lived pipeline leaf
				// (`… | awk`, `… | tee`, `$(date)`), whose chain is rebuilt
				// from /proc after the intervening shell already exited and
				// therefore breaks at the first unresolvable hop, escaped the
				// filter even though its parent was recorded. That was 7 of
				// the 41 idle-hour alerts on замер №2.9.1, and both of the
				// process_chain-less `grep` incidents that failed criterion 10.
				if _, ok := ce.observerTree.Load(node.PID); ok {
					ce.observerTree.Store(pid, struct{}{})
					return true
				}
			}
			// Fall through to the one-hop checks below rather than returning:
			// an unresolved-to-root chain is "don't know", not "not a member".
		}
	}
	// No lineage tracker, its ancestry for pid couldn't be resolved (disabled,
	// or both the event and /proc lacked ppid), or the chain resolved without
	// reaching root: fall back to the one-hop check rather than treating
	// "unresolved" as "not excluded".
	if ppid == root {
		ce.observerTree.Store(pid, struct{}{})
		return true
	}
	if _, ok := ce.observerTree.Load(ppid); ok {
		ce.observerTree.Store(pid, struct{}{})
		return true
	}
	return false
}

// regoWorker drains the async Rego evaluation queue. For each task it evaluates
// the alerts through OPA, applies analyst suppression, then accumulates enriched
// alerts in a local buffer flushed to pending periodically. Per-worker buffering
// replaces the central pendingMu per-task acquisition (P1-4).
func (ce *CorrelationEngine) regoWorker(ctx context.Context) {
	var localPending []types.Alert
	flushTicker := time.NewTicker(localFlushInterval)
	defer flushTicker.Stop()

	for {
		select {
		case task, ok := <-ce.regoQueue:
			if !ok {
				ce.flushPending(&localPending)
				return
			}
			enriched := ce.evaluateRegoPolicies(task.ctx, task.alerts)
			task.cancel()

			if ce.feedbackManager != nil && len(enriched) > 0 {
				before := len(enriched)
				enriched = ce.feedbackManager.FilterAlerts(enriched)
				// 5.9c: these alerts are already in alertsGenerated — count
				// the post-generation drop or the counter identity leaks.
				if dropped := before - len(enriched); dropped > 0 {
					ce.alertsSuppressedTotal.WithLabelValues("feedback").Add(float64(dropped))
				}
			}

			localPending = append(localPending, enriched...)
			if len(localPending) >= localFlushBatch {
				ce.flushPending(&localPending)
			}
			ce.regoWg.Done()
		case <-flushTicker.C:
			ce.flushPending(&localPending)
		case <-ctx.Done():
			ce.flushPending(&localPending)
			return
		}
	}
}

// checkDup reports whether (ruleID, pid, comm) was seen within the dedup window.
// Delegates to the sharded dedup map; does not record the key.
func (ce *CorrelationEngine) checkDup(ruleID string, pid uint32, comm string) bool {
	return ce.dedup.check(ruleID, pid, comm)
}

// recordDedupDrop counts one alert suppressed by dedup, both in aggregate and
// per rule (5.8b). Every dedup drop site must go through here — a site that
// increments only the aggregate reopens exactly the attribution gap that left
// finding №21 unresolved.
func (ce *CorrelationEngine) recordDedupDrop(ruleID string) {
	ce.alertsDedupDropped.Add(1)
	if ce.alertsDedupDroppedByRule != nil {
		ce.alertsDedupDroppedByRule.WithLabelValues(ruleID).Inc()
	}
}

// recordRateLimitDrop counts one alert suppressed by the per-rule rate
// limiter, broken down by rule (5.9.9.F.5n, №164). Every per-rule limiter
// drop site must go through here — the aggregate alertsDropped counter alone
// cannot distinguish "rule hit its 10/60s ceiling" from any other drop cause.
func (ce *CorrelationEngine) recordRateLimitDrop(ruleID string) {
	if ce.alertsRateLimitedByRule != nil {
		ce.alertsRateLimitedByRule.WithLabelValues(ruleID).Inc()
	}
}

// markDedup records that (ruleID, pid, comm) was emitted at now.
// Must be called only after the alert has passed all rate-limit checks.
// now should be captured once per Ingest call (before any lock is acquired).
func (ce *CorrelationEngine) markDedup(ruleID string, pid uint32, comm string, now time.Time) {
	ce.dedup.mark(ruleID, pid, comm, now)
}

// DrainEnforceQueue blocks until all submitted enforcement tasks have been
// processed by workers, or until ctx expires. Uses a WaitGroup instead of
// polling so there is no wakeup latency and no CPU burn while waiting.
func (ce *CorrelationEngine) DrainEnforceQueue(ctx context.Context) {
	done := make(chan struct{})
	go func() {
		ce.enforceWg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// Drain waits for all in-flight async Rego evaluations to complete so that
// every generated alert lands in the pending buffer before Flush is called.
// Returns ctx.Err() if the deadline expires before the queue is empty.
func (ce *CorrelationEngine) Drain(ctx context.Context) error {
	// Fast path: an already-expired context must always report its own error,
	// never a false "success". Without this check, an empty regoWg makes done
	// close near-instantly, racing ctx.Done() in the select below — both ready
	// at once is a coin flip, so a caller that cancels before calling Drain
	// could non-deterministically get a nil error.
	if err := ctx.Err(); err != nil {
		return err
	}
	done := make(chan struct{})
	go func() {
		ce.regoWg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// closeIngestChannels closes every ingest worker channel exactly once. Safe to
// call from both DrainIngestPool (a graceful-shutdown step that must run
// before the final Flush) and Close (final cleanup) without risking a
// double-close panic.
func (ce *CorrelationEngine) closeIngestChannels() {
	ce.closeIngestOnce.Do(func() {
		for _, w := range ce.ingestPool {
			close(w.ch)
		}
	})
}

// DrainIngestPool closes the PID-partitioned ingest worker channels and blocks
// until every worker has finished processing its already-queued events (and
// flushed any resulting alerts to pending), or until ctx expires.
//
// Production callers that dispatch events via IngestAsync must call this
// before the final Flush at shutdown: otherwise events already queued in a
// worker's channel when collectors stop would still be processed after the
// shutdown sequence's Flush+store step, and their alerts would never reach
// the store (Close, which used to be the only place this drain happened,
// runs after that step).
func (ce *CorrelationEngine) DrainIngestPool(ctx context.Context) {
	ce.closeIngestChannels()
	done := make(chan struct{})
	go func() {
		ce.ingestWg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		slog.Warn("correlator: DrainIngestPool timed out waiting for ingest workers")
	}
}

// Close stops background goroutines started by the engine and waits for graceful shutdown.
// It attempts to drain pending work with a 5-second timeout to prevent hangs.
// Returns without error even if workers don't finish within the timeout.
func (ce *CorrelationEngine) Close() {
	// Signal all background goroutines to stop via context cancellation.
	ce.cancelCleanup()

	// Use a separate context to avoid depending on the now-cancelled cleanup context.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	// Close the per-worker ingest channels (a no-op if DrainIngestPool already
	// did this) and wait for every ingest worker to drain and exit BEFORE
	// touching enforceQueue/regoQueue. An ingest worker mid-ingestWithAD can
	// still attempt `case ce.enforceQueue <- task:` (or regoQueue) via a
	// non-blocking select — sending on a closed channel panics even inside a
	// `select` with a `default` branch, so those queues must not be closed
	// while any ingest worker could still be running.
	ce.closeIngestChannels()
	ingestDone := make(chan struct{})
	go func() {
		ce.ingestWg.Wait()
		close(ingestDone)
	}()
	select {
	case <-ingestDone:
		// All ingest workers finished cleanly; safe to close downstream queues.
	case <-shutdownCtx.Done():
		// An ingest worker is still running and may still send to
		// enforceQueue/regoQueue. Leave those queues open rather than risk a
		// send-on-closed-channel panic; the process is shutting down anyway.
		slog.Warn("correlator: graceful shutdown timeout waiting for ingest workers; enforce/rego queues left open")
		return
	}

	// Now that no ingest worker is running, it is safe to close the downstream
	// queues and wait for their workers to finish.
	close(ce.enforceQueue)
	if ce.regoQueue != nil {
		close(ce.regoQueue)
	}

	done := make(chan struct{})
	go func() {
		ce.enforceWg.Wait()
		ce.regoWg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All workers finished cleanly
	case <-shutdownCtx.Done():
		// Timeout expired; workers may still be draining, but we proceed.
		// This is acceptable because channels are closed, so goroutines won't
		// deadlock indefinitely.
		slog.Warn("correlator: graceful shutdown timeout; some workers may still be running")
	}
}

// SetQueueDepthFn wires len/cap closures for the shared event channel so that
// QueueDepth() can report fill level without importing types or holding the channel.
// Called once from main after the event channel is created.
func (ce *CorrelationEngine) SetQueueDepthFn(lenFn, capFn func() int) {
	ce.queueDepthFn = lenFn
	ce.queueCapFn = capFn
}

// QueueDepth returns the current fill level of the shared event channel as a
// fraction in [0, 1]. Returns 0 if not wired (SetQueueDepthFn not called).
// Used by collectors in block strategy to implement adaptive backpressure.
func (ce *CorrelationEngine) QueueDepth() float64 {
	if ce.queueDepthFn == nil || ce.queueCapFn == nil {
		return 0
	}
	cap := ce.queueCapFn()
	if cap == 0 {
		return 0
	}
	return float64(ce.queueDepthFn()) / float64(cap)
}

// RegisterMetrics registers the engine's Prometheus metrics with the given registerer.
func (ce *CorrelationEngine) RegisterMetrics(reg prometheus.Registerer) error {
	for _, c := range []prometheus.Collector{
		ce.rlStatesGauge,
		ce.alertsDroppedGlobal,
		ce.queueDepthGauge,
		ce.latencyHistogram,
		ce.activeRulesGauge,
		ce.cooldownEntriesGauge,
		ce.dedupEntriesGauge,
		ce.enforceQueueDropped,
		ce.enforceQueueGauge,
		ce.enforcedCounter,
		ce.regoQueueDropped,
		ce.regoQueueGauge,
		ce.alertsDedupDropped,
		ce.alertsDedupDroppedByRule,
		ce.alertsRateLimitedByRule,
		ce.regoEvalErrors,
		ce.reloadTotal,
		ce.reloadDuration,
		ce.rulesActive,
		ce.lastReloadTimestamp,
		ce.selfExcludedEvents,
		ce.eventsExcludedTotal,
		ce.alertsSuppressedTotal,
	} {
		if c == nil {
			continue
		}
		if err := reg.Register(c); err != nil {
			return err
		}
	}
	return nil
}

// Ingest processes a single event synchronously and returns any alerts it
// produced. Safe to call from a single goroutine.
//
// Ingest is a convenience API for tests and single-threaded tools: it both
// returns the alerts AND buffers a copy into pending (mirroring IngestAsync's
// delivery mechanism), so Flush() also observes whatever Ingest produced.
// Production code must pick exactly one delivery path — dispatching the
// return value here AND separately draining Flush() double-delivers every
// alert. For production ingestion, use IngestAsync (which does not return
// alerts) together with a periodic Flush() to drain and dispatch pending.
func (ce *CorrelationEngine) Ingest(ctx context.Context, e types.Event) []types.Alert {
	alerts, regoQueued := ce.ingestWithAD(ctx, e, ce.anomalyDetector)
	if len(alerts) > 0 && !regoQueued {
		// Not rego-queued: the alerts aren't already headed to pending via the
		// regoWorker, so buffer them here as well so Flush() stays consistent
		// for callers relying on it (see doc comment above).
		ce.pendingMu.Lock()
		ce.pending = append(ce.pending, alerts...)
		ce.pendingMu.Unlock()
	}
	return alerts
}

// IngestAsync dispatches e to the PID-partitioned ingest worker for e.PID and
// returns without waiting for processing.  The same PID always maps to the same
// worker goroutine so each per-worker AnomalyDetector satisfies its
// single-goroutine call invariant.  Blocks under backpressure (when the worker
// channel is full) rather than dropping events; cancelled contexts abort the send.
func (ce *CorrelationEngine) IngestAsync(ctx context.Context, e types.Event) {
	if len(ce.ingestPool) == 0 {
		ce.Ingest(ctx, e)
		return
	}
	w := ce.ingestPool[e.PID&ce.ingestMask]
	t := workerTaskPool.Get().(*workerTask)
	t.ctx = ctx
	t.event = e
	select {
	case w.ch <- t:
	case <-ctx.Done():
		workerTaskPool.Put(t)
	}
}

// runIngestWorker drains one worker channel until ctx is cancelled.
// Accumulates alerts in a local buffer and flushes to ce.pending periodically,
// replacing the per-event pendingMu acquisition (P1-4).
func (ce *CorrelationEngine) runIngestWorker(ctx context.Context, w *workerState) {
	defer func() {
		// Release per-worker LRU profile memory promptly so it is not held until
		// the next GC cycle after the goroutine exits.
		if w.ad != nil {
			w.ad.FlushProfiles()
		}
		ce.ingestWg.Done()
	}()

	var localPending []types.Alert
	flushTicker := time.NewTicker(localFlushInterval)
	defer flushTicker.Stop()

	for {
		select {
		case task, ok := <-w.ch:
			if !ok {
				ce.flushPending(&localPending)
				return
			}
			tctx, ev := task.ctx, task.event
			workerTaskPool.Put(task)
			alerts, regoQueued := ce.ingestWithAD(tctx, ev, w.ad)
			if len(alerts) > 0 && !regoQueued {
				localPending = append(localPending, alerts...)
				if len(localPending) >= localFlushBatch {
					ce.flushPending(&localPending)
				}
			}
		case <-flushTicker.C:
			ce.flushPending(&localPending)
		case <-ctx.Done():
			ce.flushPending(&localPending)
			return
		}
	}
}

// ingestWithAD is the core event processing pipeline.  ad is the AnomalyDetector
// to use — nil disables anomaly scoring.  This indirection lets the PID-partitioned
// worker pool supply a per-worker detector without violating the single-goroutine
// call invariant.
//
// Returns (alerts, regoQueued). When regoQueued is true, the alerts have been
// dispatched to the async Rego evaluation queue; the caller MUST NOT buffer them
// locally because the regoWorker will publish enriched versions to pending.
func (ce *CorrelationEngine) ingestWithAD(ctx context.Context, e types.Event, ad *profiler.AnomalyDetector) ([]types.Alert, bool) {
	start := time.Now()

	// Open an OTel span only when the event carries APM trace context (extracted
	// by the TLS uprobe from HTTP/gRPC headers). Kernel-generated events (~99%
	// of traffic) have no TraceContext and skip span creation entirely, saving
	// the ~50-80 ns overhead of tracer.Start on every call.
	var span trace.Span
	if e.TraceContext != nil && e.TraceContext.TraceID != "" {
		spanOpts := []trace.SpanStartOption{
			trace.WithAttributes(
				attribute.Int("event.pid", int(e.PID)),
				attribute.Int("event.type", int(e.Type)),
				attribute.String("apm.trace_id", e.TraceContext.TraceID),
				attribute.String("apm.span_id", e.TraceContext.SpanID),
			),
		}
		if remoteCtx, err := buildRemoteSpanContext(e.TraceContext.TraceID, e.TraceContext.SpanID); err == nil {
			spanOpts = append(spanOpts, trace.WithLinks(trace.Link{
				SpanContext: remoteCtx,
				Attributes: []attribute.KeyValue{
					attribute.String("link.type", "apm_security_correlation"),
					attribute.String("link.trace_id", e.TraceContext.TraceID),
				},
			}))
		}
		ctx, span = tracer.Start(ctx, "CorrelationEngine.Ingest", spanOpts...)
		defer span.End()
	}

	// Record latency metric (always).
	defer func() {
		duration := time.Since(start).Seconds()
		ce.latencyHistogram.Observe(duration)
		if ce.onCorrelate != nil {
			ce.onCorrelate(duration)
		}
		if span != nil {
			span.SetAttributes(attribute.Float64("correlation.duration_seconds", duration))
		}
	}()

	ce.processedEvents.Add(1)

	// 5.8e (находка №18): drop events from the agent's own process tree before
	// they ever reach rule evaluation, rather than relying on a per-rule
	// "ebpf-guard-self" exception. The canary verification loop's own file
	// opens and the uprobe attacher's /proc/<pid>/maps reads both carry
	// e.PID == our own PID; per-rule exceptions on comm/path/pid remain in
	// the rule files as defense in depth (and as the mechanism protecting
	// against an impersonating binary when this filter is disabled), but
	// this is the single choke point that actually closes the 45%-of-idle-
	// noise finding regardless of which rule would otherwise have matched.
	if ce.selfExcludeEnabled && ce.isSelfOrDescendant(e.PID, e.PPID) {
		ce.selfExcludedEvents.Add(1)
		return nil, false
	}

	// 5.9a (находки №27/№28): drop events from the measurement harness's own
	// process tree the same way 5.8e drops the agent's own — the idle-run.sh
	// script and the curl/ps/grep/awk it forks otherwise supply 71% of
	// idle-hour alert volume, measuring the measurer instead of the agent.
	// Test-only: observerExcludeEnabled is false unless the deployment opts
	// in via correlator.observer_exclude.enabled (config-test.yaml).
	//
	// 5.9.1a (находка №34): isObserverDescendant needs pid's full ancestor
	// chain, not just its immediate ppid, so ancestry must be tracked BEFORE
	// the membership check runs — not after, as the one shared Track() call
	// below used to do. A short-lived leaf (e.g. curl reading /etc/passwd in
	// its first milliseconds) fires its very first — and often only — event
	// before its own parent ever gets its own tracked event; a one-hop
	// ppid==root check misses it, but a full walk (bootstrapped from /proc by
	// buildAncestry when the parent isn't cached yet) reaches the root
	// regardless of how many already-resolved or already-exited hops sit in
	// between. This second Track() call is a steady-state no-op (single shard
	// lock + comparison) for every PID whose ancestry the later call already
	// built, so the added cost is confined to observer-tree evaluation on
	// test-only deployments.
	//
	// 5.9.2g: when the in-kernel filter is live this block is skipped for the
	// event types that filter actually covers. The kernel decides membership
	// with one LRU lookup before the ring buffer, so such an event that gets
	// here is already known not to be in the harness tree — repeating the
	// lineage walk would cost a map lookup (and, on a miss, a /proc bootstrap)
	// per event to re-derive an answer we have. The counter is published from
	// the BPF per-CPU counter instead, on the same
	// ebpf_guard_events_excluded_total{reason="observer_tree"} series.
	//
	// The bypass is scoped BY EVENT TYPE, not global: observer_should_drop()
	// is compiled into three BPF objects only (syscall, fileaccess, network —
	// see bpf/common.h and the call sites in those .bpf.c files), while dns,
	// tls, lsm/kmod, privesc, iouring, gpu, bpfmonitor and http_uprobe emit
	// through their own objects with no such check. A global bypass therefore
	// turned OFF harness exclusion for those collectors the moment the kernel
	// side came up — the harness's own curl/dig traffic would re-enter the
	// "share of the observer tree" numerator through an uncovered collector,
	// which is the very quantity this wave is measured on.
	if ce.observerExcludeEnabled && !(ce.observerKernelSide.Load() && observerKernelFilteredType(e.Type)) {
		if ce.lineageTracker != nil {
			ce.lineageTracker.Track(e)
		}
		if ce.isObserverDescendant(e) {
			ce.eventsExcludedTotal.WithLabelValues("observer_tree").Add(1)
			return nil, false
		}
	}

	// Record the connection attempt exactly once per event, here rather than in
	// getFieldValue. The rule engine calls getFieldValue once per rule (and once
	// more per condition inside a condition group), so recording there counted a
	// single connection as many times as there are rules referencing
	// conn_rate_1m — inflating the rate and making the threshold depend on the
	// ruleset rather than on traffic. getFieldValue now only reads the count.
	if e.Type == types.EventTCPConnect && e.Network != nil {
		globalConnFrequency.Record(e.PID, e.Network.Dport, eventTime(e))
	}

	// Add event to per-process buffer. Gated: the buffer has no production
	// reader today, so by default we skip the shard lock + Event-struct copy on
	// every event. Enable via EnableEventBuffer when a consumer needs it.
	if ce.enableEventBuffer {
		ce.buffer.Add(e.PID, e)
	}

	// Update ancestry chain so every subsequent GetProcessTree call reflects
	// the most recent parent information available for this event's PID.
	ce.lineageTracker.Track(e)

	// Lazily compute the process tree the first time an alert actually needs it,
	// then share that result across all alerts generated by this event. The vast
	// majority of events produce no alert, so deferring the lineage read-lock and
	// slice allocation until first use keeps them off the no-alert hot path while
	// still acquiring the lock at most once per event under burst conditions.
	// ingestWithAD runs single-goroutine per call, so no synchronisation is needed.
	var (
		processTreeVal    types.ProcessTree
		processTreeCached bool
	)
	getProcessTree := func() types.ProcessTree {
		if !processTreeCached {
			processTreeVal = ce.lineageTracker.GetProcessTree(e.PID)
			processTreeCached = true
		}
		return processTreeVal
	}

	var alerts []types.Alert

	// Evaluate against rules via the zero-alloc callback path — no []Alert slice
	// is allocated regardless of match count.
	// Load the rule engine snapshot once to avoid nil pointer dereference if
	// hot-reload occurs between Load() and EvaluateInto() call.
	rulesSnapshot := ce.ruleEngine.Load()
	if rulesSnapshot != nil {
		rulesSnapshot.EvaluateInto(e, func(alert types.Alert) {
			// Drift-class matches (container/FIM drift, as opposed to threat
			// signatures) are routed through the baseline profiler instead of
			// alerting directly: it suppresses matches during the per-workload
			// learning window and matches against the learned baseline, only
			// letting through signatures never seen for this workload before.
			// nil profiler or a non-drift class alert pass through unchanged.
			if alert.Class == string(ClassDrift) && ce.driftBaselineProfiler != nil {
				if !ce.driftBaselineProfiler.ObserveRule(alert.RuleID, e, alert.DriftNovelWorkload) {
					return
				}
			}

			// Dedup check runs before rate-limiter so burst duplicates do not inflate
			// per-rule counters. isDup is checked, not a hard continue yet — enforcement
			// must still fire for deduped events (dedup suppresses alerts, not actions).
			isDup := ce.enableDedup && ce.checkDup(alert.RuleID, alert.PID, alert.Comm)

			if !isDup {
				// Per-rule rate limit check (only for non-deduped alerts).
				if !ce.rateLimiter.Allow(alert.RuleID) {
					ce.recordRateLimitDrop(alert.RuleID)
					ce.alertsDropped.Add(1)
					return
				}
				// Global token-bucket rate limit.
				if ce.globalLimiterEnabled && !ce.globalLimiter.Allow() {
					ce.alertsDropped.Add(1)
					ce.alertsDroppedGlobal.Add(1)
					return
				}
			}

			// Append monotonic sequence number to guarantee uniqueness across
			// concurrent alerts that share ruleID+timestamp+pid.
			seq := ce.alertSeq.Add(1)
			alert.ID = buildAlertID(alert.RuleID, e.Timestamp, e.PID, seq)

			// Propagate trace context to the alert for APM correlation.
			// Prefer the TLS-uprobe-extracted header context; fall back to /proc environ.
			if e.TraceContext != nil {
				alert.TraceID = e.TraceContext.TraceID
				alert.SpanID = e.TraceContext.SpanID
				tc := *e.TraceContext
				tc.Source = "tls_header"
				alert.TraceContext = &tc
			} else if tc := ce.traceCtxCache.lookup(e.PID, start); tc != nil {
				alert.TraceID = tc.TraceID
				alert.SpanID = tc.SpanID
				alert.TraceContext = tc
			}

			// Carry Kubernetes enrichment from the event onto the alert.
			if e.Enrichment != nil {
				alert.Enrichment = *e.Enrichment
			}

			// Attach full process tree for SOC triage.
			alert.ProcessTree = getProcessTree()

			// Attach the most-recent pre-alert events for this PID when the per-PID
			// buffer is enabled. The current event is already in the buffer (added at
			// the top of ingestWithAD), so GetRecent returns the temporal context
			// leading up to and including the trigger event — the attack kill chain.
			if ce.enableEventBuffer {
				alert.PreAlertContext = ce.buffer.GetRecent(e.PID, preAlertContextWindow)
			}

			// Rule-based enforcement runs regardless of dedup: the action cooldown
			// is the sole gate against enforcement spam, not the alert dedup window.
			if ce.actionExecutor != nil && isEnforcedAction(alert.Action) {
				if ce.tryAcquireEnforceCooldown(alert.RuleID, alert.PID, start) {
					alert.Enforced = true
					ce.enforcedCounter.Inc()
					// Detach from the per-request span context: the parent span ends
					// when Ingest() returns, which may be before the worker runs.
					// WithoutCancel preserves OTel baggage; the 30 s timeout prevents
					// a hung enforcer from blocking a worker indefinitely.
					enfCtx, enfCancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
					task := enforceTask{ctx: enfCtx, cancel: enfCancel, action: alert.Action, alert: alert}
					ce.enforceWg.Add(1)
					select {
					case ce.enforceQueue <- task:
					default:
						// Queue full: drop this enforcement action and record the drop.
						ce.enforceWg.Done()
						enfCancel()
						ce.enforceQueueDropped.Add(1)
					}
				}
			}

			if isDup {
				ce.recordDedupDrop(alert.RuleID)
				ce.alertsDropped.Add(1)
				return
			}

			// Alert passed all filters — record in dedup window and emit.
			if ce.enableDedup {
				ce.markDedup(alert.RuleID, alert.PID, alert.Comm, start)
			}
			alerts = append(alerts, alert)
			ce.alertsGenerated.Add(1)
		})
	}

	// WASM plugin evaluation — run custom detection plugins.
	if ce.wasmEngine != nil {
		wasmAlerts := ce.wasmEngine.Evaluate(ctx, e)
		for _, alert := range wasmAlerts {
			if ce.enableDedup && ce.checkDup(alert.RuleID, alert.PID, alert.Comm) {
				ce.recordDedupDrop(alert.RuleID)
				ce.alertsDropped.Add(1)
				continue
			}
			if !ce.rateLimiter.Allow(alert.RuleID) {
				ce.recordRateLimitDrop(alert.RuleID)
				ce.alertsDropped.Add(1)
				continue
			}
			if ce.globalLimiterEnabled && !ce.globalLimiter.Allow() {
				ce.alertsDropped.Add(1)
				ce.alertsDroppedGlobal.Add(1)
				continue
			}
			if ce.enableDedup {
				ce.markDedup(alert.RuleID, alert.PID, alert.Comm, start)
			}
			seq := ce.alertSeq.Add(1)
			alert.ID = buildAlertID(alert.RuleID, e.Timestamp, e.PID, seq)
			alert.ProcessTree = getProcessTree()
			if ce.enableEventBuffer {
				alert.PreAlertContext = ce.buffer.GetRecent(e.PID, preAlertContextWindow)
			}
			alerts = append(alerts, alert)
			ce.alertsGenerated.Add(1)
		}
	}

	// Gossip IOC matching — check event against cluster-wide indicators.
	if ce.iocMatcher != nil {
		if iocAlert := ce.checkIOCMatch(e); iocAlert != nil {
			iocAlert.ProcessTree = getProcessTree()
			if ce.enableEventBuffer {
				iocAlert.PreAlertContext = ce.buffer.GetRecent(e.PID, preAlertContextWindow)
			}
			if ce.enableDedup && ce.checkDup(iocAlert.RuleID, iocAlert.PID, iocAlert.Comm) {
				ce.recordDedupDrop(iocAlert.RuleID)
				ce.alertsDropped.Add(1)
			} else {
				perRuleOK := ce.rateLimiter.Allow(iocAlert.RuleID)
				globalOK := !ce.globalLimiterEnabled || ce.globalLimiter.Allow()
				if perRuleOK && globalOK {
					if ce.enableDedup {
						ce.markDedup(iocAlert.RuleID, iocAlert.PID, iocAlert.Comm, start)
					}
					alerts = append(alerts, *iocAlert)
					ce.alertsGenerated.Add(1)
				} else {
					ce.alertsDropped.Add(1)
					if !perRuleOK {
						ce.recordRateLimitDrop(iocAlert.RuleID)
					}
					if !globalOK {
						ce.alertsDroppedGlobal.Add(1)
					}
				}
			}
		}
	}

	// Anomaly detection (if enabled and learning complete).
	// ruleConfirmed=true suppresses EWMA baseline updates for events that
	// rule/WASM/IOC detectors already confirmed as malicious.
	if ce.enableAnomaly && ad != nil {
		ruleConfirmed := len(alerts) > 0
		if result := ad.ProcessEvent(e, ruleConfirmed); result != nil {
			// Always report the score (even non-anomalous) so the cardinality-guarded
			// Prometheus gauge tracks all active processes, not only anomaly triggers.
			if ce.scoreReporter != nil {
				ce.scoreReporter(strconv.FormatUint(uint64(e.PID), 10), util.InternBytes(e.Comm[:]), result.Score)
			}

			// Cross-node amplification (Feature F): if a peer node fired a critical
			// alert in the same namespace, we lower the effective anomaly threshold
			// so related lateral-movement activity is caught at a lower score.
			isAnomaly := result.IsAnomaly
			if !isAnomaly && ce.sensitivityAdjuster != nil &&
				e.Enrichment != nil && e.Enrichment.Namespace != "" {
				multiplier := ce.sensitivityAdjuster.GetThresholdMultiplier(e.Enrichment.Namespace)
				if multiplier < 1.0 && result.Score >= ce.baseAnomalyThreshold*multiplier {
					isAnomaly = true
				}
			}

			if isAnomaly {
				details := getDetailsMap()
				if result.Namespace != "" {
					details["namespace"] = result.Namespace
				}
				if result.AppLabel != "" {
					details["app_label"] = result.AppLabel
				}

				// Create anomaly alert
				anomalyAlert := types.Alert{
					ID:        buildAlertID("anomaly", e.Timestamp, e.PID, ce.alertSeq.Add(1)),
					Timestamp: time.Unix(0, int64(e.Timestamp)),
					RuleID:    "anomaly_detection",
					RuleName:  "Behavioral Anomaly Detected",
					Message:   formatAnomalyDescription(result),
					Severity:  types.SeverityWarning,
					PID:       e.PID,
					Comm:      util.InternBytes(e.Comm[:]),
					Details:   details,
					Event:     e,
				}

				// Propagate trace context to anomaly alert for APM correlation.
				if e.TraceContext != nil {
					anomalyAlert.TraceID = e.TraceContext.TraceID
					anomalyAlert.SpanID = e.TraceContext.SpanID
					tc := *e.TraceContext
					tc.Source = "tls_header"
					anomalyAlert.TraceContext = &tc
				} else if tc := ce.traceCtxCache.lookup(e.PID, start); tc != nil {
					anomalyAlert.TraceID = tc.TraceID
					anomalyAlert.SpanID = tc.SpanID
					anomalyAlert.TraceContext = tc
				}

				// Carry Kubernetes enrichment from the event onto the alert.
				if e.Enrichment != nil {
					anomalyAlert.Enrichment = *e.Enrichment
				}

				// Attach full process tree for SOC triage.
				anomalyAlert.ProcessTree = getProcessTree()
				if ce.enableEventBuffer {
					anomalyAlert.PreAlertContext = ce.buffer.GetRecent(e.PID, preAlertContextWindow)
				}

				// Dedup check before rate-limiter (same ordering as rule/WASM/IOC paths).
				if ce.enableDedup && ce.checkDup(anomalyAlert.RuleID, anomalyAlert.PID, anomalyAlert.Comm) {
					ce.recordDedupDrop(anomalyAlert.RuleID)
					ce.alertsDropped.Add(1)
				} else {
					perRuleOK := ce.rateLimiter.Allow(anomalyAlert.RuleID)
					globalOK := !ce.globalLimiterEnabled || ce.globalLimiter.Allow()
					if perRuleOK && globalOK {
						if ce.enableDedup {
							ce.markDedup(anomalyAlert.RuleID, anomalyAlert.PID, anomalyAlert.Comm, start)
						}
						alerts = append(alerts, anomalyAlert)
						ce.alertsGenerated.Add(1)
						// 1.75b: bump the detector's workload-profile AlertCount in
						// lock-step with the published-anomaly path. main.go will
						// call exporter.RecordAnomaly for the Prometheus counter on
						// dispatch; without this mirror write /debug/state's
						// anomalies_total (summed via AlertTotal/CountAlertTotal)
						// stays at zero while /metrics climbs — the exact
						// divergence seen in замер №1 (46 vs 0). Doing it here,
						// post-dedup/rate-limit, keeps the two counts equal by
						// construction rather than only when nothing was dropped.
						ad.RecordPublishedAnomaly(e)
					} else {
						ce.alertsDropped.Add(1)
						if !perRuleOK {
							ce.recordRateLimitDrop(anomalyAlert.RuleID)
						}
						if !globalOK {
							ce.alertsDroppedGlobal.Add(1)
						}
					}
				}
			}

			// All uses of result (score reporter, isAnomaly derivation, alert
			// fields copied by value above) are complete; return it to the pool
			// so the next ProcessEvent call can reuse its backing memory.
			profiler.ReleaseResult(result)
		}
	}

	// Syscall allowlist enforcement: record event during learning, check in enforcing.
	// Record runs unconditionally so the profile accumulates even while other
	// detectors are active; Check returns nil during the learning phase.
	if ce.allowlistProfiler != nil && e.Type == types.EventSyscall {
		ce.allowlistProfiler.Record(e)
		if v := ce.allowlistProfiler.Check(e); v != nil {
			msg := fmt.Sprintf("Unknown syscall %d not in learned allowlist for workload %s", v.SyscallNr, v.WorkloadKey.String())
			if v.Source == "global_deny" {
				msg = fmt.Sprintf("Syscall %d matches global deny list for workload %s", v.SyscallNr, v.WorkloadKey.String())
			}
			details := getDetailsMap()
			details["syscall_nr"] = v.SyscallNr
			details["source"] = v.Source
			details["workload"] = v.WorkloadKey.String()
			details["action"] = string(v.Action)
			seq := ce.alertSeq.Add(1)
			var allowlistPreCtx []types.Event
			if ce.enableEventBuffer {
				allowlistPreCtx = ce.buffer.GetRecent(e.PID, preAlertContextWindow)
			}
			allowlistAlert := types.Alert{
				ID:              buildAlertID("auto_allowlist_violation", e.Timestamp, e.PID, seq),
				Timestamp:       time.Unix(0, int64(e.Timestamp)), /* #nosec G115 -- nanosecond unix timestamp; int64 safe until year 2262 */
				RuleID:          "auto_allowlist_violation",
				RuleName:        "Syscall Allowlist Violation",
				Message:         msg,
				Severity:        types.SeverityWarning,
				PID:             e.PID,
				Comm:            util.InternBytes(e.Comm[:]),
				Details:         details,
				Event:           e,
				ProcessTree:     getProcessTree(),
				Action:          string(v.Action),
				PreAlertContext: allowlistPreCtx,
			}
			if e.Enrichment != nil {
				allowlistAlert.Enrichment = *e.Enrichment
			}
			if ce.enableDedup && ce.checkDup(allowlistAlert.RuleID, allowlistAlert.PID, allowlistAlert.Comm) {
				ce.recordDedupDrop(allowlistAlert.RuleID)
				ce.alertsDropped.Add(1)
			} else {
				perRuleOK := ce.rateLimiter.Allow(allowlistAlert.RuleID)
				globalOK := !ce.globalLimiterEnabled || ce.globalLimiter.Allow()
				if perRuleOK && globalOK {
					if ce.enableDedup {
						ce.markDedup(allowlistAlert.RuleID, allowlistAlert.PID, allowlistAlert.Comm, start)
					}
					alerts = append(alerts, allowlistAlert)
					ce.alertsGenerated.Add(1)
				} else {
					ce.alertsDropped.Add(1)
					if !perRuleOK {
						ce.recordRateLimitDrop(allowlistAlert.RuleID)
					}
					if !globalOK {
						ce.alertsDroppedGlobal.Add(1)
					}
				}
			}
		}
	}

	// Update span with alert count
	if span != nil {
		span.SetAttributes(attribute.Int("alerts.generated", len(alerts)))
	}

	// Rego policy evaluation (post-YAML filter, Sprint 23.0).
	// Dispatched to the async worker pool so Ingest returns without blocking on
	// OPA. The enriched alerts (with MITRE enrichment) land in pending via the
	// regoWorker; feedback filtering also happens there after enrichment.
	if ce.enableRegoEval && ce.regoEngine != nil && len(alerts) > 0 {
		regoCtx, regoCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		task := regoTask{ctx: regoCtx, cancel: regoCancel, alerts: alerts}
		ce.regoWg.Add(1)
		select {
		case ce.regoQueue <- task:
			// Submitted successfully — regoWorker enriches and appends to pending.
			// Return regoQueued=true so callers do NOT double-buffer (P1-4).
			return alerts, true
		default:
			// Queue full — drop the Rego evaluation rather than blocking the
			// event-processing goroutine with synchronous OPA eval (P1-5).
			// Alerts pass through without MITRE enrichment; the regoQueueDropped
			// metric signals operators to increase RegoWorkerCount or RegoQueueSize.
			ce.regoWg.Done()
			regoCancel()
			ce.regoQueueDropped.Add(1)
			// Fall through — alerts are returned to caller for direct buffering.
		}
	}

	// Analyst false-positive suppression: drop alerts whose (ruleID, comm) pair
	// has been marked as a false positive via POST /api/v1/alerts/{id}/feedback.
	if ce.feedbackManager != nil && len(alerts) > 0 {
		before := len(alerts)
		alerts = ce.feedbackManager.FilterAlerts(alerts)
		// 5.9c: post-generation drop — see alertsSuppressedTotal field doc.
		if dropped := before - len(alerts); dropped > 0 {
			ce.alertsSuppressedTotal.WithLabelValues("feedback").Add(float64(dropped))
		}
	}

	// Group alerts into incidents.
	for i := range alerts {
		ce.incidentTracker.Add(alerts[i])
	}

	// Return alerts to caller for per-worker buffered flush (P1-4).
	// The central pendingMu is acquired once per localFlushBatch alerts
	// instead of once per event/alert.
	return alerts, false
}

// evaluateRegoPolicies evaluates alerts against Rego policies.
// This is called post-YAML filter to minimize OPA evaluation overhead.
func (ce *CorrelationEngine) evaluateRegoPolicies(ctx context.Context, alerts []types.Alert) []types.Alert {
	enhancedAlerts := make([]types.Alert, 0, len(alerts))

	for _, alert := range alerts {
		// DNS pre-filter: skip Rego for benign DNS events (issue #69).
		// ShouldEvaluate covers every dns.rego rule in Go (~1.5 µs, 0 allocs for
		// cached domains) so no rule can fire on an event we bypass here.
		if alert.Event.Type == types.EventDNS && alert.Event.DNS != nil {
			comm := util.InternBytes(alert.Event.Comm[:])
			if !ce.dnsPrefilter.ShouldEvaluate(alert.Event.DNS, comm) {
				enhancedAlerts = append(enhancedAlerts, alert)
				continue
			}
		}

		// Evaluate alert against Rego policies
		decisions, err := ce.regoEngine.Evaluate(ctx, alert)
		if err != nil {
			// Alert passes through without MITRE enrichment; error is observable via metric.
			if ce.regoEvalErrors != nil {
				ce.regoEvalErrors.Add(1)
			}
			enhancedAlerts = append(enhancedAlerts, alert)
			continue
		}

		if len(decisions) == 0 {
			// No Rego decisions, keep original alert
			enhancedAlerts = append(enhancedAlerts, alert)
			continue
		}

		// Apply the most severe decision
		// In production, you might want to aggregate all decisions
		decision := selectMostSevereDecision(decisions)

		// Enhance alert with Rego decision
		enhancedAlert := alert
		enhancedAlert.RuleID = decision.RuleID
		if decision.Severity != "" {
			enhancedAlert.Severity = decision.Severity
		}
		if decision.Message != "" {
			enhancedAlert.Message = decision.Message
		}
		if enhancedAlert.Details == nil {
			enhancedAlert.Details = getDetailsMap()
		}
		enhancedAlert.Details["rego_action"] = decision.Action
		enhancedAlert.Details["mitre_technique"] = decision.MitreTechnique

		enhancedAlerts = append(enhancedAlerts, enhancedAlert)
	}

	return enhancedAlerts
}

// selectMostSevereDecision selects the most severe decision from a list.
func selectMostSevereDecision(decisions []policy.PolicyDecision) policy.PolicyDecision {
	if len(decisions) == 0 {
		return policy.PolicyDecision{}
	}

	if len(decisions) == 1 {
		return decisions[0]
	}

	// Priority: critical > warning > info. Ranked rather than a critical-only
	// scan so a warning decision still wins over an info one — without this,
	// the winner between those two was decided by rule order.
	best := decisions[0]
	bestRank := types.SeverityRank(best.Severity)
	for _, d := range decisions[1:] {
		if r := types.SeverityRank(d.Severity); r > bestRank {
			best, bestRank = d, r
		}
	}

	return best
}

// Flush returns and resets pending alerts. Production callers using
// IngestAsync must call this periodically (and dispatch the result) rather
// than only at shutdown — pending grows for the lifetime of the engine
// otherwise, since nothing else drains it.
func (ce *CorrelationEngine) Flush() []types.Alert {
	ce.pendingMu.Lock()
	defer ce.pendingMu.Unlock()
	alerts := ce.pending
	ce.pending = make([]types.Alert, 0)
	return alerts
}

// GetBuffer returns the event buffer (for testing).
func (ce *CorrelationEngine) GetBuffer() *ShardedEventBuffer {
	return ce.buffer
}

// GetEvents returns all buffered events for a PID.
func (ce *CorrelationEngine) GetEvents(pid uint32) []types.Event {
	return ce.buffer.Get(pid)
}

// GetAnomalyDetector returns the anomaly detector (may be nil).
func (ce *CorrelationEngine) GetAnomalyDetector() *profiler.AnomalyDetector {
	return ce.anomalyDetector
}

// TrackedPIDCount returns the total number of workload profiles tracked across
// all per-worker anomaly detectors and the engine-level detector.
func (ce *CorrelationEngine) TrackedPIDCount() int {
	var total int
	for _, w := range ce.ingestPool {
		if w != nil && w.ad != nil {
			if wpm := w.ad.GetProfileManager(); wpm != nil {
				total += wpm.Len()
			}
		}
	}
	if ce.anomalyDetector != nil {
		if wpm := ce.anomalyDetector.GetProfileManager(); wpm != nil {
			total += wpm.Len()
		}
	}
	return total
}

// anomalyDetectors returns every live AnomalyDetector the engine routes events
// through: the single-goroutine detector (used by Ingest) plus each per-worker
// detector in the ingest pool (used by IngestAsync). Nil detectors are skipped.
//
// This is the engine-level view that persistence (P0-3) and the /debug/state
// profiler provider (P1-10) must aggregate over: run #4 shipped
// profiler_stats=0/0/0/0 and a 174-byte state file because both walked only the
// solo detector in main.go while the real profiles lived in the pool. Question
// 7 in plan.md closes this as one shared root.
func (ce *CorrelationEngine) anomalyDetectors() []*profiler.AnomalyDetector {
	out := make([]*profiler.AnomalyDetector, 0, len(ce.ingestPool)+1)
	if ce.anomalyDetector != nil {
		out = append(out, ce.anomalyDetector)
	}
	for _, w := range ce.ingestPool {
		if w != nil && w.ad != nil {
			out = append(out, w.ad)
		}
	}
	return out
}

// SaveState persists the combined learned state of every anomaly detector the
// engine routes events through (solo detector + ingest pool) to path.
//
// P0-3: main.go previously called SaveState/LoadState on main.go's standalone
// *profiler.Profiler, whose detector never receives events once anomaly
// detection is enabled — IngestAsync routes exclusively through
// ce.anomalyDetectors() (see that method's comment). Persistence therefore
// saved an always-empty detector and restored into one nothing read from,
// making state_persistence a complete no-op end to end despite reporting
// success via ebpf_guard_profiler_state_restored. Callers must use this
// method (and LoadState below) instead.
func (ce *CorrelationEngine) SaveState(path string) error {
	return profiler.SaveDetectorsState(ce.anomalyDetectors(), path)
}

// LoadState restores previously saved combined anomaly-detector state into
// every detector the engine routes events through. See SaveState and
// anomalyDetectors for why this must run after the ingest pool (and its
// shared BaselineLearner) is constructed — call it only on an already-built
// *CorrelationEngine, never on the standalone *profiler.Profiler.
func (ce *CorrelationEngine) LoadState(path string, learningPeriod time.Duration) (bool, error) {
	return profiler.LoadDetectorsState(ce.anomalyDetectors(), path, learningPeriod)
}

// ProfilerStats aggregates profiler statistics across every anomaly detector in
// the engine (solo + ingest pool). Learning phase is sourced from the shared
// BaselineLearner that every detector was switched onto at construction
// (engine.go:801-806), so IsLearningComplete / LearningProgress /
// LearningSampleCount are already aggregate — we reuse the solo detector's view
// for those three. ProfilesActive and AnomaliesTotal are summed across every
// detector's WorkloadProfileManager because each worker owns an independent
// profile set (events are sharded by PID hash).
//
// This is the P1-10 fix: /debug/state's profiler_stats must agree with /metrics
// at request time, which requires walking the pool, not main.go's solo
// *profiler.Profiler (which receives no events under IngestAsync).
func (ce *CorrelationEngine) ProfilerStats() profiler.ProfilerStats {
	// Learning-phase fields: the shared learner makes these identical across
	// detectors, so any live detector gives the authoritative value. Fall back
	// to "learning complete" only when anomaly detection is disabled (no
	// detector configured), matching the existing IsLearningComplete() contract.
	var (
		learningComplete bool    = true
		learningProgress float64 = 1.0
		sampleCount      uint64
		profilesActive   int
		anomaliesTotal   uint64
		haveDetector     bool
	)
	// ProfilesActive counts DISTINCT workloads, not per-detector profile slots.
	// A plain sum double-counts after a restart: LoadDetectorsState broadcasts
	// the same restored baseline into every detector, so one saved workload
	// would report as len(detectors) live ones. Deduplicating by WorkloadKey
	// keeps the number meaning "how many workloads is the profiler tracking",
	// which is what /debug/state consumers read it as. AnomaliesTotal stays a
	// plain sum: each detector tallies only the anomalies it published, and
	// persistence deliberately restores that tally into a single detector.
	seenWorkloads := make(map[profiler.WorkloadKey]struct{})
	for _, ad := range ce.anomalyDetectors() {
		haveDetector = true
		if wpm := ad.GetProfileManager(); wpm != nil {
			for _, k := range wpm.Keys() {
				seenWorkloads[k] = struct{}{}
			}
		}
		anomaliesTotal += ad.AlertTotal()
	}
	profilesActive = len(seenWorkloads)
	if ce.anomalyDetector != nil {
		learningComplete = ce.anomalyDetector.IsLearningComplete()
		learningProgress = ce.anomalyDetector.LearningProgress()
		sampleCount = ce.anomalyDetector.GetSampleCount()
	} else if !haveDetector {
		// No detector configured at all — learning is trivially "complete".
		learningComplete = true
		learningProgress = 1.0
	}
	return profiler.ProfilerStats{
		LearningComplete:    learningComplete,
		LearningProgress:    learningProgress,
		ProfilesActive:      profilesActive,
		AnomaliesTotal:      anomaliesTotal,
		LearningSampleCount: sampleCount,
	}
}

// IsLearningComplete checks if anomaly detection learning is complete.
func (ce *CorrelationEngine) IsLearningComplete() bool {
	if ce.anomalyDetector == nil {
		return true // No learning needed
	}
	return ce.anomalyDetector.IsLearningComplete()
}

// LearningProgress returns the progress of anomaly detection learning (0.0-1.0).
func (ce *CorrelationEngine) LearningProgress() float64 {
	if ce.anomalyDetector == nil {
		return 1.0
	}
	return ce.anomalyDetector.LearningProgress()
}

// LearningTimeRemaining returns the time remaining in the anomaly detection
// learning phase. Zero once learning is complete or no detector is configured.
func (ce *CorrelationEngine) LearningTimeRemaining() time.Duration {
	if ce.anomalyDetector == nil {
		return 0
	}
	return ce.anomalyDetector.TimeRemaining()
}

// LearningSampleCount returns the number of samples recorded during the
// anomaly detection learning phase.
func (ce *CorrelationEngine) LearningSampleCount() uint64 {
	if ce.anomalyDetector == nil {
		return 0
	}
	return ce.anomalyDetector.GetSampleCount()
}

// GetRateLimiter returns the rate limiter.
func (ce *CorrelationEngine) GetRateLimiter() *RateLimiter {
	return ce.rateLimiter
}

// GetStats returns engine statistics.
func (ce *CorrelationEngine) GetStats() EngineStats {
	return EngineStats{
		ProcessedEvents: ce.processedEvents.Load(),
		AlertsGenerated: ce.alertsGenerated.Load(),
		AlertsDropped:   ce.alertsDropped.Load(),
		BufferedPIDs:    ce.buffer.Count(),
	}
}

// EngineStats holds correlation engine statistics.
type EngineStats struct {
	ProcessedEvents uint64
	AlertsGenerated uint64
	AlertsDropped   uint64
	BufferedPIDs    int
}

// SetSyscallFilterUpdater registers a callback that is invoked with the updated
// BPF syscall allowlist whenever rules are loaded or hot-reloaded.
// The callback is called synchronously from UpdateRules so implementations
// should be fast (a BPF map batch write takes ~50 µs).
// Pass nil to disable the hook.
func (ce *CorrelationEngine) SetSyscallFilterUpdater(fn func(nrs []uint32)) {
	ce.syscallFilterFn = fn
}

// SetSamplingCorrections propagates per-event-type inverse sampling factors
// (1.0 / bpfSamplingRate) to every AnomalyDetector in the engine — both the
// top-level detector (used by Ingest) and each per-worker detector (used by
// IngestAsync). Call this whenever the ring-buffer adaptive load controller
// changes its sampling rates so EWMA baselines stay unbiased.
func (ce *CorrelationEngine) SetSamplingCorrections(corrections map[string]float64) {
	if ce.anomalyDetector != nil {
		ce.anomalyDetector.SetSamplingCorrections(corrections)
	}
	for _, w := range ce.ingestPool {
		if w != nil && w.ad != nil {
			w.ad.SetSamplingCorrections(corrections)
		}
	}
}

// eventTypeLabel maps EventType constants to their canonical Prometheus label strings.
var eventTypeLabel = map[types.EventType]string{
	types.EventSyscall:    "syscall",
	types.EventTCPConnect: "network",
	types.EventFileAccess: "file",
	types.EventTLS:        "tls",
	types.EventDNS:        "dns",
	types.EventPrivesc:    "privesc",
	types.EventNetClose:   "net_close",
	types.EventKmodLoad:   "kmod",
	types.EventCgroupEsc:  "cgroup_esc",
	types.EventGPU:        "gpu",
	types.EventLSMAudit:   "lsm_audit",
	types.EventSequence:   "sequence",
	types.EventCloudAudit: "cloud",
}

// UpdateRules updates the rule engine with new rules.
// Compiled regex/CIDR/set entries from the previous engine are inherited so
// patterns that appear in both old and new rule sets are not recompiled.
// If a SyscallFilterUpdater is registered it is called with the new rule set's
// referenced syscall numbers so BPF-side pre-filtering stays in sync.
func (ce *CorrelationEngine) UpdateRules(rules []Rule) {
	prior := ce.ruleEngine.Load()

	t0 := time.Now()
	re := NewRuleEngineWithCache(rules, prior)
	if ce.reloadDuration != nil {
		ce.reloadDuration.WithLabelValues("rego_compile").Set(time.Since(t0).Seconds())
	}

	re.SetChainGroupResolver(ce.chainGroup)

	t1 := time.Now()
	ce.ruleEngine.Store(re)
	if ce.reloadDuration != nil {
		ce.reloadDuration.WithLabelValues("rule_engine_swap").Set(time.Since(t1).Seconds())
	}

	ce.activeRulesGauge.Set(float64(len(rules)))

	if ce.rulesActive != nil {
		for _, label := range eventTypeLabel {
			ce.rulesActive.WithLabelValues(label).Set(0)
		}
		for evType, evRules := range re.byType {
			if label, ok := eventTypeLabel[types.EventType(evType)]; ok {
				ce.rulesActive.WithLabelValues(label).Set(float64(len(evRules)))
			}
		}
	}

	if ce.reloadTotal != nil {
		ce.reloadTotal.WithLabelValues("success").Inc()
	}
	if ce.lastReloadTimestamp != nil {
		ce.lastReloadTimestamp.Set(float64(time.Now().Unix()))
	}

	// Refresh the incident tracker's rule→tactic mapping. Without this, rules
	// added or retagged by a hot reload contribute no tactics and incident
	// scoring silently degrades.
	if ce.incidentTracker != nil {
		ce.incidentTracker.SetRules(rules)
	}

	if ce.syscallFilterFn != nil {
		ce.syscallFilterFn(re.ReferencedSyscalls())
	}
}

// emitConfirmedAttackAlert queues the synthetic incident_confirmed_attack alert
// for a newly confirmed attack incident. It is registered as the incident
// tracker's attack handler and runs outside the tracker's lock.
//
// The alert is appended to pending so it drains through the same Flush() path
// as rule alerts, reaching exporters, notification fanout and the alert store.
func (ce *CorrelationEngine) emitConfirmedAttackAlert(inc types.Incident) {
	alert := buildConfirmedAttackAlert(inc)
	ce.pendingMu.Lock()
	ce.pending = append(ce.pending, alert)
	ce.pendingMu.Unlock()
	// 5.9c (находка №29): every other site that feeds an alert into the
	// pipeline increments alertsGenerated; this one didn't, so each confirmed
	// incident made engine_stats.total_alerts undercount the exported/store
	// counters by one — 11 of them broke the counter identity on №2.5 idle.
	ce.alertsGenerated.Add(1)
}

// ObserveYAMLParseDuration records the duration of the YAML rule file parsing phase.
// Called by the hot-reload handler before invoking ReloadRules.
func (ce *CorrelationEngine) ObserveYAMLParseDuration(d time.Duration) {
	if ce.reloadDuration != nil {
		ce.reloadDuration.WithLabelValues("yaml_parse").Set(d.Seconds())
	}
}

// RecordReloadFailure increments the failure counter for rule hot-reloads.
// Called by the hot-reload handler when rule loading or parsing fails.
func (ce *CorrelationEngine) RecordReloadFailure() {
	if ce.reloadTotal != nil {
		ce.reloadTotal.WithLabelValues("failure").Inc()
	}
}

// GetRules returns the currently loaded rules.
// Returns nil if no rules have been loaded yet (before the first UpdateRules call).
func (ce *CorrelationEngine) GetRules() []Rule {
	snap := ce.ruleEngine.Load()
	if snap == nil {
		return nil
	}
	return snap.GetRules()
}

// ReloadRules reloads the rules in the rule engine.
func (ce *CorrelationEngine) ReloadRules(rules []Rule) {
	ce.UpdateRules(rules)
}

// UpdateRateLimiter updates the rate limiter configuration.
func (ce *CorrelationEngine) UpdateRateLimiter(window time.Duration, maxAlerts int, enabled bool) {
	ce.rateLimiter.UpdateConfig(window, maxAlerts)
	ce.rateLimiter.SetEnabled(enabled)
}

// IncidentTracker returns the engine's incident tracker so callers (e.g. the
// HTTP server) can serve incident query results without coupling to the engine's
// internals.
func (ce *CorrelationEngine) IncidentTracker() *IncidentTracker {
	return ce.incidentTracker
}

// isEnforcedAction returns true when the action demands active enforcement
// (i.e. something beyond generating an alert).
func isEnforcedAction(action string) bool {
	return action == "block" || action == "kill" || action == "throttle"
}

// tryAcquireEnforceCooldown returns true if enforcement should proceed for
// the (ruleID, pid) pair. Successive calls within enforceCooldown return false
// to prevent enforcement spam. Delegates to the sharded cooldowns map so
// concurrent goroutines contend on different shards rather than a single mutex.
// now should be the single time.Now() captured at the start of Ingest().
func (ce *CorrelationEngine) tryAcquireEnforceCooldown(ruleID string, pid uint32, now time.Time) bool {
	return ce.cooldowns.tryAcquire(ruleID, pid, ce.enforceCooldown, now)
}

// checkIOCMatch checks e against the gossip IOC store and returns an alert when matched.
func (ce *CorrelationEngine) checkIOCMatch(e types.Event) *types.Alert {
	const ruleID = "gossip_ioc_match"

	var matched bool
	var indicator string

	switch e.Type {
	case types.EventTCPConnect:
		if e.Network != nil {
			ip := util.FormatIP16(e.Network.Daddr, e.Network.Family)
			if ce.iocMatcher.MatchIP(ip) {
				matched = true
				indicator = "ip:" + ip
			}
		}
	case types.EventDNS:
		if e.DNS != nil && ce.iocMatcher.MatchDNS(e.DNS.QName) {
			matched = true
			indicator = "dns:" + e.DNS.QName
		}
	}

	if !matched {
		return nil
	}

	seq := ce.alertSeq.Add(1)
	alert := &types.Alert{
		ID:        buildAlertID(ruleID, e.Timestamp, e.PID, seq),
		Timestamp: time.Unix(0, int64(e.Timestamp)),
		RuleID:    ruleID,
		RuleName:  "Gossip IOC Match",
		Message:   "Event matched a cluster-wide IOC: " + indicator,
		Severity:  types.SeverityCritical,
		PID:       e.PID,
		Comm:      util.InternBytes(e.Comm[:]),
		Event:     e,
	}
	if e.TraceContext != nil {
		alert.TraceID = e.TraceContext.TraceID
		alert.SpanID = e.TraceContext.SpanID
		tc := *e.TraceContext
		tc.Source = "tls_header"
		alert.TraceContext = &tc
	} else if tc := ce.traceCtxCache.lookup(e.PID, time.Now()); tc != nil {
		alert.TraceID = tc.TraceID
		alert.SpanID = tc.SpanID
		alert.TraceContext = tc
	}
	if e.Enrichment != nil {
		alert.Enrichment = *e.Enrichment
	}
	// ProcessTree is assigned by the caller (Ingest) from the pre-computed
	// shared processTree to avoid an extra lineage lock acquisition here.
	return alert
}

// buildRemoteSpanContext constructs an OTel SpanContext from W3C Trace Context hex strings
// so the correlator's internal span can be linked to the originating APM trace.
func buildRemoteSpanContext(traceID, spanID string) (trace.SpanContext, error) {
	if len(traceID) != 32 {
		return trace.SpanContext{}, fmt.Errorf("trace_id must be 32 hex chars")
	}
	traceIDBytes, err := hex.DecodeString(traceID)
	if err != nil {
		return trace.SpanContext{}, fmt.Errorf("decode trace_id: %w", err)
	}
	var tid [16]byte
	copy(tid[:], traceIDBytes)

	var sid [8]byte
	if spanID != "" && len(spanID) == 16 {
		sidBytes, err := hex.DecodeString(spanID)
		if err == nil {
			copy(sid[:], sidBytes)
		}
	}

	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    trace.TraceID(tid),
		SpanID:     trace.SpanID(sid),
		TraceFlags: trace.FlagsSampled,
		Remote:     true,
	})
	if !sc.IsValid() {
		return trace.SpanContext{}, fmt.Errorf("invalid span context")
	}
	return sc, nil
}

// alertIDPool reuses []byte buffers for alert ID construction, reducing
// hot-path allocations from ~3 (fmt.Sprintf) to 1 (the final string copy).
var alertIDPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 0, 128)
		return &b
	},
}

// getDetailsMap returns a small pre-sized map for Alert.Details.
// Alert structs outlive the engine and are passed to external consumers,
// making pool-based recycling unsafe without a reference-counting scheme.
func getDetailsMap() map[string]interface{} {
	return make(map[string]interface{}, 4)
}

// buildAlertID returns "<prefix>-<ts>-<pid>-<seq>" without fmt.Sprintf overhead.
func buildAlertID(prefix string, ts uint64, pid uint32, seq uint64) string {
	bp := alertIDPool.Get().(*[]byte)
	b := (*bp)[:0]
	b = append(b, prefix...)
	b = append(b, '-')
	b = strconv.AppendUint(b, ts, 10)
	b = append(b, '-')
	b = strconv.AppendUint(b, uint64(pid), 10)
	b = append(b, '-')
	b = strconv.AppendUint(b, seq, 10)
	id := string(b) // copy before returning buffer to pool
	*bp = b
	alertIDPool.Put(bp)
	return id
}

// formatAnomalyDescription creates a human-readable description of an anomaly.
func formatAnomalyDescription(result *profiler.AnomalyResult) string {
	if len(result.Contributions) == 0 {
		return "Anomalous behavior detected"
	}
	var b strings.Builder
	b.Grow(28 + len(result.Contributions)*32)
	b.WriteString("Anomalous behavior detected: ")
	for i, contrib := range result.Contributions {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(contrib.Field)
		b.WriteByte('=')
		b.WriteString(contrib.Value)
	}
	return b.String()
}
