// Package correlator provides event correlation and rule-based detection.
package correlator

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"runtime"
	"strconv"
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
	// Ingest processes a single event and may produce alerts.
	Ingest(ctx context.Context, e types.Event) []types.Alert
	// Flush returns and resets pending state (for testing).
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
	pending    []types.Alert
	pendingMu  sync.Mutex // Protects pending alerts slice

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
	regoEngine     *policy.RegoEngine
	enableRegoEval bool

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
	queueDepthGauge  prometheus.Gauge     // ebpf_guard_event_queue_depth
	latencyHistogram prometheus.Histogram // ebpf_guard_correlation_latency_seconds (internal histogram)
	activeRulesGauge prometheus.Gauge     // ebpf_guard_active_rules_total

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

	// Rule-based enforcement (optional)
	actionExecutor      ActionExecutor
	enforceCooldown     time.Duration
	cooldowns           map[cooldownKey]time.Time // protected by cooldownsMu
	cooldownsMu         sync.Mutex               // serialises the check-and-set to prevent duplicate enforcement
	enforcedCounter     prometheus.Counter
	enforceQueue        chan enforceTask
	enforceQueueDropped prometheus.Counter

	// scoreReporter is called after every anomaly score update so an external
	// cardinality-guarded Prometheus gauge can be kept in sync without importing
	// the exporter package (which would create a circular dependency).
	scoreReporter func(pid, comm string, score float64)
}

// MetricsCallback is a function called to record metrics.
type MetricsCallback func(duration float64)

// cooldownKey is the zero-allocation composite key for enforcement cooldown tracking.
type cooldownKey struct {
	ruleID string
	pid    uint32
}

// enforceTask is a unit of work dispatched to the enforcement worker pool.
type enforceTask struct {
	ctx    context.Context
	cancel context.CancelFunc
	action string
	alert  types.Alert
}

// CorrelationEngineConfig holds configuration for the correlation engine.
type CorrelationEngineConfig struct {
	// Rule engine configuration
	Rules []Rule

	// Buffer configuration
	BufferSize int

	// Anomaly detection configuration
	EnableAnomaly    bool
	AnomalyThreshold float64
	LearningPeriod   time.Duration
	EWMAWeight       float64
	// MinLearningSamples is the minimum number of events that must be observed
	// before the learning phase can complete (in addition to LearningPeriod
	// elapsing). Zero falls back to the detector default (100).
	MinLearningSamples uint64

	// Rate limiting configuration
	EnableRateLimit    bool
	RateLimitWindow    time.Duration
	MaxAlertsPerWindow int

	// Rego policy engine configuration (Sprint 23.0)
	EnableRegoEval bool
	RegoEngine     *policy.RegoEngine

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

	// WasmEngine evaluates custom WASM detection plugins on every event.
	// When nil, WASM plugin evaluation is skipped.
	WasmEngine WasmEvaluator

	// AnomalyScoreReporter is called after every anomaly ProcessEvent so an
	// external cardinality-guarded metric (e.g. exporter.SetAnomalyScoreWithGuard)
	// can track scores without creating a circular import.  Optional — nil disables.
	AnomalyScoreReporter func(pid, comm string, score float64)
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
		EnableRateLimit:    true,
		RateLimitWindow:    time.Minute,
		MaxAlertsPerWindow: 10,
		MaxAlertsPerSecond: 10000,
		BufferTTL:          10 * time.Minute,
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
		Name: "ebpf_guard_event_queue_depth",
		Help: "Current event channel fill level as a fraction [0,1].",
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
	// Queue depth: 1024 gives burst capacity for typical enforcement spikes
	// without consuming significant memory. Each task is ~200 bytes.
	enforceQueue := make(chan enforceTask, 1024)

	ce := &CorrelationEngine{
		buffer:               NewShardedEventBuffer(config.BufferSize),
		pending:              make([]types.Alert, 0),
		enableAnomaly:        config.EnableAnomaly,
		rateLimiter:          NewRateLimiterWithContext(ctx, config.RateLimitWindow, config.MaxAlertsPerWindow, config.EnableRateLimit),
		rlStatesGauge:        rlStatesGauge,
		cancelCleanup:        cancel,
		enableRegoEval:       config.EnableRegoEval,
		regoEngine:           config.RegoEngine,
		onCorrelate:          config.OnCorrelate,
		lineageTracker:       lt,
		feedbackManager:      config.FeedbackManager,
		iocMatcher:           config.IOCMatcher,
		sensitivityAdjuster:  config.SensitivityAdjuster,
		baseAnomalyThreshold: config.AnomalyThreshold,
		wasmEngine:           config.WasmEngine,
		actionExecutor:       config.ActionExecutor,
		enforceCooldown:      enforceCooldown,
		cooldowns:            make(map[cooldownKey]time.Time),
		enforcedCounter:      enforcedCounter,
		enforceQueue:         enforceQueue,
		enforceQueueDropped:  enforceQueueDropped,
		globalLimiter:        globalLimiter,
		globalLimiterEnabled: globalLimiterEnabled,
		alertsDroppedGlobal:  alertsDroppedGlobal,
		queueDepthGauge:      queueDepthGauge,
		latencyHistogram:     latencyHistogram,
		activeRulesGauge:     activeRulesGauge,
	}

	ce.ruleEngine.Store(NewRuleEngine(config.Rules))

	// Seed active rules gauge
	activeRulesGauge.Set(float64(len(config.Rules)))

	// Background goroutine that evicts stale per-PID event buffers.
	bufferTTL := config.BufferTTL
	if bufferTTL <= 0 {
		bufferTTL = 10 * time.Minute
	}
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
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

	// Background goroutine that evicts expired enforcement cooldown entries.
	// Without this the cooldowns sync.Map grows unbounded with unique (ruleID,PID) pairs.
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
				cutoff := time.Now().Add(-enforceCooldown)
				ce.cooldownsMu.Lock()
				for k, t := range ce.cooldowns {
					if t.Before(cutoff) {
						delete(ce.cooldowns, k)
					}
				}
				ce.cooldownsMu.Unlock()
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

	// Update the gauge periodically so it reflects the live state count.
	go ce.updateRLGaugeLoop(ctx)

	return ce
}

// updateRLGaugeLoop refreshes the ratelimiter states gauge and queue depth gauge every 30 seconds.
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
		case <-ctx.Done():
			return
		}
	}
}

// Close stops background goroutines started by the engine.
func (ce *CorrelationEngine) Close() {
	ce.cancelCleanup()
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
		ce.enforceQueueDropped,
		ce.enforcedCounter,
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

// Ingest processes a single event and may produce alerts.
func (ce *CorrelationEngine) Ingest(ctx context.Context, e types.Event) []types.Alert {
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

	// Add event to per-process buffer
	ce.buffer.Add(e.PID, e)

	// Update ancestry chain so every subsequent GetProcessTree call reflects
	// the most recent parent information available for this event's PID.
	ce.lineageTracker.Track(e)

	// Compute the process tree once and share it across all alerts generated
	// by this event. Avoids acquiring the lineage read-lock once per alert
	// (rule, WASM, anomaly, IOC) under burst conditions.
	processTree := ce.lineageTracker.GetProcessTree(e.PID)

	var alerts []types.Alert

	// Evaluate against rules
	ruleAlerts := ce.ruleEngine.Load().Evaluate(e)
	for _, alert := range ruleAlerts {
		// Per-rule rate limit check
		if !ce.rateLimiter.Allow(alert.RuleID) {
			ce.alertsDropped.Add(1)
			continue
		}
		// Global token-bucket rate limit
		if ce.globalLimiterEnabled && !ce.globalLimiter.Allow() {
			ce.alertsDropped.Add(1)
			ce.alertsDroppedGlobal.Add(1)
			continue
		}

		// Append monotonic sequence number to guarantee uniqueness across
		// concurrent alerts that share ruleID+timestamp+pid.
		seq := ce.alertSeq.Add(1)
		alert.ID = buildAlertID(alert.RuleID, e.Timestamp, e.PID, seq)

		// Propagate W3C Trace Context from event to alert for APM correlation.
		if e.TraceContext != nil {
			alert.TraceID = e.TraceContext.TraceID
			alert.SpanID = e.TraceContext.SpanID
		}

		// Carry Kubernetes enrichment from the event onto the alert.
		if e.Enrichment != nil {
			alert.Enrichment = *e.Enrichment
		}

		// Attach full process tree for SOC triage.
		alert.ProcessTree = processTree

		// Rule-based enforcement: kill / block / throttle.
		// The alert is always emitted for auditing; enforcement is dispatched
		// to a bounded worker pool to cap goroutine growth under event bursts.
		if ce.actionExecutor != nil && isEnforcedAction(alert.Action) {
			if ce.tryAcquireEnforceCooldown(alert.RuleID, alert.PID) {
				alert.Enforced = true
				ce.enforcedCounter.Inc()
				// Detach from the per-request span context: the parent span ends
				// when Ingest() returns, which may be before the worker runs.
				// WithoutCancel preserves OTel baggage; the 30 s timeout prevents
				// a hung enforcer from blocking a worker indefinitely.
				enfCtx, enfCancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
				task := enforceTask{ctx: enfCtx, cancel: enfCancel, action: alert.Action, alert: alert}
				select {
				case ce.enforceQueue <- task:
				default:
					// Queue full: drop this enforcement action and record the drop.
					enfCancel()
					ce.enforceQueueDropped.Add(1)
				}
			}
		}

		alerts = append(alerts, alert)
		ce.alertsGenerated.Add(1)
	}

	// WASM plugin evaluation — run custom detection plugins.
	if ce.wasmEngine != nil {
		wasmAlerts := ce.wasmEngine.Evaluate(ctx, e)
		for _, alert := range wasmAlerts {
			if !ce.rateLimiter.Allow(alert.RuleID) {
				ce.alertsDropped.Add(1)
				continue
			}
			if ce.globalLimiterEnabled && !ce.globalLimiter.Allow() {
				ce.alertsDropped.Add(1)
				ce.alertsDroppedGlobal.Add(1)
				continue
			}
			seq := ce.alertSeq.Add(1)
			alert.ID = buildAlertID(alert.RuleID, e.Timestamp, e.PID, seq)
			alert.ProcessTree = processTree
			alerts = append(alerts, alert)
			ce.alertsGenerated.Add(1)
		}
	}

	// Gossip IOC matching — check event against cluster-wide indicators.
	if ce.iocMatcher != nil {
		if iocAlert := ce.checkIOCMatch(e); iocAlert != nil {
			iocAlert.ProcessTree = processTree
			if ce.rateLimiter.Allow(iocAlert.RuleID) &&
				(!ce.globalLimiterEnabled || ce.globalLimiter.Allow()) {
				alerts = append(alerts, *iocAlert)
				ce.alertsGenerated.Add(1)
			} else {
				ce.alertsDropped.Add(1)
			}
		}
	}

	// Anomaly detection (if enabled and learning complete).
	// ruleConfirmed=true suppresses EWMA baseline updates for events that
	// rule/WASM/IOC detectors already confirmed as malicious.
	if ce.enableAnomaly && ce.anomalyDetector != nil {
		ruleConfirmed := len(alerts) > 0
		if result := ce.anomalyDetector.ProcessEvent(e, ruleConfirmed); result != nil {
			// Always report the score (even non-anomalous) so the cardinality-guarded
			// Prometheus gauge tracks all active processes, not only anomaly triggers.
			if ce.scoreReporter != nil {
				ce.scoreReporter(fmt.Sprintf("%d", e.PID), util.BytesToString(e.Comm[:]), result.Score)
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
				// Build workload context for alert details.
				details := map[string]interface{}{}
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
					Comm:      util.BytesToString(e.Comm[:]),
					Details:   details,
					Event:     e,
				}

				// Add trace context from event if present
				if e.TraceContext != nil {
					anomalyAlert.TraceID = e.TraceContext.TraceID
				}

				// Carry Kubernetes enrichment from the event onto the alert.
				if e.Enrichment != nil {
					anomalyAlert.Enrichment = *e.Enrichment
				}

				// Attach full process tree for SOC triage.
				anomalyAlert.ProcessTree = processTree

				// Check per-rule and global rate limiting for anomaly alerts
				perRuleOK := ce.rateLimiter.Allow(anomalyAlert.RuleID)
				globalOK := !ce.globalLimiterEnabled || ce.globalLimiter.Allow()
				if perRuleOK && globalOK {
					alerts = append(alerts, anomalyAlert)
					ce.alertsGenerated.Add(1)
				} else {
					ce.alertsDropped.Add(1)
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

	// Rego policy evaluation (post-YAML filter, Sprint 23.0)
	// This is called ONLY on alerts, not on raw events, for performance
	if ce.enableRegoEval && ce.regoEngine != nil && len(alerts) > 0 {
		alerts = ce.evaluateRegoPolicies(ctx, alerts)
	}

	// Analyst false-positive suppression: drop alerts whose (ruleID, comm) pair
	// has been marked as a false positive via POST /api/v1/alerts/{id}/feedback.
	if ce.feedbackManager != nil && len(alerts) > 0 {
		alerts = ce.feedbackManager.FilterAlerts(alerts)
	}

	// Store alerts
	ce.pendingMu.Lock()
	ce.pending = append(ce.pending, alerts...)
	ce.pendingMu.Unlock()

	return alerts
}

// evaluateRegoPolicies evaluates alerts against Rego policies.
// This is called post-YAML filter to minimize OPA evaluation overhead.
func (ce *CorrelationEngine) evaluateRegoPolicies(ctx context.Context, alerts []types.Alert) []types.Alert {
	enhancedAlerts := make([]types.Alert, 0, len(alerts))

	for _, alert := range alerts {
		// Evaluate alert against Rego policies
		decisions, err := ce.regoEngine.Evaluate(ctx, alert)
		if err != nil {
			// Log error but don't drop the alert
			// Continue with original alert
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
			enhancedAlert.Details = make(map[string]interface{})
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

	// Priority: critical > warning
	for _, d := range decisions {
		if d.Severity == types.SeverityCritical {
			return d
		}
	}

	return decisions[0]
}

// Flush returns and resets pending alerts.
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

// UpdateRules updates the rule engine with new rules.
// Compiled regex/CIDR/set entries from the previous engine are inherited so
// patterns that appear in both old and new rule sets are not recompiled.
func (ce *CorrelationEngine) UpdateRules(rules []Rule) {
	prior := ce.ruleEngine.Load()
	ce.ruleEngine.Store(NewRuleEngineWithCache(rules, prior))
	ce.activeRulesGauge.Set(float64(len(rules)))
}

// GetRules returns the currently loaded rules.
func (ce *CorrelationEngine) GetRules() []Rule {
	return ce.ruleEngine.Load().GetRules()
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

// isEnforcedAction returns true when the action demands active enforcement
// (i.e. something beyond generating an alert).
func isEnforcedAction(action string) bool {
	return action == "block" || action == "kill" || action == "throttle"
}

// tryAcquireEnforceCooldown returns true if enforcement should proceed for
// the (ruleID, pid) pair. Successive calls within enforceCooldown return false
// to prevent enforcement spam when the same process keeps triggering a rule.
//
// cooldownsMu makes the lookup+compare+store atomic so two concurrent goroutines
// for the same (ruleID, pid) cannot both slip through and fire the action twice.
func (ce *CorrelationEngine) tryAcquireEnforceCooldown(ruleID string, pid uint32) bool {
	key := cooldownKey{ruleID: ruleID, pid: pid}
	now := time.Now()

	ce.cooldownsMu.Lock()
	defer ce.cooldownsMu.Unlock()

	if prev, ok := ce.cooldowns[key]; ok && now.Sub(prev) < ce.enforceCooldown {
		return false
	}
	ce.cooldowns[key] = now
	return true
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
		Comm:      util.BytesToString(e.Comm[:]),
		Event:     e,
	}
	if e.TraceContext != nil {
		alert.TraceID = e.TraceContext.TraceID
		alert.SpanID = e.TraceContext.SpanID
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
	desc := "Anomalous behavior detected"
	if len(result.Contributions) > 0 {
		desc += ": "
		for i, contrib := range result.Contributions {
			if i > 0 {
				desc += ", "
			}
			desc += contrib.Field + "=" + contrib.Value
		}
	}
	return desc
}
