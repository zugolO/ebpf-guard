// Package correlator provides event correlation and rule-based detection.
package correlator

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zugolO/ebpf-guard/internal/policy"
	"github.com/zugolO/ebpf-guard/internal/profiler"
	"github.com/zugolO/ebpf-guard/internal/util"
	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/prometheus/client_golang/prometheus"
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
	queueDepthGauge    prometheus.Gauge     // ebpf_guard_event_queue_depth
	latencyHistogram   prometheus.Histogram // ebpf_guard_correlation_latency_seconds (internal histogram)
	activeRulesGauge   prometheus.Gauge     // ebpf_guard_active_rules_total

	// Metrics callback
	onCorrelate MetricsCallback
}

// MetricsCallback is a function called to record metrics.
type MetricsCallback func(duration float64)

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

	// Initialize anomaly detector if enabled
	if config.EnableAnomaly {
		ce.anomalyDetector = profiler.NewAnomalyDetectorWithContext(
			ctx,
			config.AnomalyThreshold,
			config.LearningPeriod,
			config.EWMAWeight,
		)
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
	} {
		if err := reg.Register(c); err != nil {
			return err
		}
	}
	return nil
}

// Ingest processes a single event and may produce alerts.
func (ce *CorrelationEngine) Ingest(ctx context.Context, e types.Event) []types.Alert {
	start := time.Now()

	// Start OpenTelemetry span
	ctx, span := tracer.Start(ctx, "CorrelationEngine.Ingest",
		trace.WithAttributes(
			attribute.Int("event.pid", int(e.PID)),
			attribute.Int("event.type", int(e.Type)),
		),
	)
	defer span.End()

	// Record duration metric
	defer func() {
		duration := time.Since(start).Seconds()
		ce.latencyHistogram.Observe(duration)
		if ce.onCorrelate != nil {
			ce.onCorrelate(duration)
		}
		span.SetAttributes(attribute.Float64("correlation.duration_seconds", duration))
	}()

	ce.processedEvents.Add(1)

	// Add event to per-process buffer
	ce.buffer.Add(e.PID, e)

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
		alert.ID = fmt.Sprintf("%s-%d-%d-%d", alert.RuleID, e.Timestamp, e.PID, seq)

		// Add trace context from event if present
		if e.TraceContext != nil {
			alert.TraceID = e.TraceContext.TraceID
		}

		alerts = append(alerts, alert)
		ce.alertsGenerated.Add(1)
	}

	// Anomaly detection (if enabled and learning complete)
	if ce.enableAnomaly && ce.anomalyDetector != nil {
		if result := ce.anomalyDetector.ProcessEvent(e); result != nil && result.IsAnomaly {
			// Create anomaly alert
			anomalyAlert := types.Alert{
				ID:        fmt.Sprintf("anomaly-%d-%d-%d", e.Timestamp, e.PID, ce.alertSeq.Add(1)),
				Timestamp: time.Unix(0, int64(e.Timestamp)),
				RuleID:    "anomaly_detection",
				RuleName:  "Behavioral Anomaly Detected",
				Message:   formatAnomalyDescription(result),
				Severity:  types.SeverityWarning,
				PID:       e.PID,
				Comm:      util.BytesToString(e.Comm[:]),
				Event:     e,
			}

			// Add trace context from event if present
			if e.TraceContext != nil {
				anomalyAlert.TraceID = e.TraceContext.TraceID
			}

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

	// Update span with alert count
	span.SetAttributes(attribute.Int("alerts.generated", len(alerts)))

	// Rego policy evaluation (post-YAML filter, Sprint 23.0)
	// This is called ONLY on alerts, not on raw events, for performance
	if ce.enableRegoEval && ce.regoEngine != nil && len(alerts) > 0 {
		alerts = ce.evaluateRegoPolicies(ctx, alerts)
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
	var enhancedAlerts []types.Alert

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
func (ce *CorrelationEngine) UpdateRules(rules []Rule) {
	ce.ruleEngine.Store(NewRuleEngine(rules))
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
