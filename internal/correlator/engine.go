// Package correlator provides event correlation and rule-based detection.
package correlator

import (
	"context"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ebpf-guard/ebpf-guard/internal/profiler"
	"github.com/ebpf-guard/ebpf-guard/pkg/types"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// tracer is the OpenTelemetry tracer for the correlator package.
var tracer = otel.Tracer("github.com/ebpf-guard/ebpf-guard/internal/correlator")

// Engine defines the interface for event correlation engines.
type Engine interface {
	// Ingest processes a single event and may produce alerts.
	Ingest(ctx context.Context, e types.Event) []types.Alert
	// Flush returns and resets pending state (for testing).
	Flush() []types.Alert
}

// CorrelationEngine correlates events and applies detection rules.
type CorrelationEngine struct {
	ruleEngine *RuleEngine
	buffer     *ShardedEventBuffer // Uses sharded locks for better concurrency
	pending    []types.Alert
	pendingMu  sync.Mutex // Protects pending alerts slice

	// Anomaly detection
	anomalyDetector *profiler.AnomalyDetector
	enableAnomaly   bool

	// Rate limiting
	rateLimiter *RateLimiter

	// Metrics
	processedEvents atomic.Uint64
	alertsGenerated atomic.Uint64
	alertsDropped   atomic.Uint64

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
	ce := &CorrelationEngine{
		ruleEngine:    NewRuleEngine(config.Rules),
		buffer:        NewShardedEventBuffer(config.BufferSize),
		pending:       make([]types.Alert, 0),
		enableAnomaly: config.EnableAnomaly,
		rateLimiter:   NewRateLimiter(config.RateLimitWindow, config.MaxAlertsPerWindow, config.EnableRateLimit),
		onCorrelate:   config.OnCorrelate,
	}

	// Initialize anomaly detector if enabled
	if config.EnableAnomaly {
		ce.anomalyDetector = profiler.NewAnomalyDetector(
			config.AnomalyThreshold,
			config.LearningPeriod,
			config.EWMAWeight,
		)
	}

	return ce
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
	ruleAlerts := ce.ruleEngine.Evaluate(e)
	for _, alert := range ruleAlerts {
		// Check rate limiting
		if !ce.rateLimiter.Allow(alert.RuleID) {
			ce.alertsDropped.Add(1)
			continue
		}

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
				ID:        "anomaly-" + strconv.FormatUint(e.Timestamp, 10) + "-" + strconv.Itoa(int(e.PID)),
				Timestamp: time.Unix(0, int64(e.Timestamp)),
				RuleID:    "anomaly_detection",
				RuleName:  "Behavioral Anomaly Detected",
				Message:   formatAnomalyDescription(result),
				Severity:  types.SeverityWarning,
				PID:       e.PID,
				Comm:      string(e.Comm[:]),
				Event:     e,
			}

			// Add trace context from event if present
			if e.TraceContext != nil {
				anomalyAlert.TraceID = e.TraceContext.TraceID
			}

			// Check rate limiting for anomaly alerts
			if ce.rateLimiter.Allow(anomalyAlert.RuleID) {
				alerts = append(alerts, anomalyAlert)
				ce.alertsGenerated.Add(1)
			} else {
				ce.alertsDropped.Add(1)
			}
		}
	}

	// Update span with alert count
	span.SetAttributes(attribute.Int("alerts.generated", len(alerts)))

	// Store alerts
	ce.pendingMu.Lock()
	ce.pending = append(ce.pending, alerts...)
	ce.pendingMu.Unlock()

	return alerts
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
	ce.ruleEngine = NewRuleEngine(rules)
}

// GetRules returns the currently loaded rules.
func (ce *CorrelationEngine) GetRules() []Rule {
	// Return a copy of the rules from the rule engine
	return ce.ruleEngine.GetRules()
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
