// Package exporter provides Prometheus metrics and Alertmanager alerting.
package exporter

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// EventsTotal counts all events by type and metadata.
	EventsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_guard_events_total",
			Help: "Total number of kernel events processed",
		},
		[]string{"type", "pod", "namespace"},
	)

	// EventsDropped counts dropped events by collector and reason.
	EventsDropped = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_guard_events_dropped_total",
			Help: "Total number of events dropped by reason",
		},
		[]string{"collector", "reason"},
	)

	// AlertsTotal counts generated alerts by rule and severity.
	AlertsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_guard_alerts_total",
			Help: "Total number of security alerts generated",
		},
		[]string{"rule_id", "severity"},
	)

	// ProfilerAnomalyScore tracks anomaly scores per process.
	ProfilerAnomalyScore = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ebpf_guard_profiler_anomaly_score",
			Help: "Current anomaly score for each process",
		},
		[]string{"pid", "comm"},
	)

	// BPFMapEntries tracks the number of entries in BPF maps.
	BPFMapEntries = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ebpf_guard_bpf_map_entries",
			Help: "Current number of entries in BPF maps",
		},
		[]string{"map_name"},
	)

	// CollectorUp indicates whether each collector is successfully loaded (1) or in stub/failed state (0).
	CollectorUp = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ebpf_guard_collector_up",
			Help: "Whether the collector is up (1) or down/stub (0)",
		},
		[]string{"collector"},
	)

	// LogLinesTotal counts log lines by level.
	LogLinesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_guard_log_lines_total",
			Help: "Total number of log lines by level",
		},
		[]string{"level"},
	)

	// CorrelationDuration measures the latency of event correlation in seconds.
	CorrelationDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ebpf_guard_correlation_duration_seconds",
			Help:    "Latency of event correlation in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{}, // No labels for now
	)

	// LearningProgress tracks the progress of the profiler learning phase (0.0-1.0).
	LearningProgress = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "ebpf_guard_learning_progress",
			Help: "Progress of the behavioral learning phase (0.0-1.0)",
		},
	)
)

// RecordEvent increments the events counter for the given type.
// Deprecated: Use RecordEventWithLabels to provide proper pod/namespace labels.
func RecordEvent(eventType string) {
	EventsTotal.WithLabelValues(eventType, "", "").Inc()
}

// RecordEventWithLabels increments the events counter with proper K8s metadata.
func RecordEventWithLabels(eventType, podName, namespace string) {
	EventsTotal.WithLabelValues(eventType, podName, namespace).Inc()
}

// RecordDropped increments the dropped events counter with reason.
func RecordDropped(collector, reason string) {
	EventsDropped.WithLabelValues(collector, reason).Inc()
}

// RecordAlert increments the alerts counter.
func RecordAlert(ruleID, severity string) {
	AlertsTotal.WithLabelValues(ruleID, severity).Inc()
}

// SetBPFMapEntries sets the entry count for a BPF map.
func SetBPFMapEntries(mapName string, count float64) {
	BPFMapEntries.WithLabelValues(mapName).Set(count)
}

// SetCollectorUp sets the collector up/down status (1 = up, 0 = down/stub).
func SetCollectorUp(collector string, up bool) {
	value := float64(0)
	if up {
		value = 1
	}
	CollectorUp.WithLabelValues(collector).Set(value)
}

// CollectorStatusReporter implements collector.StatusReporter using the global
// Prometheus CollectorUp gauge. Collectors should accept this interface rather
// than importing the exporter package directly.
type CollectorStatusReporter struct{}

// SetUp sets the named collector's up/down Prometheus gauge.
func (CollectorStatusReporter) SetUp(name string, up bool) {
	SetCollectorUp(name, up)
}

// RecordLogLine increments the log lines counter for the given level.
func RecordLogLine(level string) {
	LogLinesTotal.WithLabelValues(level).Inc()
}

// RecordCorrelationDuration records the duration of correlation processing.
func RecordCorrelationDuration(duration float64) {
	CorrelationDuration.WithLabelValues().Observe(duration)
}

// SetLearningProgress sets the learning progress gauge (0.0-1.0).
func SetLearningProgress(progress float64) {
	LearningProgress.Set(progress)
}
