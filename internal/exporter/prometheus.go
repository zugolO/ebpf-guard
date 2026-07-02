// Package exporter provides Prometheus metrics and Alertmanager alerting.
package exporter

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/zugolO/ebpf-guard/internal/util"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

func init() {
	// Register the process-wide string interner as a Prometheus collector so
	// ebpf_guard_interner_hits_total, _misses_total, and _size are scraped.
	prometheus.MustRegister(util.DefaultInterner)
}

// Global cardinality limiters for high-cardinality metrics.
// EventsTotal: limit pod (index 1) cardinality to prevent Prometheus OOM.
// AlertsTotal: limit namespace (index 2) cardinality.
var (
	eventsCardinalityLimiter = NewCardinalityLimiter(5000)  // 5K pod × 50 event types = conservative
	alertsCardinalityLimiter = NewCardinalityLimiter(10000) // 1K rule IDs × 10 namespaces
)

var (
	// EventsTotal counts all events by type and metadata.
	EventsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_guard_events_total",
			Help: "Total number of kernel events processed",
		},
		[]string{"type", "pod", "namespace", "node"},
	)

	// EventsDropped counts dropped events by collector and reason.
	EventsDropped = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_guard_events_dropped_total",
			Help: "Total number of events dropped by reason",
		},
		[]string{"collector", "reason"},
	)

	// AlertsTotal counts generated alerts by rule, severity, namespace, pod, and node.
	// Pod and node are required for the fleet-wide Grafana dashboard to attribute
	// alerts to a specific pod/node without relying on Prometheus scrape relabeling.
	AlertsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_guard_alerts_total",
			Help: "Total number of security alerts generated",
		},
		[]string{"rule_id", "severity", "namespace", "pod", "node"},
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

	// BPFLostEvents counts events dropped when the collector output channel is full.
	// Incremented by the watchdog drop-tracking loop every 10 seconds from each
	// collector's atomic counter, which is incremented on each backpressure drop.
	BPFLostEvents = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_guard_bpf_lost_events_total",
			Help: "Total number of events dropped by BPF collectors due to consumer backpressure",
		},
		[]string{"collector"},
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

	// ProfilerStateRestored indicates whether the EWMA profiler state was
	// successfully loaded from disk on startup (1) or the agent started fresh (0).
	// Use this to confirm that rolling DaemonSet updates preserve the learned baseline.
	ProfilerStateRestored = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "ebpf_guard_profiler_state_restored",
			Help: "1 if EWMA profiler state was loaded from disk on startup, 0 if fresh start",
		},
	)

	// RuleChecksumValid indicates whether the last rule checksum verification
	// passed (1) or failed (0). Only meaningful when rules.verify_checksums is true.
	RuleChecksumValid = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "ebpf_guard_rules_checksum_valid",
			Help: "1 if rule file checksums were verified successfully, 0 if verification failed or was not run",
		},
	)

	// BPFMapFull counts BPF map insert failures due to the map being at capacity.
	// Drained from the per-CPU map_full_counters BPF array by the watchdog loop.
	// A non-zero value means events are being silently dropped at the kernel level.
	BPFMapFull = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_guard_bpf_map_full_total",
			Help: "Total BPF map insert failures due to map capacity limit, by map name",
		},
		[]string{"map_name"},
	)
)

// RecordEvent increments the events counter for the given type.
// Deprecated: Use RecordEventWithLabels to provide proper pod/namespace/node labels.
func RecordEvent(eventType string) {
	EventsTotal.WithLabelValues(eventType, "", "", "").Inc()
}

// RecordEventWithLabels increments the events counter with proper K8s metadata.
// Under normal operation all of pod/namespace/node are recorded verbatim; if the
// series count ever exceeds the cardinality limit (e.g. pod churn, or a node
// label misconfigured to a per-pod value) pod, namespace, and node all collapse
// to "other" so total series stay bounded by the event type alone.
func RecordEventWithLabels(eventType, podName, namespace, node string) {
	labels := []string{eventType, podName, namespace, node}
	// Collapse pod(1)/namespace(2)/node(3) to "other" if the limit is exceeded.
	labels = eventsCardinalityLimiter.Normalize(labels, 1, 2, 3)
	EventsTotal.WithLabelValues(labels[0], labels[1], labels[2], labels[3]).Inc()
}

// EventTypeLabel converts an EventType to the short string used as the
// "type" label on ebpf_guard_events_total. Both TCP connect and close collapse
// to "network" so the metric groups connection lifecycle under one label; every
// other type defers to the canonical types.EventType.String() name, and any
// unmapped type collapses to "other" to stay low-cardinality.
func EventTypeLabel(t types.EventType) string {
	switch t {
	case types.EventTCPConnect, types.EventNetClose:
		return "network"
	}
	if name := t.String(); name != "unknown" {
		return name
	}
	return "other"
}

// RecordDropped increments the dropped events counter with reason.
func RecordDropped(collector, reason string) {
	EventsDropped.WithLabelValues(collector, reason).Inc()
}

// RecordAlert increments the alerts counter for the given rule, severity,
// namespace, pod, and node. Under normal operation all labels are recorded
// verbatim; if the series count exceeds the cardinality limit, namespace, pod,
// and node all collapse to "other" so total series stay bounded by
// rule_id × severity (rule_id and severity are inherently low-cardinality).
func RecordAlert(ruleID, severity, namespace, podName, node string) {
	labels := []string{ruleID, severity, namespace, podName, node}
	// Collapse namespace(2)/pod(3)/node(4) to "other" if the limit is exceeded.
	labels = alertsCardinalityLimiter.Normalize(labels, 2, 3, 4)
	AlertsTotal.WithLabelValues(labels[0], labels[1], labels[2], labels[3], labels[4]).Inc()
}

// SetBPFMapEntries sets the entry count for a BPF map.
func SetBPFMapEntries(mapName string, count float64) {
	BPFMapEntries.WithLabelValues(mapName).Set(count)
}

// RecordBPFMapFull increments the map-full counter by delta for the given map name.
// Called by the watchdog/collector drain loop after reading map_full_counters from BPF.
func RecordBPFMapFull(mapName string, delta uint64) {
	if delta > 0 {
		BPFMapFull.WithLabelValues(mapName).Add(float64(delta))
	}
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

// SetProfilerStateRestored sets the state-restored gauge: 1 if EWMA state was
// loaded from disk, 0 if the agent started fresh.
func SetProfilerStateRestored(restored bool) {
	if restored {
		ProfilerStateRestored.Set(1)
	} else {
		ProfilerStateRestored.Set(0)
	}
}

// SetRuleChecksumValid sets the checksum validation gauge: 1 if verification
// passed, 0 if it failed or was not performed.
func SetRuleChecksumValid(valid bool) {
	if valid {
		RuleChecksumValid.Set(1)
	} else {
		RuleChecksumValid.Set(0)
	}
}

// AddBPFLost increments the BPF ring buffer lost events counter for a collector.
func AddBPFLost(collector string, n uint64) {
	BPFLostEvents.WithLabelValues(collector).Add(float64(n))
}

var (
	// EventQueueDepth tracks the current number of events waiting in the
	// in-process channel between collectors and the correlation engine.
	EventQueueDepth = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "ebpf_guard_event_queue_depth",
			Help: "Current number of events buffered in the correlation engine input queue",
		},
	)

	// EventQueueCapacity tracks the maximum capacity of the event queue channel.
	EventQueueCapacity = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "ebpf_guard_event_queue_capacity",
			Help: "Maximum capacity of the correlation engine input queue",
		},
	)

	// EventQueueOverflow counts events dropped because the queue was full.
	EventQueueOverflow = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ebpf_guard_event_queue_dropped_total",
			Help: "Total number of events dropped due to event queue overflow",
		},
	)

	// GoroutinePoolActive tracks the number of goroutines actively processing
	// events in the bounded worker pool.
	GoroutinePoolActive = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "ebpf_guard_goroutine_pool_active",
			Help: "Number of goroutines currently processing events in the worker pool",
		},
	)
)

// RecordQueueDepth updates the event queue depth and capacity gauges.
func RecordQueueDepth(depth, capacity int) {
	EventQueueDepth.Set(float64(depth))
	EventQueueCapacity.Set(float64(capacity))
}

// RecordQueueOverflow increments the overflow counter (event dropped due to full queue).
func RecordQueueOverflow() {
	EventQueueOverflow.Inc()
}

// SetGoroutinePoolActive sets the active worker count gauge.
func SetGoroutinePoolActive(n int64) {
	GoroutinePoolActive.Set(float64(n))
}

var (
	// GPUEventsTotal counts GPU/CUDA events by operation type.
	GPUEventsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_guard_gpu_events_total",
			Help: "Total number of GPU/CUDA events processed, by operation type",
		},
		[]string{"op"},
	)
)

// RecordGPUEvent increments the GPU events counter for the given operation name.
func RecordGPUEvent(op string) {
	GPUEventsTotal.WithLabelValues(op).Inc()
}


// ── Kubernetes enricher metrics ───────────────────────────────────────────────

var (
	// K8sEnricherCachePods tracks the number of unique pods in the watcher cache.
	K8sEnricherCachePods = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ebpf_guard_k8s_enricher_cache_pods",
			Help: "Number of unique pods currently tracked in the Kubernetes enricher cache",
		},
		[]string{"node"},
	)

	// K8sEnricherCacheStaleness tracks seconds elapsed since the last watcher sync.
	K8sEnricherCacheStaleness = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ebpf_guard_k8s_enricher_cache_staleness_seconds",
			Help: "Seconds elapsed since the Kubernetes enricher last received data from the API server",
		},
		[]string{"node"},
	)

	// K8sEnricherLastSync records the Unix timestamp of the last successful watcher sync.
	K8sEnricherLastSync = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ebpf_guard_k8s_enricher_last_sync_timestamp_seconds",
			Help: "Unix timestamp of the last successful Kubernetes enricher sync",
		},
		[]string{"node"},
	)

	// K8sEnricherMissTotal counts enrichment lookups that found no matching pod.
	K8sEnricherMissTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_guard_k8s_enricher_miss_total",
			Help: "Total number of event enrichment lookups that found no matching pod in the cache",
		},
		[]string{"node"},
	)
)
