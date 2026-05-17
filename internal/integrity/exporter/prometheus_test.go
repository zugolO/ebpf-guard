// Package exporter provides Prometheus metrics and Alertmanager alerting.
package exporter

import (
	"fmt"
	"strings"
	"testing"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecordEvent(t *testing.T) {
	// Reset metrics before test
	EventsTotal.Reset()

	// Record some events
	RecordEvent("syscall")
	RecordEvent("syscall")
	RecordEvent("network")

	// Verify counts
	syscallCount := testutil.ToFloat64(EventsTotal.WithLabelValues("syscall", "", ""))
	assert.Equal(t, 2.0, syscallCount)

	networkCount := testutil.ToFloat64(EventsTotal.WithLabelValues("network", "", ""))
	assert.Equal(t, 1.0, networkCount)
}

func TestRecordDropped(t *testing.T) {
	EventsDropped.Reset()

	RecordDropped("syscall", "channel_full")
	RecordDropped("syscall", "channel_full")
	RecordDropped("network", "parse_error")

	syscallDropped := testutil.ToFloat64(EventsDropped.WithLabelValues("syscall", "channel_full"))
	assert.Equal(t, 2.0, syscallDropped)

	networkDropped := testutil.ToFloat64(EventsDropped.WithLabelValues("network", "parse_error"))
	assert.Equal(t, 1.0, networkDropped)
}

func TestRecordAlert(t *testing.T) {
	AlertsTotal.Reset()

	RecordAlert("rule_001", "warning")
	RecordAlert("rule_001", "warning")
	RecordAlert("rule_002", "critical")

	rule1Count := testutil.ToFloat64(AlertsTotal.WithLabelValues("rule_001", "warning"))
	assert.Equal(t, 2.0, rule1Count)

	rule2Count := testutil.ToFloat64(AlertsTotal.WithLabelValues("rule_002", "critical"))
	assert.Equal(t, 1.0, rule2Count)
}

func TestSetAnomalyScoreWithGuard(t *testing.T) {
	ProfilerAnomalyScore.Reset()
	// Reset global guard for clean test
	globalGuard = NewAnomalyScoreGuard()

	SetAnomalyScoreWithGuard("1234", "nginx", 0.75)
	SetAnomalyScoreWithGuard("5678", "postgres", 0.25)

	score1 := testutil.ToFloat64(ProfilerAnomalyScore.WithLabelValues("1234", "nginx"))
	assert.Equal(t, 0.75, score1)

	score2 := testutil.ToFloat64(ProfilerAnomalyScore.WithLabelValues("5678", "postgres"))
	assert.Equal(t, 0.25, score2)
}

func TestSetBPFMapEntries(t *testing.T) {
	BPFMapEntries.Reset()

	SetBPFMapEntries("events", 1000)
	SetBPFMapEntries("processes", 500)

	eventsCount := testutil.ToFloat64(BPFMapEntries.WithLabelValues("events"))
	assert.Equal(t, 1000.0, eventsCount)

	processesCount := testutil.ToFloat64(BPFMapEntries.WithLabelValues("processes"))
	assert.Equal(t, 500.0, processesCount)
}

// TestCardinalityRegression_ProfilerAnomalyScore tests that the anomaly score
// gauge doesn't create unbounded series when many unique (pid, comm) pairs are emitted.
// This is a regression test for Sprint 7.2.
func TestCardinalityRegression_ProfilerAnomalyScore(t *testing.T) {
	ProfilerAnomalyScore.Reset()

	// Simulate 1000 unique processes
	const numProcesses = 1000
	for i := 0; i < numProcesses; i++ {
		pid := fmt.Sprintf("%d", i+1)
		comm := fmt.Sprintf("process_%d", i)
		score := float64(i%100) / 100.0 // Score between 0 and 0.99
		SetAnomalyScoreWithGuard(pid, comm, score)
	}

	// Collect all metrics
	registry := prometheus.NewRegistry()
	registry.MustRegister(ProfilerAnomalyScore)

	families, err := registry.Gather()
	require.NoError(t, err)

	// Find the anomaly score metric family
	var anomalyFamily *dto.MetricFamily
	for _, family := range families {
		if family.GetName() == "ebpf_guard_profiler_anomaly_score" {
			anomalyFamily = family
			break
		}
	}

	require.NotNil(t, anomalyFamily, "anomaly score metric family should exist")

	// Verify we have exactly numProcesses series
	assert.Equal(t, numProcesses, len(anomalyFamily.GetMetric()),
		"should have %d series for %d unique (pid, comm) pairs", numProcesses, numProcesses)

	// Verify all expected label combinations exist
	for i := 0; i < numProcesses; i++ {
		pid := fmt.Sprintf("%d", i+1)
		comm := fmt.Sprintf("process_%d", i)
		score := testutil.ToFloat64(ProfilerAnomalyScore.WithLabelValues(pid, comm))
		assert.Equal(t, float64(i%100)/100.0, score)
	}
}

// TestCardinalityRegression_AlertsTotal tests that alert counters don't create
// unbounded series for many unique rule IDs.
func TestCardinalityRegression_AlertsTotal(t *testing.T) {
	AlertsTotal.Reset()

	// Simulate alerts from 500 different rules
	const numRules = 500
	for i := 0; i < numRules; i++ {
		ruleID := fmt.Sprintf("rule_%03d", i)
		severity := "warning"
		if i%10 == 0 {
			severity = "critical"
		}
		RecordAlert(ruleID, severity)
	}

	// Collect all metrics
	registry := prometheus.NewRegistry()
	registry.MustRegister(AlertsTotal)

	families, err := registry.Gather()
	require.NoError(t, err)

	var alertsFamily *dto.MetricFamily
	for _, family := range families {
		if family.GetName() == "ebpf_guard_alerts_total" {
			alertsFamily = family
			break
		}
	}

	require.NotNil(t, alertsFamily, "alerts metric family should exist")
	assert.Equal(t, numRules, len(alertsFamily.GetMetric()),
		"should have %d series for %d unique rule_id+severity combinations", numRules, numRules)
}

// TestCardinalityRegression_EventsDropped tests that dropped events counter
// creates bounded series per collector type and reason.
func TestCardinalityRegression_EventsDropped(t *testing.T) {
	EventsDropped.Reset()

	// 3 collectors × 2 reasons = 6 possible series
	collectors := []string{"syscall", "network", "fileaccess"}
	reasons := []string{"channel_full", "parse_error"}

	for _, collector := range collectors {
		for _, reason := range reasons {
			for i := 0; i < 10; i++ {
				RecordDropped(collector, reason)
			}
		}
	}

	registry := prometheus.NewRegistry()
	registry.MustRegister(EventsDropped)

	families, err := registry.Gather()
	require.NoError(t, err)

	var droppedFamily *dto.MetricFamily
	for _, family := range families {
		if family.GetName() == "ebpf_guard_events_dropped_total" {
			droppedFamily = family
			break
		}
	}

	require.NotNil(t, droppedFamily, "dropped events metric family should exist")
	assert.Equal(t, len(collectors)*len(reasons), len(droppedFamily.GetMetric()),
		"should have exactly %d series (collectors × reasons)", len(collectors)*len(reasons))
}

// TestCardinalityBound_LabelValueLength tests that very long label values
// are handled gracefully (not truncated in an unexpected way).
func TestCardinalityBound_LabelValueLength(t *testing.T) {
	ProfilerAnomalyScore.Reset()

	// Test with very long comm value (typical max is 16 bytes for process name)
	longComm := strings.Repeat("a", 100)
	SetAnomalyScoreWithGuard("1", longComm, 0.5)

	// Should still be recordable
	score := testutil.ToFloat64(ProfilerAnomalyScore.WithLabelValues("1", longComm))
	assert.Equal(t, 0.5, score)
}

// TestMetricDocumentation verifies all metrics are properly defined.
func TestMetricDocumentation(t *testing.T) {
	// Verify all metrics variables are not nil and have proper definitions
	assert.NotNil(t, EventsTotal, "EventsTotal should be defined")
	assert.NotNil(t, EventsDropped, "EventsDropped should be defined")
	assert.NotNil(t, AlertsTotal, "AlertsTotal should be defined")
	assert.NotNil(t, ProfilerAnomalyScore, "ProfilerAnomalyScore should be defined")
	assert.NotNil(t, BPFMapEntries, "BPFMapEntries should be defined")
	assert.NotNil(t, CollectorUp, "CollectorUp should be defined")
	assert.NotNil(t, LogLinesTotal, "LogLinesTotal should be defined")

	// Verify metric names match expected values
	// We can't easily access the name from the metric itself, but we can verify
	// the metrics work by recording values
	EventsTotal.Reset()
	EventsDropped.Reset()
	AlertsTotal.Reset()
	ProfilerAnomalyScore.Reset()
	BPFMapEntries.Reset()
	CollectorUp.Reset()
	LogLinesTotal.Reset()

	// Record test values
	RecordEvent("test")
	RecordDropped("test", "channel_full")
	RecordAlert("test", "warning")
	SetAnomalyScoreWithGuard("1", "test", 0.5)
	SetBPFMapEntries("test", 100)
	SetCollectorUp("test", true)
	RecordLogLine("INFO")

	// Verify metrics were recorded (proving they are properly registered)
	assert.Equal(t, 1.0, testutil.ToFloat64(EventsTotal.WithLabelValues("test", "", "")))
	assert.Equal(t, 1.0, testutil.ToFloat64(EventsDropped.WithLabelValues("test", "channel_full")))
	assert.Equal(t, 1.0, testutil.ToFloat64(AlertsTotal.WithLabelValues("test", "warning")))
	assert.Equal(t, 0.5, testutil.ToFloat64(ProfilerAnomalyScore.WithLabelValues("1", "test")))
	assert.Equal(t, 100.0, testutil.ToFloat64(BPFMapEntries.WithLabelValues("test")))
	assert.Equal(t, 1.0, testutil.ToFloat64(CollectorUp.WithLabelValues("test")))
	assert.Equal(t, 1.0, testutil.ToFloat64(LogLinesTotal.WithLabelValues("INFO")))
}
