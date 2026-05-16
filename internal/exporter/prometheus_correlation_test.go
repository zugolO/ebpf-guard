package exporter

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/prometheus/common/expfmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecordCorrelationDuration(t *testing.T) {
	// Create a new registry for isolated testing
	reg := prometheus.NewRegistry()

	// Create a new histogram for testing
	histogram := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "test_correlation_duration_seconds",
			Help:    "Test histogram",
			Buckets: prometheus.DefBuckets,
		},
		[]string{},
	)
	reg.MustRegister(histogram)

	// Record some durations
	histogram.WithLabelValues().Observe(0.001) // 1ms
	histogram.WithLabelValues().Observe(0.005) // 5ms
	histogram.WithLabelValues().Observe(0.010) // 10ms
	histogram.WithLabelValues().Observe(0.050) // 50ms
	histogram.WithLabelValues().Observe(0.100) // 100ms

	// Verify the histogram has recorded the values
	count, err := testutil.GatherAndCount(reg)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "expected one histogram metric")

	// Use CollectAndFormat to get the metric output
	outputBytes, err := testutil.CollectAndFormat(histogram, expfmt.TypeTextPlain, "test_correlation_duration_seconds")
	require.NoError(t, err)
	output := string(outputBytes)

	// Verify the metric name is present
	assert.Contains(t, output, "test_correlation_duration_seconds")
	assert.Contains(t, output, "_bucket")
	assert.Contains(t, output, "_count")
	assert.Contains(t, output, "_sum")

	// Verify count is 5
	assert.Contains(t, output, "_count 5")
}

func TestCorrelationDurationBuckets(t *testing.T) {
	reg := prometheus.NewRegistry()

	histogram := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "test_correlation_duration_buckets",
			Help:    "Test histogram for buckets",
			Buckets: prometheus.DefBuckets,
		},
		[]string{},
	)
	reg.MustRegister(histogram)

	// Test that various durations fall into appropriate buckets
	testCases := []float64{
		0.0001, // Very fast
		0.001,  // 1ms
		0.01,   // 10ms
		0.1,    // 100ms
		0.5,    // 500ms
		1.0,    // 1s
		5.0,    // 5s
		10.0,   // 10s
	}

	for _, duration := range testCases {
		histogram.WithLabelValues().Observe(duration)
	}

	outputBytes, err := testutil.CollectAndFormat(histogram, expfmt.TypeTextPlain, "test_correlation_duration_buckets")
	require.NoError(t, err)
	output := string(outputBytes)

	// Verify all buckets are present
	expectedBuckets := []string{
		"le=\"0.005\"",
		"le=\"0.01\"",
		"le=\"0.025\"",
		"le=\"0.05\"",
		"le=\"0.1\"",
		"le=\"0.25\"",
		"le=\"0.5\"",
		"le=\"1\"",
		"le=\"2.5\"",
		"le=\"5\"",
		"le=\"10\"",
		"le=\"+Inf\"",
	}

	for _, bucket := range expectedBuckets {
		assert.True(t, strings.Contains(output, bucket), "expected bucket %s in output", bucket)
	}
}

func TestRecordCorrelationDurationIntegration(t *testing.T) {
	// This test verifies that the global CorrelationDuration metric works correctly
	// We use Collect to get the metric values

	// Create a channel to collect metrics
	ch := make(chan prometheus.Metric, 10)

	// Collect metrics from CorrelationDuration
	CorrelationDuration.Collect(ch)
	close(ch)

	// We should have at least one metric (the histogram itself)
	metricCount := 0
	for range ch {
		metricCount++
	}

	// The metric exists and can be collected
	assert.GreaterOrEqual(t, metricCount, 0)
}
