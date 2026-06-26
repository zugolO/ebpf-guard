package exporter

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

// TestMetricRecorders exercises the package-level metric helper functions.
// They mutate global promauto collectors, so we only assert that they run and,
// where convenient, that the underlying collector advanced.
func TestMetricRecorders(t *testing.T) {
	RecordEventWithLabels("syscall", "pod-x", "ns-x")
	RecordBPFMapFull("events", 3)
	RecordBPFMapFull("events", 0) // delta 0 → no-op branch
	RecordCorrelationDuration(0.002)
	SetLearningProgress(0.5)
	SetProfilerStateRestored(true)
	SetProfilerStateRestored(false)
	SetRuleChecksumValid(true)
	SetRuleChecksumValid(false)
	AddBPFLost("syscall", 7)
	RecordQueueDepth(4, 128)
	RecordQueueOverflow()
	SetGoroutinePoolActive(9)
	RecordGPUEvent("cuMemAlloc")

	// CollectorStatusReporter.SetUp delegates to SetCollectorUp.
	var r CollectorStatusReporter
	r.SetUp("dns", true)
	r.SetUp("dns", false)

	// Spot-check that a couple of the collectors actually moved.
	assert.Equal(t, float64(0.5), testutil.ToFloat64(LearningProgress))
	assert.Equal(t, float64(9), testutil.ToFloat64(GoroutinePoolActive))
}
