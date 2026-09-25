package exporter

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// TestEventTypeLabel checks the metric "type" label mapping: TCP connect/close
// both group under "network", mapped types use their canonical name, and an
// unmapped value collapses to "other".
func TestEventTypeLabel(t *testing.T) {
	assert.Equal(t, "network", EventTypeLabel(types.EventTCPConnect))
	assert.Equal(t, "network", EventTypeLabel(types.EventNetClose))
	assert.Equal(t, "syscall", EventTypeLabel(types.EventSyscall))
	assert.Equal(t, "dns", EventTypeLabel(types.EventDNS))
	assert.Equal(t, "bpf_program", EventTypeLabel(types.EventBPFProgram))
	assert.Equal(t, "http_plaintext", EventTypeLabel(types.EventHTTPPlaintext))
	assert.Equal(t, "other", EventTypeLabel(types.EventType(9999)))

	// №468: ни один ТИП, у которого есть каноническое имя, не имеет права
	// уходить в "other" — иначе его объём неотличим от чужого, а метка,
	// читающая его ось, печатает приборный ноль. Список берётся из types, а не
	// зашит здесь: новый тип попадает под проверку сам.
	for i := 0; i < 64; i++ {
		et := types.EventType(i)
		if et.String() == "unknown" {
			continue // не заведён в types — "other" для него законен
		}
		assert.NotEqualf(t, "other", EventTypeLabel(et),
			"EventType(%d)=%q имеет каноническое имя, но EventTypeLabel отдаёт other", i, et.String())
	}
}

// TestMetricRecorders exercises the package-level metric helper functions.
// They mutate global promauto collectors, so we only assert that they run and,
// where convenient, that the underlying collector advanced.
func TestMetricRecorders(t *testing.T) {
	RecordEventWithLabels("syscall", "pod-x", "ns-x", "node-x")
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
