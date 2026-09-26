package collector

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"

	"github.com/zugolO/ebpf-guard/internal/exporter"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// TestDroppedByQueueMatchesDefaultEventPriority pins the queue label of
// ebpf_guard_events_dropped_by_queue_total to defaultEventPriority. The series
// exists so the wave-6.6 emitter of label 6.6.1 can read the queue↔collector
// correspondence from the runtime instead of hardwiring "fileaccess = bulk"
// (plan.md, wave 6.6 revision item 12). If the two ever disagree, the emitter
// would attribute a loss to the wrong queue while still printing a verdict, so
// the agreement is asserted here rather than left to a comment.
func TestDroppedByQueueMatchesDefaultEventPriority(t *testing.T) {
	cases := []struct {
		eventType types.EventType
		collector string
		queue     string
	}{
		{types.EventFileAccess, "fileaccess", "bulk"},
		{types.EventSyscall, "syscall", "protected"},
		{types.EventTCPConnect, "network", "protected"},
		{types.EventDNS, "dns", "protected"},
	}
	for _, c := range cases {
		high := defaultEventPriority(c.eventType)
		assert.Equal(t, c.queue, exporter.QueueNameForPriority(high),
			"defaultEventPriority(%v) must route to queue %q", c.eventType, c.queue)

		before := testutil.ToFloat64(exporter.EventsDroppedByQueue.WithLabelValues(c.collector, c.queue))
		exporter.RecordEventDrop(c.collector, "ringbuf_to_router", high)
		after := testutil.ToFloat64(exporter.EventsDroppedByQueue.WithLabelValues(c.collector, c.queue))
		assert.Equal(t, before+1, after,
			"RecordEventDrop must count %s into queue %q", c.collector, c.queue)

		// The opposite queue must stay untouched: a drop counted into both
		// would make the emitter's split unreadable while still summing right.
		other := "protected"
		if c.queue == "protected" {
			other = "bulk"
		}
		assert.Equal(t, float64(0),
			testutil.ToFloat64(exporter.EventsDroppedByQueue.WithLabelValues(c.collector, other)),
			"%s must not be counted into both queues", c.collector)
	}
}

// TestDroppedByQueueSumMatchesEventsDropped keeps the new series comparable with
// the one the emitter already reads: the by-queue series is a re-cut of the SAME
// drops, not an additional counter, so their totals per collector must agree.
func TestDroppedByQueueSumMatchesEventsDropped(t *testing.T) {
	const col = "queuesumtest"
	exporter.RecordEventDrop(col, "ringbuf_to_router", true)
	exporter.RecordEventDrop(col, "router_to_queue", true)
	exporter.RecordEventDrop(col, "ringbuf_to_router", false)

	byHop := testutil.ToFloat64(exporter.EventsDropped.WithLabelValues(col, "ringbuf_to_router")) +
		testutil.ToFloat64(exporter.EventsDropped.WithLabelValues(col, "router_to_queue"))
	byQueue := testutil.ToFloat64(exporter.EventsDroppedByQueue.WithLabelValues(col, "protected")) +
		testutil.ToFloat64(exporter.EventsDroppedByQueue.WithLabelValues(col, "bulk"))
	assert.Equal(t, byHop, byQueue, "by-queue series must be a re-cut of the same drops, not a second counter")
}
