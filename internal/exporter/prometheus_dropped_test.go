package exporter

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

func TestRecordDropped_WithReason(t *testing.T) {
	// Reset metric before test
	EventsDropped.Reset()

	// Record drops with different reasons
	RecordDropped("syscall", "channel_full")
	RecordDropped("syscall", "channel_full")
	RecordDropped("syscall", "parse_error")
	RecordDropped("network", "channel_full")
	RecordDropped("fileaccess", "parse_error")

	// Verify counts
	syscallChannelFull := testutil.ToFloat64(EventsDropped.WithLabelValues("syscall", "channel_full"))
	syscallParseError := testutil.ToFloat64(EventsDropped.WithLabelValues("syscall", "parse_error"))
	networkChannelFull := testutil.ToFloat64(EventsDropped.WithLabelValues("network", "channel_full"))
	fileaccessParseError := testutil.ToFloat64(EventsDropped.WithLabelValues("fileaccess", "parse_error"))

	assert.Equal(t, float64(2), syscallChannelFull, "expected 2 syscall channel_full drops")
	assert.Equal(t, float64(1), syscallParseError, "expected 1 syscall parse_error drop")
	assert.Equal(t, float64(1), networkChannelFull, "expected 1 network channel_full drop")
	assert.Equal(t, float64(1), fileaccessParseError, "expected 1 fileaccess parse_error drop")
}

func TestRecordLogLine(t *testing.T) {
	// Reset metric before test
	LogLinesTotal.Reset()

	// Record log lines at different levels
	RecordLogLine("DEBUG")
	RecordLogLine("INFO")
	RecordLogLine("INFO")
	RecordLogLine("WARN")
	RecordLogLine("ERROR")

	// Verify counts
	debugCount := testutil.ToFloat64(LogLinesTotal.WithLabelValues("DEBUG"))
	infoCount := testutil.ToFloat64(LogLinesTotal.WithLabelValues("INFO"))
	warnCount := testutil.ToFloat64(LogLinesTotal.WithLabelValues("WARN"))
	errorCount := testutil.ToFloat64(LogLinesTotal.WithLabelValues("ERROR"))

	assert.Equal(t, float64(1), debugCount, "expected 1 DEBUG log")
	assert.Equal(t, float64(2), infoCount, "expected 2 INFO logs")
	assert.Equal(t, float64(1), warnCount, "expected 1 WARN log")
	assert.Equal(t, float64(1), errorCount, "expected 1 ERROR log")
}

// TestRecordEventDrop_BothHopsFeedTheSameWatcher is the regression test for
// wave 5.9.2a (finding #38): before RecordEventDrop existed, only the
// router_to_queue hop updated the last-drop-time watcher that degradation
// status reads — a collector losing every event at ringbuf_to_router (its
// own readLoop's output channel being full) could never flip /health to
// degraded. Both hops must now mark the same clock.
func TestRecordEventDrop_BothHopsFeedTheSameWatcher(t *testing.T) {
	EventsDropped.Reset()
	dropBreakdownMu.Lock()
	dropBreakdown = map[dropHop]uint64{}
	dropBreakdownMu.Unlock()
	lastHighPriorityDropTime.Store(0)
	lastLowPriorityDropTime.Store(0)

	assert.Equal(t, int64(0), LastHighPriorityDropTime())
	assert.Equal(t, int64(0), LastLowPriorityDropTime())

	// ringbuf_to_router, bulk (fileaccess) — must mark the low-priority clock,
	// exactly as router_to_queue already did before this wave.
	RecordEventDrop("fileaccess", "ringbuf_to_router", false)
	assert.NotZero(t, LastLowPriorityDropTime(), "ringbuf_to_router drop must mark the low-priority watcher")
	assert.Zero(t, LastHighPriorityDropTime(), "a bulk-priority drop must not mark the protected watcher")

	// router_to_queue, protected (network) — the previously-working hop must
	// keep working after being routed through the same function.
	RecordEventDrop("network", "router_to_queue", true)
	assert.NotZero(t, LastHighPriorityDropTime(), "router_to_queue drop must mark the high-priority watcher")

	assert.Equal(t, float64(1), testutil.ToFloat64(EventsDropped.WithLabelValues("fileaccess", "ringbuf_to_router")))
	assert.Equal(t, float64(1), testutil.ToFloat64(EventsDropped.WithLabelValues("network", "router_to_queue")))

	breakdown := DropBreakdownSnapshot()
	assert.Equal(t, uint64(1), breakdown["fileaccess/ringbuf_to_router"])
	assert.Equal(t, uint64(1), breakdown["network/router_to_queue"])
}

func TestSetCollectorUp(t *testing.T) {
	// Reset metric before test
	CollectorUp.Reset()

	// Set collectors up/down
	SetCollectorUp("syscall", true)
	SetCollectorUp("network", false)
	SetCollectorUp("fileaccess", true)

	// Verify values
	syscallUp := testutil.ToFloat64(CollectorUp.WithLabelValues("syscall"))
	networkUp := testutil.ToFloat64(CollectorUp.WithLabelValues("network"))
	fileaccessUp := testutil.ToFloat64(CollectorUp.WithLabelValues("fileaccess"))

	assert.Equal(t, float64(1), syscallUp, "expected syscall to be up")
	assert.Equal(t, float64(0), networkUp, "expected network to be down")
	assert.Equal(t, float64(1), fileaccessUp, "expected fileaccess to be up")
}
