package exporter

import (
	"fmt"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Wave 6.6 revision item 7: ebpf_guard_http_plaintext_events_by_comm_total is
// the axis label 6.6.4 was missing — events_total has no comm or pid label, so
// the residual left after the control's own exchange was unattributable BY
// CONSTRUCTION. These tests pin the two properties the label's verdict rests on:
// the comm actually lands on the series, and reaching the cardinality cap is
// COUNTED rather than silent (a collapsed comm reads as an unnamed residual, so
// 6.6.4 must be able to tell the two apart).
func TestRecordHTTPPlaintextComm(t *testing.T) {
	before := testutil.ToFloat64(HTTPPlaintextEventsByComm.WithLabelValues("nginx"))
	RecordHTTPPlaintextComm("nginx")
	RecordHTTPPlaintextComm("nginx")
	assert.Equal(t, before+2, testutil.ToFloat64(HTTPPlaintextEventsByComm.WithLabelValues("nginx")))
}

func TestRecordHTTPPlaintextCommOverflowIsCounted(t *testing.T) {
	// Exhaust the limiter with distinct comms, then check that the next one is
	// collapsed AND the overflow counter moved: a silent collapse would let
	// 6.6.4 print ДОСТИГНУТО over an incomplete breakdown.
	for i := 0; i < 1200; i++ {
		RecordHTTPPlaintextComm(fmt.Sprintf("proc-%d", i))
	}
	overflowBefore := testutil.ToFloat64(HTTPPlaintextCommOverflow)
	collapsedBefore := testutil.ToFloat64(HTTPPlaintextEventsByComm.WithLabelValues("other"))

	RecordHTTPPlaintextComm("a-comm-past-the-cap")

	require.Greater(t, testutil.ToFloat64(HTTPPlaintextCommOverflow), overflowBefore,
		"reaching the cardinality cap must be counted, not silent")
	assert.Greater(t, testutil.ToFloat64(HTTPPlaintextEventsByComm.WithLabelValues("other")), collapsedBefore,
		"the collapsed event must still be counted, under comm=\"other\"")
}

// A comm that IS literally "other" must not be reported as an overflow: that
// would make the completeness number of the breakdown wrong in the safe
// direction, and 6.6.4 refuses ДОСТИГНУТО on a nonzero overflow.
func TestRecordHTTPPlaintextCommLiteralOtherIsNotOverflow(t *testing.T) {
	before := testutil.ToFloat64(HTTPPlaintextCommOverflow)
	RecordHTTPPlaintextComm("other")
	assert.Equal(t, before, testutil.ToFloat64(HTTPPlaintextCommOverflow))
}
