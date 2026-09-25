package exporter

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

func TestTLSFamilySplit(t *testing.T) {
	assert.Equal(t, 3, testutil.CollectAndCount(TLSEventsByFamily), "all families materialized at init")

	p0 := testutil.ToFloat64(TLSEventsByFamily.WithLabelValues(TLSFamilyPayload))
	j0 := testutil.ToFloat64(TLSEventsByFamily.WithLabelValues(TLSFamilyJA3))
	u0 := testutil.ToFloat64(TLSEventsByFamily.WithLabelValues(TLSFamilyUnknown))

	RecordTLSFamily(&types.Event{Type: types.EventTLS, TLS: &types.TLSEvent{DataLen: 10}})
	RecordTLSFamily(&types.Event{Type: types.EventTLS, TLS: &types.TLSEvent{JA3: "abc"}})
	RecordTLSFamily(&types.Event{Type: types.EventTLS})
	RecordTLSFamily(&types.Event{Type: types.EventSyscall})

	assert.Equal(t, p0+1, testutil.ToFloat64(TLSEventsByFamily.WithLabelValues(TLSFamilyPayload)))
	assert.Equal(t, j0+1, testutil.ToFloat64(TLSEventsByFamily.WithLabelValues(TLSFamilyJA3)))
	assert.Equal(t, u0+1, testutil.ToFloat64(TLSEventsByFamily.WithLabelValues(TLSFamilyUnknown)))
}

// A fingerprint event carries the ClientHello record length in DataLen — it is
// never zero. The first classifier required DataLen == 0, so no real JA3 event
// could ever have been counted as one. The producer-side half of this
// regression lives in internal/collector (TestTLSFamily_RealProducerIsJA3).
func TestTLSFamily_DataLenIsNotTheDiscriminator(t *testing.T) {
	assert.Equal(t, TLSFamilyJA3, TLSFamily(&types.TLSEvent{DataLen: 517, JA3: "d41d8c"}),
		"a ClientHello with a non-zero record length is still the ja3 family")
	assert.Equal(t, TLSFamilyJA3, TLSFamily(&types.TLSEvent{DataLen: 517, JA4: "t13d"}),
		"JA4 alone is enough — JA3 computation can fail independently")
	assert.Equal(t, TLSFamilyPayload, TLSFamily(&types.TLSEvent{DataLen: 517}),
		"no fingerprint fields = the uprobe payload path")
}
