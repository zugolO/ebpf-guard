package exporter

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestSetBPFMapSize(t *testing.T) {
	SetBPFMapSize("events", 32768)
	SetBPFMapSize("processes", 8192)

	if got := testutil.ToFloat64(BPFMapSize.WithLabelValues("events")); got != 32768 {
		t.Errorf("BPFMapSize[events] = %v, want 32768", got)
	}
	if got := testutil.ToFloat64(BPFMapSize.WithLabelValues("processes")); got != 8192 {
		t.Errorf("BPFMapSize[processes] = %v, want 8192", got)
	}

	// A later call for the same map name must overwrite, not accumulate.
	SetBPFMapSize("events", 65536)
	if got := testutil.ToFloat64(BPFMapSize.WithLabelValues("events")); got != 65536 {
		t.Errorf("BPFMapSize[events] after overwrite = %v, want 65536", got)
	}
}

func TestSetTrackedPIDs(t *testing.T) {
	SetTrackedPIDs(42)
	if got := testutil.ToFloat64(TrackedPIDs); got != 42 {
		t.Errorf("TrackedPIDs = %v, want 42", got)
	}

	SetTrackedPIDs(0)
	if got := testutil.ToFloat64(TrackedPIDs); got != 0 {
		t.Errorf("TrackedPIDs after reset = %v, want 0", got)
	}
}
