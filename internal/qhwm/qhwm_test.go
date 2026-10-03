package qhwm

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestTracker_PeakSurvivesDrainAndAgesOut(t *testing.T) {
	tr, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	depth := 0
	tr.Track("q", func() int { return depth }, func() int { return 100 })

	depth = 80 // burst seen by one sample, then drained
	tr.sample()
	depth = 0
	for i := 0; i < 10; i++ {
		tr.sample()
	}
	if got := testutil.ToFloat64(tr.window.WithLabelValues("q")); got != 80 {
		t.Fatalf("window hwm after drain = %v, want 80", got)
	}
	if got := testutil.ToFloat64(tr.capacity.WithLabelValues("q")); got != 100 {
		t.Fatalf("capacity = %v, want 100", got)
	}

	// Five full minutes later the burst has left the trailing window, but the
	// lifetime peak keeps it.
	for i := 0; i < bucketCount*samplesPerBucket; i++ {
		tr.sample()
	}
	if got := testutil.ToFloat64(tr.window.WithLabelValues("q")); got != 0 {
		t.Fatalf("window hwm after 5 min = %v, want 0", got)
	}
	if got := testutil.ToFloat64(tr.lifetime.WithLabelValues("q")); got != 80 {
		t.Fatalf("lifetime hwm = %v, want 80", got)
	}
}

func TestTracker_NilSafe(t *testing.T) {
	var tr *Tracker
	tr.Track("q", func() int { return 0 }, nil)
}
