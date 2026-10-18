package loadprobe

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func commOf(s string) (c [16]byte) { copy(c[:], s); return }

func TestLoadProbe_PrefixAndCount(t *testing.T) {
	if IsProbeComm(commOf("nginx")) || IsProbeComm(commOf("w8")) {
		t.Fatal("non-probe comm matched")
	}
	if !IsProbeComm(commOf("w88c3")) {
		t.Fatal("probe comm not matched")
	}
	RecordLoadProbe(commOf("w88ptest"), 0.01)
	RecordLoadProbe(commOf("w88ptest"), 0.02)
	if got := testutil.ToFloat64(loadProbeEvents.WithLabelValues("w88ptest")); got != 2 {
		t.Fatalf("count = %v, want 2", got)
	}
}

func TestLoadProbe_CardinalityBounded(t *testing.T) {
	for i := 0; i < loadProbeMaxNames+8; i++ {
		RecordLoadProbe(commOf("w88x"+string(rune('a'+i))), 0)
	}
	loadProbeMu.Lock()
	n := len(loadProbeNames)
	loadProbeMu.Unlock()
	if n > loadProbeMaxNames {
		t.Fatalf("names = %d, want <= %d", n, loadProbeMaxNames)
	}
}
