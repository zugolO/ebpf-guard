package exporter

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/zugolO/ebpf-guard/internal/bpf"
)

// TestRingbufWaitModeLabelsMatchBPF pins the duplicated mode names together.
// internal/bpf cannot import this package (exporter -> correlator, and
// correlator's in-package tests -> internal/bpf closes a cycle in that test
// binary), so the label values exist twice; a rename on one side would leave
// the gauge reporting a mode no emitter looks for, and the A/B would read as
// "mode not printed" rather than as a wrong value.
func TestRingbufWaitModeLabelsMatchBPF(t *testing.T) {
	if RingbufWaitModeBlocking != bpf.RingbufWaitModeBlocking {
		t.Fatalf("blocking label %q != %q", RingbufWaitModeBlocking, bpf.RingbufWaitModeBlocking)
	}
	if RingbufWaitModeNetpoll != bpf.RingbufWaitModeNetpoll {
		t.Fatalf("netpoll label %q != %q", RingbufWaitModeNetpoll, bpf.RingbufWaitModeNetpoll)
	}
	if RingbufFallbackUnsupported != bpf.RingbufFallbackUnsupported {
		t.Fatalf("unsupported reason %q != %q", RingbufFallbackUnsupported, bpf.RingbufFallbackUnsupported)
	}
	if RingbufFallbackWaitError != bpf.RingbufFallbackWaitError {
		t.Fatalf("wait_error reason %q != %q", RingbufFallbackWaitError, bpf.RingbufFallbackWaitError)
	}
}

// TestRingbufWaitSeriesAreMaterialized: every eligible collector must have both
// mode series and its park/fallback counters present at zero before anything
// happens, so a snapshot can never be read as "this binary predates the toggle"
// ([[metric-anchor-must-carry-full-series-name]]).
func TestRingbufWaitSeriesAreMaterialized(t *testing.T) {
	for _, c := range ringbufWaitCollectors {
		for _, m := range []string{RingbufWaitModeBlocking, RingbufWaitModeNetpoll} {
			if testutil.ToFloat64(RingbufWaitMode.WithLabelValues(c, m)) != 0 && testutil.ToFloat64(RingbufWaitMode.WithLabelValues(c, m)) != 1 {
				t.Fatalf("wait_mode{%s,%s} is not a reading", c, m)
			}
		}
		_ = testutil.ToFloat64(RingbufNetpollParks.WithLabelValues(c))
		for _, r := range []string{RingbufFallbackUnsupported, RingbufFallbackWaitError} {
			_ = testutil.ToFloat64(RingbufNetpollFallback.WithLabelValues(c, r))
		}
	}
}

// TestSetRingbufWaitMode_ExactlyOneBranchReadsOne: the two series are the only
// statement of which branch ran. Both at 1, or both at 0, would make an A/B
// window unattributable ([[toggle-needs-both-branches-counted]]).
func TestSetRingbufWaitMode_ExactlyOneBranchReadsOne(t *testing.T) {
	const c = "syscall"
	for _, want := range []string{RingbufWaitModeNetpoll, RingbufWaitModeBlocking} {
		SetRingbufWaitMode(c, want)
		sum := 0.0
		for _, m := range []string{RingbufWaitModeBlocking, RingbufWaitModeNetpoll} {
			v := testutil.ToFloat64(RingbufWaitMode.WithLabelValues(c, m))
			sum += v
			if m == want && v != 1 {
				t.Fatalf("mode %q reads %v, want 1", m, v)
			}
		}
		if sum != 1 {
			t.Fatalf("sum of mode series = %v, want exactly 1", sum)
		}
	}
	SetRingbufWaitMode(c, RingbufWaitModeBlocking)
}
