package exporter

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Wave 8.1 item 6 — the ring buffer wait path, and the three series that make
// its A/B readable.
//
// The measured quantity is sysmon's wakeup rate (2678 nanosleep/s, 16,8% of the
// agent's CPU), and it is readable only from outside the process — bpftrace on
// nanosleep. These series do not restate it; they answer what an outside
// reading cannot: WHICH branch each collector ran, and whether the new branch
// was exercised at all. Without them "the rate did not move" has two causes
// that look identical from the trace — the fix is wrong, or the fix never ran
// ([[toggle-needs-both-branches-counted]], [[gated-metric-cannot-carry-product-verdict]]).
const (
	// RingbufWaitModeBlocking / RingbufWaitModeNetpoll mirror the constants in
	// internal/bpf. They are duplicated rather than imported because
	// internal/bpf must not import this package (exporter -> correlator, and
	// correlator's in-package tests -> internal/bpf closes a cycle);
	// TestRingbufWaitModeLabelsMatchBPF pins the two copies together.
	RingbufWaitModeBlocking = "blocking"
	RingbufWaitModeNetpoll  = "netpoll"

	// RingbufFallbackUnsupported: the fd or the platform cannot be polled, the
	// netpoll path never started. RingbufFallbackWaitError: it started and was
	// abandoned. Two bounded values, because the free-form error text belongs
	// in the log and not in a metric label.
	RingbufFallbackUnsupported = "unsupported"
	RingbufFallbackWaitError   = "wait_error"
)

// ringbufWaitCollectors are the collectors whose readers can take the netpoll
// path. The syscall/fileaccess/network rings are the ones that empty and refill
// on an idle node (~587 blocking epoll_wait/s between them); the rest hold a
// single blocking wait for the whole life of the process and cost one sysmon
// wake each, not a stream of them.
var ringbufWaitCollectors = []string{"syscall", "fileaccess", "network"}

var (
	// RingbufWaitMode is 1 for the branch a collector's reader actually runs
	// and 0 for the other. Both series exist for every eligible collector from
	// init, so a snapshot always names the branch — a config file and a source
	// read are not a reading of the runtime
	// ([[entry-guard-must-read-runtime-not-config]]).
	RingbufWaitMode = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ebpf_guard_ringbuf_wait_mode",
			Help: "1 for the ring buffer wait path a collector's reader is running, 0 for the other (blocking = epoll_wait inside cilium/ebpf, netpoll = parked on the Go runtime poller, wave 8.1 item 6).",
		},
		[]string{"collector", "mode"},
	)

	// RingbufNetpollParks counts parks on the netpoll path — one per transition
	// to an empty ring, i.e. exactly the events that were blocking syscalls
	// before. It counts NOTHING on the blocking path by construction (the wait
	// happens inside the kernel, below this code), which is why the series is
	// named for the path and not for the quantity: a zero here means "the
	// netpoll path did not park", never "the reader did not wait".
	RingbufNetpollParks = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_guard_ringbuf_netpoll_parks_total",
			Help: "Parks on the netpoll ring buffer wait path, one per empty-ring transition. Counts only on mode=netpoll; a zero while that mode is active means the path never parked.",
		},
		[]string{"collector"},
	)

	// RingbufNetpollFallback counts readers that asked for the netpoll path and
	// did not get it, or lost it. Nonzero means the A/B's ON window is partly
	// or wholly the OFF branch, and the full reason is in the log next to it.
	RingbufNetpollFallback = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_guard_ringbuf_netpoll_fallback_total",
			Help: "Readers that fell back from the netpoll ring buffer wait path to the blocking one: unsupported = never started (fd or platform), wait_error = started and abandoned.",
		},
		[]string{"collector", "reason"},
	)
)

func init() {
	for _, c := range ringbufWaitCollectors {
		RingbufWaitMode.WithLabelValues(c, RingbufWaitModeBlocking)
		RingbufWaitMode.WithLabelValues(c, RingbufWaitModeNetpoll)
		RingbufNetpollParks.WithLabelValues(c)
		RingbufNetpollFallback.WithLabelValues(c, RingbufFallbackUnsupported)
		RingbufNetpollFallback.WithLabelValues(c, RingbufFallbackWaitError)
	}
}

// SetRingbufWaitMode records the branch a reader actually took: 1 for mode, 0
// for every other known branch, so the two series can never both read 1.
func SetRingbufWaitMode(collector, mode string) {
	for _, m := range []string{RingbufWaitModeBlocking, RingbufWaitModeNetpoll} {
		v := 0.0
		if m == mode {
			v = 1.0
		}
		RingbufWaitMode.WithLabelValues(collector, m).Set(v)
	}
}

// RecordRingbufNetpollPark counts one park on the netpoll path.
func RecordRingbufNetpollPark(collector string) {
	RingbufNetpollParks.WithLabelValues(collector).Inc()
}

// RecordRingbufNetpollFallback counts one reader giving up the netpoll path.
func RecordRingbufNetpollFallback(collector, reason string) {
	RingbufNetpollFallback.WithLabelValues(collector, reason).Inc()
}
