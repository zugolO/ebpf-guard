package loadprobe

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Load probes (plan.md волна 8.8, Р0): known-rate processes whose comm starts
// with LoadProbeCommPrefix are counted by name where the correlator picks the
// event up, so a load run can compare "sent" (the probe's own count) with
// "seen" per process, and read the age of their events directly. Without it the
// protected-class and control-process criteria (8.8.3, 8.8.4) would be judged on
// the class-wide mixture, where the load generator's own protected events grow
// with the bulk it is meant to be isolated from.
//
// The check is three byte compares on the comm already in the event, so it is
// free for every other process. Cardinality is bounded: at most
// loadProbeMaxNames distinct comms get their own series.
const (
	LoadProbeCommPrefix = "w88"
	loadProbeMaxNames   = 16
)

var (
	loadProbeEvents = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ebpf_guard_load_probe_events_total",
		Help: "Events of load-probe processes (comm prefix w88) that reached an ingest worker, by comm.",
	}, []string{"probe"})

	loadProbeAge = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "ebpf_guard_load_probe_event_age_seconds",
		Help:    "Wall-clock age of load-probe events when an ingest worker picks them up, by comm.",
		Buckets: []float64{0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
	}, []string{"probe"})

	loadProbeMu    sync.Mutex
	loadProbeNames = map[string]struct{}{}
)

// IsProbeComm reports whether a NUL-padded comm names a load probe.
func IsProbeComm(comm [16]byte) bool {
	return comm[0] == 'w' && comm[1] == '8' && comm[2] == '8'
}

// RecordLoadProbe counts one probe event and observes its age (seconds).
func RecordLoadProbe(comm [16]byte, ageSeconds float64) {
	n := 0
	for n < len(comm) && comm[n] != 0 {
		n++
	}
	name := string(comm[:n])
	loadProbeMu.Lock()
	if _, ok := loadProbeNames[name]; !ok {
		if len(loadProbeNames) >= loadProbeMaxNames {
			loadProbeMu.Unlock()
			return
		}
		loadProbeNames[name] = struct{}{}
	}
	loadProbeMu.Unlock()
	loadProbeEvents.WithLabelValues(name).Inc()
	loadProbeAge.WithLabelValues(name).Observe(ageSeconds)
}
