// Package correlator provides event correlation and rule-based detection.
package correlator

import (
	"math"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// beaconWindow is the trailing window over which connection timestamps to a
// single (pid, daddr, dport) destination are kept to judge periodicity. C2
// beacon intervals in the wild range from seconds to a few minutes; 5 minutes
// gives enough samples to compute a variance for anything faster than a
// once-a-minute beacon while staying well inside the wave 6.2 measurement
// window (600s) so the field is actually exercised by it.
const beaconWindow = 5 * time.Minute

// beaconMaxSamples bounds memory per destination key. Only the spacing
// between arrivals matters, not raw volume, so a small ring is enough — a
// beacon faster than one connection per second for 5 minutes is not the
// low-and-slow pattern this rule targets and conn_rate_1m already covers
// bursty high-frequency traffic.
const beaconMaxSamples = 64

// beaconInitialSamples is the ring size a key starts at; it doubles on demand
// up to beaconMaxSamples. Unlike ConnFrequencyTracker, whose key is
// (pid, dport), this tracker keys on (pid, daddr, dport) — one key per
// DESTINATION, so a node talking to many peers holds orders of magnitude more
// keys. Allocating the full ring up front would cost 1.5 KB for every key,
// and the overwhelming majority of them are the one-off connections finding
// №231 is about: they never hold more than a single timestamp.
const beaconInitialSamples = 4

// beaconMaxKeys bounds the number of tracked destinations between cleanup
// cycles. A process scanning a subnet would otherwise create a key per host
// probed; the agent runs against a 256 MiB DaemonSet limit with roughly 40 MB
// of headroom (wave 6.2.2, finding №244), which is not enough to leave this
// unbounded for the 10 minutes between Cleanup calls.
const beaconMaxKeys = 8192

// beaconKeysDroppedTotal counts connections not recorded because the tracker
// was at beaconMaxKeys and no stale key could be evicted. A non-zero value
// means conn_periodic_* went blind for those destinations — fail-closed (no
// periodicity claim), but a measurable quantity rather than a silent one.
var beaconKeysDroppedTotal = promauto.NewCounter(
	prometheus.CounterOpts{
		Name: "ebpf_guard_beacon_tracker_keys_dropped_total",
		Help: "Connections not recorded for periodicity because the beacon tracker was at its key cap",
	},
)

// beaconMinSamples is the minimum number of timestamps (i.e. 2 intervals)
// required before a coefficient of variation is considered meaningful. Below
// this, BeaconIntervalTracker reports beaconInsufficientDataCV so that a rule
// condition of the form "cv lt <threshold>" fails open (no periodicity claim
// without evidence) rather than treating "no data yet" as "perfectly
// regular".
const beaconMinSamples = 3

// beaconInsufficientDataCV is returned as the coefficient of variation when
// fewer than beaconMinSamples timestamps are on record. Chosen larger than
// any coefficient of variation a rule threshold would plausibly use (real CV
// is unbounded above but periodic-traffic thresholds sit well under 1.0), so
// "lt <threshold>" conditions correctly evaluate to false instead of
// mistaking absence of evidence for regularity.
const beaconInsufficientDataCV = 999.0

// BeaconIntervalTracker records connection attempt timestamps per
// (pid, daddr, dport) destination and computes the coefficient of variation
// (stddev/mean) of the inter-arrival intervals — a low CV means the
// connections recur at a regular cadence, which is what distinguishes an
// actual periodic C2 beacon (wave 6.2.2, finding №231) from a single
// one-off connection to a non-standard port, which the plain
// port/comm-allowlist condition it replaces could not tell apart.
type BeaconIntervalTracker struct {
	mu    sync.Mutex
	state map[beaconKey]*beaconState
}

type beaconKey struct {
	pid   uint32
	daddr [16]byte
	dport uint16
}

type beaconState struct {
	ring []time.Time // grown on demand from beaconInitialSamples to beaconMaxSamples
	head int
	size int
}

// NewBeaconIntervalTracker creates an empty tracker.
func NewBeaconIntervalTracker() *BeaconIntervalTracker {
	return &BeaconIntervalTracker{state: make(map[beaconKey]*beaconState)}
}

// globalBeaconInterval is the package-level tracker used by getFieldValue to
// evaluate the "conn_periodic_count_5m" / "conn_periodic_cv_5m" computed
// fields, mirroring globalConnFrequency.
var globalBeaconInterval = NewBeaconIntervalTracker()

func (b *BeaconIntervalTracker) prune(st *beaconState, now time.Time) {
	cutoff := now.Add(-beaconWindow)
	for st.size > 0 && st.ring[st.head].Before(cutoff) {
		st.head = (st.head + 1) % len(st.ring)
		st.size--
	}
}

// at returns the i-th oldest timestamp on record.
func (st *beaconState) at(i int) time.Time {
	return st.ring[(st.head+i)%len(st.ring)]
}

// push appends a timestamp, growing the ring up to beaconMaxSamples and, once
// there, overwriting the oldest entry so the window keeps sliding.
func (st *beaconState) push(now time.Time) {
	if st.size == len(st.ring) {
		if len(st.ring) >= beaconMaxSamples {
			st.ring[st.head] = now
			st.head = (st.head + 1) % len(st.ring)
			return
		}
		grown := make([]time.Time, min(max(beaconInitialSamples, 2*len(st.ring)), beaconMaxSamples))
		for i := 0; i < st.size; i++ {
			grown[i] = st.at(i)
		}
		st.ring, st.head = grown, 0
	}
	st.ring[(st.head+st.size)%len(st.ring)] = now
	st.size++
}

// Record registers a connection attempt at time now for (pid, daddr, dport).
func (b *BeaconIntervalTracker) Record(pid uint32, daddr [16]byte, dport uint16, now time.Time) {
	key := beaconKey{pid: pid, daddr: daddr, dport: dport}

	b.mu.Lock()
	defer b.mu.Unlock()

	st, ok := b.state[key]
	if !ok {
		if len(b.state) >= beaconMaxKeys && b.evictStale(now) == 0 {
			beaconKeysDroppedTotal.Inc()
			return
		}
		st = &beaconState{ring: make([]time.Time, beaconInitialSamples)}
		b.state[key] = st
	}

	b.prune(st, now)
	st.push(now)
}

// evictStale drops keys whose newest timestamp has fallen out of the window.
// Called only when the tracker hits its key cap between Cleanup cycles;
// b.mu must be held.
func (b *BeaconIntervalTracker) evictStale(now time.Time) int {
	cutoff := now.Add(-beaconWindow)
	removed := 0
	for key, st := range b.state {
		if st.size == 0 || st.at(st.size-1).Before(cutoff) {
			delete(b.state, key)
			removed++
		}
	}
	return removed
}

// Stats returns the number of timestamps on record for (pid, daddr, dport)
// within the trailing window, and the coefficient of variation of their
// inter-arrival intervals. When fewer than beaconMinSamples timestamps are
// present, cv is beaconInsufficientDataCV.
func (b *BeaconIntervalTracker) Stats(pid uint32, daddr [16]byte, dport uint16, now time.Time) (count int, cv float64) {
	key := beaconKey{pid: pid, daddr: daddr, dport: dport}

	b.mu.Lock()
	defer b.mu.Unlock()

	st, ok := b.state[key]
	if !ok {
		return 0, beaconInsufficientDataCV
	}

	b.prune(st, now)
	count = st.size
	if count < beaconMinSamples {
		return count, beaconInsufficientDataCV
	}

	// Two passes over the ring rather than a materialised []float64: Stats is
	// read once per rule condition on every TCP-connect event, and the slice
	// would be a heap allocation on that path for no benefit.
	n := float64(count - 1)
	var sum float64
	for i := 1; i < count; i++ {
		sum += st.at(i).Sub(st.at(i - 1)).Seconds()
	}
	mean := sum / n
	if mean <= 0 {
		// Timestamps collapsed onto the same instant (e.g. a burst faster
		// than the collector's timestamp resolution) — not a regular cadence.
		return count, beaconInsufficientDataCV
	}

	var variance float64
	for i := 1; i < count; i++ {
		d := st.at(i).Sub(st.at(i-1)).Seconds() - mean
		variance += d * d
	}
	variance /= n
	return count, math.Sqrt(variance) / mean
}

// Cleanup removes tracked keys with no activity in the last maxAge, bounding
// memory growth from short-lived PIDs. Intended to be called periodically
// alongside RateLimiter.Cleanup / ConnFrequencyTracker.Cleanup.
func (b *BeaconIntervalTracker) Cleanup(maxAge time.Duration) int {
	cutoff := time.Now().Add(-maxAge)
	b.mu.Lock()
	defer b.mu.Unlock()

	removed := 0
	for key, st := range b.state {
		if st.size == 0 || st.at(st.size-1).Before(cutoff) {
			delete(b.state, key)
			removed++
		}
	}
	return removed
}

// formatBeaconCount formats a sample count as a decimal string for use as a
// rule condition field value.
func formatBeaconCount(count int) string {
	return strconv.Itoa(count)
}

// formatBeaconCV formats a coefficient of variation as a decimal string for
// use as a rule condition field value.
func formatBeaconCV(cv float64) string {
	return strconv.FormatFloat(cv, 'f', 3, 64)
}
