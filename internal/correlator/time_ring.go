package correlator

import "time"

// timeRingInitialSamples is the capacity a timeRing starts at. It doubles on
// demand up to the ring's cap.
//
// Wave 8.1 (stage E): ConnFrequencyTracker and BurstTracker used to allocate
// their full ring on the first sample — 1024 × time.Time = 24 KiB per
// (pid, dport) key and 256 × time.Time = 6 KiB per (rule, group) key. Almost
// every key belongs to a short-lived process that records one or two samples
// and exits, so one brute-force phase on ebaka2 left 888 + 1212 such rings
// (31 MB, 47% of the live heap) pinned until the 10-minute Cleanup. This is
// the same defect finding №245 fixed in BeaconIntervalTracker; the two trackers
// it was copied from kept it.
const timeRingInitialSamples = 4

// timeRing is a sliding window of timestamps, oldest first, that grows from
// timeRingInitialSamples up to max and then overwrites its oldest entry.
type timeRing struct {
	ring []time.Time
	head int
	size int
	max  int
}

func newTimeRing(max int) *timeRing {
	return &timeRing{ring: make([]time.Time, min(timeRingInitialSamples, max)), max: max}
}

// prune drops samples older than cutoff.
func (r *timeRing) prune(cutoff time.Time) {
	for r.size > 0 && r.ring[r.head].Before(cutoff) {
		r.head = (r.head + 1) % len(r.ring)
		r.size--
	}
}

// push appends now, growing the ring up to max and, once there, overwriting
// the oldest entry so the window keeps sliding instead of freezing at the cap.
func (r *timeRing) push(now time.Time) {
	if r.size == len(r.ring) {
		if len(r.ring) >= r.max {
			r.ring[r.head] = now
			r.head = (r.head + 1) % len(r.ring)
			return
		}
		grown := make([]time.Time, min(2*len(r.ring), r.max))
		for i := 0; i < r.size; i++ {
			grown[i] = r.ring[(r.head+i)%len(r.ring)]
		}
		r.ring, r.head = grown, 0
	}
	r.ring[(r.head+r.size)%len(r.ring)] = now
	r.size++
}

// newest returns the most recent sample; ok is false when the ring is empty.
func (r *timeRing) newest() (t time.Time, ok bool) {
	if r.size == 0 {
		return time.Time{}, false
	}
	return r.ring[(r.head+r.size-1)%len(r.ring)], true
}
