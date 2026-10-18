package main

import "time"

// Visibility degradation by loss RATE (plan.md волна 8.8, Р1).
//
// The old rule — "any drop in the last 5 s" — flipped /health to degraded on a
// single lost event: Е6 steps that Е6 itself calls loss-free (311 drops in 2.8 M
// events) read degraded, while a real overload read the same flag with no way to
// tell its size. A class is degraded when its loss over a sliding window is
// material: protected (network/dns/syscall — a security-signal loss) on ANY
// drop, bulk (file — volume shedding) once the dropped share of the window
// reaches bulkLossFractionThreshold with at least bulkLossMinDrops events.
// The state is held for degradationHold after the condition last held, so a
// bursty loss does not flap between scrapes.
const (
	lossWindow                = 10 // seconds, one sample per tick
	bulkLossFractionThreshold = 0.01
	bulkLossMinDrops          = 10
	degradationHold           = 5 * time.Second
)

type lossSample struct{ dropped, accepted int64 }

// lossTracker keeps per-second (dropped, accepted) deltas of one queue class.
type lossTracker struct {
	ring [lossWindow]lossSample
	n    int // samples recorded, capped at lossWindow
	next int
	// lastBad is when the class last met its degradation condition.
	lastBad time.Time
}

// observe records one tick's deltas and returns the window totals.
func (t *lossTracker) observe(dropped, accepted int64) (wDropped, wAccepted int64) {
	if dropped < 0 {
		dropped = 0
	}
	if accepted < 0 {
		accepted = 0
	}
	t.ring[t.next] = lossSample{dropped, accepted}
	t.next = (t.next + 1) % lossWindow
	if t.n < lossWindow {
		t.n++
	}
	for i := 0; i < t.n; i++ {
		wDropped += t.ring[i].dropped
		wAccepted += t.ring[i].accepted
	}
	return
}

// degraded reports whether the class counts as degraded at now, given the
// window totals; protected selects the any-drop rule.
func (t *lossTracker) degraded(now time.Time, protected bool, wDropped, wAccepted int64) bool {
	bad := false
	if protected {
		bad = wDropped > 0
	} else {
		bad = wDropped >= bulkLossMinDrops && lossFraction(wDropped, wAccepted) >= bulkLossFractionThreshold
	}
	if bad {
		t.lastBad = now
	}
	return !t.lastBad.IsZero() && now.Sub(t.lastBad) < degradationHold
}
