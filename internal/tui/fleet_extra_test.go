//go:build tui

package tui

import (
	"testing"
	"time"
)

// TestMarkSeenEvictsOldest exercises the FIFO ring eviction path: once the
// dedup set exceeds fleetSeenLimit, the oldest key is evicted so the backing
// array never grows unbounded, yet re-seeing an evicted key counts as new.
func TestMarkSeenEvictsOldest(t *testing.T) {
	p := newAgentPoller("http://node:9090", "")

	// Fill exactly to the limit; every key is new.
	for i := 0; i < fleetSeenLimit; i++ {
		if !p.markSeen(key(i)) {
			t.Fatalf("key %d should be new on first insert", i)
		}
	}
	if len(p.ring) != fleetSeenLimit {
		t.Fatalf("ring should be full at %d, got %d", fleetSeenLimit, len(p.ring))
	}
	// A duplicate within the window is not new.
	if p.markSeen(key(fleetSeenLimit - 1)) {
		t.Error("recently seen key should not be reported new")
	}
	// One past the limit evicts the oldest (key 0) and does not grow the ring.
	if !p.markSeen(key(fleetSeenLimit)) {
		t.Error("new key past the limit should be reported new")
	}
	if len(p.ring) != fleetSeenLimit {
		t.Errorf("ring must not grow past the limit, got %d", len(p.ring))
	}
	// key(0) was evicted, so it now reads as new again.
	if !p.markSeen(key(0)) {
		t.Error("evicted key should be reported new when re-seen")
	}
}

func key(i int) string { return time.Unix(int64(i), 0).String() }
