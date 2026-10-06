package correlator

import (
	"math/rand"
	"testing"
	"time"
)

// refWindowCount is the reference the trackers must match: the number of
// samples within the trailing window, capped at max (the cap keeps the newest).
func refWindowCount(samples []time.Time, now time.Time, window time.Duration, max int) int {
	cutoff := now.Add(-window)
	n := 0
	for i := len(samples) - 1; i >= 0 && n < max; i-- {
		if samples[i].Before(cutoff) {
			break
		}
		n++
	}
	return n
}

// TestTimeRing_MatchesFullRingCounts drives the lazily grown ring with random
// arrival gaps and checks every returned count against the reference, across
// growth, the cap and wrap-around — the count is what conn_rate_1m and the
// threshold operator compare, so lazy growth must not change it (wave 8.1).
func TestTimeRing_MatchesFullRingCounts(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	const window = 60 * time.Second
	for _, max := range []int{1, 3, 4, 5, 64, 256, 1024} {
		r := newTimeRing(max)
		var all []time.Time
		now := time.Unix(1_700_000_000, 0)
		for i := 0; i < 5000; i++ {
			// Mostly dense bursts, sometimes a gap longer than the window.
			gap := time.Duration(rng.Intn(200)) * time.Millisecond
			if rng.Intn(500) == 0 {
				gap = 2 * window
			}
			now = now.Add(gap)
			all = append(all, now)
			r.prune(now.Add(-window))
			r.push(now)
			if want := refWindowCount(all, now, window, max); r.size != want {
				t.Fatalf("max=%d step=%d: size=%d, want %d", max, i, r.size, want)
			}
			if last, ok := r.newest(); !ok || !last.Equal(now) {
				t.Fatalf("max=%d step=%d: newest=%v ok=%v, want %v", max, i, last, ok, now)
			}
		}
	}
}

// TestConnFrequencyTracker_OneShotKeyStaysSmall pins the memory fix: a key
// that records one connection — the short-lived curl of a brute-force phase —
// must not hold the 1024-slot (24 KiB) ring it used to allocate up front.
func TestConnFrequencyTracker_OneShotKeyStaysSmall(t *testing.T) {
	c := NewConnFrequencyTracker()
	now := time.Now()
	for pid := uint32(1); pid <= 1000; pid++ {
		c.Record(pid, 3000, now)
	}
	for k, st := range c.state {
		if len(st.ring) > timeRingInitialSamples {
			t.Fatalf("key %+v: ring len %d after one sample, want <= %d", k, len(st.ring), timeRingInitialSamples)
		}
	}
	// A hot key still reaches the cap.
	for i := 0; i < 2*connFreqMaxSamples; i++ {
		c.Record(42, 22, now)
	}
	if got := c.Rate(42, 22, now); got != connFreqMaxSamples {
		t.Fatalf("hot key rate = %d, want cap %d", got, connFreqMaxSamples)
	}
}

// TestBurstTracker_CleanupDropsKeyPastOwnWindow checks that a (rule, group)
// key is evicted once its newest match is older than twice its own window,
// instead of surviving the full maxAge passed by the engine ticker.
func TestBurstTracker_CleanupDropsKeyPastOwnWindow(t *testing.T) {
	b := NewBurstTracker()
	now := time.Now()
	b.Record("short", 1, now.Add(-30*time.Second), 10*time.Second) // 30s > 2×10s → stale
	b.Record("long", 1, now.Add(-30*time.Second), time.Minute)     // 30s < 2×60s → kept
	if removed := b.Cleanup(10 * time.Minute); removed != 1 {
		t.Fatalf("removed %d, want 1", removed)
	}
	if _, ok := b.state[burstKey{ruleID: "long", group: 1}]; !ok {
		t.Fatal("key within its window was evicted")
	}
}
