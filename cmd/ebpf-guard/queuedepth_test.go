package main

import (
	"math"
	"testing"
)

func TestCapQueueDepthByMemLimit(t *testing.T) {
	const podLimit = 89128960 // GOMEMLIMIT пода при limits.memory 192Mi (замер 18.10)
	cases := []struct {
		name    string
		depth   int
		limit   int64
		want    int
		lowered bool
	}{
		{"no limit (host) keeps 65536", 65536, math.MaxInt64, 65536, false},
		{"pod limit lowers 65536", 65536, podLimit, 7736 /* 85 МиБ × 0,05 / (2 × 288 Б) */, true},
		{"explicit small depth kept", 2048, podLimit, 2048, false},
		{"tiny limit floors at minQueueDepth", 65536, 8 << 20, minQueueDepth, true},
		{"non-positive depth untouched", 0, podLimit, 0, false},
	}
	for _, c := range cases {
		got, lowered := capQueueDepthByMemLimit(c.depth, c.limit)
		if got != c.want || lowered != c.lowered {
			t.Errorf("%s: got (%d, %v), want (%d, %v)", c.name, got, lowered, c.want, c.lowered)
		}
	}
	// Обе полные очереди не превышают долю предела.
	if d, _ := capQueueDepthByMemLimit(65536, podLimit); float64(2*d*queuedEventBytes) > queueMemShare*podLimit {
		t.Errorf("full queues %d B exceed %.0f%% of the limit", 2*d*queuedEventBytes, queueMemShare*100)
	}
}
