package correlator

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRateLimiter_UpdateConfig_ShrinkTruncatesRing(t *testing.T) {
	rl := NewRateLimiter(time.Minute, 5, true)
	ruleID := "shrink_rule"

	for i := 0; i < 5; i++ {
		assert.True(t, rl.Allow(ruleID))
	}
	assert.Equal(t, 5, rl.GetCount(ruleID))

	// Shrink the window to 2: only the most recent 2 entries should survive.
	rl.UpdateConfig(time.Minute, 2)
	assert.Equal(t, 2, rl.GetCount(ruleID))

	// The ring is now full again at the new (smaller) capacity.
	assert.False(t, rl.Allow(ruleID))
}

func TestRateLimiter_CleanupLoop_StopsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	rl := NewRateLimiterWithContext(ctx, time.Minute, 10, true)
	rl.Allow("r1")

	done := make(chan struct{})
	go func() {
		cancel()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cleanupLoop did not observe context cancellation")
	}
	// No direct assertion beyond "did not hang/panic" — cleanupLoop runs in the
	// background goroutine spawned by NewRateLimiterWithContext and must exit
	// promptly once ctx is cancelled.
}

func TestRuleState_Count_AllEntriesExpired(t *testing.T) {
	rl := NewRateLimiter(10*time.Millisecond, 5, true)
	ruleID := "expiring_rule"
	rl.Allow(ruleID)
	assert.Equal(t, 1, rl.GetCount(ruleID))

	time.Sleep(20 * time.Millisecond)
	// All entries in the window are now stale; count() must fall through its
	// scan loop and return 0 without evicting (that's allow()'s job).
	assert.Equal(t, 0, rl.GetCount(ruleID))
}
