// Package correlator provides event correlation and rule-based detection.
package correlator

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRateLimiter_Allow(t *testing.T) {
	// Create rate limiter: max 3 alerts per 100ms
	rl := NewRateLimiter(100*time.Millisecond, 3, true)

	ruleID := "test_rule"

	// First 3 alerts should be allowed
	assert.True(t, rl.Allow(ruleID))
	assert.True(t, rl.Allow(ruleID))
	assert.True(t, rl.Allow(ruleID))

	// 4th alert should be denied
	assert.False(t, rl.Allow(ruleID))

	// Different rule should still be allowed
	assert.True(t, rl.Allow("other_rule"))
}

func TestRateLimiter_Disabled(t *testing.T) {
	rl := NewRateLimiter(100*time.Millisecond, 1, false)

	// Should always allow when disabled
	for i := 0; i < 10; i++ {
		assert.True(t, rl.Allow("test_rule"))
	}
}

func TestRateLimiter_WindowExpiration(t *testing.T) {
	rl := NewRateLimiter(50*time.Millisecond, 2, true)

	ruleID := "test_rule"

	// Use up the quota
	assert.True(t, rl.Allow(ruleID))
	assert.True(t, rl.Allow(ruleID))
	assert.False(t, rl.Allow(ruleID))

	// Wait for window to expire
	time.Sleep(60 * time.Millisecond)

	// Should be allowed again
	assert.True(t, rl.Allow(ruleID))
}

func TestRateLimiter_GetCount(t *testing.T) {
	rl := NewRateLimiter(100*time.Millisecond, 5, true)

	ruleID := "test_rule"

	// Initially 0
	assert.Equal(t, 0, rl.GetCount(ruleID))

	// Add alerts
	rl.Allow(ruleID)
	rl.Allow(ruleID)
	assert.Equal(t, 2, rl.GetCount(ruleID))

	// Different rule
	assert.Equal(t, 0, rl.GetCount("other_rule"))
}

func TestRateLimiter_Reset(t *testing.T) {
	rl := NewRateLimiter(100*time.Millisecond, 2, true)

	ruleID := "test_rule"

	// Use up quota
	rl.Allow(ruleID)
	rl.Allow(ruleID)
	assert.False(t, rl.Allow(ruleID))

	// Reset
	rl.Reset()

	// Should be allowed again
	assert.True(t, rl.Allow(ruleID))
	assert.Equal(t, 1, rl.GetCount(ruleID))
}

func TestRateLimiter_GetRuleIDs(t *testing.T) {
	rl := NewRateLimiter(100*time.Millisecond, 5, true)

	// Initially empty
	assert.Empty(t, rl.GetRuleIDs())

	// Add alerts for different rules
	rl.Allow("rule1")
	rl.Allow("rule2")
	rl.Allow("rule3")

	ids := rl.GetRuleIDs()
	assert.Len(t, ids, 3)
	assert.Contains(t, ids, "rule1")
	assert.Contains(t, ids, "rule2")
	assert.Contains(t, ids, "rule3")
}

func TestRateLimiter_Cleanup(t *testing.T) {
	rl := NewRateLimiter(100*time.Millisecond, 5, true)

	// Add alerts
	rl.Allow("rule1")
	rl.Allow("rule2")

	// Wait a bit
	time.Sleep(50 * time.Millisecond)

	// Add more recent alert
	rl.Allow("rule3")

	// Cleanup old rules (older than 30ms)
	removed := rl.Cleanup(30 * time.Millisecond)
	assert.Equal(t, 2, removed)

	// rule3 should still exist
	ids := rl.GetRuleIDs()
	assert.Len(t, ids, 1)
	assert.Contains(t, ids, "rule3")
}

func TestRateLimiter_GetStats(t *testing.T) {
	rl := NewRateLimiter(100*time.Millisecond, 5, true)

	// Add alerts
	rl.Allow("rule1")
	rl.Allow("rule1")
	rl.Allow("rule2")

	stats := rl.GetStats()
	assert.Equal(t, 2, stats.TotalRules)
	assert.Equal(t, 3, stats.TotalAlerts)
}

func TestRateLimiter_SetEnabled(t *testing.T) {
	rl := NewRateLimiter(100*time.Millisecond, 1, true)

	// Use up quota
	rl.Allow("rule")
	assert.False(t, rl.Allow("rule"))

	// Disable rate limiting
	rl.SetEnabled(false)
	assert.False(t, rl.IsEnabled())

	// Should now allow
	assert.True(t, rl.Allow("rule"))
	assert.True(t, rl.Allow("rule"))

	// Re-enable
	rl.SetEnabled(true)
	assert.True(t, rl.IsEnabled())

	// Should still respect the limit
	assert.False(t, rl.Allow("rule"))
}

func TestRateLimiter_UpdateConfig(t *testing.T) {
	rl := NewRateLimiter(100*time.Millisecond, 2, true)

	ruleID := "test_rule"

	// Use up initial quota
	rl.Allow(ruleID)
	rl.Allow(ruleID)
	assert.False(t, rl.Allow(ruleID))

	// Increase limit
	rl.UpdateConfig(100*time.Millisecond, 5)

	// Should allow more alerts now
	assert.True(t, rl.Allow(ruleID))
	assert.True(t, rl.Allow(ruleID))
	assert.True(t, rl.Allow(ruleID))
}

func TestRateLimiter_ConcurrentAccess(t *testing.T) {
	rl := NewRateLimiter(1*time.Second, 100, true)

	// Concurrent allows from multiple goroutines
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 10; j++ {
				rl.Allow("concurrent_rule")
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Should have exactly 100 alerts (the limit)
	assert.Equal(t, 100, rl.GetCount("concurrent_rule"))
}

// TestRateLimiterNoDuplicateState verifies that two concurrent Allow() calls for a new
// ruleID create exactly one ruleState entry (no double-create race).
func TestRateLimiterNoDuplicateState(t *testing.T) {
	rl := NewRateLimiterWithContext(context.Background(), 1*time.Second, 1000, true)

	const ruleID = "new_rule"
	const goroutines = 50

	var wg sync.WaitGroup
	start := make(chan struct{})

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			<-start
			rl.Allow(ruleID)
		}()
	}

	close(start)
	wg.Wait()

	// All goroutines targeted the same ruleID — there must be exactly one state entry.
	assert.Equal(t, 1, rl.StateCount(), "expected exactly one ruleState for %q", ruleID)
	assert.Equal(t, goroutines, rl.GetCount(ruleID))
}

// BenchmarkRateLimiterCleanup measures Cleanup with many stale entries.
func BenchmarkRateLimiterCleanup(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		rl := NewRateLimiterWithContext(context.Background(), time.Second, 1000, true)
		for j := 0; j < 500; j++ {
			rl.Allow(fmt.Sprintf("rule_%d", j))
		}
		b.StartTimer()
		rl.Cleanup(0) // maxAge=0 makes all entries stale
	}
}

// TestRateLimiterCleanupRemovesExpired verifies that Cleanup deletes stale entries.
func TestRateLimiterCleanupRemovesExpired(t *testing.T) {
	rl := NewRateLimiterWithContext(context.Background(), 1*time.Second, 10, true)

	rl.Allow("old_rule")
	rl.Allow("old_rule2")

	// Wait so alerts age past the cleanup threshold
	time.Sleep(60 * time.Millisecond)

	// Add a fresh entry after the sleep
	rl.Allow("fresh_rule")

	removed := rl.Cleanup(50 * time.Millisecond)
	assert.Equal(t, 2, removed)

	ids := rl.GetRuleIDs()
	assert.Len(t, ids, 1)
	assert.Contains(t, ids, "fresh_rule")
}
