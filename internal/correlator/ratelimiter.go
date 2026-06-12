// Package correlator provides event correlation and rule-based detection.
package correlator

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// RateLimiter implements per-rule alert rate limiting.
// Uses sync.Map for lock-free reads of existing rule states on the hot path.
// Config fields (window, maxAlerts, enabled) use atomics to avoid locks.
type RateLimiter struct {
	states sync.Map // map[string]*ruleState — lock-free reads via Load

	window    atomic.Int64 // time.Duration as int64
	maxAlerts atomic.Int32
	enabled   atomic.Bool
}

// ruleState tracks alert history for a single rule using a ring buffer.
// The ring buffer gives amortized O(1) allow() instead of O(n) scan.
type ruleState struct {
	mu       sync.Mutex
	ring     []time.Time // circular buffer; cap == maxCount
	head     int         // index of the oldest live entry
	size     int         // number of live entries
	window   time.Duration
	maxCount int
}

func newRuleState(window time.Duration, maxCount int) *ruleState {
	return &ruleState{
		ring:     make([]time.Time, maxCount),
		window:   window,
		maxCount: maxCount,
	}
}

// NewRateLimiter creates a new rate limiter with a background cleanup goroutine
// that runs until the process exits.
func NewRateLimiter(window time.Duration, maxAlerts int, enabled bool) *RateLimiter {
	return NewRateLimiterWithContext(context.Background(), window, maxAlerts, enabled)
}

// NewRateLimiterWithContext creates a rate limiter whose cleanup goroutine
// stops when ctx is cancelled.
func NewRateLimiterWithContext(ctx context.Context, window time.Duration, maxAlerts int, enabled bool) *RateLimiter {
	rl := &RateLimiter{}
	rl.window.Store(int64(window))
	rl.maxAlerts.Store(int32(maxAlerts))
	rl.enabled.Store(enabled)
	go rl.cleanupLoop(ctx)
	return rl
}

// cleanupLoop runs Cleanup every 5 minutes until ctx is cancelled.
func (rl *RateLimiter) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rl.Cleanup(10 * time.Minute)
		}
	}
}

// Allow checks if an alert should be allowed for the given rule.
// Returns true if the alert is within the rate limit.
// Hot path: lock-free Load for existing states; LoadOrStore for new ones.
func (rl *RateLimiter) Allow(ruleID string) bool {
	if !rl.enabled.Load() {
		return true
	}

	if v, ok := rl.states.Load(ruleID); ok {
		return v.(*ruleState).allow()
	}

	state := newRuleState(rl.windowDuration(), rl.maxAlertCount())
	actual, loaded := rl.states.LoadOrStore(ruleID, state)
	if loaded {
		return actual.(*ruleState).allow()
	}
	return state.allow()
}

// allow checks if an alert should be allowed (internal, called with state lock).
// Amortized O(1): expired entries are evicted from the ring head one by one.
func (rs *ruleState) allow() bool {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rs.window)

	for rs.size > 0 && rs.ring[rs.head].Before(cutoff) {
		rs.head = (rs.head + 1) % rs.maxCount
		rs.size--
	}

	if rs.size >= rs.maxCount {
		return false
	}

	tail := (rs.head + rs.size) % rs.maxCount
	rs.ring[tail] = now
	rs.size++
	return true
}

// GetCount returns the number of alerts in the current window for a rule.
func (rl *RateLimiter) GetCount(ruleID string) int {
	v, ok := rl.states.Load(ruleID)
	if !ok {
		return 0
	}
	return v.(*ruleState).count()
}

// count returns the number of entries within the window (internal).
func (rs *ruleState) count() int {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	if rs.size == 0 {
		return 0
	}

	now := time.Now()
	cutoff := now.Add(-rs.window)

	for i := 0; i < rs.size; i++ {
		if !rs.ring[(rs.head+i)%rs.maxCount].Before(cutoff) {
			return rs.size - i
		}
	}
	return 0
}

// Reset clears all rate limiter state.
func (rl *RateLimiter) Reset() {
	rl.states.Range(func(key, value any) bool {
		rl.states.Delete(key)
		return true
	})
}

// GetRuleIDs returns all tracked rule IDs.
func (rl *RateLimiter) GetRuleIDs() []string {
	var ids []string
	rl.states.Range(func(key, value any) bool {
		ids = append(ids, key.(string))
		return true
	})
	return ids
}

// StateCount returns the number of tracked rule states (for observability).
func (rl *RateLimiter) StateCount() int {
	count := 0
	rl.states.Range(func(key, value any) bool {
		count++
		return true
	})
	return count
}

// Cleanup removes state for rules that haven't had alerts recently.
// Collects stale entries under per-state locks, then deletes them from the map,
// keeping sync.Map operations minimal and avoiding iterator invalidation.
func (rl *RateLimiter) Cleanup(maxAge time.Duration) int {
	cutoff := time.Now().Add(-maxAge)
	var stale []string

	rl.states.Range(func(key, value any) bool {
		id := key.(string)
		state := value.(*ruleState)

		state.mu.Lock()
		hasRecent := state.size > 0 &&
			!state.ring[(state.head+state.size-1)%state.maxCount].Before(cutoff)
		state.mu.Unlock()

		if !hasRecent {
			stale = append(stale, id)
		}
		return true
	})

	for _, id := range stale {
		rl.states.Delete(id)
	}
	return len(stale)
}

// RateLimiterStats holds rate limiter statistics.
type RateLimiterStats struct {
	TotalRules    int
	TotalAlerts   int
	LimitedAlerts int
}

// GetStats returns statistics about the rate limiter.
func (rl *RateLimiter) GetStats() RateLimiterStats {
	stats := RateLimiterStats{}

	rl.states.Range(func(key, value any) bool {
		stats.TotalRules++
		state := value.(*ruleState)
		state.mu.Lock()
		stats.TotalAlerts += state.size
		state.mu.Unlock()
		return true
	})

	return stats
}

// SetEnabled enables or disables rate limiting.
func (rl *RateLimiter) SetEnabled(enabled bool) {
	rl.enabled.Store(enabled)
}

// IsEnabled returns whether rate limiting is enabled.
func (rl *RateLimiter) IsEnabled() bool {
	return rl.enabled.Load()
}

// UpdateConfig updates the rate limiter configuration.
// If maxAlerts changes the ring buffer for every existing state is resized,
// preserving as many recent entries as possible.
func (rl *RateLimiter) UpdateConfig(window time.Duration, maxAlerts int) {
	rl.window.Store(int64(window))
	rl.maxAlerts.Store(int32(maxAlerts))

	rl.states.Range(func(key, value any) bool {
		state := value.(*ruleState)
		state.mu.Lock()
		state.window = window
		if state.maxCount != maxAlerts {
			newRing := make([]time.Time, maxAlerts)
			keep := state.size
			if keep > maxAlerts {
				keep = maxAlerts
			}
			skip := state.size - keep
			for i := 0; i < keep; i++ {
				newRing[i] = state.ring[(state.head+skip+i)%state.maxCount]
			}
			state.ring = newRing
			state.head = 0
			state.size = keep
			state.maxCount = maxAlerts
		}
		state.mu.Unlock()
		return true
	})
}

// windowDuration returns the current window as time.Duration.
func (rl *RateLimiter) windowDuration() time.Duration {
	return time.Duration(rl.window.Load())
}

// maxAlertCount returns the current maxAlerts as int.
func (rl *RateLimiter) maxAlertCount() int {
	return int(rl.maxAlerts.Load())
}
