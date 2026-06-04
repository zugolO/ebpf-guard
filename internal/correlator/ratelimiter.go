// Package correlator provides event correlation and rule-based detection.
package correlator

import (
	"context"
	"sync"
	"time"
)

// RateLimiter implements per-rule alert rate limiting.
type RateLimiter struct {
	mu sync.Mutex // single mutex: eliminates double-checked locking race

	// Configuration
	window    time.Duration
	maxAlerts int
	enabled   bool

	// State: map[ruleID] -> *ruleState
	states map[string]*ruleState
}

// ruleState tracks alert history for a single rule using a ring buffer.
// The ring buffer gives amortized O(1) allow() instead of the previous O(n)
// linear scan over a growing []time.Time slice.
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
	rl := &RateLimiter{
		window:    window,
		maxAlerts: maxAlerts,
		enabled:   enabled,
		states:    make(map[string]*ruleState),
	}
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
func (rl *RateLimiter) Allow(ruleID string) bool {
	if !rl.enabled {
		return true
	}

	rl.mu.Lock()
	state, exists := rl.states[ruleID]
	if !exists {
		state = newRuleState(rl.window, rl.maxAlerts)
		rl.states[ruleID] = state
	}
	rl.mu.Unlock()

	return state.allow()
}

// allow checks if an alert should be allowed (internal, called with state lock).
// Amortized O(1): expired entries are evicted from the ring head one by one.
func (rs *ruleState) allow() bool {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rs.window)

	// Evict entries from the head that have left the window.
	// Since entries are appended in chronological order the head is always
	// the oldest, so this loop terminates in O(expired) ≈ O(1) amortized.
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
	rl.mu.Lock()
	state, exists := rl.states[ruleID]
	rl.mu.Unlock()

	if !exists {
		return 0
	}

	return state.count()
}

// count returns the number of entries within the window (internal).
// Entries are time-ordered, so we stop as soon as we hit the first recent one
// and return the rest of the ring as in-window.
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
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.states = make(map[string]*ruleState)
}

// GetRuleIDs returns all tracked rule IDs.
func (rl *RateLimiter) GetRuleIDs() []string {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	ids := make([]string, 0, len(rl.states))
	for id := range rl.states {
		ids = append(ids, id)
	}
	return ids
}

// StateCount returns the number of tracked rule states (for observability).
func (rl *RateLimiter) StateCount() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return len(rl.states)
}

// Cleanup removes state for rules that haven't had alerts recently.
// Fine-grained locking: snapshot the map under rl.mu, then check each
// state under its own mutex (rl.mu released), then delete stale entries
// under rl.mu again. This avoids holding the global map lock while
// iterating per-state rings.
func (rl *RateLimiter) Cleanup(maxAge time.Duration) int {
	rl.mu.Lock()
	snapshot := make(map[string]*ruleState, len(rl.states))
	for id, s := range rl.states {
		snapshot[id] = s
	}
	rl.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	var stale []string
	for id, state := range snapshot {
		state.mu.Lock()
		// The last entry in the ring is the most recent one — O(1) check.
		hasRecent := state.size > 0 &&
			!state.ring[(state.head+state.size-1)%state.maxCount].Before(cutoff)
		state.mu.Unlock()
		if !hasRecent {
			stale = append(stale, id)
		}
	}

	if len(stale) == 0 {
		return 0
	}

	rl.mu.Lock()
	for _, id := range stale {
		delete(rl.states, id)
	}
	removed := len(stale)
	rl.mu.Unlock()
	return removed
}

// RateLimiterStats holds rate limiter statistics.
type RateLimiterStats struct {
	TotalRules    int
	TotalAlerts   int
	LimitedAlerts int
}

// GetStats returns statistics about the rate limiter.
func (rl *RateLimiter) GetStats() RateLimiterStats {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	stats := RateLimiterStats{
		TotalRules: len(rl.states),
	}

	for _, state := range rl.states {
		state.mu.Lock()
		stats.TotalAlerts += state.size
		state.mu.Unlock()
	}

	return stats
}

// SetEnabled enables or disables rate limiting.
func (rl *RateLimiter) SetEnabled(enabled bool) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.enabled = enabled
}

// IsEnabled returns whether rate limiting is enabled.
func (rl *RateLimiter) IsEnabled() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return rl.enabled
}

// UpdateConfig updates the rate limiter configuration.
// If maxAlerts changes the ring buffer for every existing state is resized,
// preserving as many recent entries as possible.
func (rl *RateLimiter) UpdateConfig(window time.Duration, maxAlerts int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.window = window
	rl.maxAlerts = maxAlerts

	for _, state := range rl.states {
		state.mu.Lock()
		state.window = window
		if state.maxCount != maxAlerts {
			newRing := make([]time.Time, maxAlerts)
			// Keep the min(maxAlerts, size) most recent entries.
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
	}
}
