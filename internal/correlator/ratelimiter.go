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

// ruleState tracks alert history for a single rule.
type ruleState struct {
	mu       sync.Mutex
	alerts   []time.Time
	window   time.Duration
	maxCount int
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
		state = &ruleState{
			window:   rl.window,
			maxCount: rl.maxAlerts,
		}
		rl.states[ruleID] = state
	}
	rl.mu.Unlock()

	return state.allow()
}

// allow checks if an alert should be allowed (internal, called with state lock).
func (rs *ruleState) allow() bool {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rs.window)

	// Remove old alerts outside the window
	validStart := 0
	for i, ts := range rs.alerts {
		if ts.After(cutoff) || ts.Equal(cutoff) {
			validStart = i
			break
		}
		if i == len(rs.alerts)-1 {
			validStart = len(rs.alerts)
		}
	}
	rs.alerts = rs.alerts[validStart:]

	if len(rs.alerts) >= rs.maxCount {
		return false
	}

	rs.alerts = append(rs.alerts, now)
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

// count returns the current count (internal, called with state lock).
func (rs *ruleState) count() int {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rs.window)

	count := 0
	for _, ts := range rs.alerts {
		if ts.After(cutoff) {
			count++
		}
	}
	return count
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
// iterating per-state slices.
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
		hasRecent := false
		for _, ts := range state.alerts {
			if ts.After(cutoff) {
				hasRecent = true
				break
			}
		}
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
		stats.TotalAlerts += len(state.alerts)
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
func (rl *RateLimiter) UpdateConfig(window time.Duration, maxAlerts int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.window = window
	rl.maxAlerts = maxAlerts

	for _, state := range rl.states {
		state.mu.Lock()
		state.window = window
		state.maxCount = maxAlerts
		state.mu.Unlock()
	}
}
