// Package correlator provides event correlation and rule-based detection.
package correlator

import (
	"sync"
	"time"
)

// RateLimiter implements per-rule alert rate limiting.
type RateLimiter struct {
	mu sync.RWMutex

	// Configuration
	window     time.Duration // Time window for rate limiting
	maxAlerts  int           // Maximum alerts per window
	enabled    bool

	// State: map[ruleID] -> *ruleState
	states map[string]*ruleState
}

// ruleState tracks alert history for a single rule.
type ruleState struct {
	mu       sync.Mutex
	alerts   []time.Time // Timestamps of recent alerts
	window   time.Duration
	maxCount int
}

// NewRateLimiter creates a new rate limiter.
func NewRateLimiter(window time.Duration, maxAlerts int, enabled bool) *RateLimiter {
	return &RateLimiter{
		window:    window,
		maxAlerts: maxAlerts,
		enabled:   enabled,
		states:    make(map[string]*ruleState),
	}
}

// Allow checks if an alert should be allowed for the given rule.
// Returns true if the alert is within the rate limit.
func (rl *RateLimiter) Allow(ruleID string) bool {
	if !rl.enabled {
		return true
	}

	rl.mu.RLock()
	state, exists := rl.states[ruleID]
	rl.mu.RUnlock()

	if !exists {
		rl.mu.Lock()
		// Double-check after acquiring write lock
		state, exists = rl.states[ruleID]
		if !exists {
			state = &ruleState{
				window:   rl.window,
				maxCount: rl.maxAlerts,
			}
			rl.states[ruleID] = state
		}
		rl.mu.Unlock()
	}

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
		// If we reach the end without finding a valid timestamp, all are expired
		if i == len(rs.alerts)-1 {
			validStart = len(rs.alerts)
		}
	}
	rs.alerts = rs.alerts[validStart:]

	// Check if we can add another alert
	if len(rs.alerts) >= rs.maxCount {
		return false
	}

	// Record this alert
	rs.alerts = append(rs.alerts, now)
	return true
}

// GetCount returns the number of alerts in the current window for a rule.
func (rl *RateLimiter) GetCount(ruleID string) int {
	rl.mu.RLock()
	state, exists := rl.states[ruleID]
	rl.mu.RUnlock()

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

	// Count alerts within window
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
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	ids := make([]string, 0, len(rl.states))
	for id := range rl.states {
		ids = append(ids, id)
	}
	return ids
}

// Cleanup removes state for rules that haven't had alerts recently.
func (rl *RateLimiter) Cleanup(maxAge time.Duration) int {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-maxAge)
	removed := 0

	for id, state := range rl.states {
		state.mu.Lock()
		// Check if any recent alerts
		hasRecent := false
		for _, ts := range state.alerts {
			if ts.After(cutoff) {
				hasRecent = true
				break
			}
		}
		state.mu.Unlock()

		if !hasRecent {
			delete(rl.states, id)
			removed++
		}
	}

	return removed
}

// Stats holds rate limiter statistics.
type RateLimiterStats struct {
	TotalRules    int
	TotalAlerts   int
	LimitedAlerts int
}

// GetStats returns statistics about the rate limiter.
func (rl *RateLimiter) GetStats() RateLimiterStats {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

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
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	return rl.enabled
}

// UpdateConfig updates the rate limiter configuration.
func (rl *RateLimiter) UpdateConfig(window time.Duration, maxAlerts int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.window = window
	rl.maxAlerts = maxAlerts

	// Update existing states
	for _, state := range rl.states {
		state.mu.Lock()
		state.window = window
		state.maxCount = maxAlerts
		state.mu.Unlock()
	}
}
