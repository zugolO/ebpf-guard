// Package exporter provides Prometheus metrics and Alertmanager alerting.
package exporter

import (
	"context"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// AlertSilencer provides alert silencing based on rules.
type AlertSilencer struct {
	mu      sync.RWMutex
	windows map[string]*silenceWindow

	// active mirrors len(windows) for a lock-free fast path in IsSilenced
	// (wave 6.3.L): the silencer sits on the per-alert dispatch path, and an
	// agent with no silence window configured — the overwhelming default —
	// must not pay a mutex per alert for a map that is empty. Every mutation
	// of windows updates it under the same lock.
	active atomic.Int64
}

// silenceWindow tracks a silence period for a specific alert key.
type silenceWindow struct {
	until   time.Time
	reason  string
}

// NewAlertSilencer creates a new alert silencer.
func NewAlertSilencer() *AlertSilencer {
	return &AlertSilencer{
		windows: make(map[string]*silenceWindow),
	}
}

// Silence silences alerts matching the given key for the specified duration.
func (s *AlertSilencer) Silence(key string, duration time.Duration, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	s.windows[key] = &silenceWindow{
		until:  time.Now().Add(duration),
		reason: reason,
	}
	s.active.Store(int64(len(s.windows)))
	
	slog.Info("exporter/silencer: alert silenced",
		slog.String("key", key),
		slog.Duration("duration", duration),
		slog.String("reason", reason))
}

// IsSilenced checks if an alert is currently silenced.
func (s *AlertSilencer) IsSilenced(alert types.Alert) bool {
	// Fast path: nothing is silenced, so no lock and no key building.
	if s.active.Load() == 0 {
		return false
	}
	key := s.makeKey(alert)
	
	// Use single full Lock to avoid TOCTOU race between check and delete
	s.mu.Lock()
	defer s.mu.Unlock()
	
	window, exists := s.windows[key]
	if !exists {
		return false
	}
	
	if time.Now().After(window.until) {
		// Window expired, clean it up
		delete(s.windows, key)
		s.active.Store(int64(len(s.windows)))
		return false
	}
	
	return true
}

// RemoveSilence manually removes a silence window.
func (s *AlertSilencer) RemoveSilence(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.windows, key)
	s.active.Store(int64(len(s.windows)))
}

// Cleanup removes expired silence windows.
func (s *AlertSilencer) Cleanup() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	now := time.Now()
	removed := 0
	
	for key, window := range s.windows {
		if now.After(window.until) {
			delete(s.windows, key)
			removed++
		}
	}
	s.active.Store(int64(len(s.windows)))

	return removed
}

// makeKey creates a silence key from an alert.
//
// Keyed on BaseRuleID(), not RuleID (wave 6.3.L, item 2, №414): silencer sits
// downstream of Rego enrichment, so alert.RuleID is already the renamed name
// by the time IsSilenced runs. A window an operator created against the base
// rule that actually fired (the only identity they could name in the current
// rules.local_tuning_path / feedback flow — the same base id
// feedback.FilterAlerts and rate limiter/dedup/drift baseline key on) must
// still gate the alert after Rego renames it, or the silence would stop
// working the moment Rego is enabled.
//
// The symmetric failure mode — a window created literally on the Rego-visible
// name silently expanding to gate every base rule that happens to share that
// name (nine, for dga_domain) — is made structurally impossible rather than
// merely avoided: IsSilenced never looks a window up by the renamed name, so
// a window keyed on it simply never matches anything. Widening a silence to
// cover a whole Rego-name family remains possible, but only by an operator
// explicitly enumerating those base rule_ids — never as a side effect of
// silencing one alert by the name they saw in the dashboard.
func (s *AlertSilencer) makeKey(alert types.Alert) string {
	return SilenceKey(alert.BaseRuleID(), alert.Severity)
}

// Start begins the background cleanup goroutine.
func (s *AlertSilencer) Start(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			removed := s.Cleanup()
			if removed > 0 {
				slog.Debug("exporter/silencer: cleaned up expired windows",
					slog.Int("removed", removed))
			}
		}
	}
}

// SilenceKey builds the silence key for a base rule id and severity. It is the
// ONE place outside makeKey that knows the key layout, so an operator-facing
// entry point (the HTTP handler) and the per-alert check can never drift apart:
// makeKey derives the same string from an alert's BaseRuleID.
func SilenceKey(baseRuleID string, severity types.Severity) string {
	return baseRuleID + ":" + string(severity)
}

// SilenceWindowInfo describes one active silence window.
type SilenceWindowInfo struct {
	Key    string    `json:"key"`
	Until  time.Time `json:"until"`
	Reason string    `json:"reason"`
}

// Windows returns the currently registered silence windows, expired ones
// included (Cleanup removes those) — sorted by key so the listing is stable.
func (s *AlertSilencer) Windows() []SilenceWindowInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]SilenceWindowInfo, 0, len(s.windows))
	for key, w := range s.windows {
		out = append(out, SilenceWindowInfo{Key: key, Until: w.until, Reason: w.reason})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// Active reports whether any silence window is registered. Callers on the
// per-alert path use it to skip the filtering loop entirely when no operator
// has silenced anything — the default state of every agent.
func (s *AlertSilencer) Active() bool {
	return s.active.Load() > 0
}
