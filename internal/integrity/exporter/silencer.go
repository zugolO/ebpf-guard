// Package exporter provides Prometheus metrics and Alertmanager alerting.
package exporter

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/ebpf-guard/ebpf-guard/pkg/types"
)

// AlertSilencer provides alert silencing based on rules.
type AlertSilencer struct {
	mu        sync.RWMutex
	windows   map[string]*silenceWindow
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
	
	slog.Info("exporter/silencer: alert silenced",
		slog.String("key", key),
		slog.Duration("duration", duration),
		slog.String("reason", reason))
}

// IsSilenced checks if an alert is currently silenced.
func (s *AlertSilencer) IsSilenced(alert types.Alert) bool {
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
		return false
	}
	
	return true
}

// RemoveSilence manually removes a silence window.
func (s *AlertSilencer) RemoveSilence(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.windows, key)
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
	
	return removed
}

// makeKey creates a silence key from an alert.
func (s *AlertSilencer) makeKey(alert types.Alert) string {
	return alert.RuleID + ":" + string(alert.Severity)
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
