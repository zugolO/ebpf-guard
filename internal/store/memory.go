// Package store provides in-memory implementations for testing.
package store

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// MemoryStore is an in-memory AlertStore implementation for testing.
type MemoryStore struct {
	mu     sync.RWMutex
	alerts map[string]types.Alert
	seq    int64
}

// NewMemoryStore creates a new in-memory alert store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		alerts: make(map[string]types.Alert),
	}
}

// Store persists a single alert.
func (s *MemoryStore) Store(ctx context.Context, alert types.Alert) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if alert.ID == "" {
		s.seq++
		alert.ID = fmt.Sprintf("mem-%d", s.seq)
	}
	if alert.Timestamp.IsZero() {
		alert.Timestamp = time.Now()
	}

	s.alerts[alert.ID] = alert
	return nil
}

// StoreBatch persists multiple alerts.
func (s *MemoryStore) StoreBatch(ctx context.Context, alerts []types.Alert) error {
	for _, alert := range alerts {
		if err := s.Store(ctx, alert); err != nil {
			return err
		}
	}
	return nil
}

// Query retrieves alerts matching the filters.
func (s *MemoryStore) Query(ctx context.Context, filters QueryFilters) ([]types.Alert, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []types.Alert
	for _, alert := range s.alerts {
		if !matchesFilters(alert, filters) {
			continue
		}
		results = append(results, alert)
	}

	// Sort by timestamp descending
	sort.Slice(results, func(i, j int) bool {
		return results[i].Timestamp.After(results[j].Timestamp)
	})

	// Apply offset and limit
	if filters.Offset > 0 {
		if filters.Offset >= len(results) {
			return []types.Alert{}, nil
		}
		results = results[filters.Offset:]
	}
	if filters.Limit > 0 && filters.Limit < len(results) {
		results = results[:filters.Limit]
	}

	return results, nil
}

// QueryByID retrieves a single alert by ID.
func (s *MemoryStore) QueryByID(ctx context.Context, alertID string) (*types.Alert, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	alert, ok := s.alerts[alertID]
	if !ok {
		return nil, fmt.Errorf("alert not found: %s", alertID)
	}
	return &alert, nil
}

// Count returns the number of matching alerts.
func (s *MemoryStore) Count(ctx context.Context, filters QueryFilters) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var count int64
	for _, alert := range s.alerts {
		if matchesFilters(alert, filters) {
			count++
		}
	}
	return count, nil
}

// Delete removes alerts older than the given duration.
func (s *MemoryStore) Delete(ctx context.Context, olderThan time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-olderThan)
	var deleted int64
	for id, alert := range s.alerts {
		if alert.Timestamp.Before(cutoff) {
			delete(s.alerts, id)
			deleted++
		}
	}
	return deleted, nil
}

// Close is a no-op for memory store.
func (s *MemoryStore) Close() error {
	return nil
}

// Healthy always returns true for memory store.
func (s *MemoryStore) Healthy(ctx context.Context) bool {
	return true
}

// matchesFilters checks if an alert matches the given filters.
func matchesFilters(alert types.Alert, filters QueryFilters) bool {
	if !filters.Since.IsZero() && alert.Timestamp.Before(filters.Since) {
		return false
	}
	if !filters.Until.IsZero() && alert.Timestamp.After(filters.Until) {
		return false
	}
	if len(filters.PIDs) > 0 {
		found := false
		for _, pid := range filters.PIDs {
			if alert.PID == pid {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if len(filters.Severity) > 0 {
		found := false
		for _, sev := range filters.Severity {
			if alert.Severity == sev {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if len(filters.RuleIDs) > 0 {
		found := false
		for _, ruleID := range filters.RuleIDs {
			if alert.RuleID == ruleID {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if filters.PodName != "" && alert.Enrichment.PodName != filters.PodName {
		return false
	}
	if filters.Namespace != "" && alert.Enrichment.Namespace != filters.Namespace {
		return false
	}
	return true
}

// MemoryProfileStore is an in-memory ProfileStore implementation.
type MemoryProfileStore struct {
	mu       sync.RWMutex
	profiles map[string]*types.ProcessProfile
}

// NewMemoryProfileStore creates a new in-memory profile store.
func NewMemoryProfileStore() *MemoryProfileStore {
	return &MemoryProfileStore{
		profiles: make(map[string]*types.ProcessProfile),
	}
}

// Store persists a process profile.
func (s *MemoryProfileStore) Store(ctx context.Context, profile *types.ProcessProfile) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := profileKey(profile)
	s.profiles[key] = profile
	return nil
}

// Load retrieves a profile by key.
func (s *MemoryProfileStore) Load(ctx context.Context, key string) (*types.ProcessProfile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	profile, ok := s.profiles[key]
	if !ok {
		return nil, fmt.Errorf("profile not found: %s", key)
	}
	return profile, nil
}

// LoadAll retrieves all stored profiles.
func (s *MemoryProfileStore) LoadAll(ctx context.Context) ([]*types.ProcessProfile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	results := make([]*types.ProcessProfile, 0, len(s.profiles))
	for _, profile := range s.profiles {
		results = append(results, profile)
	}
	return results, nil
}

// Delete removes a profile.
func (s *MemoryProfileStore) Delete(ctx context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.profiles, key)
	return nil
}

// Close is a no-op.
func (s *MemoryProfileStore) Close() error {
	return nil
}

// profileKey generates a unique key for a profile.
func profileKey(profile *types.ProcessProfile) string {
	return fmt.Sprintf("%s:%s", profile.Comm, profile.Namespace)
}
