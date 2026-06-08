// Package store provides in-memory implementations for testing.
package store

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// byTimeEntry is a compact index record stored in the time-ordered index.
// Caching ts, severity, and namespace avoids a 488-byte Alert map lookup for
// entries that don't pass the two most common Query filters, so the hot path
// does full s.alerts lookups only for O(limit) results that pass all filters.
type byTimeEntry struct {
	id        string
	ts        time.Time
	severity  types.Severity // pod severity — cached for pre-filtering
	namespace string         // pod namespace — cached for pre-filtering
}

// MemoryStore is an in-memory AlertStore implementation for testing.
type MemoryStore struct {
	// count is the total number of alerts currently in the store.
	// Kept as the first field to guarantee 64-bit alignment on 32-bit platforms.
	// Incremented by Store/StoreBatch on new inserts, decremented by Delete.
	// Read lock-free by Count() via atomic.Int64.Load().
	count  atomic.Int64
	mu     sync.RWMutex
	alerts map[string]types.Alert
	// byTime holds index entries sorted by ts DESC (newest first).
	// insertSorted maintains this invariant on every write; binary search on
	// entry.ts (no map lookup) narrows time-range queries to O(log n).
	byTime []byTimeEntry
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

	// Remove the old index entry if this is an update.
	_, exists := s.alerts[alert.ID]
	if exists {
		s.removeFromByTime(alert.ID)
	}

	s.alerts[alert.ID] = alert
	s.insertSorted(alert.ID, alert.Timestamp, alert.Severity, alert.Enrichment.Namespace)
	if !exists {
		s.count.Add(1)
	}
	return nil
}

// insertSorted inserts an entry into byTime maintaining DESC timestamp order.
// Binary search uses entry.ts directly — no map lookup needed.
// Caller must hold s.mu write lock.
func (s *MemoryStore) insertSorted(id string, ts time.Time, sev types.Severity, ns string) {
	pos := sort.Search(len(s.byTime), func(i int) bool {
		return s.byTime[i].ts.Before(ts)
	})
	s.byTime = append(s.byTime, byTimeEntry{})
	copy(s.byTime[pos+1:], s.byTime[pos:])
	s.byTime[pos] = byTimeEntry{id: id, ts: ts, severity: sev, namespace: ns}
}

// removeFromByTime removes the entry for id from byTime.  Called only on
// updates (rare); linear scan is acceptable on a hot-path miss.
// Caller must hold s.mu write lock.
func (s *MemoryStore) removeFromByTime(id string) {
	for i := range s.byTime {
		if s.byTime[i].id == id {
			s.byTime = append(s.byTime[:i], s.byTime[i+1:]...)
			return
		}
	}
}

// StoreBatch persists multiple alerts in a single critical section.
// Unlike calling Store N times, this holds the lock once, bulk-appends all
// entries, and re-sorts byTime once at the end — O(n log n) total instead of
// O(n²) from N individual insertSorted calls.
func (s *MemoryStore) StoreBatch(ctx context.Context, alerts []types.Alert) error {
	if len(alerts) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	// Pre-grow byTime to avoid repeated slice reallocations during append.
	needed := len(s.byTime) + len(alerts)
	if cap(s.byTime) < needed {
		grown := make([]byTimeEntry, len(s.byTime), needed)
		copy(grown, s.byTime)
		s.byTime = grown
	}

	var newCount int64
	for i := range alerts {
		a := alerts[i] // local copy — do not modify caller's slice
		if a.ID == "" {
			s.seq++
			a.ID = fmt.Sprintf("mem-%d", s.seq)
		}
		if a.Timestamp.IsZero() {
			a.Timestamp = time.Now()
		}
		_, exists := s.alerts[a.ID]
		if exists {
			s.removeFromByTime(a.ID)
		} else {
			newCount++
		}
		s.alerts[a.ID] = a
		s.byTime = append(s.byTime, byTimeEntry{
			id:        a.ID,
			ts:        a.Timestamp,
			severity:  a.Severity,
			namespace: a.Enrichment.Namespace,
		})
	}
	s.count.Add(newCount)

	// Single sort instead of N insertSorted calls — O(n log n) vs O(n²).
	sort.Slice(s.byTime, func(i, j int) bool {
		return s.byTime[j].ts.Before(s.byTime[i].ts)
	})
	return nil
}

// Query retrieves alerts matching the filters.
// byTime is kept sorted DESC, so time-range narrowing is O(log n) (using
// entry.ts with no map lookup) and results are already in newest-first order.
// The scan loop pre-filters on the cached severity and namespace fields before
// doing the expensive 488-byte Alert map lookup, so only O(limit) full lookups
// are needed on queries that use those filters.
func (s *MemoryStore) Query(ctx context.Context, filters QueryFilters) ([]types.Alert, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Binary-search entry.ts directly — no map lookup needed.
	start, end := 0, len(s.byTime)
	if !filters.Until.IsZero() {
		start = sort.Search(len(s.byTime), func(i int) bool {
			return !s.byTime[i].ts.After(filters.Until)
		})
	}
	if !filters.Since.IsZero() {
		end = sort.Search(len(s.byTime), func(i int) bool {
			return s.byTime[i].ts.Before(filters.Since)
		})
	}

	var results []types.Alert
	skipped := 0
	for i := start; i < end; i++ {
		e := &s.byTime[i]

		// Pre-filter on cached index fields before the expensive map lookup.
		if len(filters.Severity) > 0 {
			found := false
			for _, sev := range filters.Severity {
				if e.severity == sev {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		if filters.Namespace != "" && e.namespace != filters.Namespace {
			continue
		}

		// Remaining filters (PIDs, RuleIDs, PodName, time boundary) require the
		// full alert.  Only reached by entries that pass the pre-filter above.
		alert := s.alerts[e.id]
		if !matchesFilters(alert, filters) {
			continue
		}
		if skipped < filters.Offset {
			skipped++
			continue
		}
		results = append(results, alert)
		if filters.Limit > 0 && len(results) >= filters.Limit {
			break
		}
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

// Count returns the total number of alerts currently in the store.
// The result is O(1): it reads the atomic counter maintained by Store,
// StoreBatch, and Delete — no lock acquisition or iteration required.
// Filters are accepted for interface compatibility but are not applied;
// callers that need filtered counts should use Query.
func (s *MemoryStore) Count(_ context.Context, _ QueryFilters) (int64, error) {
	return s.count.Load(), nil
}

// Delete removes alerts older than the given duration.
// byTime is sorted DESC so old alerts cluster at the tail — O(log n) to find
// the cut point, then O(k) to remove the k expired entries.
func (s *MemoryStore) Delete(ctx context.Context, olderThan time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-olderThan)
	// entry.ts is directly comparable — no map lookup needed.
	idx := sort.Search(len(s.byTime), func(i int) bool {
		return s.byTime[i].ts.Before(cutoff)
	})
	var deleted int64
	for _, e := range s.byTime[idx:] {
		delete(s.alerts, e.id)
		deleted++
	}
	s.byTime = s.byTime[:idx]
	s.count.Add(-deleted)
	return deleted, nil
}

// Flush is a no-op for memory store — all writes are immediately consistent.
func (s *MemoryStore) Flush(_ context.Context) error {
	return nil
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
