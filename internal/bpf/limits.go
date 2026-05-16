// Package bpf provides BPF map management and resource limits.
package bpf

import (
	"fmt"
	"sync"
	"time"
)

// MapLimits defines size limits and eviction policy for BPF maps.
type MapLimits struct {
	// MaxEntries is the maximum number of entries in the map
	MaxEntries int
	// EvictionPolicy determines how entries are evicted when full
	EvictionPolicy EvictionPolicy
	// TTL is the time-to-live for entries (0 = no TTL)
	TTL time.Duration
}

// EvictionPolicy defines how map entries are evicted.
type EvictionPolicy int

const (
	// EvictNone disables automatic eviction
	EvictNone EvictionPolicy = iota
	// EvictLRU evicts least recently used entries
	EvictLRU
	// EvictOldest evicts oldest entries by timestamp
	EvictOldest
	// EvictRandom evicts random entries
	EvictRandom
)

// String returns the string representation of the eviction policy.
func (e EvictionPolicy) String() string {
	switch e {
	case EvictNone:
		return "none"
	case EvictLRU:
		return "lru"
	case EvictOldest:
		return "oldest"
	case EvictRandom:
		return "random"
	default:
		return "unknown"
	}
}

// MapStats tracks statistics for a BPF map.
type MapStats struct {
	Name         string
	CurrentSize  int
	MaxSize      int
	Evictions    uint64
	Insertions   uint64
	Deletions    uint64
	LookupHits   uint64
	LookupMisses uint64
	LastEviction time.Time
}

// MapManager manages BPF maps with size limits and eviction.
type MapManager struct {
	limits  map[string]MapLimits
	stats   map[string]*MapStats
	entries map[string]map[uint32]time.Time // map name -> key -> last access
	mu      sync.RWMutex
}

// NewMapManager creates a new map manager.
func NewMapManager() *MapManager {
	return &MapManager{
		limits:  make(map[string]MapLimits),
		stats:   make(map[string]*MapStats),
		entries: make(map[string]map[uint32]time.Time),
	}
}

// RegisterMap registers a map with limits.
func (m *MapManager) RegisterMap(name string, limits MapLimits) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.limits[name] = limits
	m.stats[name] = &MapStats{
		Name:    name,
		MaxSize: limits.MaxEntries,
	}
	m.entries[name] = make(map[uint32]time.Time)
}

// GetLimits returns the limits for a map.
func (m *MapManager) GetLimits(name string) (MapLimits, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	limits, ok := m.limits[name]
	return limits, ok
}

// GetStats returns statistics for a map.
func (m *MapManager) GetStats(name string) (MapStats, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats, ok := m.stats[name]
	if !ok {
		return MapStats{}, false
	}
	// Return a copy
	return *stats, true
}

// RecordInsertion records a map insertion and handles eviction if needed.
func (m *MapManager) RecordInsertion(mapName string, key uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	limits, ok := m.limits[mapName]
	if !ok {
		return fmt.Errorf("bpf/limits: map %s not registered", mapName)
	}

	stats := m.stats[mapName]
	entries := m.entries[mapName]

	stats.Insertions++

	// Check if we need to evict
	if len(entries) >= limits.MaxEntries && limits.EvictionPolicy != EvictNone {
		if err := m.evict(mapName, limits.EvictionPolicy); err != nil {
			return fmt.Errorf("bpf/limits: eviction failed: %w", err)
		}
	}

	entries[key] = time.Now()
	stats.CurrentSize = len(entries)

	return nil
}

// RecordLookup records a map lookup.
func (m *MapManager) RecordLookup(mapName string, key uint32, hit bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	stats, ok := m.stats[mapName]
	if !ok {
		return
	}

	if hit {
		stats.LookupHits++
		// Update access time for LRU
		if entries, ok := m.entries[mapName]; ok {
			entries[key] = time.Now()
		}
	} else {
		stats.LookupMisses++
	}
}

// RecordDeletion records a map deletion.
func (m *MapManager) RecordDeletion(mapName string, key uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()

	stats, ok := m.stats[mapName]
	if !ok {
		return
	}

	stats.Deletions++
	if entries, ok := m.entries[mapName]; ok {
		delete(entries, key)
		stats.CurrentSize = len(entries)
	}
}

// evict removes an entry based on the eviction policy.
func (m *MapManager) evict(mapName string, policy EvictionPolicy) error {
	entries := m.entries[mapName]
	if len(entries) == 0 {
		return nil
	}

	var keyToEvict uint32
	var found bool

	switch policy {
	case EvictLRU:
		// Find least recently used
		var oldest time.Time
		for key, accessTime := range entries {
			if !found || accessTime.Before(oldest) {
				oldest = accessTime
				keyToEvict = key
				found = true
			}
		}

	case EvictOldest:
		// Find oldest by insertion (we use access time as proxy)
		var oldest time.Time
		for key, accessTime := range entries {
			if !found || accessTime.Before(oldest) {
				oldest = accessTime
				keyToEvict = key
				found = true
			}
		}

	case EvictRandom:
		// Pick first key (Go map iteration is randomized)
		for key := range entries {
			keyToEvict = key
			found = true
			break
		}
	}

	if found {
		delete(entries, keyToEvict)
		m.stats[mapName].Evictions++
		m.stats[mapName].LastEviction = time.Now()
		m.stats[mapName].CurrentSize = len(entries)
	}

	return nil
}

// CleanupExpired removes expired entries based on TTL.
func (m *MapManager) CleanupExpired() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	totalCleaned := 0
	now := time.Now()

	for mapName, limits := range m.limits {
		if limits.TTL <= 0 {
			continue
		}

		entries := m.entries[mapName]
		stats := m.stats[mapName]

		for key, accessTime := range entries {
			if now.Sub(accessTime) > limits.TTL {
				delete(entries, key)
				stats.Deletions++
				totalCleaned++
			}
		}

		stats.CurrentSize = len(entries)
	}

	return totalCleaned
}

// GetAllStats returns statistics for all registered maps.
func (m *MapManager) GetAllStats() map[string]MapStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]MapStats, len(m.stats))
	for name, stats := range m.stats {
		result[name] = *stats
	}
	return result
}
