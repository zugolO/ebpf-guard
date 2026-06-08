// Package gossip implements cross-node IOC (Indicator of Compromise) sharing
// between ebpf-guard agents via a lightweight HTTP-based gossip protocol.
package gossip

import (
	"container/list"
	"fmt"
	"sync"
	"time"
)

// IOCType classifies what kind of indicator is being shared.
type IOCType string

const (
	// IOCTypeIP represents a destination IP address IOC.
	IOCTypeIP IOCType = "ip"
	// IOCTypeDNS represents a DNS domain name IOC.
	IOCTypeDNS IOCType = "dns"
	// IOCTypeFingerprint represents a rule-match fingerprint IOC.
	IOCTypeFingerprint IOCType = "fingerprint"
)

// maxIOCValueLen caps the byte length of an IOC Value field accepted from a
// peer. 253 bytes covers the maximum DNS name length and is generous for IP
// addresses and SHA-256 fingerprints.
const maxIOCValueLen = 253

// maxIOCSourceLen caps the byte length of the Source field to prevent log
// injection via crafted peer names.
const maxIOCSourceLen = 253

// validIOCType returns true if t is one of the recognised IOC type strings.
func validIOCType(t IOCType) bool {
	switch t {
	case IOCTypeIP, IOCTypeDNS, IOCTypeFingerprint:
		return true
	}
	return false
}

// validateIOC returns an error when the IOC contains values that exceed safe
// bounds or use an unrecognised type.
func validateIOC(ioc IOC) error {
	if !validIOCType(ioc.Type) {
		return fmt.Errorf("unknown IOC type %q", ioc.Type)
	}
	if ioc.Value == "" {
		return fmt.Errorf("IOC value must not be empty")
	}
	if len(ioc.Value) > maxIOCValueLen {
		return fmt.Errorf("IOC value length %d exceeds limit %d", len(ioc.Value), maxIOCValueLen)
	}
	if len(ioc.Source) > maxIOCSourceLen {
		return fmt.Errorf("IOC source length %d exceeds limit %d", len(ioc.Source), maxIOCSourceLen)
	}
	return nil
}

// IOC is an indicator of compromise shared between nodes.
type IOC struct {
	Type      IOCType   `json:"type"`
	Value     string    `json:"value"`
	Source    string    `json:"source"`              // originating node name
	RuleID    string    `json:"rule_id,omitempty"`
	Severity  string    `json:"severity,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
}

// iocEntry pairs an IOC with its position in the LRU list.
type iocEntry struct {
	ioc  IOC
	elem *list.Element // element in lru list; Value is the map key string
}

// IOCStore is a thread-safe, TTL-aware, LRU-bounded in-memory IOC store.
// Lookups are O(1). Insertions evict expired entries first, then the
// least-recently-used entry when the store is at capacity.
type IOCStore struct {
	mu      sync.RWMutex
	entries map[string]*iocEntry // keyed by "type:value"
	lru     *list.List           // front=most recently used, back=LRU candidate
	maxSize int
	ttl     time.Duration
}

// NewIOCStore creates a new IOCStore.
func NewIOCStore(maxSize int, ttl time.Duration) *IOCStore {
	if maxSize <= 0 {
		maxSize = 100_000
	}
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &IOCStore{
		entries: make(map[string]*iocEntry),
		lru:     list.New(),
		maxSize: maxSize,
		ttl:     ttl,
	}
}

func iocKey(t IOCType, value string) string {
	return fmt.Sprintf("%s:%s", t, value)
}

// Add inserts or refreshes an IOC. Evicts expired or LRU entries when at capacity.
// Returns false and discards the IOC if validation fails.
func (s *IOCStore) Add(ioc IOC) bool {
	if err := validateIOC(ioc); err != nil {
		return false
	}
	key := iocKey(ioc.Type, ioc.Value)

	s.mu.Lock()
	defer s.mu.Unlock()

	if e, ok := s.entries[key]; ok {
		s.lru.MoveToFront(e.elem)
		// Refresh expiry only if the incoming entry lives longer.
		if ioc.ExpiresAt.After(e.ioc.ExpiresAt) {
			e.ioc = ioc
		}
		return true
	}

	// Make room: first try to reclaim expired slots, then evict LRU.
	if s.lru.Len() >= s.maxSize {
		s.evictExpiredLocked()
	}
	if s.lru.Len() >= s.maxSize {
		s.evictLRULocked()
	}

	elem := s.lru.PushFront(key)
	s.entries[key] = &iocEntry{ioc: ioc, elem: elem}
	return true
}

// Match returns true when an IOC of the given type and value is known and not expired.
// This is the hot path — O(1) read-locked map lookup.
func (s *IOCStore) Match(t IOCType, value string) bool {
	key := iocKey(t, value)
	s.mu.RLock()
	e, ok := s.entries[key]
	if !ok {
		s.mu.RUnlock()
		return false
	}
	// Read ExpiresAt under the lock — Add() may update e.ioc concurrently.
	expiry := e.ioc.ExpiresAt
	s.mu.RUnlock()
	return time.Now().Before(expiry)
}

// Snapshot returns all non-expired IOCs for peer synchronisation.
func (s *IOCStore) Snapshot() []IOC {
	now := time.Now()
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]IOC, 0, len(s.entries))
	for _, e := range s.entries {
		if now.Before(e.ioc.ExpiresAt) {
			out = append(out, e.ioc)
		}
	}
	return out
}

// Merge adds non-expired IOCs received from a peer.
func (s *IOCStore) Merge(iocs []IOC) {
	now := time.Now()
	for _, ioc := range iocs {
		if now.Before(ioc.ExpiresAt) {
			s.Add(ioc)
		}
	}
}

// CleanExpired removes all stale entries and returns how many were deleted.
func (s *IOCStore) CleanExpired() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.evictExpiredLocked()
}

// Size returns the number of entries currently in the store.
func (s *IOCStore) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

// evictExpiredLocked removes all expired entries. Caller must hold s.mu write lock.
func (s *IOCStore) evictExpiredLocked() int {
	now := time.Now()
	removed := 0
	for key, e := range s.entries {
		if !now.Before(e.ioc.ExpiresAt) {
			s.lru.Remove(e.elem)
			delete(s.entries, key)
			removed++
		}
	}
	return removed
}

// evictLRULocked removes the least recently used entry. Caller must hold s.mu write lock.
func (s *IOCStore) evictLRULocked() {
	back := s.lru.Back()
	if back == nil {
		return
	}
	key := back.Value.(string)
	s.lru.Remove(back)
	delete(s.entries, key)
}
