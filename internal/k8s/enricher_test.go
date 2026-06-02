package k8s

import (
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestEnricherConfig(t *testing.T) {
	_ = slog.New(slog.NewTextHandler(os.Stdout, nil))

	config := EnricherConfig{
		KubeconfigPath: "",
		ResyncPeriod:   5 * time.Minute,
		CacheTTL:       30 * time.Second,
	}

	// We can't actually create an enricher without a k8s cluster,
	// but we can verify the config structure
	assert.Equal(t, 5*time.Minute, config.ResyncPeriod)
	assert.Equal(t, 30*time.Second, config.CacheTTL)

	// Test with zero CacheTTL (should default to 30s)
	configZeroTTL := EnricherConfig{
		ResyncPeriod: 5 * time.Minute,
	}
	assert.Equal(t, time.Duration(0), configZeroTTL.CacheTTL)
}

func TestEnrichmentInfo(t *testing.T) {
	info := &EnrichmentInfo{
		PodName:     "test-pod",
		Namespace:   "default",
		PodUID:      "abc-123",
		NodeName:    "node-1",
		Labels:      map[string]string{"app": "test"},
		Annotations: map[string]string{"sidecar": "true"},
		ContainerID: "container123",
		CachedAt:    time.Now(),
	}

	assert.Equal(t, "test-pod", info.PodName)
	assert.Equal(t, "default", info.Namespace)
	assert.Equal(t, "abc-123", info.PodUID)
	assert.Equal(t, "node-1", info.NodeName)
	assert.Equal(t, "test", info.Labels["app"])
	assert.Equal(t, "true", info.Annotations["sidecar"])
	assert.Equal(t, "container123", info.ContainerID)
}

func TestCacheCleanup(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	e := &Enricher{
		logger:          logger.With("component", "k8s_enricher"),
		enrichmentCache: make(map[uint32]*EnrichmentInfo),
		cacheTTL:        100 * time.Millisecond,
	}

	// Add expired entry
	e.enrichmentCache[1234] = &EnrichmentInfo{
		PodName:  "expired-pod",
		CachedAt: time.Now().Add(-200 * time.Millisecond),
	}

	// Add fresh entry
	e.enrichmentCache[5678] = &EnrichmentInfo{
		PodName:  "fresh-pod",
		CachedAt: time.Now(),
	}

	// Run cleanup
	e.cleanupCache()

	// Expired entry should be removed
	_, exists := e.enrichmentCache[1234]
	assert.False(t, exists, "expired entry should be removed")

	// Fresh entry should remain
	info, exists := e.enrichmentCache[5678]
	assert.True(t, exists, "fresh entry should remain")
	assert.Equal(t, "fresh-pod", info.PodName)
}

func TestEnrichEvent(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	e := &Enricher{
		logger:          logger.With("component", "k8s_enricher"),
		enrichmentCache: make(map[uint32]*EnrichmentInfo),
		cacheTTL:        30 * time.Second,
	}

	// Test nil event
	e.EnrichEvent(nil) // Should not panic

	// Test event without cached info (no watcher, so no enrichment)
	event := &types.Event{
		PID:  1234,
		Type: types.EventSyscall,
	}
	e.EnrichEvent(event)
	// Event should remain unchanged (no panic)
	assert.Equal(t, uint32(1234), event.PID)
}

func TestEnrichAlert(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	e := &Enricher{
		logger:          logger.With("component", "k8s_enricher"),
		enrichmentCache: make(map[uint32]*EnrichmentInfo),
		cacheTTL:        30 * time.Second,
	}

	// Test nil alert
	e.EnrichAlert(nil) // Should not panic

	// Test alert without cached info
	alert := &types.Alert{
		RuleID:   "test-rule",
		Severity: types.SeverityWarning,
		Event: types.Event{
			PID:  1234,
			Type: types.EventSyscall,
		},
	}
	e.EnrichAlert(alert)
	// Alert should remain valid (no panic)
	assert.Equal(t, "test-rule", alert.RuleID)
}

func TestGetEnrichmentInfo(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	e := &Enricher{
		logger:          logger.With("component", "k8s_enricher"),
		enrichmentCache: make(map[uint32]*EnrichmentInfo),
		cacheTTL:        30 * time.Second,
	}

	// Test with no watcher (should return nil)
	info := e.getEnrichmentInfo(1234)
	assert.Nil(t, info)

	// Test cache miss
	info, ok := e.GetEnrichmentInfo(1234)
	assert.False(t, ok)
	assert.Nil(t, info)
}

func TestIsHealthy(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Without watcher, should report not healthy
	e := &Enricher{
		logger:          logger.With("component", "k8s_enricher"),
		enrichmentCache: make(map[uint32]*EnrichmentInfo),
		cacheTTL:        30 * time.Second,
	}
	assert.False(t, e.IsHealthy())

	// With watcher (mock), should report healthy
	eWithWatcher := &Enricher{
		logger:          logger.With("component", "k8s_enricher"),
		enrichmentCache: make(map[uint32]*EnrichmentInfo),
		cacheTTL:        30 * time.Second,
		watcher:         &Watcher{}, // Mock watcher
	}
	assert.True(t, eWithWatcher.IsHealthy())
}

func TestReadyCheck(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Without watcher, should fail
	e := &Enricher{
		logger:          logger.With("component", "k8s_enricher"),
		enrichmentCache: make(map[uint32]*EnrichmentInfo),
		cacheTTL:        30 * time.Second,
	}
	err := e.ReadyCheck()
	assert.Error(t, err)

	// With watcher, should pass
	eWithWatcher := &Enricher{
		logger:          logger.With("component", "k8s_enricher"),
		enrichmentCache: make(map[uint32]*EnrichmentInfo),
		cacheTTL:        30 * time.Second,
		watcher:         &Watcher{}, // Mock watcher
	}
	err = eWithWatcher.ReadyCheck()
	assert.NoError(t, err)
}

func TestLiveCheck(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	e := &Enricher{
		logger:          logger.With("component", "k8s_enricher"),
		enrichmentCache: make(map[uint32]*EnrichmentInfo),
		cacheTTL:        30 * time.Second,
	}

	// Should always pass
	err := e.LiveCheck()
	assert.NoError(t, err)
}

// TestCacheExpiryWithTTL specifically tests that entries expire after TTL
// and are properly evicted from the cache.
func TestCacheExpiryWithTTL(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Use a short TTL for testing
	ttl := 50 * time.Millisecond
	e := &Enricher{
		logger:          logger.With("component", "k8s_enricher"),
		enrichmentCache: make(map[uint32]*EnrichmentInfo),
		cacheTTL:        ttl,
	}

	// Populate cache with multiple entries
	for i := uint32(1); i <= 10; i++ {
		e.enrichmentCache[i] = &EnrichmentInfo{
			PodName:     fmt.Sprintf("pod-%d", i),
			Namespace:   "default",
			CachedAt:    time.Now(),
		}
	}

	// Verify all entries exist
	assert.Equal(t, 10, len(e.enrichmentCache), "all entries should be in cache")

	// Wait for TTL to expire
	time.Sleep(ttl + 10*time.Millisecond)

	// Run cleanup
	e.cleanupCache()

	// All entries should be expired and removed
	assert.Equal(t, 0, len(e.enrichmentCache), "all entries should be expired and removed")
}

// TestCacheExpiryPartial tests partial expiry where only some entries expire.
func TestCacheExpiryPartial(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	ttl := 100 * time.Millisecond
	e := &Enricher{
		logger:          logger.With("component", "k8s_enricher"),
		enrichmentCache: make(map[uint32]*EnrichmentInfo),
		cacheTTL:        ttl,
	}

	// Add entries at different times
	now := time.Now()

	// Old entries (will expire)
	for i := uint32(1); i <= 5; i++ {
		e.enrichmentCache[i] = &EnrichmentInfo{
			PodName:   fmt.Sprintf("old-pod-%d", i),
			Namespace: "default",
			CachedAt:  now.Add(-ttl - 10*time.Millisecond), // Already expired
		}
	}

	// Fresh entries (won't expire yet)
	for i := uint32(6); i <= 10; i++ {
		e.enrichmentCache[i] = &EnrichmentInfo{
			PodName:   fmt.Sprintf("fresh-pod-%d", i),
			Namespace: "default",
			CachedAt:  now, // Just added
		}
	}

	// Run cleanup
	e.cleanupCache()

	// Only old entries should be removed
	assert.Equal(t, 5, len(e.enrichmentCache), "only fresh entries should remain")

	// Verify fresh entries are still there
	for i := uint32(6); i <= 10; i++ {
		_, exists := e.enrichmentCache[i]
		assert.True(t, exists, "fresh entry %d should still exist", i)
	}

	// Verify old entries are gone
	for i := uint32(1); i <= 5; i++ {
		_, exists := e.enrichmentCache[i]
		assert.False(t, exists, "old entry %d should be removed", i)
	}
}

// TestCacheExpiryEdgeCases tests edge cases around TTL boundaries.
func TestCacheExpiryEdgeCases(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	ttl := 100 * time.Millisecond
	e := &Enricher{
		logger:          logger.With("component", "k8s_enricher"),
		enrichmentCache: make(map[uint32]*EnrichmentInfo),
		cacheTTL:        ttl,
	}

	now := time.Now()

	// Entry clearly past TTL boundary (should be expired)
	e.enrichmentCache[1] = &EnrichmentInfo{
		PodName:   "expired-pod",
		Namespace: "default",
		CachedAt:  now.Add(-ttl - 10*time.Millisecond),
	}

	// Entry clearly within TTL (should NOT be expired)
	e.enrichmentCache[2] = &EnrichmentInfo{
		PodName:   "fresh-pod",
		Namespace: "default",
		CachedAt:  now.Add(-ttl + 20*time.Millisecond),
	}

	// Run cleanup
	e.cleanupCache()

	// Check results
	_, exists := e.enrichmentCache[1]
	assert.False(t, exists, "entry past TTL should be expired")

	_, exists = e.enrichmentCache[2]
	assert.True(t, exists, "entry within TTL should remain")
}
