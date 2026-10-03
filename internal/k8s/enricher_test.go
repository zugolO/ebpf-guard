package k8s

import (
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	cruntime "github.com/zugolO/ebpf-guard/internal/runtime"
	"github.com/zugolO/ebpf-guard/pkg/types"
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

// TestGetEnrichmentInfo_ContainerIDFallbackWithoutPodMatch is the wave 6.1
// regression test for the enricher bug: GetPodInfoByPID reads container ID
// from /proc/<pid>/cgroup internally, but used to discard it entirely when
// no k8s pod matched — the exact situation on a stand with no k8s API
// server (podCache always empty), where the cgroup read itself works fine.
// getEnrichmentInfo must now fall back to the bare container ID instead of
// returning nil, so container.id is usable as a rule axis without k8s.
func TestGetEnrichmentInfo_ContainerIDFallbackWithoutPodMatch(t *testing.T) {
	if _, err := os.ReadFile("/proc/self/cgroup"); err != nil {
		t.Skip("no /proc/self/cgroup on this platform")
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	watcher := &Watcher{
		logger:   logger,
		podCache: make(map[string]*PodInfo), // empty: no k8s API server, exactly like the no-k8s test stand
	}
	e := &Enricher{
		watcher:         watcher,
		logger:          logger.With("component", "k8s_enricher"),
		enrichmentCache: make(map[uint32]*EnrichmentInfo),
		cacheTTL:        30 * time.Second,
	}

	pid := uint32(os.Getpid())
	wantID, cErr := watcher.getContainerIDFromPID(pid)

	info := e.getEnrichmentInfo(pid)

	if cErr != nil {
		// This test process itself isn't in a container cgroup — the
		// documented miss path, not the fallback under test.
		assert.Nil(t, info)
		return
	}

	require.NotNil(t, info, "container ID was resolvable from cgroup (%s) but "+
		"getEnrichmentInfo returned nil instead of falling back to it", wantID)
	assert.Equal(t, wantID, info.ContainerID)
	assert.Empty(t, info.PodName, "no k8s pod matched, so pod metadata must stay empty")
}

func TestIsHealthy(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Without watcher, should report not healthy.
	e := &Enricher{
		logger:          logger.With("component", "k8s_enricher"),
		enrichmentCache: make(map[uint32]*EnrichmentInfo),
		cacheTTL:        30 * time.Second,
	}
	assert.False(t, e.IsHealthy())

	// With watcher that has not yet synced, should report not healthy.
	eNotSynced := &Enricher{
		logger:          logger.With("component", "k8s_enricher"),
		enrichmentCache: make(map[uint32]*EnrichmentInfo),
		cacheTTL:        30 * time.Second,
		watcher:         &Watcher{},
	}
	assert.False(t, eNotSynced.IsHealthy())

	// With watcher that has synced, should report healthy.
	w := &Watcher{}
	w.lastSyncAt.Store(time.Now().UnixNano())
	eWithWatcher := &Enricher{
		logger:          logger.With("component", "k8s_enricher"),
		enrichmentCache: make(map[uint32]*EnrichmentInfo),
		cacheTTL:        30 * time.Second,
		watcher:         w,
	}
	assert.True(t, eWithWatcher.IsHealthy())
}

func TestReadyCheck(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Without watcher, should fail.
	e := &Enricher{
		logger:          logger.With("component", "k8s_enricher"),
		enrichmentCache: make(map[uint32]*EnrichmentInfo),
		cacheTTL:        30 * time.Second,
	}
	err := e.ReadyCheck()
	assert.Error(t, err)

	// With watcher that has not synced, should fail.
	eNotSynced := &Enricher{
		logger:          logger.With("component", "k8s_enricher"),
		enrichmentCache: make(map[uint32]*EnrichmentInfo),
		cacheTTL:        30 * time.Second,
		watcher:         &Watcher{},
		resyncPeriod:    5 * time.Minute,
	}
	err = eNotSynced.ReadyCheck()
	assert.Error(t, err, "unsynchronised watcher should fail ReadyCheck")

	// With watcher that has synced recently, should pass.
	w := &Watcher{}
	w.lastSyncAt.Store(time.Now().UnixNano())
	eWithWatcher := &Enricher{
		logger:          logger.With("component", "k8s_enricher"),
		enrichmentCache: make(map[uint32]*EnrichmentInfo),
		cacheTTL:        30 * time.Second,
		watcher:         w,
		resyncPeriod:    5 * time.Minute,
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
			PodName:   fmt.Sprintf("pod-%d", i),
			Namespace: "default",
			CachedAt:  time.Now(),
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

// readGaugeValue reads the current float64 value of a prometheus.Gauge.
func readGaugeValue(t *testing.T, g prometheus.Gauge) float64 {
	t.Helper()
	m := &dto.Metric{}
	require.NoError(t, g.Write(m))
	return m.GetGauge().GetValue()
}

// readCounterValue reads the current float64 value of a prometheus.Counter.
func readCounterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	m := &dto.Metric{}
	require.NoError(t, c.Write(m))
	return m.GetCounter().GetValue()
}

// TestEnricherMetrics_MissCounterIncrement verifies that the miss counter is
// incremented when an enrichment lookup finds no matching pod.
func TestEnricherMetrics_MissCounterIncrement(t *testing.T) {
	missCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "test_k8s_enricher_miss_total",
	})

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	e := &Enricher{
		logger:          logger.With("component", "k8s_enricher"),
		enrichmentCache: make(map[uint32]*EnrichmentInfo),
		cacheTTL:        30 * time.Second,
		metrics:         EnricherMetrics{MissTotal: missCounter},
		// watcher is nil → GetPodInfoByPID will always miss
	}

	// Each call to getEnrichmentInfo with no watcher should increment missCount.
	e.getEnrichmentInfo(1001)
	e.getEnrichmentInfo(1002)
	e.getEnrichmentInfo(1003)
	assert.Equal(t, int64(3), e.missCount.Load())

	// updateMetrics drains missCount into the Prometheus counter.
	e.updateMetrics()
	assert.Equal(t, int64(0), e.missCount.Load(), "missCount should be drained")
	assert.Equal(t, float64(3), readCounterValue(t, missCounter),
		"prometheus counter should reflect the 3 misses")

	// A second updateMetrics call should not double-count.
	e.updateMetrics()
	assert.Equal(t, float64(3), readCounterValue(t, missCounter),
		"counter should not increase when no new misses occurred")
}

// TestEnricherMetrics_CachePods verifies that the pod count gauge is updated
// from the watcher when updateMetrics is called.
func TestEnricherMetrics_CachePods(t *testing.T) {
	cachePods := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "test_k8s_enricher_cache_pods",
	})

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Build a minimal watcher with a pre-populated podCache.
	w := &Watcher{
		logger:   logger.With("component", "k8s_watcher"),
		podCache: make(map[string]*PodInfo),
	}
	w.podCache["cid-aaa"] = &PodInfo{Name: "pod-1", UID: "uid-1"}
	w.podCache["cid-bbb"] = &PodInfo{Name: "pod-2", UID: "uid-2"}
	w.podCache["cid-ccc"] = &PodInfo{Name: "pod-2", UID: "uid-2"} // same pod, two containers

	e := &Enricher{
		logger:          logger.With("component", "k8s_enricher"),
		enrichmentCache: make(map[uint32]*EnrichmentInfo),
		cacheTTL:        30 * time.Second,
		watcher:         w,
		metrics:         EnricherMetrics{CachePods: cachePods},
	}

	e.updateMetrics()
	// Two unique pods (uid-1 and uid-2) despite three cache entries.
	assert.Equal(t, float64(2), readGaugeValue(t, cachePods))
}

// TestEnricherMetrics_StalenessAndLastSync verifies that the staleness and
// last-sync gauges are populated from the watcher's lastSyncAt field.
func TestEnricherMetrics_StalenessAndLastSync(t *testing.T) {
	staleness := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "test_k8s_enricher_staleness",
	})
	lastSync := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "test_k8s_enricher_last_sync",
	})

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	w := &Watcher{
		logger:   logger.With("component", "k8s_watcher"),
		podCache: make(map[string]*PodInfo),
	}

	syncTime := time.Now().Add(-5 * time.Second)
	w.lastSyncAt.Store(syncTime.UnixNano())

	e := &Enricher{
		logger:          logger.With("component", "k8s_enricher"),
		enrichmentCache: make(map[uint32]*EnrichmentInfo),
		cacheTTL:        30 * time.Second,
		watcher:         w,
		metrics: EnricherMetrics{
			CacheStaleness: staleness,
			LastSync:       lastSync,
		},
	}

	e.updateMetrics()

	gotLastSync := readGaugeValue(t, lastSync)
	assert.InDelta(t, float64(syncTime.Unix()), gotLastSync, 1.0,
		"last-sync gauge should match watcher lastSyncAt")

	gotStaleness := readGaugeValue(t, staleness)
	assert.InDelta(t, 5.0, gotStaleness, 1.0,
		"staleness gauge should be ~5 seconds")
}

// TestEnricherReadyCheck_NotSynced verifies that ReadyCheck returns an error
// before the initial cache sync completes.
func TestEnricherReadyCheck_NotSynced(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	w := &Watcher{
		logger:   logger.With("component", "k8s_watcher"),
		podCache: make(map[string]*PodInfo),
	}
	// lastSyncAt is zero — watcher has never synced.

	e := &Enricher{
		logger:          logger.With("component", "k8s_enricher"),
		enrichmentCache: make(map[uint32]*EnrichmentInfo),
		cacheTTL:        30 * time.Second,
		watcher:         w,
		resyncPeriod:    5 * time.Minute,
	}

	err := e.ReadyCheck()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "initial cache sync not completed")
}

// TestEnricherReadyCheck_StaleSyncFails verifies that ReadyCheck returns an
// error when the last sync is older than 2× the resync period.
func TestEnricherReadyCheck_StaleSyncFails(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	w := &Watcher{
		logger:   logger.With("component", "k8s_watcher"),
		podCache: make(map[string]*PodInfo),
	}
	// Simulate a sync that happened 15 minutes ago with a 5-minute resync period.
	w.lastSyncAt.Store(time.Now().Add(-15 * time.Minute).UnixNano())

	e := &Enricher{
		logger:          logger.With("component", "k8s_enricher"),
		enrichmentCache: make(map[uint32]*EnrichmentInfo),
		cacheTTL:        30 * time.Second,
		watcher:         w,
		resyncPeriod:    5 * time.Minute, // 2× = 10 min threshold
	}

	err := e.ReadyCheck()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cache stale")
}

// TestEnricherReadyCheck_HealthySyncPasses verifies that ReadyCheck returns nil
// when the watcher has synced recently.
func TestEnricherReadyCheck_HealthySyncPasses(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	w := &Watcher{
		logger:   logger.With("component", "k8s_watcher"),
		podCache: make(map[string]*PodInfo),
	}
	// Sync happened 30 seconds ago with a 5-minute resync period.
	w.lastSyncAt.Store(time.Now().Add(-30 * time.Second).UnixNano())

	e := &Enricher{
		logger:          logger.With("component", "k8s_enricher"),
		enrichmentCache: make(map[uint32]*EnrichmentInfo),
		cacheTTL:        30 * time.Second,
		watcher:         w,
		resyncPeriod:    5 * time.Minute,
	}

	err := e.ReadyCheck()
	assert.NoError(t, err)
}

// TestWatcher_LastSyncAt verifies that lastSyncAt is set after touchSyncAt and
// that HasSynced returns true only after a sync.
func TestWatcher_LastSyncAt(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	w := &Watcher{
		logger:   logger.With("component", "k8s_watcher"),
		podCache: make(map[string]*PodInfo),
	}

	assert.False(t, w.HasSynced(), "should not be synced before any event")
	assert.True(t, w.LastSyncAt().IsZero(), "zero time before sync")

	before := time.Now()
	w.touchSyncAt()
	after := time.Now()

	assert.True(t, w.HasSynced())
	assert.False(t, w.LastSyncAt().IsZero())
	assert.True(t, w.LastSyncAt().After(before) || w.LastSyncAt().Equal(before))
	assert.True(t, w.LastSyncAt().Before(after) || w.LastSyncAt().Equal(after))
}

// TestEnricherMetrics_HasMetrics verifies hasMetrics detection.
func TestEnricherMetrics_HasMetrics(t *testing.T) {
	e := &Enricher{}
	assert.False(t, e.hasMetrics(), "no metrics configured")

	e.metrics.MissTotal = prometheus.NewCounter(prometheus.CounterOpts{Name: "x"})
	assert.True(t, e.hasMetrics(), "metrics configured")
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

// Item 10 wave 6.6: a pid that is gone (watcher-less pid path misses) is
// resolved through the in-kernel cgroup id remembered from an earlier hit.
func TestEnrichEvent_CgroupRecoversProcGone(t *testing.T) {
	e := &Enricher{cacheTTL: time.Minute, enrichmentCache: map[uint32]*EnrichmentInfo{}}
	info := &EnrichmentInfo{PodName: "web", Namespace: "d", ContainerID: "abc", CachedAt: time.Now()}

	e.rememberCgroup(77, info)
	ev := &types.Event{PID: 999999, CgroupID: 77}
	e.EnrichEvent(ev)
	if ev.Enrichment == nil || ev.Enrichment.PodName != "web" {
		t.Fatalf("cgroup id did not recover the attribution: %+v", ev.Enrichment)
	}

	// Unknown cgroup and cgroup 0 (old BPF object) stay unattributed.
	for _, id := range []uint64{78, 0} {
		ev := &types.Event{PID: 999999, CgroupID: id}
		e.EnrichEvent(ev)
		if ev.Enrichment != nil {
			t.Fatalf("cgroup %d must not resolve: %+v", id, ev.Enrichment)
		}
	}

	// A host process (no container, no pod) never poisons a cgroup.
	e.rememberCgroup(1, &EnrichmentInfo{CachedAt: time.Now()})
	if e.lookupCgroup(1) != nil {
		t.Fatal("empty attribution was remembered under cgroup 1")
	}

	// Expired entries are not served.
	e.rememberCgroup(79, &EnrichmentInfo{PodName: "old", CachedAt: time.Now().Add(-2 * time.Minute)})
	if e.lookupCgroup(79) != nil {
		t.Fatal("expired cgroup entry served")
	}
}

// TestEnricher_DefaultsToSharedResolver pins wave 8.1 item 2 (в) on the k8s
// side: the enricher must resolve through the same process-wide resolver the
// runtime enricher uses, otherwise one event reads /proc twice.
func TestEnricher_DefaultsToSharedResolver(t *testing.T) {
	e := &Enricher{}
	if e.containerResolver() != cruntime.DefaultContainerIDResolver() {
		t.Fatal("k8s enricher must default to the shared cgroup-id resolver")
	}
}

// TestEnricher_CgroupPathMatchesPIDPath is the wave 8.1 item 2 identity guard
// on the k8s side: over one event stream the new cgroup-id-keyed path and the
// old pid-keyed path must produce the same attribution. container_id/pod_name
// are rule-exclusion axes ([[exclusions-key-on-cgroup-not-comm]]), so a change
// here would be a detection change, not only a performance one.
func TestEnricher_CgroupPathMatchesPIDPath(t *testing.T) {
	const (
		cidWithPod  = "3333333333333333333333333333333333333333333333333333333333333333"
		cidNoPod    = "4444444444444444444444444444444444444444444444444444444444444444"
		cidCgroupfs = "5555555555555555555555555555555555555555555555555555555555555555"
	)
	contentByPID := map[uint32]string{
		4242: "0::/system.slice/cri-containerd-" + cidWithPod + ".scope",
		4243: "0::/system.slice/docker-" + cidNoPod + ".scope",
		// cgroupfs driver (classic k8s ≤1.21 via cri-dockerd): a container line
		// with no runtime keyword, only /kubepods/. The pid-path parser matches
		// it, so the cgroup-id path must too — otherwise attribution silently
		// drifts on that layout and every exclusion keyed on container_id/
		// pod_name stops matching.
		4244: "12:devices:/kubepods/burstable/pod1234/" + cidCgroupfs,
	}

	w := newTestWatcher()
	w.podCache[cidWithPod] = &PodInfo{
		Name: "web-0", Namespace: "prod", UID: "uid-1", NodeName: "node-1",
	}
	w.podCache[cidCgroupfs] = &PodInfo{
		Name: "cgroupfs-0", Namespace: "prod", UID: "uid-2", NodeName: "node-1",
	}

	e := &Enricher{
		watcher:         w,
		logger:          k8sQuietLogger(),
		enrichmentCache: make(map[uint32]*EnrichmentInfo),
		cacheTTL:        time.Minute,
		resolver: cruntime.NewContainerIDResolverWithReader(time.Minute, func(pid uint32) (string, error) {
			return contentByPID[pid], nil
		}),
	}

	stream := []struct {
		cgroupID uint64
		pid      uint32
		wantPod  string
		wantCID  string
	}{
		{7, 4242, "web-0", ""},      // pod matched: runtime enricher fills container_id
		{8, 4243, "", cidNoPod},     // no pod: bare cgroup container id
		{9, 4244, "cgroupfs-0", ""}, // keyword-less kubepods layout, pod matched
	}

	for i, tc := range stream {
		// Old path: k8s's own cgroup parser, then the same pod cache the pid
		// path consulted (GetPodInfoByPID discarded the id, the fallback kept
		// it, so container_id is empty exactly when a pod matched).
		oldID, err := extractContainerID(contentByPID[tc.pid])
		require.NoError(t, err)
		if pod, ok := w.GetPodInfo(oldID); ok {
			assert.Equal(t, tc.wantPod, pod.Name)
		} else {
			assert.Empty(t, tc.wantPod)
			assert.Equal(t, tc.wantCID, oldID)
		}

		// New path: a single event carrying the kernel cgroup id.
		ev := &types.Event{PID: tc.pid, CgroupID: tc.cgroupID}
		e.EnrichEvent(ev)
		require.NotNil(t, ev.Enrichment, "event %d must be attributed", i)
		assert.Equal(t, tc.wantPod, ev.Enrichment.PodName)
		assert.Equal(t, tc.wantCID, ev.Enrichment.ContainerID)
	}
}
