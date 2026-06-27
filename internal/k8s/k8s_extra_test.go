package k8s

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

func k8sQuietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

const fakeCID = "1111111111111111111111111111111111111111111111111111111111111111"

func newTestWatcher() *Watcher {
	return &Watcher{
		podCache: make(map[string]*PodInfo),
		logger:   k8sQuietLogger(),
	}
}

func testPod() *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "web-0",
			Namespace:   "prod",
			UID:         "uid-123",
			Labels:      map[string]string{"app": "web"},
			Annotations: map[string]string{"team": "sre"},
		},
		Spec: corev1.PodSpec{NodeName: "node-1"},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{ContainerID: "containerd://" + fakeCID},
			},
		},
	}
}

func TestWatcher_PodLifecycle(t *testing.T) {
	w := newTestWatcher()
	assert.False(t, w.HasSynced())

	w.onPodAdd(testPod())
	assert.True(t, w.HasSynced())
	assert.False(t, w.LastSyncAt().IsZero())

	info, ok := w.GetPodInfo(fakeCID)
	require.True(t, ok)
	assert.Equal(t, "web-0", info.Name)
	assert.Equal(t, "prod", info.Namespace)
	assert.Equal(t, "node-1", info.NodeName)
	assert.Equal(t, 1, w.CachePodCount())

	// Update keeps the entry present.
	w.onPodUpdate(nil, testPod())
	_, ok = w.GetPodInfo(fakeCID)
	assert.True(t, ok)

	// Unexpected object types are ignored, not panics.
	w.onPodAdd("not a pod")
	w.onPodDelete(123)

	// Delete removes it.
	w.onPodDelete(testPod())
	_, ok = w.GetPodInfo(fakeCID)
	assert.False(t, ok)

	// GetPodInfoByPID on a bogus PID hits the cgroup-read error path.
	_, ok = w.GetPodInfoByPID(0)
	assert.False(t, ok)
}

func TestEnricher_GetEnrichmentInfo(t *testing.T) {
	w := newTestWatcher()
	w.onPodAdd(testPod())

	e := &Enricher{
		watcher:         w,
		logger:          k8sQuietLogger(),
		enrichmentCache: make(map[uint32]*EnrichmentInfo),
		cacheTTL:        time.Minute,
	}

	// No pod for an unknown PID → miss (nil watcher result via cgroup miss).
	info, ok := e.GetEnrichmentInfo(0)
	assert.False(t, ok)
	assert.Nil(t, info)

	assert.Equal(t, 1, e.GetCachedPodCount())

	// cleanupCache evicts stale entries without error.
	e.mu.Lock()
	e.enrichmentCache[42] = &EnrichmentInfo{CachedAt: time.Now().Add(-time.Hour)}
	e.mu.Unlock()
	e.cleanupCache()
	e.mu.RLock()
	_, present := e.enrichmentCache[42]
	e.mu.RUnlock()
	assert.False(t, present)
}

func TestEnrichmentInfo_ToTypesEnrichment(t *testing.T) {
	var nilInfo *EnrichmentInfo
	assert.Nil(t, nilInfo.ToTypesEnrichment())

	ei := &EnrichmentInfo{
		PodName:     "p",
		Namespace:   "ns",
		PodUID:      "u",
		NodeName:    "n",
		Labels:      map[string]string{"a": "b"},
		ContainerID: fakeCID,
	}
	got := ei.ToTypesEnrichment()
	require.NotNil(t, got)
	assert.Equal(t, "p", got.PodName)
	assert.Equal(t, "ns", got.Namespace)
	assert.Equal(t, fakeCID, got.ContainerID)
	assert.Equal(t, "b", got.Labels["a"])
}

func TestEnricher_EnrichEventNilSafe(t *testing.T) {
	e := &Enricher{
		watcher:         newTestWatcher(),
		logger:          k8sQuietLogger(),
		enrichmentCache: make(map[uint32]*EnrichmentInfo),
		cacheTTL:        time.Minute,
	}
	// Nil event/alert must be handled without panicking.
	e.EnrichAlert(nil)

	ev := &types.Event{PID: 7}
	e.EnrichEvent(ev) // no matching pod → enrichment left nil
	assert.Nil(t, ev.Enrichment)
}

// ── Watcher: Stop ─────────────────────────────────────────────────────────────

func TestWatcher_StopIdempotent(t *testing.T) {
	w := &Watcher{
		logger:   k8sQuietLogger(),
		podCache: make(map[string]*PodInfo),
		stopCh:   make(chan struct{}),
	}
	require.NoError(t, w.Stop())
	require.NoError(t, w.Stop(), "Stop must be safe to call multiple times")
}

// ── Watcher: newWatcherWithClient + Start/Stop ────────────────────────────────

func TestNewWatcherWithClient_FakeK8s(t *testing.T) {
	fakeClient := k8sfake.NewClientset()
	cfg := WatcherConfig{ResyncPeriod: 0}

	w, err := newWatcherWithClient(fakeClient, cfg, k8sQuietLogger())
	require.NoError(t, err)
	require.NotNil(t, w)
	assert.NotNil(t, w.informer)
	assert.NotNil(t, w.stopCh)
}

func TestWatcher_StartStop_FakeK8s(t *testing.T) {
	fakeClient := k8sfake.NewClientset()
	cfg := WatcherConfig{ResyncPeriod: 0}

	w, err := newWatcherWithClient(fakeClient, cfg, k8sQuietLogger())
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- w.Start(ctx) }()

	// Wait until the informer reports synced.
	deadline := time.Now().Add(3 * time.Second)
	for !w.HasSynced() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	assert.True(t, w.HasSynced(), "watcher should complete initial cache sync")

	cancel()
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not stop within timeout")
	}
}

func TestWatcher_StartStop_FakeK8s_WithPod(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "nginx-0", Namespace: "default", UID: "uid-abc",
			Labels: map[string]string{"app": "nginx"},
		},
		Spec: corev1.PodSpec{NodeName: "node-1"},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{ContainerID: "containerd://" + fakeCID},
			},
		},
	}

	fakeClient := k8sfake.NewClientset(pod)
	cfg := WatcherConfig{ResyncPeriod: 0}

	w, err := newWatcherWithClient(fakeClient, cfg, k8sQuietLogger())
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- w.Start(ctx) }()

	deadline := time.Now().Add(3 * time.Second)
	for !w.HasSynced() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	assert.True(t, w.HasSynced())

	info, ok := w.GetPodInfo(fakeCID)
	require.True(t, ok, "pod should be in cache after informer sync")
	assert.Equal(t, "nginx-0", info.Name)

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not stop within timeout")
	}
}

func TestWatcher_NodeScopedInformer(t *testing.T) {
	fakeClient := k8sfake.NewClientset()
	cfg := WatcherConfig{ResyncPeriod: 0, NodeName: "node-42"}

	w, err := newWatcherWithClient(fakeClient, cfg, k8sQuietLogger())
	require.NoError(t, err)
	require.NotNil(t, w)
}

// ── Enricher: cacheCleanupLoop ───────────────────────────────────────────────

func TestEnricher_CacheCleanupLoop_ContextCancel(t *testing.T) {
	e := &Enricher{
		logger:          k8sQuietLogger(),
		enrichmentCache: make(map[uint32]*EnrichmentInfo),
		cacheTTL:        50 * time.Millisecond,
	}
	e.enrichmentCache[1] = &EnrichmentInfo{
		PodName:  "test-pod",
		CachedAt: time.Now().Add(-time.Hour), // already expired
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.cacheCleanupLoop(ctx)
	}()

	// Let at least one tick fire.
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cacheCleanupLoop did not stop")
	}

	e.mu.RLock()
	_, present := e.enrichmentCache[1]
	e.mu.RUnlock()
	assert.False(t, present, "expired entry should be evicted by cleanup loop")
}

func TestEnricher_CacheCleanupLoop_ImmediateCancel(t *testing.T) {
	e := &Enricher{
		logger:          k8sQuietLogger(),
		enrichmentCache: make(map[uint32]*EnrichmentInfo),
		cacheTTL:        30 * time.Second, // long ticker so only ctx.Done fires
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	done := make(chan struct{})
	go func() {
		defer close(done)
		e.cacheCleanupLoop(ctx)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cacheCleanupLoop did not respect immediate context cancellation")
	}
}

// ── Enricher: metricsUpdateLoop ──────────────────────────────────────────────

func k8sReadCounter(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	m := &dto.Metric{}
	require.NoError(t, c.Write(m))
	return m.GetCounter().GetValue()
}

func TestEnricher_MetricsUpdateLoop_ImmediateCancel(t *testing.T) {
	e := &Enricher{
		logger:          k8sQuietLogger(),
		enrichmentCache: make(map[uint32]*EnrichmentInfo),
		cacheTTL:        30 * time.Second,
		metrics: EnricherMetrics{
			MissTotal: prometheus.NewCounter(prometheus.CounterOpts{Name: "test_k8s_loop_miss"}),
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		e.metricsUpdateLoop(ctx)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("metricsUpdateLoop did not respect cancelled context")
	}
}

// ── Enricher: Stop ───────────────────────────────────────────────────────────

func TestEnricher_Stop_DelegatesToWatcher(t *testing.T) {
	w := &Watcher{
		logger:   k8sQuietLogger(),
		podCache: make(map[string]*PodInfo),
		stopCh:   make(chan struct{}),
	}
	e := newEnricherWithWatcher(w, EnricherConfig{}, k8sQuietLogger())
	require.NoError(t, e.Stop())
	// Watcher.Stop closes stopCh; second Stop must be a no-op.
	require.NoError(t, e.Stop())
}

// ── Enricher: GetPodInfo ─────────────────────────────────────────────────────

func TestEnricher_GetPodInfo_DelegatesToWatcher(t *testing.T) {
	w := newTestWatcher()
	w.onPodAdd(testPod())

	e := newEnricherWithWatcher(w, EnricherConfig{}, k8sQuietLogger())

	// PID 0 has no cgroup entry on the host — must miss cleanly.
	info, ok := e.GetPodInfo(0)
	assert.False(t, ok)
	assert.Nil(t, info)
}

// ── newEnricherWithWatcher ────────────────────────────────────────────────────

func TestNewEnricherWithWatcher_DefaultTTLs(t *testing.T) {
	w := newTestWatcher()
	e := newEnricherWithWatcher(w, EnricherConfig{}, k8sQuietLogger())

	assert.Equal(t, 30*time.Second, e.cacheTTL)
	assert.Equal(t, 300*time.Second, e.resyncPeriod)
}

func TestNewEnricherWithWatcher_CustomTTLs(t *testing.T) {
	w := newTestWatcher()
	e := newEnricherWithWatcher(w, EnricherConfig{
		CacheTTL:     time.Minute,
		ResyncPeriod: 10 * time.Minute,
	}, k8sQuietLogger())

	assert.Equal(t, time.Minute, e.cacheTTL)
	assert.Equal(t, 10*time.Minute, e.resyncPeriod)
}

func TestNewEnricherWithWatcher_MetricsWired(t *testing.T) {
	missTotal := prometheus.NewCounter(prometheus.CounterOpts{Name: "test_k8s_enricher_watcher_miss"})
	w := newTestWatcher()
	e := newEnricherWithWatcher(w, EnricherConfig{
		Metrics: EnricherMetrics{MissTotal: missTotal},
	}, k8sQuietLogger())

	// Drive 3 misses via getEnrichmentInfo (no watcher result for PID 0).
	e.getEnrichmentInfo(1)
	e.getEnrichmentInfo(2)
	e.getEnrichmentInfo(3)
	assert.Equal(t, int64(3), e.missCount.Load())

	// updateMetrics should drain into the Prometheus counter.
	e.updateMetrics()
	assert.Equal(t, float64(3), k8sReadCounter(t, missTotal))
}

// ── Enricher: Start (with fake k8s) ─────────────────────────────────────────

func TestEnricher_Start_FakeK8s(t *testing.T) {
	fakeClient := k8sfake.NewClientset()
	w, err := newWatcherWithClient(fakeClient, WatcherConfig{ResyncPeriod: 0}, k8sQuietLogger())
	require.NoError(t, err)

	e := newEnricherWithWatcher(w, EnricherConfig{}, k8sQuietLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- e.Start(ctx) }()

	// Allow informer to sync, then cancel.
	deadline := time.Now().Add(3 * time.Second)
	for !w.HasSynced() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()

	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("enricher Start did not stop within timeout")
	}
}

func TestEnricher_Start_FakeK8s_WithMetrics(t *testing.T) {
	cachePods := prometheus.NewGauge(prometheus.GaugeOpts{Name: "test_k8s_start_cache_pods"})
	missTotal := prometheus.NewCounter(prometheus.CounterOpts{Name: "test_k8s_start_miss_total"})

	fakeClient := k8sfake.NewClientset()
	w, err := newWatcherWithClient(fakeClient, WatcherConfig{ResyncPeriod: 0}, k8sQuietLogger())
	require.NoError(t, err)

	e := newEnricherWithWatcher(w, EnricherConfig{
		Metrics: EnricherMetrics{CachePods: cachePods, MissTotal: missTotal},
	}, k8sQuietLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- e.Start(ctx) }()

	deadline := time.Now().Add(3 * time.Second)
	for !w.HasSynced() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("enricher Start did not stop within timeout")
	}
}

// ── Enricher: getEnrichmentInfo cache hit path ───────────────────────────────

func TestEnricher_GetEnrichmentInfo_CacheHit(t *testing.T) {
	w := newTestWatcher()
	e := newEnricherWithWatcher(w, EnricherConfig{CacheTTL: time.Minute}, k8sQuietLogger())

	// Manually seed the enrichment cache.
	e.mu.Lock()
	e.enrichmentCache[42] = &EnrichmentInfo{
		PodName:   "cached-pod",
		Namespace: "prod",
		CachedAt:  time.Now(),
	}
	e.mu.Unlock()

	info, ok := e.GetEnrichmentInfo(42)
	require.True(t, ok)
	assert.Equal(t, "cached-pod", info.PodName)
}

func TestEnricher_GetCachedPodCount(t *testing.T) {
	w := newTestWatcher()
	w.onPodAdd(testPod())

	e := newEnricherWithWatcher(w, EnricherConfig{}, k8sQuietLogger())
	assert.Equal(t, 1, e.GetCachedPodCount())
}

// ── Enricher: EnrichAlert sets fields from cache ──────────────────────────────

func TestEnricher_EnrichAlert_FromCache(t *testing.T) {
	w := newTestWatcher()
	e := newEnricherWithWatcher(w, EnricherConfig{CacheTTL: time.Minute}, k8sQuietLogger())

	// Seed enrichment info directly.
	e.mu.Lock()
	e.enrichmentCache[99] = &EnrichmentInfo{
		PodName:   "my-pod",
		Namespace: "staging",
		CachedAt:  time.Now(),
	}
	e.mu.Unlock()

	alert := &types.Alert{Event: types.Event{PID: 99}}
	e.EnrichAlert(alert)

	assert.Equal(t, "my-pod", alert.Enrichment.PodName)
	assert.Equal(t, "staging", alert.Enrichment.Namespace)
}

// ── Enricher: EnrichEvent sets fields from cache ──────────────────────────────

func TestEnricher_EnrichEvent_FromCache(t *testing.T) {
	w := newTestWatcher()
	e := newEnricherWithWatcher(w, EnricherConfig{CacheTTL: time.Minute}, k8sQuietLogger())

	e.mu.Lock()
	e.enrichmentCache[55] = &EnrichmentInfo{
		PodName:   "event-pod",
		Namespace: "kube-system",
		CachedAt:  time.Now(),
	}
	e.mu.Unlock()

	event := &types.Event{PID: 55}
	e.EnrichEvent(event)

	require.NotNil(t, event.Enrichment)
	assert.Equal(t, "event-pod", event.Enrichment.PodName)
}
