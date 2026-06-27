package runtime

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// stubClient is a RuntimeClient that returns fixed data for testing.
type stubClient struct {
	containers map[string]*ContainerInfo
	calls      int
}

func (s *stubClient) GetContainerInfo(_ context.Context, id string) (*ContainerInfo, error) {
	s.calls++
	if info, ok := s.containers[id]; ok {
		return info, nil
	}
	return nil, errors.New("not found")
}

func (s *stubClient) Close() error { return nil }

func newTestEnricher(t *testing.T, stub *stubClient) *Enricher {
	t.Helper()
	return &Enricher{
		client:         stub,
		source:         "docker",
		logger:         newTestLogger(),
		cacheTTL:       30 * time.Second,
		pidCache:       make(map[uint32]string),
		containerCache: make(map[string]*ContainerInfo),
	}
}

func TestEnrichEvent_NilSafe(t *testing.T) {
	e := newTestEnricher(t, &stubClient{containers: map[string]*ContainerInfo{}})
	e.EnrichEvent(nil) // must not panic
}

func TestEnrichEvent_PopulatesFields(t *testing.T) {
	const containerID = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	stub := &stubClient{
		containers: map[string]*ContainerInfo{
			containerID: {
				ContainerID:   containerID,
				ContainerName: "my-service",
				Image:         "nginx:latest",
				Labels:        map[string]string{"env": "prod"},
				CachedAt:      time.Now(),
			},
		},
	}
	e := newTestEnricher(t, stub)
	// Seed the pid cache so we bypass the /proc read.
	e.pidCache[1234] = containerID

	event := &types.Event{PID: 1234}
	e.EnrichEvent(event)

	if event.Enrichment == nil {
		t.Fatal("enrichment is nil")
	}
	if event.Enrichment.ContainerID != containerID {
		t.Errorf("ContainerID = %q, want %q", event.Enrichment.ContainerID, containerID)
	}
	if event.Enrichment.ContainerName != "my-service" {
		t.Errorf("ContainerName = %q, want my-service", event.Enrichment.ContainerName)
	}
	if event.Enrichment.ContainerImage != "nginx:latest" {
		t.Errorf("ContainerImage = %q, want nginx:latest", event.Enrichment.ContainerImage)
	}
	if event.Enrichment.RuntimeSource != "docker" {
		t.Errorf("RuntimeSource = %q, want docker", event.Enrichment.RuntimeSource)
	}
}

func TestEnrichEvent_PopulatesPodIdentityFromOCIAnnotations(t *testing.T) {
	const containerID = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	stub := &stubClient{
		containers: map[string]*ContainerInfo{
			containerID: {
				ContainerID:   containerID,
				ContainerName: "web",
				Image:         "nginx:latest",
				// CRI/OCI spec annotations carry pod identity node-locally.
				Labels: map[string]string{
					"io.kubernetes.pod.namespace": "production",
					"io.kubernetes.pod.name":      "web-7d9f",
					"io.kubernetes.pod.uid":       "abc-123-uid",
				},
				CachedAt: time.Now(),
			},
		},
	}
	e := newTestEnricher(t, stub)
	e.pidCache[2222] = containerID

	event := &types.Event{PID: 2222}
	e.EnrichEvent(event)

	if event.Enrichment == nil {
		t.Fatal("enrichment is nil")
	}
	if event.Enrichment.Namespace != "production" {
		t.Errorf("Namespace = %q, want production", event.Enrichment.Namespace)
	}
	if event.Enrichment.PodName != "web-7d9f" {
		t.Errorf("PodName = %q, want web-7d9f", event.Enrichment.PodName)
	}
	if event.Enrichment.PodUID != "abc-123-uid" {
		t.Errorf("PodUID = %q, want abc-123-uid", event.Enrichment.PodUID)
	}
}

func TestEnrichEvent_CachesResults(t *testing.T) {
	const containerID = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	stub := &stubClient{
		containers: map[string]*ContainerInfo{
			containerID: {
				ContainerID:   containerID,
				ContainerName: "cached-service",
				Image:         "alpine:3",
				CachedAt:      time.Now(),
			},
		},
	}
	e := newTestEnricher(t, stub)
	e.pidCache[9000] = containerID

	// First call should hit the runtime.
	e.EnrichEvent(&types.Event{PID: 9000})
	if stub.calls != 1 {
		t.Fatalf("expected 1 runtime call, got %d", stub.calls)
	}

	// Second call should use the cache.
	e.EnrichEvent(&types.Event{PID: 9000})
	if stub.calls != 1 {
		t.Errorf("expected cached result (still 1 call), got %d", stub.calls)
	}
}

func TestEnrichAlert_PopulatesFields(t *testing.T) {
	const containerID = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	stub := &stubClient{
		containers: map[string]*ContainerInfo{
			containerID: {
				ContainerID:   containerID,
				ContainerName: "alert-target",
				Image:         "redis:7",
				CachedAt:      time.Now(),
			},
		},
	}
	e := newTestEnricher(t, stub)
	e.pidCache[5555] = containerID

	alert := &types.Alert{Event: types.Event{PID: 5555}}
	e.EnrichAlert(alert)

	if alert.Enrichment.ContainerName != "alert-target" {
		t.Errorf("ContainerName = %q, want alert-target", alert.Enrichment.ContainerName)
	}
}

func TestEnrichEvent_PreservesK8sFields(t *testing.T) {
	const containerID = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	stub := &stubClient{
		containers: map[string]*ContainerInfo{
			containerID: {
				ContainerID:   containerID,
				ContainerName: "runtime-name",
				Image:         "myimage:v1",
				CachedAt:      time.Now(),
			},
		},
	}
	e := newTestEnricher(t, stub)
	e.pidCache[7777] = containerID

	// Simulate an event that already has K8s enrichment (pod name / namespace).
	event := &types.Event{
		PID: 7777,
		Enrichment: &types.EnrichmentInfo{
			PodName:       "my-pod",
			Namespace:     "production",
			ContainerID:   containerID,
			RuntimeSource: "k8s",
		},
	}
	e.EnrichEvent(event)

	// K8s-set fields must not be overwritten.
	if event.Enrichment.PodName != "my-pod" {
		t.Errorf("PodName overwritten: got %q", event.Enrichment.PodName)
	}
	if event.Enrichment.RuntimeSource != "k8s" {
		t.Errorf("RuntimeSource overwritten: got %q", event.Enrichment.RuntimeSource)
	}
	// Runtime-only fields should still be filled in.
	if event.Enrichment.ContainerName != "runtime-name" {
		t.Errorf("ContainerName not filled: got %q", event.Enrichment.ContainerName)
	}
}

func TestCleanupLoop_EvictsExpiredEntries(t *testing.T) {
	const containerID = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	e := newTestEnricher(t, &stubClient{containers: map[string]*ContainerInfo{}})
	e.cacheTTL = 10 * time.Millisecond

	// Seed an already-expired container entry.
	e.containerCache[containerID] = &ContainerInfo{
		ContainerID: containerID,
		CachedAt:    time.Now().Add(-time.Second),
	}
	e.pidCache[1] = containerID

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.cleanupLoop(ctx)

	time.Sleep(50 * time.Millisecond)

	e.containerMu.RLock()
	_, still := e.containerCache[containerID]
	e.containerMu.RUnlock()
	if still {
		t.Error("expired container entry was not evicted")
	}
}

func TestCacheSize(t *testing.T) {
	e := newTestEnricher(t, &stubClient{containers: map[string]*ContainerInfo{}})
	if e.CacheSize() != 0 {
		t.Errorf("initial cache size = %d, want 0", e.CacheSize())
	}
	e.containerCache["x"] = &ContainerInfo{}
	if e.CacheSize() != 1 {
		t.Errorf("cache size = %d, want 1", e.CacheSize())
	}
}

// newTestLogger returns a no-op slog.Logger for use in tests.
func newTestLogger() *slog.Logger {
	return slog.Default()
}

// ── min helper ───────────────────────────────────────────────────────────────

func TestMin(t *testing.T) {
	assert.Equal(t, 0, min(0, 5))
	assert.Equal(t, 0, min(5, 0))
	assert.Equal(t, 3, min(3, 3))
	assert.Equal(t, 1, min(1, 100))
	assert.Equal(t, 1, min(100, 1))
}

// ── newEnricherWithClient ────────────────────────────────────────────────────

func TestNewEnricherWithClient_SetsSource(t *testing.T) {
	stub := &stubClient{containers: map[string]*ContainerInfo{}}
	e := newEnricherWithClient(stub, "containerd", EnricherConfig{}, newTestLogger())
	assert.Equal(t, "containerd", e.Source())
}

func TestNewEnricherWithClient_DefaultCacheTTL(t *testing.T) {
	stub := &stubClient{containers: map[string]*ContainerInfo{}}
	e := newEnricherWithClient(stub, "docker", EnricherConfig{CacheTTL: 0}, newTestLogger())
	assert.Equal(t, 30*time.Second, e.cacheTTL)
}

func TestNewEnricherWithClient_CustomCacheTTL(t *testing.T) {
	stub := &stubClient{containers: map[string]*ContainerInfo{}}
	e := newEnricherWithClient(stub, "docker", EnricherConfig{CacheTTL: 5 * time.Minute}, newTestLogger())
	assert.Equal(t, 5*time.Minute, e.cacheTTL)
}

// ── NewEnricher (mode=off) ───────────────────────────────────────────────────

func TestNewEnricher_ModeOff_ReturnsError(t *testing.T) {
	_, err := NewEnricher(EnricherConfig{Mode: "off"}, newTestLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "disabled")
}

func TestNewEnricher_EmptyMode_ReturnsError(t *testing.T) {
	_, err := NewEnricher(EnricherConfig{Mode: ""}, newTestLogger())
	require.Error(t, err)
}

// ── Source ───────────────────────────────────────────────────────────────────

func TestSource(t *testing.T) {
	for _, src := range []string{"docker", "containerd", "crio"} {
		e := newEnricherWithClient(&stubClient{containers: map[string]*ContainerInfo{}}, src, EnricherConfig{}, newTestLogger())
		assert.Equal(t, src, e.Source())
	}
}

// ── Start / Stop ─────────────────────────────────────────────────────────────

func TestEnricher_StartStop(t *testing.T) {
	stub := &stubClient{containers: map[string]*ContainerInfo{}}
	e := newEnricherWithClient(stub, "docker", EnricherConfig{}, newTestLogger())

	ctx, cancel := context.WithCancel(context.Background())
	e.Start(ctx)
	cancel()

	// Allow goroutines time to exit; cleanupLoop uses e.cacheTTL ticker.
	time.Sleep(20 * time.Millisecond)
	require.NoError(t, e.Stop())
}

func TestEnricher_StartStop_WithMetrics(t *testing.T) {
	cacheSize := prometheus.NewGauge(prometheus.GaugeOpts{Name: "test_rt_cache_size"})
	missTotal := prometheus.NewCounter(prometheus.CounterOpts{Name: "test_rt_miss_total"})

	stub := &stubClient{containers: map[string]*ContainerInfo{}}
	e := newEnricherWithClient(stub, "docker", EnricherConfig{
		Metrics: EnricherMetrics{CacheSize: cacheSize, MissTotal: missTotal},
	}, newTestLogger())

	ctx, cancel := context.WithCancel(context.Background())
	e.Start(ctx) // starts both cleanupLoop and metricsLoop
	cancel()

	time.Sleep(20 * time.Millisecond)
	require.NoError(t, e.Stop())
}

// ── updateMetrics ────────────────────────────────────────────────────────────

func readGaugeValue(t *testing.T, g prometheus.Gauge) float64 {
	t.Helper()
	m := &dto.Metric{}
	require.NoError(t, g.Write(m))
	return m.GetGauge().GetValue()
}

func readCounterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	m := &dto.Metric{}
	require.NoError(t, c.Write(m))
	return m.GetCounter().GetValue()
}

func TestUpdateMetrics_DrainsMissCount(t *testing.T) {
	missTotal := prometheus.NewCounter(prometheus.CounterOpts{Name: "test_rt_miss_drain"})
	stub := &stubClient{containers: map[string]*ContainerInfo{}}
	e := newEnricherWithClient(stub, "docker", EnricherConfig{
		Metrics: EnricherMetrics{MissTotal: missTotal},
	}, newTestLogger())

	e.missCount.Add(7)
	e.updateMetrics()

	assert.Equal(t, int64(0), e.missCount.Load(), "missCount should be drained")
	assert.Equal(t, float64(7), readCounterValue(t, missTotal))

	// Second call must not double-count.
	e.updateMetrics()
	assert.Equal(t, float64(7), readCounterValue(t, missTotal))
}

func TestUpdateMetrics_ReportsCacheSize(t *testing.T) {
	cacheSize := prometheus.NewGauge(prometheus.GaugeOpts{Name: "test_rt_cache_size2"})
	stub := &stubClient{containers: map[string]*ContainerInfo{}}
	e := newEnricherWithClient(stub, "docker", EnricherConfig{
		Metrics: EnricherMetrics{CacheSize: cacheSize},
	}, newTestLogger())

	e.containerCache["a"] = &ContainerInfo{}
	e.containerCache["b"] = &ContainerInfo{}
	e.updateMetrics()

	assert.Equal(t, float64(2), readGaugeValue(t, cacheSize))
}

func TestUpdateMetrics_NilMetricsNoOp(t *testing.T) {
	stub := &stubClient{containers: map[string]*ContainerInfo{}}
	e := newEnricherWithClient(stub, "docker", EnricherConfig{}, newTestLogger())
	e.missCount.Add(3)
	// Must not panic with nil metrics.
	e.updateMetrics()
}
