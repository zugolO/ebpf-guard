package runtime

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

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
