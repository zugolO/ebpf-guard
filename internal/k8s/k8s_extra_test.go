package k8s

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
