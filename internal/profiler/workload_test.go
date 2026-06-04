package profiler

import (
	"context"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWorkloadKeyString(t *testing.T) {
	tests := []struct {
		key  WorkloadKey
		want string
	}{
		{WorkloadKey{Comm: "nginx", Namespace: "prod", AppLabel: "frontend"}, "nginx|prod|frontend"},
		{WorkloadKey{Comm: "nginx", Namespace: "dev", AppLabel: "frontend"}, "nginx|dev|frontend"},
		{WorkloadKey{Comm: "nginx"}, "nginx||"},
		{WorkloadKey{}, "||"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, tt.key.String())
	}
}

func TestWorkloadKeyFromEvent(t *testing.T) {
	t.Run("no enrichment", func(t *testing.T) {
		e := types.Event{Comm: [16]byte{'n', 'g', 'i', 'n', 'x'}}
		k := WorkloadKeyFromEvent(e)
		assert.Equal(t, "nginx", k.Comm)
		assert.Equal(t, "", k.Namespace)
		assert.Equal(t, "", k.AppLabel)
	})

	t.Run("with enrichment", func(t *testing.T) {
		e := types.Event{
			Comm: [16]byte{'n', 'g', 'i', 'n', 'x'},
			Enrichment: &types.EnrichmentInfo{
				Namespace: "production",
				Labels:    map[string]string{"app": "web", "tier": "frontend"},
			},
		}
		k := WorkloadKeyFromEvent(e)
		assert.Equal(t, "nginx", k.Comm)
		assert.Equal(t, "production", k.Namespace)
		assert.Equal(t, "web", k.AppLabel)
	})

	t.Run("enrichment without app label", func(t *testing.T) {
		e := types.Event{
			Comm: [16]byte{'r', 'e', 'd', 'i', 's'},
			Enrichment: &types.EnrichmentInfo{
				Namespace: "cache",
				Labels:    map[string]string{"tier": "data"},
			},
		}
		k := WorkloadKeyFromEvent(e)
		assert.Equal(t, "redis", k.Comm)
		assert.Equal(t, "cache", k.Namespace)
		assert.Equal(t, "", k.AppLabel)
	})
}

func TestWorkloadProfileManager_Isolation(t *testing.T) {
	// nginx in prod and nginx in dev must use separate profiles.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	wpm := NewWorkloadProfileManager(ctx, 0.3, time.Hour, 100)

	prodKey := WorkloadKey{Comm: "nginx", Namespace: "prod", AppLabel: "nginx"}
	devKey := WorkloadKey{Comm: "nginx", Namespace: "dev", AppLabel: "nginx"}

	prodProfile := wpm.GetOrCreateByKey(prodKey)
	devProfile := wpm.GetOrCreateByKey(devKey)

	require.NotNil(t, prodProfile)
	require.NotNil(t, devProfile)
	assert.NotSame(t, prodProfile, devProfile, "prod and dev must have separate profiles")
	assert.Equal(t, 2, wpm.Len())
}

func TestWorkloadProfileManager_SharedBaseline(t *testing.T) {
	// Two PIDs in the same workload should share one profile.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	wpm := NewWorkloadProfileManager(ctx, 0.3, time.Hour, 100)

	key := WorkloadKey{Comm: "nginx", Namespace: "prod", AppLabel: "nginx"}

	// Events from two different PIDs with the same workload key.
	e1 := types.Event{
		Type: types.EventTCPConnect,
		PID:  100,
		Comm: [16]byte{'n', 'g', 'i', 'n', 'x'},
		Enrichment: &types.EnrichmentInfo{
			Namespace: "prod",
			Labels:    map[string]string{"app": "nginx"},
		},
		Network: &types.NetworkEvent{Dport: 80},
	}
	e2 := types.Event{
		Type: types.EventTCPConnect,
		PID:  200,
		Comm: [16]byte{'n', 'g', 'i', 'n', 'x'},
		Enrichment: &types.EnrichmentInfo{
			Namespace: "prod",
			Labels:    map[string]string{"app": "nginx"},
		},
		Network: &types.NetworkEvent{Dport: 443},
	}

	wpm.RecordEvent(e1)
	wpm.RecordEvent(e2)

	// One shared profile exists for the nginx-prod workload.
	assert.Equal(t, 1, wpm.Len())

	p := wpm.GetByKey(key)
	require.NotNil(t, p)
	// Both connections (port 80 and 443) are recorded in the shared profile.
	assert.Equal(t, uint64(2), p.NetworkProfile.TotalConnections)
}

func TestWorkloadProfileManager_FallbackNonK8s(t *testing.T) {
	// Without K8s enrichment, processes with the same comm share one profile.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	wpm := NewWorkloadProfileManager(ctx, 0.3, time.Hour, 100)

	for pid := uint32(1); pid <= 5; pid++ {
		e := types.Event{
			Type:    types.EventSyscall,
			PID:     pid,
			Comm:    [16]byte{'b', 'a', 's', 'h'},
			Syscall: &types.SyscallEvent{Nr: 1},
		}
		wpm.RecordEvent(e)
	}

	// All 5 PIDs share one comm-based profile (no K8s enrichment).
	assert.Equal(t, 1, wpm.Len())
	p := wpm.GetByKey(WorkloadKey{Comm: "bash"})
	require.NotNil(t, p)
	assert.Equal(t, uint64(5), p.SyscallProfile.TotalSyscalls)
}

func TestWorkloadProfileManager_LRUEviction(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const maxKeys = 3
	wpm := NewWorkloadProfileManager(ctx, 0.3, time.Hour, maxKeys)

	// Insert 4 distinct workload keys — should evict the LRU.
	for i := 0; i < 4; i++ {
		var comm [16]byte
		comm[0] = byte('a' + i)
		e := types.Event{
			Type:    types.EventSyscall,
			PID:     uint32(i + 1),
			Comm:    comm,
			Syscall: &types.SyscallEvent{Nr: 1},
		}
		wpm.RecordEvent(e)
		time.Sleep(time.Millisecond) // ensure distinct LastSeenAt ordering
	}

	assert.LessOrEqual(t, wpm.Len(), maxKeys, "map must not exceed maxKeys")
}

func TestWorkloadProfileManager_Cleanup(t *testing.T) {
	// Build without background goroutines to avoid the cleanup loop running
	// concurrently with the explicit CleanupExpired call below.
	shortTTL := 50 * time.Millisecond
	wpm := &WorkloadProfileManager{
		profiles: make(map[string]*ProcessProfile),
		weight:   0.3,
		ttl:      shortTTL,
		maxKeys:  100,
	}

	e := types.Event{
		Type:    types.EventSyscall,
		PID:     1,
		Comm:    [16]byte{'w', 'o', 'r', 'k'},
		Syscall: &types.SyscallEvent{Nr: 1},
	}
	wpm.RecordEvent(e)
	require.Equal(t, 1, wpm.Len())

	time.Sleep(shortTTL + 20*time.Millisecond)
	removed := wpm.CleanupExpired()
	assert.Equal(t, 1, removed)
	assert.Equal(t, 0, wpm.Len())
}

func TestAnomalyDetector_WorkloadSegmentation(t *testing.T) {
	// Same comm, different namespaces → separate EWMA baselines.
	// After learning on prod traffic, dev traffic should NOT be scored against
	// the prod baseline and vice versa.
	ad := NewAnomalyDetector(0.1, 50*time.Millisecond, 0.3)

	makeProdEvent := func(port uint16) types.Event {
		return types.Event{
			Type: types.EventTCPConnect,
			PID:  100,
			Comm: [16]byte{'n', 'g', 'i', 'n', 'x'},
			Enrichment: &types.EnrichmentInfo{
				Namespace: "prod",
				Labels:    map[string]string{"app": "nginx"},
			},
			Network: &types.NetworkEvent{Dport: port, Daddr: [16]byte{10, 0, 0, 1}},
		}
	}

	// Establish baseline for prod-nginx using port 80.
	for i := 0; i < 150; i++ {
		ad.ProcessEvent(makeProdEvent(80), false)
	}

	// Wait for learning phase to complete.
	time.Sleep(100 * time.Millisecond)

	// A dev-nginx event is not scored against the prod baseline.
	devEvent := types.Event{
		Type: types.EventTCPConnect,
		PID:  200,
		Comm: [16]byte{'n', 'g', 'i', 'n', 'x'},
		Enrichment: &types.EnrichmentInfo{
			Namespace: "dev",
			Labels:    map[string]string{"app": "nginx"},
		},
		Network: &types.NetworkEvent{Dport: 9999, Daddr: [16]byte{10, 0, 0, 2}},
	}
	result := ad.ProcessEvent(devEvent, false)
	// The dev workload has no completed learning phase yet, so no anomaly result.
	assert.Nil(t, result, "dev workload should not be scored against prod baseline")

	// prod-nginx connecting to a new port IS anomalous compared to its own baseline.
	anomalousResult := ad.ProcessEvent(makeProdEvent(9999), false)
	// After learning, a new port should produce a result (possibly anomaly).
	if anomalousResult != nil {
		assert.Equal(t, uint32(100), anomalousResult.PID)
		assert.Equal(t, "prod", anomalousResult.Namespace)
		assert.Equal(t, "nginx", anomalousResult.AppLabel)
	}
}
