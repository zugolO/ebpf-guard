package profiler

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func wlEvent(comm string, pid uint32) types.Event {
	var c [16]byte
	copy(c[:], comm)
	return types.Event{
		Type:    types.EventSyscall,
		PID:     pid,
		Comm:    c,
		Syscall: &types.SyscallEvent{Nr: 1, Args: [6]uint64{}},
	}
}

func TestWorkloadProfileManager_RecordAndQuery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	wpm := NewWorkloadProfileManager(ctx, 0.3, time.Hour, 100)

	wpm.RecordEvent(wlEvent("nginx", 1))
	wpm.RecordEvent(wlEvent("nginx", 2)) // same workload, touch path
	wpm.RecordEvent(wlEvent("redis", 3))

	assert.Equal(t, 2, wpm.Len())
	assert.Len(t, wpm.Keys(), 2)
	assert.Len(t, wpm.GetAll(), 2)

	// GetOrCreateByKey returns the same profile on repeat.
	k := WorkloadKey{Comm: "nginx"}
	p1 := wpm.GetOrCreateByKey(k)
	p2 := wpm.GetOrCreateByKey(k)
	assert.Same(t, p1, p2)

	// RegisterMetrics succeeds against a fresh registry.
	require.NoError(t, wpm.RegisterMetrics(prometheus.NewRegistry()))

	wpm.Flush()
	assert.Equal(t, 0, wpm.Len())
}

func TestWorkloadProfileManager_Eviction(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// maxKeys=4 forces eviction once a 5th distinct workload appears.
	wpm := NewWorkloadProfileManager(ctx, 0.3, time.Hour, 4)

	for i := 0; i < 12; i++ {
		wpm.RecordEvent(wlEvent(fmt.Sprintf("proc-%d", i), uint32(i)))
	}

	// The global cap must hold the tracked set at or below maxKeys.
	assert.LessOrEqual(t, wpm.Len(), 4)
}

func TestWorkloadProfileManager_CleanupExpired(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Tiny TTL so the recorded profile is immediately expired.
	wpm := NewWorkloadProfileManager(ctx, 0.3, time.Nanosecond, 100)
	wpm.RecordEvent(wlEvent("ephemeral", 1))
	time.Sleep(2 * time.Millisecond)

	removed := wpm.CleanupExpired()
	assert.GreaterOrEqual(t, removed, 1)
	assert.Equal(t, 0, wpm.Len())
}
