package profiler

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProfileManager_ConcurrentRecordEvent tests for race conditions in RecordEvent
func TestProfileManager_ConcurrentRecordEvent(t *testing.T) {
	pm := NewProfileManager(0.1, 24*60*60)

	var wg sync.WaitGroup
	numGoroutines := 100
	numEvents := 100

	// Concurrent events for same PID
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numEvents; j++ {
				event := types.Event{
					Type: types.EventTCPConnect,
					PID:  1234, // Same PID
					Network: &types.NetworkEvent{
						Dport: 80,
						Daddr: [16]byte{8, 8, 8, 8},
					},
				}
				pm.RecordEvent(event)
			}
		}(i)
	}

	wg.Wait()

	// Verify profile was created and has expected data
	profile := pm.Get(1234)
	assert.NotNil(t, profile)
	assert.Equal(t, uint64(numGoroutines*numEvents), profile.NetworkProfile.TotalConnections)
}

// TestProfileManager_ConcurrentRecordAndGet tests concurrent RecordEvent and Get
func TestProfileManager_ConcurrentRecordAndGet(t *testing.T) {
	pm := NewProfileManager(0.1, 24*60*60)

	var wg sync.WaitGroup
	numGoroutines := 50
	numOperations := 100

	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				event := types.Event{
					Type: types.EventSyscall,
					PID:  uint32(id),
					Syscall: &types.SyscallEvent{
						Nr: int64(j % 10),
					},
				}
				pm.RecordEvent(event)
			}
		}(i)
	}

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				_ = pm.Get(uint32(id))
			}
		}(i)
	}

	wg.Wait()
}

// TestProfileManager_ConcurrentRecordAndCalculateAnomaly tests the race between
// RecordEvent and calculateAnomalyScore (the main Race B scenario)
func TestProfileManager_ConcurrentRecordAndCalculateAnomaly(t *testing.T) {
	pm := NewProfileManager(0.1, 24*60*60)

	// Pre-populate profile
	for i := 0; i < 100; i++ {
		event := types.Event{
			Type: types.EventTCPConnect,
			PID:  1234,
			Network: &types.NetworkEvent{
				Dport: 80,
				Daddr: [16]byte{8, 8, 8, 8},
			},
		}
		pm.RecordEvent(event)
	}

	var wg sync.WaitGroup

	// Concurrent record events
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				event := types.Event{
					Type: types.EventTCPConnect,
					PID:  1234,
					Network: &types.NetworkEvent{
						Dport: uint16(80 + j%10),
						Daddr: [16]byte{8, 8, 8, 8},
					},
				}
				pm.RecordEvent(event)
			}
		}()
	}

	// Concurrent anomaly detection (simulates calculateAnomalyScore)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				profile := pm.Get(1234)
				if profile != nil {
					// Read profile data (simulates what calculateAnomalyScore does)
					_ = profile.GetAnomalyScore()
					_ = profile.NetworkProfile.TotalConnections
				}
			}
		}()
	}

	wg.Wait()
}

// TestProfileManager_ConcurrentDifferentEventTypes tests concurrent different event types
func TestProfileManager_ConcurrentDifferentEventTypes(t *testing.T) {
	pm := NewProfileManager(0.1, 24*60*60)

	var wg sync.WaitGroup
	numGoroutines := 30
	numEvents := 50

	// Network events
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numEvents; j++ {
				event := types.Event{
					Type: types.EventTCPConnect,
					PID:  uint32(id),
					Network: &types.NetworkEvent{
						Dport: 80,
						Daddr: [16]byte{8, 8, 8, 8},
					},
				}
				pm.RecordEvent(event)
			}
		}(i)
	}

	// File events
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numEvents; j++ {
				event := types.Event{
					Type: types.EventFileAccess,
					PID:  uint32(id),
					File: &types.FileEvent{
						Filename: [256]byte{'/', 'e', 't', 'c', '/', 'p', 'a', 's', 's', 'w', 'd'},
					},
				}
				pm.RecordEvent(event)
			}
		}(i)
	}

	// Syscall events
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numEvents; j++ {
				event := types.Event{
					Type: types.EventSyscall,
					PID:  uint32(id),
					Syscall: &types.SyscallEvent{
						Nr: int64(j % 10),
					},
				}
				pm.RecordEvent(event)
			}
		}(i)
	}

	wg.Wait()
}

// TestProfileManager_ConcurrentCleanup tests concurrent CleanupExpired
func TestProfileManager_ConcurrentCleanup(t *testing.T) {
	pm := NewProfileManager(0.1, 1) // 1 nanosecond TTL for quick expiration

	// Create profiles
	for i := 0; i < 100; i++ {
		event := types.Event{
			Type:    types.EventSyscall,
			PID:     uint32(i),
			Syscall: &types.SyscallEvent{Nr: 1},
		}
		pm.RecordEvent(event)
	}

	var wg sync.WaitGroup

	// Concurrent cleanup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pm.CleanupExpired()
		}()
	}

	// Concurrent record
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				event := types.Event{
					Type:    types.EventSyscall,
					PID:     uint32(id),
					Syscall: &types.SyscallEvent{Nr: int64(j)},
				}
				pm.RecordEvent(event)
			}
		}(i)
	}

	wg.Wait()
}

// TestProcessProfile_ConcurrentRecordAndRead tests concurrent record and read on same profile
func TestProcessProfile_ConcurrentRecordAndRead(t *testing.T) {
	profile := NewProcessProfile(1234, "test")

	var wg sync.WaitGroup

	// Concurrent record network events
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				event := &types.NetworkEvent{
					Dport: uint16(80 + id),
					Daddr: [16]byte{8, 8, uint8(id), uint8(j)},
				}
				profile.RecordNetworkEvent(event, 0.1)
			}
		}(i)
	}

	// Concurrent read
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = profile.GetAnomalyScore()
				_ = profile.IsExpired(24 * 60 * 60)
			}
		}()
	}

	wg.Wait()

	// Verify total
	assert.Equal(t, uint64(1000), profile.NetworkProfile.TotalConnections)
}

// TestProfileManager_MaxPIDsCap verifies that the map never exceeds maxPIDs under load.
func TestProfileManager_MaxPIDsCap(t *testing.T) {
	const maxPIDs = 100
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pm := NewProfileManagerWithContext(ctx, 0.1, 24*time.Hour, maxPIDs)

	// Spawn 200k unique PIDs
	var wg sync.WaitGroup
	for i := 0; i < 200_000; i++ {
		wg.Add(1)
		go func(pid uint32) {
			defer wg.Done()
			pm.RecordEvent(types.Event{
				Type:    types.EventSyscall,
				PID:     pid,
				Syscall: &types.SyscallEvent{Nr: 1},
			})
		}(uint32(i))
	}
	wg.Wait()

	pm.mu.RLock()
	size := len(pm.profiles)
	pm.mu.RUnlock()

	require.LessOrEqual(t, size, maxPIDs, "map size must never exceed maxPIDs")
}

// TestProfileManager_CleanupRemovesStale verifies that CleanupExpired removes
// entries after their TTL and the goroutine exits cleanly on context cancellation.
func TestProfileManager_CleanupRemovesStale(t *testing.T) {
	const ttl = 50 * time.Millisecond
	// Use a long cleanup interval so the background goroutine doesn't race with
	// the manual CleanupExpired call below.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Build manually (no goroutine) to avoid race with manual call.
	pm := &ProfileManager{
		profiles: make(map[uint32]*ProcessProfile),
		weight:   0.1,
		ttl:      ttl,
		maxPIDs:  65536,
	}

	// Insert 10 profiles
	for i := 0; i < 10; i++ {
		pm.RecordEvent(types.Event{
			Type:    types.EventSyscall,
			PID:     uint32(i),
			Syscall: &types.SyscallEvent{Nr: 1},
		})
	}

	pm.mu.RLock()
	before := len(pm.profiles)
	pm.mu.RUnlock()
	require.Equal(t, 10, before)

	// Wait for TTL to pass then trigger cleanup
	time.Sleep(ttl + 20*time.Millisecond)
	removed := pm.CleanupExpired()
	assert.Equal(t, 10, removed, "all stale entries should be removed")

	pm.mu.RLock()
	after := len(pm.profiles)
	pm.mu.RUnlock()
	assert.Equal(t, 0, after)

	// Verify background goroutine exits on cancel (no panic/race).
	pmWithCtx := NewProfileManagerWithContext(ctx, 0.1, time.Hour, 65536)
	_ = pmWithCtx
	cancel()
	time.Sleep(10 * time.Millisecond)
}

// TestSequenceProfiler_MaxPIDsCap verifies SequenceProfiler never exceeds maxPIDs.
func TestSequenceProfiler_MaxPIDsCap(t *testing.T) {
	const maxPIDs = 50
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sp := NewSequenceProfilerWithContext(ctx, DefaultSequenceConfig(), time.Hour, maxPIDs)

	var wg sync.WaitGroup
	for i := 0; i < 10_000; i++ {
		wg.Add(1)
		go func(pid uint32) {
			defer wg.Done()
			sp.Update(types.Event{
				Type:    types.EventSyscall,
				PID:     pid,
				Syscall: &types.SyscallEvent{Nr: 1},
			})
		}(uint32(i))
	}
	wg.Wait()

	sp.mu.RLock()
	size := len(sp.states)
	sp.mu.RUnlock()

	require.LessOrEqual(t, size, maxPIDs, "SequenceProfiler map must not exceed maxPIDs")
}
