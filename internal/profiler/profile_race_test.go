package profiler

import (
	"sync"
	"testing"

	"github.com/ebpf-guard/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
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
			Type: types.EventSyscall,
			PID:  uint32(i),
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
					Type: types.EventSyscall,
					PID:  uint32(id),
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
