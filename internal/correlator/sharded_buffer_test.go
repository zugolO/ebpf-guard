package correlator

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShardedEventBuffer_AddAndGet(t *testing.T) {
	sb := NewShardedEventBuffer(10)

	event := types.Event{
		Type: types.EventSyscall,
		PID:  1234,
	}

	sb.Add(1234, event)

	events := sb.Get(1234)
	require.Len(t, events, 1)
	assert.Equal(t, types.EventSyscall, events[0].Type)
	assert.Equal(t, uint32(1234), events[0].PID)
}

func TestShardedEventBuffer_GetNonExistent(t *testing.T) {
	sb := NewShardedEventBuffer(10)

	events := sb.Get(9999)
	assert.Nil(t, events)
}

func TestShardedEventBuffer_CircularBuffer(t *testing.T) {
	sb := NewShardedEventBuffer(5)

	// Add 7 events (more than capacity)
	for i := 0; i < 7; i++ {
		event := types.Event{
			Type:      types.EventSyscall,
			PID:       1234,
			Timestamp: uint64(i),
		}
		sb.Add(1234, event)
	}

	events := sb.Get(1234)
	require.Len(t, events, 5)

	// Should contain events 2-6 (oldest 2 were overwritten)
	for i, e := range events {
		assert.Equal(t, uint64(i+2), e.Timestamp)
	}
}

func TestShardedEventBuffer_GetRecent(t *testing.T) {
	sb := NewShardedEventBuffer(10)

	for i := 0; i < 10; i++ {
		event := types.Event{
			Type:      types.EventSyscall,
			PID:       1234,
			Timestamp: uint64(i),
		}
		sb.Add(1234, event)
	}

	recent := sb.GetRecent(1234, 3)
	require.Len(t, recent, 3)
	assert.Equal(t, uint64(7), recent[0].Timestamp)
	assert.Equal(t, uint64(8), recent[1].Timestamp)
	assert.Equal(t, uint64(9), recent[2].Timestamp)
}

func TestShardedEventBuffer_Remove(t *testing.T) {
	sb := NewShardedEventBuffer(10)

	sb.Add(1234, types.Event{Type: types.EventSyscall, PID: 1234})
	sb.Remove(1234)

	events := sb.Get(1234)
	assert.Nil(t, events)
}

func TestShardedEventBuffer_Clear(t *testing.T) {
	sb := NewShardedEventBuffer(10)

	for i := uint32(1); i <= 5; i++ {
		sb.Add(i, types.Event{Type: types.EventSyscall, PID: i})
	}

	sb.Clear()

	for i := uint32(1); i <= 5; i++ {
		events := sb.Get(i)
		assert.Nil(t, events)
	}
}

func TestShardedEventBuffer_PIDs(t *testing.T) {
	sb := NewShardedEventBuffer(10)

	for i := uint32(1); i <= 5; i++ {
		sb.Add(i, types.Event{Type: types.EventSyscall, PID: i})
	}

	pids := sb.PIDs()
	assert.Len(t, pids, 5)

	pidMap := make(map[uint32]bool)
	for _, pid := range pids {
		pidMap[pid] = true
	}

	for i := uint32(1); i <= 5; i++ {
		assert.True(t, pidMap[i], "PID %d should be in the list", i)
	}
}

func TestShardedEventBuffer_Count(t *testing.T) {
	sb := NewShardedEventBuffer(10)

	assert.Equal(t, 0, sb.Count())

	for i := uint32(1); i <= 5; i++ {
		sb.Add(i, types.Event{Type: types.EventSyscall, PID: i})
	}

	assert.Equal(t, 5, sb.Count())
}

func TestShardedEventBuffer_ConcurrentAccess(t *testing.T) {
	sb := NewShardedEventBuffer(100)

	var wg sync.WaitGroup
	numGoroutines := 100
	eventsPerGoroutine := 100

	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(pid uint32) {
			defer wg.Done()
			for j := 0; j < eventsPerGoroutine; j++ {
				sb.Add(pid, types.Event{
					Type: types.EventSyscall,
					PID:  pid,
				})
			}
		}(uint32(i))
	}

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(pid uint32) {
			defer wg.Done()
			for j := 0; j < eventsPerGoroutine; j++ {
				sb.Get(pid)
			}
		}(uint32(i))
	}

	wg.Wait()

	// Verify all data is present
	assert.Equal(t, numGoroutines, sb.Count())
}

func TestShardedEventBuffer_Distribution(t *testing.T) {
	// Test that events are distributed across shards
	sb := NewShardedEventBuffer(10)

	// Add events with PIDs that hash to different shards
	for i := uint32(0); i < 1000; i++ {
		sb.Add(i, types.Event{Type: types.EventSyscall, PID: i})
	}

	// Count events per shard
	counts := make([]int, shardCount)
	for i := 0; i < shardCount; i++ {
		shard := sb.shards[i]
		shard.mu.RLock()
		counts[i] = len(shard.buffers)
		shard.mu.RUnlock()
	}

	// All shards should have some data (with 1000 PIDs and 16 shards)
	for i, count := range counts {
		assert.Greater(t, count, 0, "Shard %d should have data", i)
	}
}

func TestShardedLock_Basic(t *testing.T) {
	sl := NewShardedLock()
	pid := uint32(1234)

	sl.Lock(pid)
	assert.True(t, true) // Lock acquired
	sl.Unlock(pid)
}

func TestShardedLock_TryLock(t *testing.T) {
	sl := NewShardedLock()
	pid := uint32(1234)

	assert.True(t, sl.TryLock(pid))
	sl.Unlock(pid)
}

func TestShardedLock_Concurrent(t *testing.T) {
	sl := NewShardedLock()
	var counter atomic.Int64
	var wg sync.WaitGroup

	numGoroutines := 100
	iterations := 1000

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(pid uint32) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				sl.Lock(pid)
				counter.Add(1)
				sl.Unlock(pid)
			}
		}(uint32(i % shardCount)) // Use only shardCount different PIDs
	}

	wg.Wait()
	assert.Equal(t, int64(numGoroutines*iterations), counter.Load())
}

func BenchmarkShardedEventBuffer_Add(b *testing.B) {
	sb := NewShardedEventBuffer(100)
	event := types.Event{Type: types.EventSyscall}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		pid := uint32(1)
		for pb.Next() {
			sb.Add(pid, event)
			pid++
		}
	})
}

func BenchmarkShardedEventBuffer_AddSamePID(b *testing.B) {
	sb := NewShardedEventBuffer(100)
	event := types.Event{Type: types.EventSyscall, PID: 1234}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			sb.Add(1234, event)
		}
	})
}

func BenchmarkEventBuffer_Add(b *testing.B) {
	eb := NewEventBuffer(100)
	event := types.Event{Type: types.EventSyscall}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		pid := uint32(1)
		for pb.Next() {
			eb.Add(pid, event)
			pid++
		}
	})
}

// BenchmarkPIDs measures ShardedEventBuffer.PIDs() with a populated buffer.
func BenchmarkPIDs(b *testing.B) {
	sb := NewShardedEventBuffer(100)
	event := types.Event{Type: types.EventSyscall}
	for i := uint32(0); i < 10000; i++ {
		sb.Add(i, event)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = sb.PIDs()
	}
}

func BenchmarkShardedLock_Contention(b *testing.B) {
	sl := NewShardedLock()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		pid := uint32(1)
		for pb.Next() {
			start := time.Now()
			sl.Lock(pid)
			sl.RecordContention(pid, time.Since(start).Nanoseconds())
			sl.Unlock(pid)
			pid++
		}
	})
}

func BenchmarkShardedLock_SamePID(b *testing.B) {
	sl := NewShardedLock()
	pid := uint32(1234)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			sl.Lock(pid)
			sl.Unlock(pid)
		}
	})
}

// TestShardedBufferCleanup verifies that CleanupExpired removes stale PID entries.
func TestShardedBufferCleanup(t *testing.T) {
	sb := NewShardedEventBuffer(10)

	// Add events for 100 PIDs
	for i := uint32(0); i < 100; i++ {
		sb.Add(i, types.Event{Type: types.EventSyscall, PID: i})
	}
	require.Equal(t, 100, sb.Count())

	// Wait to ensure all lastSeen timestamps are older than the TTL we pass.
	time.Sleep(20 * time.Millisecond)

	removed := sb.CleanupExpired(10 * time.Millisecond)

	assert.Equal(t, 100, removed, "all 100 PID entries should have been removed")
	assert.Equal(t, 0, sb.Count(), "buffer should be empty after cleanup")

	// Verify individual PIDs are gone
	for i := uint32(0); i < 5; i++ {
		assert.Nil(t, sb.Get(i), "PID %d should have no events after cleanup", i)
	}
}

// TestShardedBufferCleanup_KeepsRecent verifies that recently-active PIDs survive cleanup.
func TestShardedBufferCleanup_KeepsRecent(t *testing.T) {
	sb := NewShardedEventBuffer(10)

	// Add events for PIDs 0–49
	for i := uint32(0); i < 50; i++ {
		sb.Add(i, types.Event{Type: types.EventSyscall, PID: i})
	}

	// Wait a tiny bit so those entries are older
	time.Sleep(5 * time.Millisecond)

	// Add events for PIDs 50–99 (fresher timestamps)
	for i := uint32(50); i < 100; i++ {
		sb.Add(i, types.Event{Type: types.EventSyscall, PID: i})
	}

	// CleanupExpired with a TTL of 2ms — only the first batch is stale
	removed := sb.CleanupExpired(2 * time.Millisecond)

	assert.Equal(t, 50, removed, "only the 50 stale PIDs should have been removed")
	assert.Equal(t, 50, sb.Count(), "50 recent PIDs should remain")

	// Verify the recent PIDs still have events
	for i := uint32(50); i < 55; i++ {
		assert.NotNil(t, sb.Get(i), "PID %d should still have events", i)
	}
}

// BenchmarkShardedLockReadContention measures 8 concurrent readers sharing the same shard.
// With sync.RWMutex, concurrent RLock calls don't block each other; with sync.Mutex they would.
func BenchmarkShardedLockReadContention(b *testing.B) {
	sl := NewShardedLock()
	// All goroutines use the same shard to maximise read contention measurement.
	pid := uint32(0)

	b.ResetTimer()
	b.SetParallelism(8)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			sl.RLock(pid)
			sl.RUnlock(pid)
		}
	})
}

// TestShardedBufferCleanup_ZeroRemoved verifies cleanup on an already-empty buffer.
func TestShardedBufferCleanup_ZeroRemoved(t *testing.T) {
	sb := NewShardedEventBuffer(10)
	removed := sb.CleanupExpired(time.Hour)
	assert.Equal(t, 0, removed)
}
