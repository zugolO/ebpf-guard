package correlator

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// ─────────────────────────────────────────────────────────────────────────────
// computeBufferShards / computeLockShards
// ─────────────────────────────────────────────────────────────────────────────

func TestComputeBufferShards_PowerOfTwoAndBounds(t *testing.T) {
	count, mask := computeBufferShards()
	assert.GreaterOrEqual(t, count, 4)
	assert.LessOrEqual(t, count, 256)
	assert.Equal(t, uint32(count-1), mask)
	assert.Equal(t, count&(count-1), 0, "count must be a power of 2")
}

func TestComputeLockShards_PowerOfTwoAndBounds(t *testing.T) {
	count, mask := computeLockShards()
	assert.GreaterOrEqual(t, count, 16)
	assert.LessOrEqual(t, count, 256)
	assert.Equal(t, uint32(count-1), mask)
	assert.Equal(t, count&(count-1), 0, "count must be a power of 2")
}

func TestComputeBufferShards_ScalesWithGOMAXPROCS(t *testing.T) {
	orig := runtime.GOMAXPROCS(0)
	defer runtime.GOMAXPROCS(orig)

	runtime.GOMAXPROCS(1)
	lowCount, _ := computeBufferShards()

	runtime.GOMAXPROCS(64)
	highCount, _ := computeBufferShards()

	assert.GreaterOrEqual(t, highCount, lowCount)
}

// ─────────────────────────────────────────────────────────────────────────────
// ShardedEventBuffer.ForEachPID / ShardCount
// ─────────────────────────────────────────────────────────────────────────────

func TestShardedEventBuffer_ForEachPID(t *testing.T) {
	sb := NewShardedEventBuffer(10)
	sb.Add(1, types.Event{PID: 1})
	sb.Add(2, types.Event{PID: 2})
	sb.Add(3, types.Event{PID: 3})

	seen := make(map[uint32]bool)
	sb.ForEachPID(func(pid uint32) { seen[pid] = true })

	assert.Len(t, seen, 3)
	assert.True(t, seen[1])
	assert.True(t, seen[2])
	assert.True(t, seen[3])
}

func TestShardedEventBuffer_ForEachPID_Empty(t *testing.T) {
	sb := NewShardedEventBuffer(10)
	calls := 0
	sb.ForEachPID(func(pid uint32) { calls++ })
	assert.Equal(t, 0, calls)
}

func TestShardedEventBuffer_ShardCount(t *testing.T) {
	sb := NewShardedEventBuffer(10)
	wantCount, _ := computeBufferShards()
	assert.Equal(t, wantCount, sb.ShardCount())
}

// ─────────────────────────────────────────────────────────────────────────────
// ShardedLock.RLock/RUnlock/RecordContention/GetContentionStats/ShardCount
// ─────────────────────────────────────────────────────────────────────────────

func TestShardedLock_RLockRUnlock(t *testing.T) {
	sl := NewShardedLock()
	// Multiple concurrent readers on the same PID must not deadlock.
	sl.RLock(42)
	sl.RLock(42)
	sl.RUnlock(42)
	sl.RUnlock(42)

	// A writer must be able to acquire the lock afterward.
	sl.Lock(42)
	sl.Unlock(42)
}

func TestShardedLock_RecordContentionAndStats(t *testing.T) {
	sl := NewShardedLock()
	stats := sl.GetContentionStats()
	for _, v := range stats {
		assert.Equal(t, int64(0), v)
	}

	sl.RecordContention(7, 100)
	sl.RecordContention(7, 50)

	stats = sl.GetContentionStats()
	shardIdx := 7 & (sl.mask)
	assert.Equal(t, int64(150), stats[shardIdx])
}

func TestShardedLock_ShardCount(t *testing.T) {
	sl := NewShardedLock()
	wantCount, _ := computeLockShards()
	assert.Equal(t, wantCount, sl.ShardCount())
	assert.Len(t, sl.GetContentionStats(), wantCount)
}
