// Package correlator provides event correlation and rule-based detection.
package correlator

import (
	"sync"
	"sync/atomic"

	"github.com/ebpf-guard/ebpf-guard/pkg/types"
)

// shardCount is the number of shards for the sharded lock.
// Using 16 shards provides good balance between contention reduction and memory overhead.
const shardCount = 16

// shardIndex returns the shard index for a given PID.
func shardIndex(pid uint32) uint32 {
	return pid % shardCount
}

// ShardedEventBuffer stores events per process using sharded locks for better concurrency.
// It replaces the single sync.Mutex with 16 shard-specific locks to reduce contention.
type ShardedEventBuffer struct {
	shards  [shardCount]*eventBufferShard
	maxSize int
}

// eventBufferShard is a single shard of the sharded buffer.
type eventBufferShard struct {
	mu      sync.RWMutex
	buffers map[uint32]*ringBuffer
}

// NewShardedEventBuffer creates a new sharded event buffer with the given max size per process.
func NewShardedEventBuffer(maxSize int) *ShardedEventBuffer {
	sb := &ShardedEventBuffer{
		maxSize: maxSize,
	}
	for i := 0; i < shardCount; i++ {
		sb.shards[i] = &eventBufferShard{
			buffers: make(map[uint32]*ringBuffer),
		}
	}
	return sb
}

// Add adds an event to the buffer for the given PID.
func (sb *ShardedEventBuffer) Add(pid uint32, e types.Event) {
	shard := sb.shards[shardIndex(pid)]

	shard.mu.Lock()
	defer shard.mu.Unlock()

	rb, exists := shard.buffers[pid]
	if !exists {
		rb = &ringBuffer{
			events: make([]types.Event, sb.maxSize),
		}
		shard.buffers[pid] = rb
	}

	// Add event to circular buffer
	rb.events[rb.head] = e
	rb.head = (rb.head + 1) % sb.maxSize
	if rb.size < sb.maxSize {
		rb.size++
	}
}

// Get returns all events for a given PID.
func (sb *ShardedEventBuffer) Get(pid uint32) []types.Event {
	shard := sb.shards[shardIndex(pid)]

	shard.mu.RLock()
	defer shard.mu.RUnlock()

	rb, exists := shard.buffers[pid]
	if !exists || rb.size == 0 {
		return nil
	}

	// Copy events in chronological order
	result := make([]types.Event, rb.size)
	if rb.size < sb.maxSize {
		// Buffer not full yet, events are in [0, size)
		copy(result, rb.events[:rb.size])
	} else {
		// Buffer full, events wrap around
		// Copy from head to end, then from start to head
		copied := copy(result, rb.events[rb.head:])
		copy(result[copied:], rb.events[:rb.head])
	}

	return result
}

// GetRecent returns the last n events for a given PID.
func (sb *ShardedEventBuffer) GetRecent(pid uint32, n int) []types.Event {
	events := sb.Get(pid)
	if len(events) <= n {
		return events
	}
	return events[len(events)-n:]
}

// Remove deletes the buffer for a given PID.
func (sb *ShardedEventBuffer) Remove(pid uint32) {
	shard := sb.shards[shardIndex(pid)]

	shard.mu.Lock()
	defer shard.mu.Unlock()
	delete(shard.buffers, pid)
}

// Clear removes all buffers.
func (sb *ShardedEventBuffer) Clear() {
	for i := 0; i < shardCount; i++ {
		shard := sb.shards[i]
		shard.mu.Lock()
		shard.buffers = make(map[uint32]*ringBuffer)
		shard.mu.Unlock()
	}
}

// PIDs returns all PIDs with buffered events.
// Single-pass: holds each shard lock once, appends directly, pre-allocates
// with a rough estimate to avoid reallocation in the common case.
func (sb *ShardedEventBuffer) PIDs() []uint32 {
	pids := make([]uint32, 0, shardCount*8)
	for i := 0; i < shardCount; i++ {
		shard := sb.shards[i]
		shard.mu.RLock()
		for pid := range shard.buffers {
			pids = append(pids, pid)
		}
		shard.mu.RUnlock()
	}
	return pids
}

// Count returns the total number of buffered PIDs across all shards.
func (sb *ShardedEventBuffer) Count() int {
	var count int
	for i := 0; i < shardCount; i++ {
		shard := sb.shards[i]
		shard.mu.RLock()
		count += len(shard.buffers)
		shard.mu.RUnlock()
	}
	return count
}

// ShardedLock provides a sharded mutex for PID-keyed locking.
// It reduces contention by distributing locks across 16 shards.
type ShardedLock struct {
	shards [shardCount]sync.Mutex
	// contentionStats tracks lock acquisition time for metrics (nanoseconds)
	contentionStats [shardCount]atomic.Int64
}

// NewShardedLock creates a new sharded lock.
func NewShardedLock() *ShardedLock {
	return &ShardedLock{}
}

// Lock locks the shard for the given PID.
func (sl *ShardedLock) Lock(pid uint32) {
	sl.shards[shardIndex(pid)].Lock()
}

// Unlock unlocks the shard for the given PID.
func (sl *ShardedLock) Unlock(pid uint32) {
	sl.shards[shardIndex(pid)].Unlock()
}

// TryLock attempts to lock the shard for the given PID without blocking.
func (sl *ShardedLock) TryLock(pid uint32) bool {
	return sl.shards[shardIndex(pid)].TryLock()
}

// RLock locks the shard for reading.
func (sl *ShardedLock) RLock(pid uint32) {
	sl.shards[shardIndex(pid)].Lock()
}

// RUnlock unlocks the shard for reading.
func (sl *ShardedLock) RUnlock(pid uint32) {
	sl.shards[shardIndex(pid)].Unlock()
}

// RecordContention records lock contention time for metrics.
func (sl *ShardedLock) RecordContention(pid uint32, nanoseconds int64) {
	sl.contentionStats[shardIndex(pid)].Add(nanoseconds)
}

// GetContentionStats returns total contention time per shard.
func (sl *ShardedLock) GetContentionStats() [shardCount]int64 {
	var stats [shardCount]int64
	for i := 0; i < shardCount; i++ {
		stats[i] = sl.contentionStats[i].Load()
	}
	return stats
}
