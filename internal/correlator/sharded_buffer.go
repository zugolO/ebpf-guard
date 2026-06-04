// Package correlator provides event correlation and rule-based detection.
package correlator

import (
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// computeBufferShards returns the optimal shard count for ShardedEventBuffer.
// Uses max(NumCPU, GOMAXPROCS)*4 rounded to the next power of 2, clamped to [4, 256].
// The 4× multiplier gives headroom for goroutine bursts beyond CPU count; the
// power-of-2 result enables fast PID→shard mapping via bitmask (pid & mask).
// Tests can call runtime.GOMAXPROCS(N) before creating a buffer to raise the shard
// count and eliminate contention (e.g. GOMAXPROCS=32 → 128 shards for 100 PIDs).
func computeBufferShards() (count int, mask uint32) {
	n := runtime.NumCPU()
	if gmp := runtime.GOMAXPROCS(0); gmp > n {
		n = gmp
	}
	n *= 4
	if n < 4 {
		n = 4
	}
	p := 4
	for p < n {
		p <<= 1
	}
	if p > 256 {
		p = 256
	}
	return p, uint32(p - 1)
}

// computeLockShards returns the shard count for ShardedLock and the sharded maps
// (shardedCooldowns, shardedDedup). Uses max(NumCPU, GOMAXPROCS)*4, rounded to the
// next power of 2, clamped to [16, 256].  The 4× multiplier provides headroom for
// goroutine bursts; power-of-2 enables bitmask PID→shard lookup (O(1), no division).
// Tests can call runtime.GOMAXPROCS(N) before NewShardedLock/newShardedCooldowns to
// scale the shard count for their concurrency level.
func computeLockShards() (count int, mask uint32) {
	n := runtime.NumCPU()
	if gmp := runtime.GOMAXPROCS(0); gmp > n {
		n = gmp
	}
	n *= 4
	if n < 16 {
		n = 16
	}
	p := 16
	for p < n {
		p <<= 1
	}
	if p > 256 {
		p = 256
	}
	return p, uint32(p - 1)
}

// ShardedEventBuffer stores events per process using sharded locks for better concurrency.
// The shard count scales with max(NumCPU, GOMAXPROCS)*4, so high-core-count servers
// and test environments with elevated GOMAXPROCS benefit from reduced lock contention.
type ShardedEventBuffer struct {
	shards   []*eventBufferShard
	numShards int
	mask     uint32 // numShards-1; enables fast pid→shard via bitmasking
	maxSize  int
}

// eventBufferShard is a single shard of the sharded buffer.
type eventBufferShard struct {
	mu       sync.RWMutex
	buffers  map[uint32]*ringBuffer
	lastSeen map[uint32]time.Time
}

// bufferShardIdx returns the shard index for a given PID using a bitmask (O(1), no division).
func (sb *ShardedEventBuffer) bufferShardIdx(pid uint32) uint32 {
	return pid & sb.mask
}

// NewShardedEventBuffer creates a new sharded event buffer with the given max size per process.
// The number of shards scales with runtime.NumCPU() so high-core servers reduce contention automatically.
func NewShardedEventBuffer(maxSize int) *ShardedEventBuffer {
	numShards, mask := computeBufferShards()
	sb := &ShardedEventBuffer{
		shards:    make([]*eventBufferShard, numShards),
		numShards: numShards,
		mask:      mask,
		maxSize:   maxSize,
	}
	for i := 0; i < numShards; i++ {
		sb.shards[i] = &eventBufferShard{
			buffers:  make(map[uint32]*ringBuffer),
			lastSeen: make(map[uint32]time.Time),
		}
	}
	return sb
}

// Add adds an event to the buffer for the given PID.
func (sb *ShardedEventBuffer) Add(pid uint32, e types.Event) {
	shard := sb.shards[sb.bufferShardIdx(pid)]
	now := time.Now() // capture before acquiring lock to keep time.Now() off the hot path

	shard.mu.Lock()
	defer shard.mu.Unlock()

	rb, exists := shard.buffers[pid]
	if !exists {
		rb = &ringBuffer{
			events: make([]types.Event, sb.maxSize),
		}
		shard.buffers[pid] = rb
	}
	shard.lastSeen[pid] = now

	// Add event to circular buffer
	rb.events[rb.head] = e
	rb.head = (rb.head + 1) % sb.maxSize
	if rb.size < sb.maxSize {
		rb.size++
	}
}

// Get returns all events for a given PID.
func (sb *ShardedEventBuffer) Get(pid uint32) []types.Event {
	shard := sb.shards[sb.bufferShardIdx(pid)]

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
// Unlike Get, it acquires the lock only once and allocates exactly n elements,
// avoiding the full-size allocation that Get performs when rb.size >> n.
func (sb *ShardedEventBuffer) GetRecent(pid uint32, n int) []types.Event {
	if n <= 0 {
		return nil
	}
	shard := sb.shards[sb.bufferShardIdx(pid)]
	shard.mu.RLock()
	defer shard.mu.RUnlock()

	rb, exists := shard.buffers[pid]
	if !exists || rb.size == 0 {
		return nil
	}

	if n >= rb.size {
		// Return all events in chronological order.
		result := make([]types.Event, rb.size)
		if rb.size < sb.maxSize {
			copy(result, rb.events[:rb.size])
		} else {
			copied := copy(result, rb.events[rb.head:])
			copy(result[copied:], rb.events[:rb.head])
		}
		return result
	}

	// n < rb.size: allocate only n elements.
	result := make([]types.Event, n)
	if rb.size < sb.maxSize {
		// Buffer not yet full: events are at [0, rb.size). The last n are at [rb.size-n, rb.size).
		copy(result, rb.events[rb.size-n:rb.size])
	} else {
		// Buffer full: logical order is oldest at rb.head. The last n events
		// start at physical position (rb.head + sb.maxSize - n) % sb.maxSize.
		start := (rb.head + sb.maxSize - n) % sb.maxSize
		if start+n <= sb.maxSize {
			copy(result, rb.events[start:start+n])
		} else {
			copied := copy(result, rb.events[start:])
			copy(result[copied:], rb.events[:n-copied])
		}
	}
	return result
}

// Remove deletes the buffer for a given PID.
func (sb *ShardedEventBuffer) Remove(pid uint32) {
	shard := sb.shards[sb.bufferShardIdx(pid)]

	shard.mu.Lock()
	defer shard.mu.Unlock()
	delete(shard.buffers, pid)
	delete(shard.lastSeen, pid)
}

// Clear removes all buffers.
func (sb *ShardedEventBuffer) Clear() {
	for i := 0; i < sb.numShards; i++ {
		shard := sb.shards[i]
		shard.mu.Lock()
		shard.buffers = make(map[uint32]*ringBuffer)
		shard.lastSeen = make(map[uint32]time.Time)
		shard.mu.Unlock()
	}
}

// CleanupExpired removes per-PID buffers that have not received an event within ttl.
// Returns the number of PID entries removed across all shards.
func (sb *ShardedEventBuffer) CleanupExpired(ttl time.Duration) int {
	var removed int
	cutoff := time.Now().Add(-ttl)
	for i := 0; i < sb.numShards; i++ {
		shard := sb.shards[i]
		shard.mu.Lock()
		for pid, ts := range shard.lastSeen {
			if ts.Before(cutoff) {
				delete(shard.buffers, pid)
				delete(shard.lastSeen, pid)
				removed++
			}
		}
		shard.mu.Unlock()
	}
	return removed
}

// PIDs returns all PIDs with buffered events.
// Single-pass: holds each shard lock once, appends directly, pre-allocates
// with a rough estimate to avoid reallocation in the common case.
func (sb *ShardedEventBuffer) PIDs() []uint32 {
	pids := make([]uint32, 0, sb.numShards*8)
	for i := 0; i < sb.numShards; i++ {
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
	for i := 0; i < sb.numShards; i++ {
		shard := sb.shards[i]
		shard.mu.RLock()
		count += len(shard.buffers)
		shard.mu.RUnlock()
	}
	return count
}

// ShardCount returns the number of shards (for observability/testing).
func (sb *ShardedEventBuffer) ShardCount() int {
	return sb.numShards
}

// ShardedLock provides a sharded mutex for PID-keyed locking.
// The shard count is determined at construction time by computeLockShards()
// (max(NumCPU,GOMAXPROCS)*4, power-of-2, clamped [16,256]), so it scales
// automatically with the machine's core count. All indexing uses a bitmask
// (pid & mask) rather than modulo — O(1) with no division.
type ShardedLock struct {
	shards          []sync.RWMutex
	contentionStats []atomic.Int64
	mask            uint32
}

// NewShardedLock creates a new sharded lock sized for the current machine.
func NewShardedLock() *ShardedLock {
	count, mask := computeLockShards()
	return &ShardedLock{
		shards:          make([]sync.RWMutex, count),
		contentionStats: make([]atomic.Int64, count),
		mask:            mask,
	}
}

// Lock acquires an exclusive write lock on the shard for the given PID.
func (sl *ShardedLock) Lock(pid uint32) { sl.shards[pid&sl.mask].Lock() }

// Unlock releases the exclusive write lock on the shard for the given PID.
func (sl *ShardedLock) Unlock(pid uint32) { sl.shards[pid&sl.mask].Unlock() }

// TryLock attempts to acquire an exclusive write lock without blocking.
func (sl *ShardedLock) TryLock(pid uint32) bool { return sl.shards[pid&sl.mask].TryLock() }

// RLock acquires a shared read lock on the shard for the given PID.
func (sl *ShardedLock) RLock(pid uint32) { sl.shards[pid&sl.mask].RLock() }

// RUnlock releases a shared read lock on the shard for the given PID.
func (sl *ShardedLock) RUnlock(pid uint32) { sl.shards[pid&sl.mask].RUnlock() }

// RecordContention records lock contention time for metrics.
func (sl *ShardedLock) RecordContention(pid uint32, nanoseconds int64) {
	sl.contentionStats[pid&sl.mask].Add(nanoseconds)
}

// GetContentionStats returns total contention time per shard.
func (sl *ShardedLock) GetContentionStats() []int64 {
	stats := make([]int64, len(sl.shards))
	for i := range stats {
		stats[i] = sl.contentionStats[i].Load()
	}
	return stats
}

// ShardCount returns the number of shards in use (for observability/testing).
func (sl *ShardedLock) ShardCount() int { return len(sl.shards) }
