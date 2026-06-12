// Package correlator provides event correlation and rule-based detection.
package correlator

import (
	"sync"
	"sync/atomic"
	"time"
)

// MaxCooldownEntries is the hard cap on total entries across all cooldown shards.
// Under a pod storm each unique (ruleID, PID) pair adds one entry; without this
// cap the map grows unboundedly and can reach 100MB+ before the cleanup ticker fires.
const MaxCooldownEntries = 1_000_000

// MaxDedupEntries is the hard cap on total entries across all dedup shards.
const MaxDedupEntries = 1_000_000

// ---------------------------------------------------------------------------
// shardedCooldowns — enforcement cooldown map with per-shard locking
// ---------------------------------------------------------------------------

// cooldownShard holds one stripe of the cooldown map.
type cooldownShard struct {
	mu sync.Mutex
	m  map[cooldownKey]time.Time
}

// shardedCooldowns distributes (ruleID, pid) cooldown entries across dynamically
// sized shards keyed by pid & mask.  The shard count is determined by
// computeLockShards() at construction time so it scales with the machine's core
// count and reduces enforcement-burst lock contention automatically.
type shardedCooldowns struct {
	shards []cooldownShard
	mask   uint32
	total  atomic.Int64 // total entries across all shards (approximate, for metrics)
}

func newShardedCooldowns() *shardedCooldowns {
	count, mask := computeLockShards()
	sc := &shardedCooldowns{
		shards: make([]cooldownShard, count),
		mask:   mask,
	}
	for i := range sc.shards {
		sc.shards[i].m = make(map[cooldownKey]time.Time)
	}
	return sc
}

// Size returns the approximate total number of entries across all shards.
func (sc *shardedCooldowns) Size() int64 { return sc.total.Load() }

// tryAcquire returns true and records the timestamp when the cooldown for
// (ruleID, pid) has expired or was never set.  Returns false if the last
// acquisition is within cooldown of now — prevents enforcement spam.
// When the total entry count reaches MaxCooldownEntries, the oldest entry in the
// target shard is evicted (FIFO within the shard) to keep memory bounded.
// now must be captured by the caller before entering any hot-path lock.
func (sc *shardedCooldowns) tryAcquire(ruleID string, pid uint32, cooldown time.Duration, now time.Time) bool {
	key := cooldownKey{ruleID: ruleID, pid: pid}
	shard := &sc.shards[pid&sc.mask]

	shard.mu.Lock()
	defer shard.mu.Unlock()

	if prev, ok := shard.m[key]; ok && now.Sub(prev) < cooldown {
		return false
	}

	isNew := !func() bool { _, ok := shard.m[key]; return ok }()
	if isNew && sc.total.Load() >= MaxCooldownEntries {
		// Evict the oldest entry in this shard to stay within the global cap.
		var oldest cooldownKey
		var oldestTime time.Time
		first := true
		for k, t := range shard.m {
			if first || t.Before(oldestTime) {
				oldest, oldestTime, first = k, t, false
			}
		}
		if !first {
			delete(shard.m, oldest)
			sc.total.Add(-1)
		}
	}

	if isNew {
		sc.total.Add(1)
	}
	shard.m[key] = now
	return true
}

// cleanup removes entries whose timestamp is before cutoff.
// Each shard is locked independently so cleanup does not block Ingest.
func (sc *shardedCooldowns) cleanup(cutoff time.Time) {
	for i := range sc.shards {
		shard := &sc.shards[i]
		shard.mu.Lock()
		removed := 0
		for k, t := range shard.m {
			if t.Before(cutoff) {
				delete(shard.m, k)
				removed++
			}
		}
		shard.mu.Unlock()
		if removed > 0 {
			sc.total.Add(-int64(removed))
		}
	}
}

// ---------------------------------------------------------------------------
// shardedDedup — sliding-window dedup map with per-shard locking
// ---------------------------------------------------------------------------

// dedupShard holds one stripe of the dedup map.
type dedupShard struct {
	mu sync.Mutex
	m  map[dedupKey]time.Time
}

// shardedDedup distributes (ruleID, pid, comm) dedup entries across dynamically
// sized shards keyed by pid & mask.  check and mark are split so rate-limit
// counters are not inflated by burst duplicates (mark is called only after an
// alert passes all rate-limit filters).
type shardedDedup struct {
	shards []dedupShard
	mask   uint32
	window time.Duration
	total  atomic.Int64 // total entries across all shards (approximate, for metrics)
}

func newShardedDedup(window time.Duration) *shardedDedup {
	count, mask := computeLockShards()
	sd := &shardedDedup{
		window: window,
		shards: make([]dedupShard, count),
		mask:   mask,
	}
	for i := range sd.shards {
		sd.shards[i].m = make(map[dedupKey]time.Time)
	}
	return sd
}

// Size returns the approximate total number of entries across all shards.
func (sd *shardedDedup) Size() int64 { return sd.total.Load() }

// check reports whether (ruleID, pid, comm) was recorded within the window.
// It is read-only: it does not update the map.  Call mark after the alert
// passes all rate-limit filters.
func (sd *shardedDedup) check(ruleID string, pid uint32, comm string) bool {
	cutoff := time.Now().Add(-sd.window)
	key := dedupKey{ruleID: ruleID, pid: pid, comm: comm}
	shard := &sd.shards[pid&sd.mask]

	shard.mu.Lock()
	prev, ok := shard.m[key]
	shard.mu.Unlock()

	return ok && prev.After(cutoff)
}

// mark records that (ruleID, pid, comm) was emitted at now.
// When the total entry count reaches MaxDedupEntries, the oldest entry in the
// target shard is evicted (FIFO within the shard) to keep memory bounded.
// now must be captured by the caller before entering any hot-path lock.
func (sd *shardedDedup) mark(ruleID string, pid uint32, comm string, now time.Time) {
	key := dedupKey{ruleID: ruleID, pid: pid, comm: comm}
	shard := &sd.shards[pid&sd.mask]

	shard.mu.Lock()
	_, exists := shard.m[key]
	if !exists && sd.total.Load() >= MaxDedupEntries {
		// Evict the oldest entry in this shard to stay within the global cap.
		var oldest dedupKey
		var oldestTime time.Time
		first := true
		for k, t := range shard.m {
			if first || t.Before(oldestTime) {
				oldest, oldestTime, first = k, t, false
			}
		}
		if !first {
			delete(shard.m, oldest)
			sd.total.Add(-1)
		}
	}
	if !exists {
		sd.total.Add(1)
	}
	shard.m[key] = now
	shard.mu.Unlock()
}

// cleanup removes entries older than the window.
func (sd *shardedDedup) cleanup(cutoff time.Time) {
	for i := range sd.shards {
		shard := &sd.shards[i]
		shard.mu.Lock()
		removed := 0
		for k, t := range shard.m {
			if t.Before(cutoff) {
				delete(shard.m, k)
				removed++
			}
		}
		shard.mu.Unlock()
		if removed > 0 {
			sd.total.Add(-int64(removed))
		}
	}
}
