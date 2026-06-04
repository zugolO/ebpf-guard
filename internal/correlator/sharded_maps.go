// Package correlator provides event correlation and rule-based detection.
package correlator

import (
	"sync"
	"time"
)

// mapShardCount is the number of shards used by shardedCooldowns and shardedDedup.
// Reuses lockShardCount (16) from sharded_buffer.go so the pid→shard function
// is consistent across all sharded structures in the package.
const mapShardCount = lockShardCount

// ---------------------------------------------------------------------------
// shardedCooldowns — enforcement cooldown map with per-shard locking
// ---------------------------------------------------------------------------

// cooldownShard holds one stripe of the cooldown map.
type cooldownShard struct {
	mu sync.Mutex
	m  map[cooldownKey]time.Time
}

// shardedCooldowns distributes (ruleID, pid) cooldown entries across
// mapShardCount shards keyed by pid % mapShardCount.  Under concurrent
// enforcement bursts this reduces lock contention by ~16× vs. a single mutex.
type shardedCooldowns struct {
	shards [mapShardCount]cooldownShard
}

func newShardedCooldowns() *shardedCooldowns {
	sc := &shardedCooldowns{}
	for i := range sc.shards {
		sc.shards[i].m = make(map[cooldownKey]time.Time)
	}
	return sc
}

// tryAcquire returns true and records the timestamp when the cooldown for
// (ruleID, pid) has expired or was never set.  Returns false if the last
// acquisition is within cooldown of now — prevents enforcement spam.
// The check-and-set is atomic within the shard's mutex.
func (sc *shardedCooldowns) tryAcquire(ruleID string, pid uint32, cooldown time.Duration) bool {
	key := cooldownKey{ruleID: ruleID, pid: pid}
	shard := &sc.shards[shardIndex(pid)]
	now := time.Now()

	shard.mu.Lock()
	defer shard.mu.Unlock()

	if prev, ok := shard.m[key]; ok && now.Sub(prev) < cooldown {
		return false
	}
	shard.m[key] = now
	return true
}

// cleanup removes entries whose timestamp is before cutoff.
// Each shard is locked independently so cleanup does not block Ingest.
func (sc *shardedCooldowns) cleanup(cutoff time.Time) {
	for i := range sc.shards {
		sc.shards[i].mu.Lock()
		for k, t := range sc.shards[i].m {
			if t.Before(cutoff) {
				delete(sc.shards[i].m, k)
			}
		}
		sc.shards[i].mu.Unlock()
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

// shardedDedup distributes (ruleID, pid, comm) dedup entries across
// mapShardCount shards keyed by pid % mapShardCount.
// check and mark are split so rate-limit counters are not inflated by
// burst duplicates (mark is called only after an alert passes rate-limiting).
type shardedDedup struct {
	shards [mapShardCount]dedupShard
	window time.Duration
}

func newShardedDedup(window time.Duration) *shardedDedup {
	sd := &shardedDedup{window: window}
	for i := range sd.shards {
		sd.shards[i].m = make(map[dedupKey]time.Time)
	}
	return sd
}

// check reports whether (ruleID, pid, comm) was recorded within the window.
// It is read-only: it does not update the map.  Call mark after the alert
// passes all rate-limit filters.
func (sd *shardedDedup) check(ruleID string, pid uint32, comm string) bool {
	cutoff := time.Now().Add(-sd.window)
	key := dedupKey{ruleID: ruleID, pid: pid, comm: comm}
	shard := &sd.shards[shardIndex(pid)]

	shard.mu.Lock()
	prev, ok := shard.m[key]
	shard.mu.Unlock()

	return ok && prev.After(cutoff)
}

// mark records that (ruleID, pid, comm) was emitted now.
func (sd *shardedDedup) mark(ruleID string, pid uint32, comm string) {
	key := dedupKey{ruleID: ruleID, pid: pid, comm: comm}
	shard := &sd.shards[shardIndex(pid)]

	shard.mu.Lock()
	shard.m[key] = time.Now()
	shard.mu.Unlock()
}

// cleanup removes entries older than the window.
func (sd *shardedDedup) cleanup(cutoff time.Time) {
	for i := range sd.shards {
		sd.shards[i].mu.Lock()
		for k, t := range sd.shards[i].m {
			if t.Before(cutoff) {
				delete(sd.shards[i].m, k)
			}
		}
		sd.shards[i].mu.Unlock()
	}
}
