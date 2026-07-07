package correlator

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// ─────────────────────────────────────────────────────────────────────────────
// shardedCooldowns — eviction at capacity
//
// Inserting MaxCooldownEntries (1M) real entries just to trigger the eviction
// branch would make the test suite unacceptably slow. Instead, force the
// shard's atomic counter to the cap directly (same-package white-box access)
// so tryAcquire's eviction path runs against a handful of real entries.
// ─────────────────────────────────────────────────────────────────────────────

func TestShardedCooldowns_EvictsOldestAtCapacity(t *testing.T) {
	sc := newShardedCooldowns()
	now := time.Now()

	// Seed a few entries in the same shard (pid=1) with increasing timestamps.
	shard := &sc.shards[1&sc.mask]
	shard.m[cooldownKey{ruleID: "old", pid: 1}] = now.Add(-time.Hour)
	shard.m[cooldownKey{ruleID: "newer", pid: 1}] = now.Add(-time.Minute)
	sc.total.Store(MaxCooldownEntries)

	// A brand-new key at the cap must evict the oldest entry in its shard.
	ok := sc.tryAcquire("fresh", 1, time.Second, now)
	assert.True(t, ok)

	_, oldStillPresent := shard.m[cooldownKey{ruleID: "old", pid: 1}]
	assert.False(t, oldStillPresent, "oldest entry must be evicted to stay within the cap")
	_, newerStillPresent := shard.m[cooldownKey{ruleID: "newer", pid: 1}]
	assert.True(t, newerStillPresent)
	_, freshPresent := shard.m[cooldownKey{ruleID: "fresh", pid: 1}]
	assert.True(t, freshPresent)

	// Total should stay at the cap (one evicted, one added).
	assert.Equal(t, int64(MaxCooldownEntries), sc.total.Load())
}

func TestShardedCooldowns_ExistingKeyRefreshDoesNotEvict(t *testing.T) {
	sc := newShardedCooldowns()
	now := time.Now()
	shard := &sc.shards[1&sc.mask]
	shard.m[cooldownKey{ruleID: "r", pid: 1}] = now.Add(-time.Hour)
	sc.total.Store(MaxCooldownEntries)

	// Re-acquiring an EXISTING key at capacity must not trigger eviction logic
	// (isNew is false), and must simply refresh the timestamp.
	ok := sc.tryAcquire("r", 1, time.Second, now)
	assert.True(t, ok)
	assert.Equal(t, int64(MaxCooldownEntries), sc.total.Load())
	assert.Equal(t, now, shard.m[cooldownKey{ruleID: "r", pid: 1}])
}

// ─────────────────────────────────────────────────────────────────────────────
// shardedDedup — eviction at capacity
// ─────────────────────────────────────────────────────────────────────────────

func TestShardedDedup_EvictsOldestAtCapacity(t *testing.T) {
	sd := newShardedDedup(time.Minute)
	now := time.Now()

	shard := &sd.shards[1&sd.mask]
	shard.m[dedupKey{ruleID: "old", pid: 1, comm: "a"}] = now.Add(-time.Hour)
	shard.m[dedupKey{ruleID: "newer", pid: 1, comm: "a"}] = now.Add(-time.Second)
	sd.total.Store(MaxDedupEntries)

	sd.mark("fresh", 1, "a", now)

	_, oldStillPresent := shard.m[dedupKey{ruleID: "old", pid: 1, comm: "a"}]
	assert.False(t, oldStillPresent, "oldest entry must be evicted to stay within the cap")
	_, freshPresent := shard.m[dedupKey{ruleID: "fresh", pid: 1, comm: "a"}]
	assert.True(t, freshPresent)
	assert.Equal(t, int64(MaxDedupEntries), sd.total.Load())
}

func TestShardedDedup_ExistingKeyRefreshDoesNotEvict(t *testing.T) {
	sd := newShardedDedup(time.Minute)
	now := time.Now()
	shard := &sd.shards[1&sd.mask]
	shard.m[dedupKey{ruleID: "r", pid: 1, comm: "a"}] = now.Add(-time.Hour)
	sd.total.Store(MaxDedupEntries)

	sd.mark("r", 1, "a", now)
	assert.Equal(t, int64(MaxDedupEntries), sd.total.Load())
	assert.Equal(t, now, shard.m[dedupKey{ruleID: "r", pid: 1, comm: "a"}])
}

func TestShardedDedup_SizeReflectsEntryCount(t *testing.T) {
	sd := newShardedDedup(time.Minute)
	assert.Equal(t, int64(0), sd.Size())
	sd.mark("r1", 1, "a", time.Now())
	sd.mark("r2", 2, "b", time.Now())
	assert.Equal(t, int64(2), sd.Size())
}

func TestShardedCooldowns_SizeReflectsEntryCount(t *testing.T) {
	sc := newShardedCooldowns()
	assert.Equal(t, int64(0), sc.Size())
	sc.tryAcquire("r1", 1, time.Second, time.Now())
	sc.tryAcquire("r2", 2, time.Second, time.Now())
	assert.Equal(t, int64(2), sc.Size())
}
