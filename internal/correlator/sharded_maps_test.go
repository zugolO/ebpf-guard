package correlator

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShardedCooldowns(t *testing.T) {
	sc := newShardedCooldowns()
	now := time.Now()

	// First acquire succeeds and records the entry.
	assert.True(t, sc.tryAcquire("rule-1", 100, time.Minute, now))
	assert.Equal(t, int64(1), sc.Size())

	// A second acquire within the cooldown window is blocked.
	assert.False(t, sc.tryAcquire("rule-1", 100, time.Minute, now.Add(time.Second)))

	// After the cooldown expires it succeeds again (same entry, no new count).
	assert.True(t, sc.tryAcquire("rule-1", 100, time.Minute, now.Add(2*time.Minute)))
	assert.Equal(t, int64(1), sc.Size())

	// A different (rule, pid) is an independent entry.
	assert.True(t, sc.tryAcquire("rule-2", 200, time.Minute, now))
	assert.Equal(t, int64(2), sc.Size())

	// cleanup with a future cutoff removes all stale entries.
	sc.cleanup(now.Add(time.Hour))
	assert.Equal(t, int64(0), sc.Size())
}

func TestShardedDedup(t *testing.T) {
	sd := newShardedDedup(time.Minute)
	now := time.Now()

	// Unseen key is not a duplicate.
	assert.False(t, sd.check("rule-1", 100, "bash"))

	sd.mark("rule-1", 100, "bash", now)
	assert.Equal(t, int64(1), sd.Size())

	// Within the window it is reported as a duplicate.
	assert.True(t, sd.check("rule-1", 100, "bash"))

	// A different comm is independent.
	assert.False(t, sd.check("rule-1", 100, "sh"))

	// mark again on the same key does not grow the count.
	sd.mark("rule-1", 100, "bash", now.Add(time.Second))
	assert.Equal(t, int64(1), sd.Size())

	// cleanup with a future cutoff clears the map.
	sd.cleanup(now.Add(time.Hour))
	assert.Equal(t, int64(0), sd.Size())
	assert.False(t, sd.check("rule-1", 100, "bash"))
}

func TestShardedDedup_WindowExpiry(t *testing.T) {
	sd := newShardedDedup(10 * time.Millisecond)
	sd.mark("r", 1, "c", time.Now().Add(-time.Hour)) // recorded far in the past
	// The recorded timestamp is older than the window, so it is not a duplicate.
	require.False(t, sd.check("r", 1, "c"))
}
