package bpf

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMapManager(t *testing.T) {
	m := NewMapManager()
	require.NotNil(t, m)
	assert.NotNil(t, m.limits)
	assert.NotNil(t, m.stats)
	assert.NotNil(t, m.entries)
}

func TestMapManager_RegisterMap(t *testing.T) {
	m := NewMapManager()

	limits := MapLimits{
		MaxEntries:     100,
		EvictionPolicy: EvictLRU,
		TTL:            time.Minute,
	}

	m.RegisterMap("test_map", limits)

	retrieved, ok := m.GetLimits("test_map")
	require.True(t, ok)
	assert.Equal(t, limits.MaxEntries, retrieved.MaxEntries)
	assert.Equal(t, limits.EvictionPolicy, retrieved.EvictionPolicy)
	assert.Equal(t, limits.TTL, retrieved.TTL)

	stats, ok := m.GetStats("test_map")
	require.True(t, ok)
	assert.Equal(t, "test_map", stats.Name)
	assert.Equal(t, 100, stats.MaxSize)
}

func TestMapManager_RecordInsertion(t *testing.T) {
	t.Run("unregistered map", func(t *testing.T) {
		m := NewMapManager()
		err := m.RecordInsertion("unknown", 1)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not registered")
	})

	t.Run("insertion without eviction", func(t *testing.T) {
		m := NewMapManager()
		m.RegisterMap("test_map", MapLimits{
			MaxEntries:     10,
			EvictionPolicy: EvictNone,
		})

		err := m.RecordInsertion("test_map", 1)
		require.NoError(t, err)

		stats, _ := m.GetStats("test_map")
		assert.Equal(t, 1, stats.CurrentSize)
		assert.Equal(t, uint64(1), stats.Insertions)
	})

	t.Run("insertion with LRU eviction", func(t *testing.T) {
		m := NewMapManager()
		m.RegisterMap("test_map", MapLimits{
			MaxEntries:     2,
			EvictionPolicy: EvictLRU,
		})

		// Insert 2 entries
		require.NoError(t, m.RecordInsertion("test_map", 1))
		time.Sleep(10 * time.Millisecond)
		require.NoError(t, m.RecordInsertion("test_map", 2))

		// Access key 1 to make it more recent
		m.RecordLookup("test_map", 1, true)
		time.Sleep(10 * time.Millisecond)

		// Insert 3rd entry - should evict key 2 (least recently used)
		require.NoError(t, m.RecordInsertion("test_map", 3))

		stats, _ := m.GetStats("test_map")
		assert.Equal(t, 2, stats.CurrentSize)
		assert.Equal(t, uint64(1), stats.Evictions)
	})

	t.Run("insertion with random eviction", func(t *testing.T) {
		m := NewMapManager()
		m.RegisterMap("test_map", MapLimits{
			MaxEntries:     2,
			EvictionPolicy: EvictRandom,
		})

		require.NoError(t, m.RecordInsertion("test_map", 1))
		require.NoError(t, m.RecordInsertion("test_map", 2))
		require.NoError(t, m.RecordInsertion("test_map", 3))

		stats, _ := m.GetStats("test_map")
		assert.Equal(t, 2, stats.CurrentSize)
		assert.Equal(t, uint64(1), stats.Evictions)
	})
}

func TestMapManager_RecordLookup(t *testing.T) {
	m := NewMapManager()
	m.RegisterMap("test_map", MapLimits{
		MaxEntries:     10,
		EvictionPolicy: EvictLRU,
	})

	require.NoError(t, m.RecordInsertion("test_map", 1))

	// Record hit
	m.RecordLookup("test_map", 1, true)

	// Record miss
	m.RecordLookup("test_map", 2, false)

	stats, _ := m.GetStats("test_map")
	assert.Equal(t, uint64(1), stats.LookupHits)
	assert.Equal(t, uint64(1), stats.LookupMisses)
}

func TestMapManager_RecordDeletion(t *testing.T) {
	m := NewMapManager()
	m.RegisterMap("test_map", MapLimits{
		MaxEntries:     10,
		EvictionPolicy: EvictNone,
	})

	require.NoError(t, m.RecordInsertion("test_map", 1))
	require.NoError(t, m.RecordInsertion("test_map", 2))

	m.RecordDeletion("test_map", 1)

	stats, _ := m.GetStats("test_map")
	assert.Equal(t, 1, stats.CurrentSize)
	assert.Equal(t, uint64(1), stats.Deletions)
}

func TestMapManager_CleanupExpired(t *testing.T) {
	m := NewMapManager()
	m.RegisterMap("test_map", MapLimits{
		MaxEntries:     10,
		EvictionPolicy: EvictNone,
		TTL:            50 * time.Millisecond,
	})

	require.NoError(t, m.RecordInsertion("test_map", 1))
	require.NoError(t, m.RecordInsertion("test_map", 2))

	// Wait for TTL to expire
	time.Sleep(100 * time.Millisecond)

	// Add a fresh entry
	require.NoError(t, m.RecordInsertion("test_map", 3))

	// Cleanup should remove 2 expired entries
	cleaned := m.CleanupExpired()
	assert.Equal(t, 2, cleaned)

	stats, _ := m.GetStats("test_map")
	assert.Equal(t, 1, stats.CurrentSize)
	assert.Equal(t, uint64(2), stats.Deletions)
}

func TestMapManager_GetAllStats(t *testing.T) {
	m := NewMapManager()
	m.RegisterMap("map1", MapLimits{MaxEntries: 10})
	m.RegisterMap("map2", MapLimits{MaxEntries: 20})

	allStats := m.GetAllStats()
	assert.Len(t, allStats, 2)
	assert.Contains(t, allStats, "map1")
	assert.Contains(t, allStats, "map2")
}

func TestEvictionPolicy_String(t *testing.T) {
	tests := []struct {
		policy   EvictionPolicy
		expected string
	}{
		{EvictNone, "none"},
		{EvictLRU, "lru"},
		{EvictOldest, "oldest"},
		{EvictRandom, "random"},
		{EvictionPolicy(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.policy.String())
		})
	}
}
