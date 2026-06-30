package correlator

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// TestTraceContextCache_NegativeCachingAndTTL verifies that a miss is cached
// (including the nil/negative result), reused within the TTL, and re-evaluated
// after expiry.
func TestTraceContextCache_NegativeCachingAndTTL(t *testing.T) {
	c := newTraceContextCache()
	now := time.Now()

	// PID 0 has no /proc/0/environ → extractTraceContext returns nil. The nil is
	// cached so a second lookup within the TTL does not re-read /proc.
	got := c.lookup(0, now)
	assert.Nil(t, got)

	c.mu.RLock()
	e, ok := c.entries[0]
	c.mu.RUnlock()
	require.True(t, ok, "negative result must be cached")
	assert.Nil(t, e.tc)
	assert.True(t, e.expires.After(now), "entry must carry a future expiry")

	// Within TTL: entry is retained.
	c.cleanup(now.Add(traceContextTTL / 2))
	c.mu.RLock()
	_, ok = c.entries[0]
	c.mu.RUnlock()
	assert.True(t, ok, "entry must survive cleanup before expiry")

	// After TTL: entry is evicted.
	c.cleanup(now.Add(traceContextTTL + time.Second))
	c.mu.RLock()
	_, ok = c.entries[0]
	c.mu.RUnlock()
	assert.False(t, ok, "entry must be evicted after expiry")
}

// TestTraceContextCache_CloneIsolation verifies lookup returns an independent
// copy so a caller mutating the result cannot corrupt the cached entry.
func TestTraceContextCache_CloneIsolation(t *testing.T) {
	c := newTraceContextCache()
	now := time.Now()

	// Seed a positive entry directly (avoids depending on a real /proc layout).
	c.mu.Lock()
	c.entries[42] = traceCacheEntry{
		tc:      &types.TraceContext{TraceID: "trace", SpanID: "span", Source: "environ"},
		expires: now.Add(traceContextTTL),
	}
	c.mu.Unlock()

	first := c.lookup(42, now)
	require.NotNil(t, first)
	first.Source = "mutated"

	second := c.lookup(42, now)
	require.NotNil(t, second)
	assert.Equal(t, "environ", second.Source, "cached entry must not be affected by caller mutation")
	assert.NotSame(t, first, second, "each lookup must return a distinct pointer")
}
