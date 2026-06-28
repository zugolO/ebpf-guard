package store

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// trackingStore wraps MemoryStore and records every StoreBatch call so tests
// can inspect how alerts were grouped.
type trackingStore struct {
	*MemoryStore
	mu     sync.Mutex
	batches [][]types.Alert
}

func newTrackingStore() *trackingStore {
	return &trackingStore{MemoryStore: NewMemoryStore()}
}

func (t *trackingStore) StoreBatch(ctx context.Context, alerts []types.Alert) error {
	cp := make([]types.Alert, len(alerts))
	copy(cp, alerts)
	t.mu.Lock()
	t.batches = append(t.batches, cp)
	t.mu.Unlock()
	return t.MemoryStore.StoreBatch(ctx, alerts)
}

func (t *trackingStore) batchCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.batches)
}

func (t *trackingStore) totalStored() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for _, b := range t.batches {
		n += len(b)
	}
	return n
}

// ---- helpers ----------------------------------------------------------------

func makeAlert(id string) types.Alert {
	return types.Alert{
		ID:        id,
		Timestamp: time.Now(),
		RuleID:    "rule-1",
		Severity:  types.SeverityWarning,
	}
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}

// ---- tests ------------------------------------------------------------------

// TestBatchingStore_FlushOnBatchSize verifies that a flush occurs as soon as
// the buffer accumulates BatchSize alerts, without waiting for the timer.
func TestBatchingStore_FlushOnBatchSize(t *testing.T) {
	inner := newTrackingStore()
	bs := NewBatchingStore(inner, BatchingStoreConfig{
		BatchSize:     5,
		FlushInterval: 10 * time.Second, // long timer — must not trigger
		MaxBuffer:     50,
	})
	defer bs.Close()

	ctx := context.Background()
	for i := 0; i < 5; i++ {
		require.NoError(t, bs.Store(ctx, makeAlert(fmt.Sprintf("a%d", i))))
	}

	waitFor(t, 2*time.Second, func() bool { return inner.batchCount() >= 1 })

	assert.Equal(t, 1, inner.batchCount(), "expected exactly one batch flush")
	assert.Equal(t, 5, inner.totalStored(), "expected 5 alerts stored")
}

// TestBatchingStore_FlushOnTimer verifies that a flush occurs after FlushInterval
// even when BatchSize has not been reached.
func TestBatchingStore_FlushOnTimer(t *testing.T) {
	inner := newTrackingStore()
	bs := NewBatchingStore(inner, BatchingStoreConfig{
		BatchSize:     100,
		FlushInterval: 50 * time.Millisecond,
		MaxBuffer:     200,
	})
	defer bs.Close()

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		require.NoError(t, bs.Store(ctx, makeAlert(fmt.Sprintf("b%d", i))))
	}

	waitFor(t, 2*time.Second, func() bool { return inner.totalStored() == 3 })

	assert.Equal(t, 3, inner.totalStored(), "expected 3 alerts stored after timer flush")
}

// TestBatchingStore_NoLossOnClose verifies that all buffered alerts are written
// before Close returns — no data is lost on shutdown.
func TestBatchingStore_NoLossOnClose(t *testing.T) {
	inner := newTrackingStore()
	bs := NewBatchingStore(inner, BatchingStoreConfig{
		BatchSize:     1000,           // large — won't trigger on its own
		FlushInterval: 10 * time.Second, // long — won't trigger on its own
		MaxBuffer:     500,
	})

	ctx := context.Background()
	const n = 200
	for i := 0; i < n; i++ {
		require.NoError(t, bs.Store(ctx, makeAlert(fmt.Sprintf("c%d", i))))
	}

	require.NoError(t, bs.Close())

	stored := inner.totalStored()
	assert.Equal(t, n, stored, "no alerts should be lost on close")
}

// TestBatchingStore_NoDuplicatesOnClose verifies that Close does not cause
// alerts to be written more than once.
func TestBatchingStore_NoDuplicatesOnClose(t *testing.T) {
	inner := newTrackingStore()
	bs := NewBatchingStore(inner, BatchingStoreConfig{
		BatchSize:     10,
		FlushInterval: 50 * time.Millisecond,
		MaxBuffer:     500,
	})

	ctx := context.Background()
	const n = 25
	for i := 0; i < n; i++ {
		require.NoError(t, bs.Store(ctx, makeAlert(fmt.Sprintf("d%d", i))))
	}

	require.NoError(t, bs.Close())

	assert.Equal(t, n, inner.totalStored(), "each alert must be stored exactly once")
}

// TestBatchingStore_Overflow verifies that alerts are dropped (not blocking the
// caller) when the buffer is full, and that the drop counter is incremented.
func TestBatchingStore_Overflow(t *testing.T) {
	// Use a blocked inner store so the queue fills up.
	blockCh := make(chan struct{})
	var flushes atomic.Int32
	blocking := &blockedStore{
		MemoryStore: NewMemoryStore(),
		block:       blockCh,
		flushCount:  &flushes,
	}

	bs := NewBatchingStore(blocking, BatchingStoreConfig{
		BatchSize:     5,
		FlushInterval: 10 * time.Second,
		MaxBuffer:     10,
	})

	counter := prometheus.NewCounter(prometheus.CounterOpts{Name: "test_drops_total"})
	bs.RegisterDropMetric(counter)

	ctx := context.Background()

	// Fill the queue (10 slots) and then overflow it.
	for i := 0; i < 25; i++ {
		_ = bs.Store(ctx, makeAlert(fmt.Sprintf("e%d", i)))
	}

	// At least some should have been dropped.
	dropped := bs.DroppedTotal()
	assert.Greater(t, dropped, int64(0), "expected some alerts to be dropped on overflow")

	// Unblock and close cleanly.
	close(blockCh)
	bs.Close() //nolint:errcheck
}

// TestBatchingStore_StoreBatch_Enqueues verifies that StoreBatch enqueues all
// items for async writing rather than writing synchronously.
func TestBatchingStore_StoreBatch_Enqueues(t *testing.T) {
	inner := newTrackingStore()
	bs := NewBatchingStore(inner, BatchingStoreConfig{
		BatchSize:     50,
		FlushInterval: 50 * time.Millisecond,
		MaxBuffer:     200,
	})
	defer bs.Close()

	ctx := context.Background()
	alerts := make([]types.Alert, 12)
	for i := range alerts {
		alerts[i] = makeAlert(fmt.Sprintf("f%d", i))
	}
	require.NoError(t, bs.StoreBatch(ctx, alerts))

	waitFor(t, 2*time.Second, func() bool { return inner.totalStored() == 12 })
	assert.Equal(t, 12, inner.totalStored())
}

// TestBatchingStore_Flush_DrainsBuffer verifies that Flush synchronously drains
// the queue and forwards to the inner store.
func TestBatchingStore_Flush_DrainsBuffer(t *testing.T) {
	inner := newTrackingStore()
	bs := NewBatchingStore(inner, BatchingStoreConfig{
		BatchSize:     1000,
		FlushInterval: 10 * time.Second,
		MaxBuffer:     500,
	})
	defer bs.Close()

	ctx := context.Background()
	for i := 0; i < 7; i++ {
		require.NoError(t, bs.Store(ctx, makeAlert(fmt.Sprintf("g%d", i))))
	}

	require.NoError(t, bs.Flush(ctx))

	// After Flush all 7 alerts must be in the inner store.
	count, err := inner.Count(ctx, QueryFilters{})
	require.NoError(t, err)
	assert.Equal(t, int64(7), count)
}

// TestBatchingStore_ConcurrentStore verifies race-detector cleanliness under
// concurrent Store calls.
func TestBatchingStore_ConcurrentStore(t *testing.T) {
	inner := newTrackingStore()
	bs := NewBatchingStore(inner, BatchingStoreConfig{
		BatchSize:     20,
		FlushInterval: 20 * time.Millisecond,
		MaxBuffer:     1000,
	})

	ctx := context.Background()
	const workers = 20
	const perWorker = 50

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				_ = bs.Store(ctx, makeAlert(fmt.Sprintf("h%d-%d", w, i)))
			}
		}(w)
	}
	wg.Wait()

	require.NoError(t, bs.Close())

	assert.Equal(t, workers*perWorker, inner.totalStored())
}

// TestBatchingStore_Delegates_Read verifies that read operations are forwarded
// to the inner store even while the batching layer is active.
func TestBatchingStore_Delegates_Read(t *testing.T) {
	ctx := context.Background()
	inner := NewMemoryStore()

	// Pre-populate the inner store directly.
	require.NoError(t, inner.Store(ctx, makeAlert("direct-1")))
	require.NoError(t, inner.Store(ctx, makeAlert("direct-2")))

	bs := NewBatchingStore(inner, BatchingStoreConfig{
		BatchSize:     10,
		FlushInterval: 10 * time.Second,
		MaxBuffer:     50,
	})
	defer bs.Close()

	// QueryByID and Count should see the directly-stored alerts.
	a, err := bs.QueryByID(ctx, "direct-1")
	require.NoError(t, err)
	assert.Equal(t, "direct-1", a.ID)

	count, err := bs.Count(ctx, QueryFilters{})
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)

	assert.True(t, bs.Healthy(ctx))
}

// TestBatchingStore_DefaultConfig verifies that zero-value config is filled
// with sensible defaults.
func TestBatchingStore_DefaultConfig(t *testing.T) {
	cfg := BatchingStoreConfig{}
	out := cfg.withDefaults()

	assert.Equal(t, 100, out.BatchSize)
	assert.Equal(t, 500*time.Millisecond, out.FlushInterval)
	assert.Equal(t, 1000, out.MaxBuffer)
}

// ---- helpers ----------------------------------------------------------------

// blockedStore is an AlertStore whose StoreBatch blocks until block is closed.
type blockedStore struct {
	*MemoryStore
	block      chan struct{}
	flushCount *atomic.Int32
}

func (b *blockedStore) StoreBatch(ctx context.Context, alerts []types.Alert) error {
	<-b.block
	b.flushCount.Add(1)
	return b.MemoryStore.StoreBatch(ctx, alerts)
}
