package store

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// BatchingStoreConfig controls the async-batching behaviour of BatchingStore.
type BatchingStoreConfig struct {
	// BatchSize is the number of alerts that trigger an immediate flush.
	// Zero defaults to 100.
	BatchSize int
	// FlushInterval is the maximum time an alert waits in the buffer before
	// being flushed regardless of batch size. Zero defaults to 500ms.
	FlushInterval time.Duration
	// MaxBuffer is the upper bound on queued alerts. When the buffer is full
	// new Store() calls return immediately and the alert is dropped (the drop
	// is counted in the batchDropped Prometheus counter). Zero defaults to
	// 10 × BatchSize (or 1000 when BatchSize is also zero).
	MaxBuffer int
}

func (c *BatchingStoreConfig) withDefaults() BatchingStoreConfig {
	out := *c
	if out.BatchSize <= 0 {
		out.BatchSize = 100
	}
	if out.FlushInterval <= 0 {
		out.FlushInterval = 500 * time.Millisecond
	}
	if out.MaxBuffer <= 0 {
		out.MaxBuffer = out.BatchSize * 10
	}
	return out
}

// BatchingStore is a decorator over any AlertStore that collects alerts in an
// in-memory channel and flushes them in batches via StoreBatch, either when the
// batch reaches BatchSize or when FlushInterval elapses, whichever comes first.
//
// All read operations (Query, QueryByID, Count, Delete, Healthy) are forwarded
// synchronously to the inner store — only writes are buffered.
type BatchingStore struct {
	inner  AlertStore
	cfg    BatchingStoreConfig
	queue  chan types.Alert
	closed chan struct{}
	wg     sync.WaitGroup

	// dropped counts alerts discarded because the queue was full.
	dropped prometheus.Counter
	// droppedTotal is a raw atomic used when no Prometheus counter is set.
	droppedTotal atomic.Int64
}

// NewBatchingStore wraps inner with async-batching writes.
// The background flush goroutine is started immediately and stops when Close
// is called. Register a Prometheus counter with RegisterDropMetric to expose
// the overflow metric; otherwise it is tracked internally via atomic.
func NewBatchingStore(inner AlertStore, cfg BatchingStoreConfig) *BatchingStore {
	c := cfg.withDefaults()
	s := &BatchingStore{
		inner:  inner,
		cfg:    c,
		queue:  make(chan types.Alert, c.MaxBuffer),
		closed: make(chan struct{}),
	}
	s.wg.Add(1)
	go s.flushLoop()
	return s
}

// RegisterDropMetric wires the provided Prometheus counter to count drops.
// Must be called before the store is put into use.
func (s *BatchingStore) RegisterDropMetric(c prometheus.Counter) {
	s.dropped = c
}

func (s *BatchingStore) incDropped() {
	s.droppedTotal.Add(1)
	if s.dropped != nil {
		s.dropped.Add(1)
	}
}

// DroppedTotal returns the number of alerts dropped due to a full buffer.
// This is the raw atomic counter; use the Prometheus counter for dashboards.
func (s *BatchingStore) DroppedTotal() int64 {
	return s.droppedTotal.Load()
}

// Store enqueues alert for async batch writing. If the buffer is full the
// alert is dropped and the overflow metric is incremented.
func (s *BatchingStore) Store(_ context.Context, alert types.Alert) error {
	select {
	case s.queue <- alert:
	default:
		s.incDropped()
	}
	return nil
}

// StoreBatch enqueues each alert individually. Alerts that would overflow the
// buffer are dropped and counted.
func (s *BatchingStore) StoreBatch(_ context.Context, alerts []types.Alert) error {
	for _, a := range alerts {
		select {
		case s.queue <- a:
		default:
			s.incDropped()
		}
	}
	return nil
}

// Flush drains the internal queue and calls the inner store's StoreBatch, then
// calls Flush on the inner store to ensure durability.
func (s *BatchingStore) Flush(ctx context.Context) error {
	if err := s.drainQueue(ctx); err != nil {
		return err
	}
	return s.inner.Flush(ctx)
}

// drainQueue reads all currently queued alerts (non-blocking) and writes them
// via the inner store's StoreBatch.
func (s *BatchingStore) drainQueue(ctx context.Context) error {
	batch := make([]types.Alert, 0, len(s.queue))
	for {
		select {
		case a := <-s.queue:
			batch = append(batch, a)
		default:
			// queue is empty
			if len(batch) == 0 {
				return nil
			}
			return s.inner.StoreBatch(ctx, batch)
		}
	}
}

// Close stops the background flush goroutine and waits for the final flush to
// complete, ensuring no buffered alerts are lost.
func (s *BatchingStore) Close() error {
	close(s.closed)
	s.wg.Wait()
	return s.inner.Close()
}

// Query delegates to the inner store.
func (s *BatchingStore) Query(ctx context.Context, filters QueryFilters) ([]types.Alert, error) {
	return s.inner.Query(ctx, filters)
}

// QueryByID delegates to the inner store.
func (s *BatchingStore) QueryByID(ctx context.Context, alertID string) (*types.Alert, error) {
	return s.inner.QueryByID(ctx, alertID)
}

// Count delegates to the inner store.
func (s *BatchingStore) Count(ctx context.Context, filters QueryFilters) (int64, error) {
	return s.inner.Count(ctx, filters)
}

// Delete delegates to the inner store.
func (s *BatchingStore) Delete(ctx context.Context, olderThan time.Duration) (int64, error) {
	return s.inner.Delete(ctx, olderThan)
}

// Healthy delegates to the inner store.
func (s *BatchingStore) Healthy(ctx context.Context) bool {
	return s.inner.Healthy(ctx)
}

// flushLoop is the background goroutine that batches and writes alerts.
func (s *BatchingStore) flushLoop() {
	defer s.wg.Done()

	batch := make([]types.Alert, 0, s.cfg.BatchSize)
	ticker := time.NewTicker(s.cfg.FlushInterval)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		// Use a background context — the caller's context is gone by the time
		// Close() triggers a final flush, and StoreBatch must still succeed.
		ctx := context.Background()
		_ = s.inner.StoreBatch(ctx, batch)
		batch = batch[:0]
	}

	for {
		select {
		case a := <-s.queue:
			batch = append(batch, a)
			if len(batch) >= s.cfg.BatchSize {
				flush()
				ticker.Reset(s.cfg.FlushInterval)
			}

		case <-ticker.C:
			flush()

		case <-s.closed:
			// Drain remaining queued alerts before stopping.
			for {
				select {
				case a := <-s.queue:
					batch = append(batch, a)
				default:
					flush()
					return
				}
			}
		}
	}
}
