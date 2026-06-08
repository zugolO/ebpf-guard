package exporter

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Circuit breaker state constants (stored in CircuitBreaker.state).
const (
	cbStateClosed   int32 = 0
	cbStateOpen     int32 = 1
	cbStateHalfOpen int32 = 2
)

// CircuitBreaker implements a Closed → Open → Half-Open state machine that
// protects the Alertmanager exporter from cascading failures when the
// Alertmanager endpoint is unavailable.
//
//   - Closed  : requests pass through; consecutive failures are counted.
//   - Open    : requests are rejected immediately (sent to FallbackQueue);
//               after resetTimeout a single probe is allowed (Half-Open).
//   - HalfOpen: one probe request is allowed; success → Closed,
//               failure → Open (resetTimeout restarts).
type CircuitBreaker struct {
	state    atomic.Int32
	failCount atomic.Int32
	threshold int32
	resetTimeout time.Duration
	openedAt atomic.Int64 // UnixNano; 0 when not open

	mu sync.Mutex // serialises state transitions

	// Optional Prometheus metrics; nil disables recording.
	stateGauge   prometheus.Gauge
	droppedTotal prometheus.Counter
}

func newCircuitBreaker(threshold int, resetTimeout time.Duration, stateGauge prometheus.Gauge, droppedTotal prometheus.Counter) *CircuitBreaker {
	if threshold <= 0 {
		threshold = 5
	}
	if resetTimeout <= 0 {
		resetTimeout = 30 * time.Second
	}
	cb := &CircuitBreaker{
		threshold:    int32(threshold),
		resetTimeout: resetTimeout,
		stateGauge:   stateGauge,
		droppedTotal: droppedTotal,
	}
	if stateGauge != nil {
		stateGauge.Set(float64(cbStateClosed))
	}
	return cb
}

// TryRecover transitions Open→HalfOpen if resetTimeout has elapsed since opening.
// Safe to call from any goroutine.
func (cb *CircuitBreaker) TryRecover(now time.Time) {
	if cb.state.Load() != cbStateOpen {
		return
	}
	openedAt := time.Unix(0, cb.openedAt.Load())
	if now.Sub(openedAt) < cb.resetTimeout {
		return
	}

	cb.mu.Lock()
	defer cb.mu.Unlock()
	if cb.state.Load() == cbStateOpen { // double-check under lock
		cb.state.Store(cbStateHalfOpen)
		if cb.stateGauge != nil {
			cb.stateGauge.Set(float64(cbStateHalfOpen))
		}
		slog.Info("exporter/alertmanager: circuit breaker half-open, sending probe")
	}
}

// Allow returns true when a request should be attempted (Closed or HalfOpen).
func (cb *CircuitBreaker) Allow() bool {
	return cb.state.Load() != cbStateOpen
}

// State returns the current circuit breaker state (0=Closed, 1=Open, 2=HalfOpen).
func (cb *CircuitBreaker) State() int32 {
	return cb.state.Load()
}

// RecordSuccess resets the fail counter. If in HalfOpen, transitions to Closed.
// Returns true when the circuit transitioned from HalfOpen to Closed so the
// caller can trigger a fallback-queue drain.
func (cb *CircuitBreaker) RecordSuccess() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failCount.Store(0)
	if cb.state.Load() == cbStateHalfOpen {
		cb.state.Store(cbStateClosed)
		cb.openedAt.Store(0)
		if cb.stateGauge != nil {
			cb.stateGauge.Set(float64(cbStateClosed))
		}
		slog.Info("exporter/alertmanager: circuit breaker closed after successful probe")
		return true
	}
	return false
}

// RecordFailure increments the failure counter.
//   - Closed  : when count ≥ threshold → Open.
//   - HalfOpen: immediately → Open (probe failed).
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	state := cb.state.Load()
	newCount := cb.failCount.Add(1)

	switch {
	case state == cbStateHalfOpen:
		cb.state.Store(cbStateOpen)
		cb.openedAt.Store(time.Now().UnixNano())
		cb.failCount.Store(0)
		if cb.stateGauge != nil {
			cb.stateGauge.Set(float64(cbStateOpen))
		}
		slog.Warn("exporter/alertmanager: circuit breaker re-opened (probe failed)")

	case state == cbStateClosed && newCount >= cb.threshold:
		cb.state.Store(cbStateOpen)
		cb.openedAt.Store(time.Now().UnixNano())
		if cb.stateGauge != nil {
			cb.stateGauge.Set(float64(cbStateOpen))
		}
		slog.Warn("exporter/alertmanager: circuit breaker opened",
			slog.Int("failures", int(newCount)),
			slog.Duration("reset_timeout", cb.resetTimeout))
	}

	if cb.droppedTotal != nil {
		cb.droppedTotal.Inc()
	}
}

// FallbackQueue is a bounded FIFO buffer that holds alerts while the circuit
// breaker is open.  When maxSize is reached, the oldest entry is evicted
// (drop-oldest policy) so memory usage is always bounded.
// Alerts are replayed in order when the circuit recovers.
type FallbackQueue struct {
	mu      sync.Mutex
	items   []types.AlertPayload
	maxSize int

	sizeGauge    prometheus.Gauge  // ebpf_guard_alertmanager_fallback_queue_size
	droppedTotal prometheus.Counter // ebpf_guard_alertmanager_dropped_total
}

func newFallbackQueue(maxSize int, sizeGauge prometheus.Gauge, droppedTotal prometheus.Counter) *FallbackQueue {
	if maxSize <= 0 {
		maxSize = 10_000
	}
	initial := min(maxSize, 256)
	return &FallbackQueue{
		items:        make([]types.AlertPayload, 0, initial),
		maxSize:      maxSize,
		sizeGauge:    sizeGauge,
		droppedTotal: droppedTotal,
	}
}

// Enqueue adds payload to the queue.  When full, the oldest entry is dropped.
func (q *FallbackQueue) Enqueue(payload types.AlertPayload) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.items) >= q.maxSize {
		q.items = q.items[1:] // drop oldest
		if q.droppedTotal != nil {
			q.droppedTotal.Inc()
		}
		slog.Warn("exporter/alertmanager: fallback queue full, dropping oldest alert")
	}

	q.items = append(q.items, payload)
	if q.sizeGauge != nil {
		q.sizeGauge.Set(float64(len(q.items)))
	}
}

// DrainAll removes and returns all queued payloads.
// The caller takes ownership of the returned slice.
func (q *FallbackQueue) DrainAll() []types.AlertPayload {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.items) == 0 {
		return nil
	}

	out := make([]types.AlertPayload, len(q.items))
	copy(out, q.items)
	q.items = q.items[:0]

	if q.sizeGauge != nil {
		q.sizeGauge.Set(0)
	}
	return out
}

// Len returns the number of buffered payloads.
func (q *FallbackQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}
