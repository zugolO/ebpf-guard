package exporter

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// ── CircuitBreaker unit tests ─────────────────────────────────────────────────

func TestCircuitBreaker_InitialStateClosed(t *testing.T) {
	cb := newCircuitBreaker(5, 30*time.Second, nil, nil)
	assert.Equal(t, cbStateClosed, cb.State())
	assert.True(t, cb.Allow())
}

func TestCircuitBreaker_OpenAfterThreshold(t *testing.T) {
	cb := newCircuitBreaker(3, 30*time.Second, nil, nil)

	// Two failures should not open the circuit.
	cb.RecordFailure()
	cb.RecordFailure()
	assert.Equal(t, cbStateClosed, cb.State())
	assert.True(t, cb.Allow())

	// Third failure meets threshold → Open.
	cb.RecordFailure()
	assert.Equal(t, cbStateOpen, cb.State())
	assert.False(t, cb.Allow())
}

func TestCircuitBreaker_SuccessResetsFailCount(t *testing.T) {
	cb := newCircuitBreaker(3, 30*time.Second, nil, nil)

	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordSuccess()

	// After success, fail count resets; circuit stays Closed.
	assert.Equal(t, cbStateClosed, cb.State())
	assert.Equal(t, int32(0), cb.failCount.Load())

	// Needs threshold new failures to open again.
	cb.RecordFailure()
	cb.RecordFailure()
	assert.Equal(t, cbStateClosed, cb.State())
	cb.RecordFailure()
	assert.Equal(t, cbStateOpen, cb.State())
}

func TestCircuitBreaker_HalfOpenAfterTimeout(t *testing.T) {
	cb := newCircuitBreaker(2, 50*time.Millisecond, nil, nil)

	cb.RecordFailure()
	cb.RecordFailure()
	assert.Equal(t, cbStateOpen, cb.State())

	// Before timeout: still Open.
	cb.TryRecover(time.Now())
	assert.Equal(t, cbStateOpen, cb.State())

	// After timeout: HalfOpen.
	time.Sleep(60 * time.Millisecond)
	cb.TryRecover(time.Now())
	assert.Equal(t, cbStateHalfOpen, cb.State())
	assert.True(t, cb.Allow(), "HalfOpen should allow one probe")
}

func TestCircuitBreaker_HalfOpenSuccessCloses(t *testing.T) {
	cb := newCircuitBreaker(2, 10*time.Millisecond, nil, nil)

	cb.RecordFailure()
	cb.RecordFailure()
	time.Sleep(15 * time.Millisecond)
	cb.TryRecover(time.Now())
	require.Equal(t, cbStateHalfOpen, cb.State())

	recovered := cb.RecordSuccess()
	assert.True(t, recovered, "RecordSuccess should return true on HalfOpen→Closed")
	assert.Equal(t, cbStateClosed, cb.State())
}

func TestCircuitBreaker_HalfOpenFailureReopens(t *testing.T) {
	cb := newCircuitBreaker(2, 10*time.Millisecond, nil, nil)

	cb.RecordFailure()
	cb.RecordFailure()
	time.Sleep(15 * time.Millisecond)
	cb.TryRecover(time.Now())
	require.Equal(t, cbStateHalfOpen, cb.State())

	cb.RecordFailure() // probe fails
	assert.Equal(t, cbStateOpen, cb.State())
}

func TestCircuitBreaker_ClosedSuccessNoTransition(t *testing.T) {
	cb := newCircuitBreaker(3, 30*time.Second, nil, nil)
	recovered := cb.RecordSuccess()
	assert.False(t, recovered, "RecordSuccess on Closed should return false")
	assert.Equal(t, cbStateClosed, cb.State())
}

// ── FallbackQueue unit tests ──────────────────────────────────────────────────

func TestFallbackQueue_EnqueueDrain(t *testing.T) {
	q := newFallbackQueue(10, nil, nil)

	p1 := types.AlertPayload{Labels: types.AlertLabels{RuleID: "r1"}}
	p2 := types.AlertPayload{Labels: types.AlertLabels{RuleID: "r2"}}

	q.Enqueue(p1)
	q.Enqueue(p2)
	assert.Equal(t, 2, q.Len())

	items := q.DrainAll()
	require.Len(t, items, 2)
	assert.Equal(t, "r1", items[0].Labels.RuleID)
	assert.Equal(t, "r2", items[1].Labels.RuleID)
	assert.Equal(t, 0, q.Len())
}

func TestFallbackQueue_DropOldestWhenFull(t *testing.T) {
	q := newFallbackQueue(3, nil, nil)

	for i := 0; i < 5; i++ {
		q.Enqueue(types.AlertPayload{Labels: types.AlertLabels{RuleID: string(rune('a' + i))}})
	}

	assert.Equal(t, 3, q.Len())
	items := q.DrainAll()
	// First 2 (a, b) were dropped; c, d, e remain in FIFO order.
	require.Len(t, items, 3)
	assert.Equal(t, "c", items[0].Labels.RuleID)
	assert.Equal(t, "d", items[1].Labels.RuleID)
	assert.Equal(t, "e", items[2].Labels.RuleID)
}

func TestFallbackQueue_DrainEmptyReturnsNil(t *testing.T) {
	q := newFallbackQueue(10, nil, nil)
	assert.Nil(t, q.DrainAll())
}

func TestFallbackQueue_Concurrent(t *testing.T) {
	q := newFallbackQueue(1000, nil, nil)
	var wg sync.WaitGroup

	// 20 writers, 5 drainers.
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				q.Enqueue(types.AlertPayload{Labels: types.AlertLabels{RuleID: "r"}})
			}
		}()
	}
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				q.DrainAll()
				time.Sleep(time.Millisecond)
			}
		}()
	}
	wg.Wait()
}

// ── Integration tests ─────────────────────────────────────────────────────────

// TestCircuitBreaker_AlertsBufferedWhenOpen verifies that alerts are placed in
// the fallback queue (not dropped) when the circuit is open.
func TestCircuitBreaker_AlertsBufferedWhenOpen(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client := NewAlertmanagerClient(server.URL, "http://eg:9090", 1, 10, 2)
	defer client.Close()

	ctx := context.Background()

	// Trigger circuit open with exactly `threshold` (2) failures.
	for i := 0; i < 2; i++ {
		client.SendAlert(ctx, types.Alert{RuleID: "trigger"})
		client.Flush()
		time.Sleep(20 * time.Millisecond) // let async sendBatch record failure
	}
	assert.Equal(t, cbStateOpen, client.cb.State(), "circuit should be open")

	// Send 5 more alerts while circuit is open — they route to fallback immediately
	// in SendAlert (no flush needed since circuit check happens before batching).
	for i := 0; i < 5; i++ {
		client.SendAlert(ctx, types.Alert{RuleID: "buffered"})
	}
	assert.Equal(t, 5, client.fallback.Len(), "all 5 alerts should be in fallback queue")
}

// TestCircuitBreaker_FallbackDrainedOnRecovery is the integration scenario from
// the issue:
//
//	AM down → alerts queued in fallback → AM up → Flush → alerts drained and sent
func TestCircuitBreaker_FallbackDrainedOnRecovery(t *testing.T) {
	var (
		mu           sync.Mutex
		failMode     = true
		receivedIDs  []string
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		fail := failMode
		mu.Unlock()

		if fail {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var payloads []types.AlertPayload
		if err := json.Unmarshal(body, &payloads); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		mu.Lock()
		for _, p := range payloads {
			receivedIDs = append(receivedIDs, p.Labels.RuleID)
		}
		mu.Unlock()

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Short reset timeout so the test runs fast.
	client := &AlertmanagerClient{
		webhookURL:   server.URL,
		generatorURL: "http://eg:9090",
		batchSize:    100,
		batchTimeout: 10 * time.Second,
		batch:        make([]types.AlertPayload, 0, 100),
		client:       &http.Client{Timeout: 5 * time.Second},
		cb:           newCircuitBreaker(2, 50*time.Millisecond, nil, nil),
		fallback:     newFallbackQueue(200, nil, nil),
	}

	ctx := context.Background()

	// ── Phase 1: AM is down ──────────────────────────────────────────────────
	// Send exactly `threshold` (2) alerts to open the circuit.
	for i := 0; i < 2; i++ {
		client.SendAlert(ctx, types.Alert{RuleID: "trigger"})
		client.Flush()
		time.Sleep(10 * time.Millisecond) // let async sendBatch record failure
	}
	assert.Equal(t, cbStateOpen, client.cb.State())

	// Send 5 alerts while circuit is open — they route directly to fallback.
	for i := 0; i < 5; i++ {
		client.SendAlert(ctx, types.Alert{RuleID: "queued"})
	}
	assert.Equal(t, 5, client.fallback.Len(), "5 alerts should be buffered")

	// ── Phase 2: AM recovers ─────────────────────────────────────────────────
	mu.Lock()
	failMode = false
	mu.Unlock()
	time.Sleep(60 * time.Millisecond) // wait for reset timeout

	// ── Phase 3: Flush — probe succeeds, fallback is drained ─────────────────
	client.SendAlert(ctx, types.Alert{RuleID: "probe"})
	client.Flush()
	time.Sleep(100 * time.Millisecond)

	assert.Equal(t, cbStateClosed, client.cb.State(), "circuit should close after successful probe")
	assert.Equal(t, 0, client.fallback.Len(), "fallback queue should be empty after drain")

	mu.Lock()
	ids := make([]string, len(receivedIDs))
	copy(ids, receivedIDs)
	mu.Unlock()

	// All 5 queued alerts + the probe must have reached the server.
	require.GreaterOrEqual(t, len(ids), 6, "all queued and new alerts should be delivered")
}

// TestCircuitBreaker_FallbackBoundedCapacity verifies that the fallback queue
// drops oldest entries (not new ones) when it reaches maxSize.
func TestCircuitBreaker_FallbackBoundedCapacity(t *testing.T) {
	var (
		mu       sync.Mutex
		failMode = true
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		fail := failMode
		mu.Unlock()
		if fail {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	const maxBuf = 3
	client := &AlertmanagerClient{
		webhookURL:   server.URL,
		generatorURL: "http://eg:9090",
		batchSize:    1,
		batchTimeout: 10 * time.Second,
		batch:        make([]types.AlertPayload, 0, 1),
		client:       &http.Client{Timeout: 5 * time.Second},
		cb:           newCircuitBreaker(1, 50*time.Millisecond, nil, nil),
		fallback:     newFallbackQueue(maxBuf, nil, nil),
	}

	ctx := context.Background()

	// Open the circuit.
	client.SendAlert(ctx, types.Alert{RuleID: "open"})
	client.Flush()
	time.Sleep(20 * time.Millisecond)
	assert.Equal(t, cbStateOpen, client.cb.State())

	// Enqueue more alerts than the buffer can hold.
	for i := 0; i < 10; i++ {
		client.SendAlert(ctx, types.Alert{RuleID: "overflow"})
	}
	assert.Equal(t, maxBuf, client.fallback.Len(),
		"fallback queue must not exceed maxSize")
}

// TestCircuitBreaker_PrometheusMetrics verifies that circuit state and fallback
// size are reflected in Prometheus gauges.
func TestCircuitBreaker_PrometheusMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	stateGauge := prometheus.NewGauge(prometheus.GaugeOpts{Name: "test_circuit_state"})
	sizeGauge := prometheus.NewGauge(prometheus.GaugeOpts{Name: "test_fallback_size"})
	reg.MustRegister(stateGauge, sizeGauge)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client := NewAlertmanagerClientFull(
		server.URL, "http://eg:9090",
		1, 10,
		CircuitBreakerConfig{Threshold: 2},
		nil,
		stateGauge, sizeGauge, nil,
	)
	defer client.Close()

	// Initial state: Closed (0).
	assert.InDelta(t, float64(cbStateClosed), gaugeValue(t, stateGauge), 0.01)

	ctx := context.Background()

	// Trigger exactly `threshold` failures to open the circuit.
	// batchSize=1 so each SendAlert flushes immediately.
	for i := 0; i < 2; i++ {
		client.SendAlert(ctx, types.Alert{RuleID: "fail"})
		time.Sleep(15 * time.Millisecond) // let async sendBatch record failure
	}
	assert.InDelta(t, float64(cbStateOpen), gaugeValue(t, stateGauge), 0.01,
		"gauge should reflect Open state")

	// Enqueue 2 alerts to fallback — circuit is open so they go to the queue.
	client.SendAlert(ctx, types.Alert{RuleID: "buf"})
	client.SendAlert(ctx, types.Alert{RuleID: "buf"})
	assert.InDelta(t, 2.0, gaugeValue(t, sizeGauge), 0.01,
		"gauge should reflect fallback queue size")
}

// ── helpers ───────────────────────────────────────────────────────────────────

// gaugeValue reads the current float64 value of a prometheus.Gauge.
func gaugeValue(t *testing.T, g prometheus.Gauge) float64 {
	t.Helper()
	m := &dto.Metric{}
	require.NoError(t, g.Write(m))
	return m.GetGauge().GetValue()
}
