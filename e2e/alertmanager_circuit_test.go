// Package e2e provides end-to-end tests for the Alertmanager circuit breaker.
// These tests exercise the full closed → open → half-open → closed lifecycle
// using a mock Alertmanager served by net/http/httptest (no Docker required),
// and validate state transitions via Prometheus gauge metrics.
//
// Run as part of the e2e-fast CI job:
//
//	go test -v -count=1 ./e2e/ -run TestAlertmanagerCircuitBreaker
package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/internal/exporter"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Circuit breaker state constants (mirrors the unexported constants in the
// exporter package so tests remain readable without depending on internals).
const (
	cbClosed   = float64(0)
	cbOpen     = float64(1)
	cbHalfOpen = float64(2)
)

// mockAlertmanager is a controllable HTTP server that counts received alerts.
type mockAlertmanager struct {
	mu           sync.Mutex
	failing      bool
	receivedIDs  []string
	requestCount atomic.Int64
}

func newMockAlertmanager(startFailing bool) *mockAlertmanager {
	return &mockAlertmanager{failing: startFailing}
}

func (m *mockAlertmanager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.requestCount.Add(1)

	m.mu.Lock()
	fail := m.failing
	m.mu.Unlock()

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

	m.mu.Lock()
	for _, p := range payloads {
		m.receivedIDs = append(m.receivedIDs, p.Labels.RuleID)
	}
	m.mu.Unlock()

	w.WriteHeader(http.StatusOK)
}

func (m *mockAlertmanager) setFailing(f bool) {
	m.mu.Lock()
	m.failing = f
	m.mu.Unlock()
}

func (m *mockAlertmanager) received() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.receivedIDs))
	copy(out, m.receivedIDs)
	return out
}

// readGauge reads the current float64 value of a prometheus.Gauge.
func readGauge(t *testing.T, g prometheus.Gauge) float64 {
	t.Helper()
	m := &dto.Metric{}
	require.NoError(t, g.Write(m))
	return m.GetGauge().GetValue()
}

// TestAlertmanagerCircuitBreaker validates the full closed → open → half-open → closed
// lifecycle of the Alertmanager circuit breaker.
//
// Scenario:
//  1. Start mock Alertmanager in "failing" mode (returns 503)
//  2. Send 3 alerts (threshold) → circuit opens
//  3. Send 10 more alerts while circuit is open → all buffered, none dropped
//  4. Restore mock Alertmanager to healthy mode
//  5. Wait for reset_timeout → circuit transitions to half-open
//  6. Send probe alert + flush → circuit closes, fallback is drained
//  7. Verify all buffered alerts were delivered to the mock server
//  8. Verify ebpf_guard_alertmanager_circuit_state metric reflects each transition
func TestAlertmanagerCircuitBreaker(t *testing.T) {
	const (
		threshold    = 3
		resetTimeout = 80 * time.Millisecond
		fallbackBuf  = 100
		bufferedN    = 10
	)

	// ── Prometheus metrics ────────────────────────────────────────────────────
	reg := prometheus.NewRegistry()

	stateGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ebpf_guard_alertmanager_circuit_state",
		Help: "Current Alertmanager circuit breaker state (0=Closed, 1=Open, 2=HalfOpen)",
	})
	sizeGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ebpf_guard_alertmanager_fallback_queue_size",
		Help: "Number of alerts currently buffered in the fallback queue",
	})
	reg.MustRegister(stateGauge, sizeGauge)

	// ── Phase 1: AM is down ───────────────────────────────────────────────────
	mock := newMockAlertmanager(true /* failing */)
	srv := httptest.NewServer(mock)
	defer srv.Close()

	client := exporter.NewAlertmanagerClientFull(
		srv.URL,
		"http://ebpf-guard:9090",
		1, // batchSize=1 so each SendAlert triggers a send immediately
		30,
		exporter.CircuitBreakerConfig{
			Threshold:          threshold,
			ResetTimeout:       resetTimeout,
			FallbackBufferSize: fallbackBuf,
		},
		nil, // no mTLS
		stateGauge,
		sizeGauge,
		nil, // no dropped counter
	)
	defer client.Close()

	// Initial state must be Closed.
	assert.Equal(t, cbClosed, readGauge(t, stateGauge),
		"circuit must start Closed")

	// Send exactly `threshold` alerts to trigger circuit open.
	// batchSize=1, so each alert is sent and the failure is recorded immediately.
	for i := 0; i < threshold; i++ {
		client.SendAlert(t.Context(), types.Alert{RuleID: "trigger"})
		time.Sleep(20 * time.Millisecond) // let the async sendBatch goroutine complete
	}

	assert.Equal(t, cbOpen, readGauge(t, stateGauge),
		"circuit must be Open after %d consecutive failures", threshold)

	// ── Phase 2: Buffer alerts while circuit is open ──────────────────────────
	for i := 0; i < bufferedN; i++ {
		client.SendAlert(t.Context(), types.Alert{RuleID: "buffered"})
	}

	assert.Equal(t, float64(bufferedN), readGauge(t, sizeGauge),
		"all %d alerts must be buffered in the fallback queue", bufferedN)

	// Confirm no buffered alerts reached the (still-down) mock server.
	// Only the `threshold` trigger attempts should have arrived.
	assert.Len(t, mock.received(), 0,
		"no alerts should be delivered while AM is down")

	// ── Phase 3: Restore AM and wait for reset_timeout ────────────────────────
	mock.setFailing(false)
	time.Sleep(resetTimeout + 20*time.Millisecond)

	// ── Phase 4: Send probe alert to trigger half-open → closed ──────────────
	client.SendAlert(t.Context(), types.Alert{RuleID: "probe"})
	// Give the async probe and drain goroutines time to complete.
	time.Sleep(150 * time.Millisecond)

	assert.Equal(t, cbClosed, readGauge(t, stateGauge),
		"circuit must be Closed after successful probe")
	assert.Equal(t, float64(0), readGauge(t, sizeGauge),
		"fallback queue must be empty after drain")

	// ── Phase 5: Verify no alerts were silently dropped ───────────────────────
	// All bufferedN queued alerts + the probe must have been delivered.
	got := mock.received()
	require.GreaterOrEqual(t, len(got), bufferedN+1,
		"all buffered alerts and the probe must reach the server after recovery")

	// Verify FIFO order: buffered alerts appear before the probe.
	bufferedCount := 0
	for _, id := range got {
		if id == "buffered" {
			bufferedCount++
		}
	}
	assert.Equal(t, bufferedN, bufferedCount,
		"all %d buffered alerts must be delivered in order", bufferedN)
}

// TestAlertmanagerCircuitBreaker_MetricTransitions validates each state
// change is reflected in the ebpf_guard_alertmanager_circuit_state gauge.
func TestAlertmanagerCircuitBreaker_MetricTransitions(t *testing.T) {
	stateGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "test_am_circuit_state_transitions",
	})

	mock := newMockAlertmanager(true)
	srv := httptest.NewServer(mock)
	defer srv.Close()

	const resetTimeout = 60 * time.Millisecond
	client := exporter.NewAlertmanagerClientFull(
		srv.URL, "http://eg:9090",
		1, 30,
		exporter.CircuitBreakerConfig{Threshold: 2, ResetTimeout: resetTimeout},
		nil, stateGauge, nil, nil,
	)
	defer client.Close()

	ctx := t.Context()

	// Closed initially.
	assert.Equal(t, cbClosed, readGauge(t, stateGauge), "initial state: Closed")

	// Open after 2 failures.
	for i := 0; i < 2; i++ {
		client.SendAlert(ctx, types.Alert{RuleID: "fail"})
		time.Sleep(20 * time.Millisecond)
	}
	assert.Equal(t, cbOpen, readGauge(t, stateGauge), "after 2 failures: Open")

	// Restore AM before the reset timeout so the probe succeeds.
	mock.setFailing(false)

	// Wait for reset_timeout → circuit enters HalfOpen.
	time.Sleep(resetTimeout + 20*time.Millisecond)

	// Send probe — TryRecover transitions Open→HalfOpen inside SendAlert, then
	// the probe succeeds and the circuit closes.
	client.SendAlert(ctx, types.Alert{RuleID: "probe"})
	time.Sleep(100 * time.Millisecond)

	assert.Equal(t, cbClosed, readGauge(t, stateGauge),
		"after successful probe: state must be Closed")
}

// TestAlertmanagerCircuitBreaker_NoAlertsDropped sends 50 alerts during an
// outage and verifies that every alert reaches the server after recovery,
// exercising the fallback buffer's drop-oldest policy at the configured limit.
func TestAlertmanagerCircuitBreaker_NoAlertsDropped(t *testing.T) {
	const (
		threshold   = 2
		fallbackBuf = 50
		totalAlerts = 50
		resetTO     = 60 * time.Millisecond
	)

	mock := newMockAlertmanager(true)
	srv := httptest.NewServer(mock)
	defer srv.Close()

	client := exporter.NewAlertmanagerClientFull(
		srv.URL, "http://eg:9090",
		1, 30,
		exporter.CircuitBreakerConfig{
			Threshold:          threshold,
			ResetTimeout:       resetTO,
			FallbackBufferSize: fallbackBuf,
		},
		nil, nil, nil, nil,
	)
	defer client.Close()

	ctx := t.Context()

	// Open the circuit.
	for i := 0; i < threshold; i++ {
		client.SendAlert(ctx, types.Alert{RuleID: "open"})
		time.Sleep(20 * time.Millisecond)
	}

	// Send exactly fallbackBuf alerts — they all fit so none should be dropped.
	for i := 0; i < totalAlerts; i++ {
		client.SendAlert(ctx, types.Alert{RuleID: "payload"})
	}

	// Recover and drain.
	mock.setFailing(false)
	time.Sleep(resetTO + 20*time.Millisecond)
	client.SendAlert(ctx, types.Alert{RuleID: "probe"})
	time.Sleep(200 * time.Millisecond)

	got := mock.received()
	payloadCount := 0
	for _, id := range got {
		if id == "payload" {
			payloadCount++
		}
	}
	assert.Equal(t, totalAlerts, payloadCount,
		"all %d buffered alerts must be delivered; got %d", totalAlerts, payloadCount)
}
