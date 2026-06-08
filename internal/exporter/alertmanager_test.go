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

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAlertmanagerClient_SendAlert(t *testing.T) {
	var mu sync.Mutex
	var receivedAlerts []types.AlertPayload

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var alerts []types.AlertPayload
		err = json.Unmarshal(body, &alerts)
		require.NoError(t, err)

		mu.Lock()
		receivedAlerts = alerts
		mu.Unlock()

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewAlertmanagerClient(
		server.URL,
		"http://ebpf-guard:9090",
		10, // batch size
		1,  // batch timeout (second)
		5,  // circuit breaker threshold
	)
	defer client.Close()

	// Send test alert
	alert := types.Alert{
		ID:        "alert-1",
		Timestamp: time.Now(),
		RuleID:    "rule_001",
		RuleName:  "Test Rule",
		Severity:  types.SeverityCritical,
		Message:   "Test alert",
		PID:       1234,
		Comm:      "test",
	}

	ctx := context.Background()
	client.SendAlert(ctx, alert)

	// Force flush
	client.Flush()

	// Wait for async send
	time.Sleep(100 * time.Millisecond)

	// Verify alert was received
	mu.Lock()
	defer mu.Unlock()
	require.Len(t, receivedAlerts, 1)
	assert.Equal(t, "EbpfGuardAlert", receivedAlerts[0].Labels.Alertname)
	assert.Equal(t, "rule_001", receivedAlerts[0].Labels.RuleID)
	assert.Equal(t, "critical", receivedAlerts[0].Labels.Severity)
	assert.Equal(t, "Test Rule", receivedAlerts[0].Annotations.Summary)
	assert.Equal(t, "http://ebpf-guard:9090", receivedAlerts[0].GeneratorURL)
}

func TestAlertmanagerClient_BatchSending(t *testing.T) {
	var mu sync.Mutex
	var receivedBatches int
	var totalAlerts int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var alerts []types.AlertPayload
		json.Unmarshal(body, &alerts)

		mu.Lock()
		receivedBatches++
		totalAlerts += len(alerts)
		mu.Unlock()

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewAlertmanagerClient(
		server.URL,
		"http://ebpf-guard:9090",
		5,  // batch size
		10, // batch timeout (seconds)
		5,
	)
	defer client.Close()

	ctx := context.Background()

	// Send 12 alerts (should result in 2 batches: 5 + 5 + 2 remaining)
	for i := 0; i < 12; i++ {
		client.SendAlert(ctx, types.Alert{
			RuleID:   "rule_batch",
			RuleName: "Batch Test",
			Severity: types.SeverityWarning,
		})
	}

	// Force flush remaining
	client.Flush()
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	assert.GreaterOrEqual(t, receivedBatches, 2)
	assert.Equal(t, 12, totalAlerts)
}

func TestAlertmanagerClient_CircuitBreaker(t *testing.T) {
	failures := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		failures++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client := NewAlertmanagerClient(
		server.URL,
		"http://ebpf-guard:9090",
		1, // batch size 1 to trigger immediately
		10,
		3, // circuit breaker after 3 failures
	)
	defer client.Close()

	ctx := context.Background()

	// Send alerts until circuit opens
	for i := 0; i < 5; i++ {
		client.SendAlert(ctx, types.Alert{
			RuleID:   "rule_cb",
			RuleName: "Circuit Breaker Test",
			Severity: types.SeverityWarning,
		})
		client.Flush()
		time.Sleep(50 * time.Millisecond)
	}

	// Circuit should be open after 3 failures
	// The 4th and 5th alerts should be dropped
	assert.GreaterOrEqual(t, failures, 3)
}

func TestAlertmanagerClient_alertToPayload(t *testing.T) {
	client := NewAlertmanagerClient(
		"http://alertmanager:9093",
		"http://ebpf-guard:9090",
		10, 5, 5,
	)

	alert := types.Alert{
		ID:        "alert-2",
		Timestamp: time.Now(),
		RuleID:    "rule_002",
		RuleName:  "Sensitive File Access",
		Severity:  types.SeverityCritical,
		Message:   "Process accessed /etc/shadow",
		PID:       1234,
		Comm:      "test",
	}

	payload := client.alertToPayload(alert)

	assert.Equal(t, "EbpfGuardAlert", payload.Labels.Alertname)
	assert.Equal(t, "rule_002", payload.Labels.RuleID)
	assert.Equal(t, "critical", payload.Labels.Severity)
	assert.Equal(t, "Sensitive File Access", payload.Annotations.Summary)
	assert.Equal(t, "Process accessed /etc/shadow", payload.Annotations.Description)
	assert.Equal(t, "http://ebpf-guard:9090", payload.GeneratorURL)
}

// TestAlertmanagerClient_CircuitBreakerCooldown tests that the circuit breaker
// recovers after the cooldown period expires when the server becomes healthy.
func TestAlertmanagerClient_CircuitBreakerCooldown(t *testing.T) {
	var mu sync.Mutex
	failMode := true
	requestCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		fail := failMode
		requestCount++
		mu.Unlock()

		if fail {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	ctx := context.Background()

	// Create client with short reset timeout for testing.
	client := &AlertmanagerClient{
		webhookURL:   server.URL,
		generatorURL: "http://ebpf-guard:9090",
		batchSize:    1,
		batchTimeout: 10 * time.Second,
		batch:        make([]types.AlertPayload, 0, 1),
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		cb:       newCircuitBreaker(2, 200*time.Millisecond, nil, nil),
		fallback: newFallbackQueue(100, nil, nil),
	}

	// Phase 1: trigger circuit open via consecutive failures.
	for i := 0; i < 3; i++ {
		client.SendAlert(ctx, types.Alert{
			RuleID:   "rule_cooldown",
			Severity: types.SeverityWarning,
		})
		client.Flush()
		time.Sleep(50 * time.Millisecond)
	}
	assert.Equal(t, cbStateOpen, client.cb.State(), "circuit should be open after failures")

	// Phase 2: server recovers; wait for reset timeout to elapse.
	mu.Lock()
	failMode = false
	mu.Unlock()
	time.Sleep(250 * time.Millisecond)

	// Phase 3: next flush transitions Open→HalfOpen and sends a probe.
	mu.Lock()
	requestCount = 0
	mu.Unlock()

	client.SendAlert(ctx, types.Alert{
		RuleID:   "rule_cooldown",
		Severity: types.SeverityWarning,
	})
	client.Flush()
	time.Sleep(100 * time.Millisecond)

	// Probe should succeed; circuit transitions HalfOpen→Closed.
	mu.Lock()
	count := requestCount
	mu.Unlock()
	assert.GreaterOrEqual(t, count, 1, "circuit should allow probe after reset timeout")
	assert.Equal(t, cbStateClosed, client.cb.State(), "circuit should be closed after successful probe")
}

// TestAlertmanagerClient_TraceIDInPayload tests that trace_id is included in the alert payload.
func TestAlertmanagerClient_TraceIDInPayload(t *testing.T) {
	client := NewAlertmanagerClient(
		"http://alertmanager:9093",
		"http://ebpf-guard:9090",
		10, 5, 5,
	)

	alert := types.Alert{
		ID:        "alert-trace",
		Timestamp: time.Now(),
		RuleID:    "rule_trace",
		RuleName:  "Trace Test",
		Severity:  types.SeverityWarning,
		Message:   "Test alert with trace",
		TraceID:   "abc123def456",
		PID:       1234,
		Comm:      "test",
	}

	payload := client.alertToPayload(alert)

	assert.Equal(t, "EbpfGuardAlert", payload.Labels.Alertname)
	assert.Equal(t, "rule_trace", payload.Labels.RuleID)
	// Trace ID should be included in the description
	assert.Contains(t, payload.Annotations.Description, "[trace_id: abc123def456]")
}

// TestAlertmanagerClient_NoTraceIDWhenEmpty tests that trace_id is not added when empty.
func TestAlertmanagerClient_NoTraceIDWhenEmpty(t *testing.T) {
	client := NewAlertmanagerClient(
		"http://alertmanager:9093",
		"http://ebpf-guard:9090",
		10, 5, 5,
	)

	alert := types.Alert{
		ID:        "alert-no-trace",
		Timestamp: time.Now(),
		RuleID:    "rule_no_trace",
		RuleName:  "No Trace Test",
		Severity:  types.SeverityWarning,
		Message:   "Test alert without trace",
		TraceID:   "", // Empty trace ID
		PID:       1234,
		Comm:      "test",
	}

	payload := client.alertToPayload(alert)

	// Description should not contain trace_id
	assert.Equal(t, "Test alert without trace", payload.Annotations.Description)
	assert.NotContains(t, payload.Annotations.Description, "trace_id")
}
