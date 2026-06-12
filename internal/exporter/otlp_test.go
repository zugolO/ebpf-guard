package exporter

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

func makeTestAlert() types.Alert {
	return types.Alert{
		ID:          "test-001",
		Timestamp:   time.Now(),
		RuleID:      "rule_001",
		RuleName:    "Test Rule",
		Severity:    types.SeverityCritical,
		PID:         1234,
		Comm:        "bash",
		Message:     "suspicious exec detected",
		Fingerprint: "deadbeef",
		TraceID:     "4bf92f3577b34da6a3ce929d0e0e4736",
		SpanID:      "00f067aa0ba902b7",
		Enrichment: types.EnrichmentInfo{
			PodName:   "my-pod",
			Namespace: "production",
			NodeName:  "node-01",
		},
	}
}

func TestOTLPNotifier_Disabled(t *testing.T) {
	n := NewOTLPNotifier(OTLPConfig{Enabled: false}, slog.Default())
	assert.False(t, n.Enabled())
}

func TestOTLPNotifier_MissingEndpoint(t *testing.T) {
	n := NewOTLPNotifier(OTLPConfig{Enabled: true, Endpoint: ""}, slog.Default())
	assert.False(t, n.Enabled())
}

func TestOTLPNotifier_Send(t *testing.T) {
	var received []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/logs", r.URL.Path)
		require.Equal(t, "application/json", r.Header.Get("Content-Type"))
		body, _ := io.ReadAll(r.Body)
		received = body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := NewOTLPNotifier(OTLPConfig{
		Enabled:  true,
		Endpoint: srv.URL,
	}, slog.Default())
	require.True(t, n.Enabled())

	alert := makeTestAlert()
	err := n.Send(context.Background(), alert)
	require.NoError(t, err)
	require.NotNil(t, received)

	var payload map[string]interface{}
	require.NoError(t, json.Unmarshal(received, &payload))

	rl := payload["resourceLogs"].([]interface{})
	require.Len(t, rl, 1)

	scopeLogs := rl[0].(map[string]interface{})["scopeLogs"].([]interface{})
	records := scopeLogs[0].(map[string]interface{})["logRecords"].([]interface{})
	require.Len(t, records, 1)

	rec := records[0].(map[string]interface{})
	assert.Equal(t, float64(21), rec["severityNumber"]) // FATAL for critical
	assert.Equal(t, "critical", rec["severityText"])
	assert.Equal(t, alert.TraceID, rec["traceId"])
	assert.Equal(t, alert.SpanID, rec["spanId"])
}

func TestOTLPNotifier_MinSeverityFilter(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := NewOTLPNotifier(OTLPConfig{
		Enabled:     true,
		Endpoint:    srv.URL,
		MinSeverity: "critical",
	}, slog.Default())

	// warning alert should be filtered out
	alert := makeTestAlert()
	alert.Severity = types.SeverityWarning
	err := n.Send(context.Background(), alert)
	require.NoError(t, err)
	assert.False(t, called, "warning alert should not be sent when min_severity=critical")
}

func TestOTLPNotifier_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	n := NewOTLPNotifier(OTLPConfig{
		Enabled:  true,
		Endpoint: srv.URL,
	}, slog.Default())

	err := n.Send(context.Background(), makeTestAlert())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "502")
}

func TestOTLPNotifier_CustomHeaders(t *testing.T) {
	var gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Api-Key")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := NewOTLPNotifier(OTLPConfig{
		Enabled:  true,
		Endpoint: srv.URL,
		Headers:  map[string]string{"X-Api-Key": "secret"},
	}, slog.Default())

	require.NoError(t, n.Send(context.Background(), makeTestAlert()))
	assert.Equal(t, "secret", gotHeader)
}

func TestOTLPNotifier_Close(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := NewOTLPNotifier(OTLPConfig{Enabled: true, Endpoint: srv.URL}, slog.Default())
	require.NoError(t, n.Close())

	// Send after close should be a no-op
	_ = n.Send(context.Background(), makeTestAlert())
	assert.False(t, called)
}

func TestOTLPSeverityNumbers(t *testing.T) {
	assert.Equal(t, 21, otlpSeverityNumber(types.SeverityCritical))
	assert.Equal(t, 13, otlpSeverityNumber(types.SeverityWarning))
}
