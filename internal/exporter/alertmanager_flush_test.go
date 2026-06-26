package exporter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAlertmanagerClient_FlushContext(t *testing.T) {
	received := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case received <- struct{}{}:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewAlertmanagerClient(server.URL, "http://ebpf-guard:9090", 10, 1, 5)
	defer client.Close()

	ctx := context.Background()
	client.SendAlert(ctx, types.Alert{
		ID: "a1", Timestamp: time.Now(), RuleID: "r1",
		Severity: types.SeverityCritical, Message: "m", PID: 1, Comm: "x",
	})

	// FlushContext drains the batch and waits for in-flight sends.
	require.NoError(t, client.FlushContext(ctx))

	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("alertmanager webhook was not called")
	}
}

func TestAlertmanagerClient_FlushContext_CancelledCtx(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewAlertmanagerClient(server.URL, "http://ebpf-guard:9090", 10, 1, 5)
	defer client.Close()

	client.SendAlert(context.Background(), types.Alert{
		ID: "a1", Timestamp: time.Now(), RuleID: "r1", Severity: types.SeverityCritical, Message: "m",
	})

	// An already-cancelled context makes FlushContext return its error promptly.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := client.FlushContext(ctx)
	assert.True(t, err == nil || err == context.Canceled)
}
