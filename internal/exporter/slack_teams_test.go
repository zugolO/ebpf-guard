package exporter

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func notifierLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func criticalAlert() types.Alert {
	return types.Alert{
		ID: "a1", Timestamp: time.Now(), RuleID: "rule-1", RuleName: "Test",
		Severity: types.SeverityCritical, PID: 42, Comm: "evil", Message: "boom",
		Enrichment: types.EnrichmentInfo{Namespace: "prod", PodName: "pod-1"},
	}
}

func TestSlackNotifier_Send(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := NewSlackNotifier(SlackConfig{Enabled: true, WebhookURL: srv.URL, Channel: "#sec"}, notifierLogger(), false)
	assert.Equal(t, "slack", n.Name())
	require.True(t, n.Enabled())
	require.NoError(t, n.Send(context.Background(), criticalAlert()))
	assert.Equal(t, int32(1), atomic.LoadInt32(&hits))

	// Disabled notifier reports not-enabled and does not call the webhook.
	off := NewSlackNotifier(SlackConfig{Enabled: false}, notifierLogger(), false)
	assert.False(t, off.Enabled())
	_ = off.Send(context.Background(), criticalAlert())
}

func TestTeamsNotifier_Send(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := NewTeamsNotifier(TeamsConfig{Enabled: true, WebhookURL: srv.URL}, notifierLogger(), false)
	require.True(t, n.Enabled())
	require.NoError(t, n.Send(context.Background(), criticalAlert()))
	assert.Equal(t, int32(1), atomic.LoadInt32(&hits))
}

func TestWebhookNotifier_Send(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := NewGenericWebhookNotifier(WebhookConfig{
		Enabled: true, URL: srv.URL, Headers: map[string]string{"X-Test": "1"},
	}, notifierLogger(), false)
	require.True(t, n.Enabled())
	require.NoError(t, n.Send(context.Background(), criticalAlert()))
	assert.Equal(t, int32(1), atomic.LoadInt32(&hits))
}
