//go:build tui

package tui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

func newFakeAgent(t *testing.T, alerts []types.Alert, requireToken string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requireToken != "" {
			if r.Header.Get("Authorization") != "Bearer "+requireToken {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}
		switch r.URL.Path {
		case "/api/v1/alerts":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(alerts)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestAgentPoller_PollMergesAlertsAndDedups(t *testing.T) {
	alerts := []types.Alert{
		{ID: "a1", RuleID: "rule_001", Severity: types.SeverityCritical, PID: 1, Comm: "nginx"},
		{ID: "a2", RuleID: "rule_002", Severity: types.SeverityWarning, PID: 2, Comm: "curl",
			Enrichment: types.EnrichmentInfo{NodeName: "node-b", PodName: "curl-pod"}},
	}
	srv := newFakeAgent(t, alerts, "secret-token")

	feed := NewFeed()
	poller := newAgentPoller(srv.URL, "secret-token")

	poller.poll(context.Background(), feed, "10s")

	got, _, _ := feed.Snapshot(10, 0)
	require.Len(t, got, 2)

	// a1 had no NodeName; the poller should fall back to the endpoint's host:port.
	byID := map[string]types.Alert{}
	for _, a := range got {
		byID[a.ID] = a
	}
	assert.NotEmpty(t, byID["a1"].Enrichment.NodeName)
	assert.Equal(t, "node-b", byID["a2"].Enrichment.NodeName)
	assert.Equal(t, "curl-pod", byID["a2"].Enrichment.PodName)

	statuses := feed.AgentStatuses()
	require.Len(t, statuses, 1)
	assert.True(t, statuses[0].Healthy)
	assert.Equal(t, int64(2), statuses[0].AlertCount)

	// Polling again with the same alerts must not duplicate them (dedup by ID).
	poller.poll(context.Background(), feed, "10s")
	got2, _, _ := feed.Snapshot(10, 0)
	assert.Len(t, got2, 2)
}

func TestAgentPoller_PollMarksUnhealthyOnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	feed := NewFeed()
	poller := newAgentPoller(srv.URL, "wrong-token")
	poller.poll(context.Background(), feed, "10s")

	statuses := feed.AgentStatuses()
	require.Len(t, statuses, 1)
	assert.False(t, statuses[0].Healthy)
	assert.NotEmpty(t, statuses[0].LastError)
}

func TestFeed_AgentStatuses_SortedByEndpoint(t *testing.T) {
	feed := NewFeed()
	feed.SetAgentStatus(AgentStatus{Endpoint: "http://b", Healthy: true})
	feed.SetAgentStatus(AgentStatus{Endpoint: "http://a", Healthy: true})

	statuses := feed.AgentStatuses()
	require.Len(t, statuses, 2)
	assert.Equal(t, "http://a", statuses[0].Endpoint)
	assert.Equal(t, "http://b", statuses[1].Endpoint)
}

func TestRunFleet_NoEndpoints(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := RunFleet(ctx, NewFeed(), FleetConfig{})
	require.Error(t, err)
}
