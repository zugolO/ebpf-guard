//go:build tui

package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
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

	poller.poll(context.Background(), feed, 10*time.Second)

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
	poller.poll(context.Background(), feed, 10*time.Second)
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
	poller.poll(context.Background(), feed, 10*time.Second)

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

// TestAgentPoller_PreservesStatusOnFailure verifies that a failed poll does not
// clobber the node name or alert count discovered by earlier successful polls.
func TestAgentPoller_PreservesStatusOnFailure(t *testing.T) {
	fail := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]types.Alert{
			{ID: "a1", RuleID: "r", Enrichment: types.EnrichmentInfo{NodeName: "real-node"}},
		})
	}))
	t.Cleanup(srv.Close)

	feed := NewFeed()
	poller := newAgentPoller(srv.URL, "")

	poller.poll(context.Background(), feed, 10*time.Second)
	before := feed.AgentStatuses()
	require.Len(t, before, 1)
	assert.True(t, before[0].Healthy)
	assert.Equal(t, "real-node", before[0].NodeName)
	assert.Equal(t, int64(1), before[0].AlertCount)
	firstSeen := before[0].LastSeen

	// Now the agent fails: status must flip to unhealthy but keep the
	// discovered node name, the monotonic alert count, and the last-success time.
	fail = true
	poller.poll(context.Background(), feed, 10*time.Second)
	after := feed.AgentStatuses()
	require.Len(t, after, 1)
	assert.False(t, after[0].Healthy)
	assert.NotEmpty(t, after[0].LastError)
	assert.Equal(t, "real-node", after[0].NodeName, "node name must survive a failed poll")
	assert.Equal(t, int64(1), after[0].AlertCount, "alert count must not reset on failure")
	assert.Equal(t, firstSeen, after[0].LastSeen, "LastSeen must stay at the last successful poll")
}

// TestAgentPoller_PaginatesLargeBursts verifies that a burst larger than one
// page is fully fetched via pagination rather than truncated at the page limit.
func TestAgentPoller_PaginatesLargeBursts(t *testing.T) {
	const total = fleetPageLimit*2 + 37
	all := make([]types.Alert, total)
	for i := range all {
		all[i] = types.Alert{ID: fmt.Sprintf("id-%d", i), RuleID: "r"}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		if limit <= 0 {
			limit = len(all)
		}
		end := offset + limit
		if offset > len(all) {
			offset = len(all)
		}
		if end > len(all) {
			end = len(all)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(all[offset:end])
	}))
	t.Cleanup(srv.Close)

	feed := NewFeed()
	poller := newAgentPoller(srv.URL, "")
	poller.poll(context.Background(), feed, 10*time.Second)

	got, _, _ := feed.Snapshot(total+10, 0)
	assert.Len(t, got, total, "all alerts across pages should be merged, not truncated at one page")
}

// TestAgentPoller_EmptyIDAlertsNotCollapsed verifies that distinct alerts with
// empty IDs are not all deduplicated into a single entry.
func TestAgentPoller_EmptyIDAlertsNotCollapsed(t *testing.T) {
	alerts := []types.Alert{
		{ID: "", RuleID: "r1", PID: 1, Comm: "a", Timestamp: time.Unix(1, 0)},
		{ID: "", RuleID: "r2", PID: 2, Comm: "b", Timestamp: time.Unix(2, 0)},
		{ID: "", RuleID: "r3", PID: 3, Comm: "c", Timestamp: time.Unix(3, 0)},
	}
	srv := newFakeAgent(t, alerts, "")
	feed := NewFeed()
	poller := newAgentPoller(srv.URL, "")
	poller.poll(context.Background(), feed, 10*time.Second)

	got, _, _ := feed.Snapshot(10, 0)
	assert.Len(t, got, 3, "distinct empty-ID alerts must not collapse into one")
}
