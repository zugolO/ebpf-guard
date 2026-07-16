package exporter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/internal/store"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

func TestDashboardRoutes(t *testing.T) {
	srv := newTestServer()
	mux := http.NewServeMux()
	srv.RegisterAPIRoutes(mux)

	t.Run("root redirects to /ui/", func(t *testing.T) {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, "/ui/", w.Header().Get("Location"))
	})

	t.Run("unknown path is 404, not swallowed by root handler", func(t *testing.T) {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/does-not-exist", nil))
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("/ui/ serves the embedded dashboard index", func(t *testing.T) {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/ui/", nil))
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "ebpf-guard")
		assert.NotEmpty(t, w.Header().Get("Content-Security-Policy"))
	})

	t.Run("/ui/app.js is served as a static asset", func(t *testing.T) {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/ui/app.js", nil))
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestDashboardRequiresAuthWhenEnabled(t *testing.T) {
	srv := NewServerWithMultiTenant("localhost:0", "/metrics", "/health", false, false,
		nil, "viewer-token", "admin-token", true)

	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	w := httptest.NewRecorder()
	srv.server.Handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code, "dashboard must require auth like the rest of the read-only API")

	req = httptest.NewRequest(http.MethodGet, "/ui/", nil)
	req.Header.Set("Authorization", "Bearer viewer-token")
	w = httptest.NewRecorder()
	srv.server.Handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "viewer role must be able to reach the dashboard")
}

func TestHandleSummary(t *testing.T) {
	now := time.Now().UTC()
	mock := &mockAlertStore{
		alerts: []types.Alert{
			{ID: "a1", Timestamp: now, RuleID: "rule_001", Severity: types.SeverityCritical, Comm: "bash", Message: "m"},
			{ID: "a2", Timestamp: now.Add(-1 * time.Hour), RuleID: "rule_001", Severity: types.SeverityWarning, Comm: "sh", Message: "m"},
			{ID: "a3", Timestamp: now.Add(-2 * time.Hour), RuleID: "rule_002", Severity: types.SeverityWarning, Comm: "curl", Message: "m"},
		},
		healthy: true,
	}

	t.Run("no store → 503", func(t *testing.T) {
		srv := newTestServer()
		w := httptest.NewRecorder()
		srv.handleSummary(w, httptest.NewRequest(http.MethodGet, "/api/v1/summary", nil))
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	srv := newTestServer()
	srv.SetAlertStore(mock)

	t.Run("wrong method → 405", func(t *testing.T) {
		w := httptest.NewRecorder()
		srv.handleSummary(w, httptest.NewRequest(http.MethodPost, "/api/v1/summary", nil))
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("aggregates severities, rules, and timeline", func(t *testing.T) {
		w := httptest.NewRecorder()
		srv.handleSummary(w, httptest.NewRequest(http.MethodGet, "/api/v1/summary?since=24h", nil))
		require.Equal(t, http.StatusOK, w.Code)

		var summary AlertSummary
		require.NoError(t, json.NewDecoder(w.Body).Decode(&summary))

		assert.Equal(t, 3, summary.Total)
		assert.Equal(t, 1, summary.BySeverity["critical"])
		assert.Equal(t, 2, summary.BySeverity["warning"])
		require.NotEmpty(t, summary.TopRules)
		assert.Equal(t, "rule_001", summary.TopRules[0].RuleID)
		assert.Equal(t, 2, summary.TopRules[0].Count)
		assert.GreaterOrEqual(t, len(summary.Timeline), 3)
	})
}

func TestHandleSummary_ForbiddenNamespaceParam(t *testing.T) {
	ms := store.NewMemoryStore()
	srv := NewServerWithMultiTenant("", "/metrics", "/health", false, false, nil, "", "", false)
	srv.SetAlertStore(ms)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/summary?namespace=team-b", nil)
	req = req.WithContext(context.WithValue(req.Context(), tokenScopeKey{}, TokenScope{
		Role:       RoleViewer,
		Namespaces: []string{"team-a"},
	}))
	w := httptest.NewRecorder()
	srv.handleSummary(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestHandleSummary_DefaultsToTwentyFourHourWindow(t *testing.T) {
	now := time.Now().UTC()
	mock := &mockAlertStore{
		alerts: []types.Alert{
			{ID: "recent", Timestamp: now, RuleID: "rule_001", Severity: types.SeverityWarning, Comm: "sh", Message: "m"},
		},
		healthy: true,
	}
	srv := newTestServer()
	srv.SetAlertStore(mock)

	w := httptest.NewRecorder()
	srv.handleSummary(w, httptest.NewRequest(http.MethodGet, "/api/v1/summary", nil))
	require.Equal(t, http.StatusOK, w.Code)

	var summary AlertSummary
	require.NoError(t, json.NewDecoder(w.Body).Decode(&summary))
	assert.Equal(t, 1, summary.Total)
}

func TestBuildAlertSummaryEmpty(t *testing.T) {
	summary := buildAlertSummary(nil)
	assert.Equal(t, 0, summary.Total)
	assert.Empty(t, summary.TopRules)
	assert.Empty(t, summary.Timeline)
}
