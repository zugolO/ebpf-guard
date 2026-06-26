package exporter

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestServer() *Server {
	return NewServerWithAuth("localhost:0", "/metrics", "/health", false, false, "", false)
}

func TestHandleExportCEF(t *testing.T) {
	store := &mockAlertStore{
		alerts: []types.Alert{
			{ID: "a1", Timestamp: time.Now(), RuleID: "r1", Severity: types.SeverityCritical, Comm: "x", Message: "m"},
		},
		healthy: true,
	}
	srv := newTestServer()
	srv.SetAlertStore(store)

	t.Run("returns CEF lines", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/alerts/export/cef", nil)
		w := httptest.NewRecorder()
		srv.handleExportCEF(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Header().Get("Content-Disposition"), "alerts.cef")
		assert.Contains(t, w.Body.String(), "CEF:")
	})

	t.Run("method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/alerts/export/cef", nil)
		w := httptest.NewRecorder()
		srv.handleExportCEF(w, req)
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("no store configured", func(t *testing.T) {
		bare := newTestServer()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/alerts/export/cef", nil)
		w := httptest.NewRecorder()
		bare.handleExportCEF(w, req)
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestHandleIncidentByID(t *testing.T) {
	srv := newTestServer()

	t.Run("not configured", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents/abc", nil)
		w := httptest.NewRecorder()
		srv.handleIncidentByID(w, req)
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	// Wire a real (empty) incident tracker from a correlation engine.
	ce := correlator.NewCorrelationEngine(nil)
	srv.SetIncidentTracker(ce.IncidentTracker())

	t.Run("unknown id → 404", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents/missing", nil)
		w := httptest.NewRecorder()
		srv.handleIncidentByID(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("missing id → 400", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents/", nil)
		w := httptest.NewRecorder()
		srv.handleIncidentByID(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/incidents/abc", nil)
		w := httptest.NewRecorder()
		srv.handleIncidentByID(w, req)
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}

func TestHandleBPFReload(t *testing.T) {
	srv := newTestServer()

	t.Run("not configured", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/bpf/reload", nil)
		w := httptest.NewRecorder()
		srv.handleBPFReload(w, req)
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("success", func(t *testing.T) {
		srv.SetBPFReloader(func(context.Context) error { return nil })
		req := httptest.NewRequest(http.MethodPost, "/api/v1/bpf/reload", nil)
		w := httptest.NewRecorder()
		srv.handleBPFReload(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "ok")
	})

	t.Run("reloader error", func(t *testing.T) {
		srv.SetBPFReloader(func(context.Context) error { return errors.New("boom") })
		req := httptest.NewRequest(http.MethodPost, "/api/v1/bpf/reload", nil)
		w := httptest.NewRecorder()
		srv.handleBPFReload(w, req)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/bpf/reload", nil)
		w := httptest.NewRecorder()
		srv.handleBPFReload(w, req)
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}

func TestHandleStatusAndAPIDocs(t *testing.T) {
	srv := newTestServer()
	srv.SetAlertStore(&mockAlertStore{healthy: true})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	w := httptest.NewRecorder()
	srv.handleStatus(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "healthy")

	req = httptest.NewRequest(http.MethodGet, "/api/docs", nil)
	w = httptest.NewRecorder()
	srv.handleAPIDocs(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "swagger-ui")
}
