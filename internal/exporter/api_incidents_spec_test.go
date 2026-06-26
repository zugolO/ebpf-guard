package exporter

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleIncidents(t *testing.T) {
	srv := newTestServer()

	t.Run("not configured → 503", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents", nil)
		w := httptest.NewRecorder()
		srv.handleIncidents(w, req)
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("wrong method → 405", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/incidents", nil)
		w := httptest.NewRecorder()
		srv.handleIncidents(w, req)
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	ce := correlator.NewCorrelationEngine(nil)
	srv.SetIncidentTracker(ce.IncidentTracker())

	t.Run("configured → 200 with empty list", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents?namespace=prod&status=open&limit=5", nil)
		w := httptest.NewRecorder()
		srv.handleIncidents(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "[]")
	})
}

func TestHandleOpenAPISpec(t *testing.T) {
	srv := newTestServer()

	t.Run("plain", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/openapi.yaml", nil)
		w := httptest.NewRecorder()
		srv.handleOpenAPISpec(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "application/yaml", w.Header().Get("Content-Type"))
		assert.NotEmpty(t, w.Body.Bytes())
	})

	t.Run("CORS wildcard", func(t *testing.T) {
		srv.SetCORSAllowedOrigins([]string{"*"})
		req := httptest.NewRequest(http.MethodGet, "/api/openapi.yaml", nil)
		req.Header.Set("Origin", "https://app.example.com")
		w := httptest.NewRecorder()
		srv.handleOpenAPISpec(w, req)
		assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("CORS specific origin reflected", func(t *testing.T) {
		srv.SetCORSAllowedOrigins([]string{"https://app.example.com"})
		req := httptest.NewRequest(http.MethodGet, "/api/openapi.yaml", nil)
		req.Header.Set("Origin", "https://app.example.com")
		w := httptest.NewRecorder()
		srv.handleOpenAPISpec(w, req)
		assert.Equal(t, "https://app.example.com", w.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "Origin", w.Header().Get("Vary"))
	})
}
