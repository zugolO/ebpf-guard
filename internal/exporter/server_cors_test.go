package exporter

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestCORSMiddleware_ReadOnlyEndpointsGetHeaders verifies that the fleet
// dashboard (issue #312) can poll another agent's read-only /api/v1/*
// endpoints cross-origin: the configured allowlist is reflected on the
// response, and an OPTIONS preflight succeeds without a bearer token since a
// browser preflight never carries the Authorization header.
func TestCORSMiddleware_ReadOnlyEndpointsGetHeaders(t *testing.T) {
	srv := NewServerWithMultiTenant("localhost:0", "/metrics", "/health", false, false,
		nil, "viewer-token", "admin-token", true)
	srv.SetCORSAllowedOrigins([]string{"https://node-a.example"})

	t.Run("preflight OPTIONS succeeds without auth", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/api/v1/summary", nil)
		req.Header.Set("Origin", "https://node-a.example")
		req.Header.Set("Access-Control-Request-Method", "GET")
		w := httptest.NewRecorder()
		srv.server.Handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
		assert.Equal(t, "https://node-a.example", w.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("GET with matching origin and valid token gets CORS header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
		req.Header.Set("Origin", "https://node-a.example")
		req.Header.Set("Authorization", "Bearer viewer-token")
		w := httptest.NewRecorder()
		srv.server.Handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "https://node-a.example", w.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("GET from an origin not in the allowlist gets no CORS header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
		req.Header.Set("Origin", "https://evil.example")
		req.Header.Set("Authorization", "Bearer viewer-token")
		w := httptest.NewRecorder()
		srv.server.Handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("write endpoints never receive CORS headers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/api/v1/tuning/exceptions", nil)
		req.Header.Set("Origin", "https://node-a.example")
		w := httptest.NewRecorder()
		srv.server.Handler.ServeHTTP(w, req)

		assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
	})
}

// TestCORSMiddleware_NoOriginConfigured verifies default construction (no
// SetCORSAllowedOrigins call) leaves CORS headers off, matching pre-#312
// behavior for callers that never opt in.
func TestCORSMiddleware_NoOriginConfigured(t *testing.T) {
	srv := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.Header.Set("Origin", "https://node-a.example")
	w := httptest.NewRecorder()
	srv.server.Handler.ServeHTTP(w, req)

	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
}
