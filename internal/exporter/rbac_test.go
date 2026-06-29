package exporter

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testViewerToken = "viewer-token-abc123"
	testAdminToken  = "admin-token-xyz789"
)

// okHandler is a trivial handler that always returns 200.
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func rbacRequest(method, path, token string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

// --- isViewerAllowed unit tests ---

func TestIsViewerAllowed_GET(t *testing.T) {
	cases := []struct {
		method string
		path   string
		want   bool
	}{
		{http.MethodGet, "/metrics", true},
		{http.MethodGet, "/api/v1/alerts", true},
		{http.MethodGet, "/api/v1/alerts/abc123", true},
		{http.MethodGet, "/api/v1/alerts/abc123/explain", true},
		{http.MethodGet, "/api/v1/rules", true},
		{http.MethodGet, "/api/v1/status", true},
		{http.MethodGet, "/api/v1/feedback", true},
		{http.MethodGet, "/api/v1/incidents", true},
		{http.MethodGet, "/api/v1/incidents/42", true},
		// Write ops are admin-only
		{http.MethodPost, "/api/v1/alerts/abc/feedback", false},
		{http.MethodPost, "/api/v1/rules/reload", false},
		{http.MethodPut, "/api/v1/rules", false},
		{http.MethodDelete, "/api/v1/alerts/abc", false},
		// Unknown paths
		{http.MethodGet, "/api/v1/unknown", false},
		{http.MethodGet, "/debug/state", false},
	}
	for _, tc := range cases {
		got := isViewerAllowed(tc.method, tc.path)
		assert.Equal(t, tc.want, got, "%s %s", tc.method, tc.path)
	}
}

// --- RBACMiddleware unit tests via httptest ---

func TestRBACMiddleware_NoToken(t *testing.T) {
	mw := RBACMiddleware(testViewerToken, testAdminToken)(okHandler)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, rbacRequest(http.MethodGet, "/api/v1/alerts", ""))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACMiddleware_InvalidToken(t *testing.T) {
	mw := RBACMiddleware(testViewerToken, testAdminToken)(okHandler)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, rbacRequest(http.MethodGet, "/api/v1/alerts", "totally-wrong"))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACMiddleware_HealthAlwaysPublic(t *testing.T) {
	mw := RBACMiddleware(testViewerToken, testAdminToken)(okHandler)
	for _, path := range []string{"/health", "/health/ready", "/health/live"} {
		w := httptest.NewRecorder()
		mw.ServeHTTP(w, rbacRequest(http.MethodGet, path, ""))
		assert.Equal(t, http.StatusOK, w.Code, "path: %s", path)
	}
}

func TestRBACMiddleware_ViewerCanReadAlerts(t *testing.T) {
	mw := RBACMiddleware(testViewerToken, testAdminToken)(okHandler)
	paths := []string{
		"/api/v1/alerts",
		"/api/v1/alerts/abc123",
		"/api/v1/alerts/abc123/explain",
		"/api/v1/rules",
		"/api/v1/status",
		"/api/v1/feedback",
		"/api/v1/incidents",
		"/metrics",
	}
	for _, path := range paths {
		w := httptest.NewRecorder()
		mw.ServeHTTP(w, rbacRequest(http.MethodGet, path, testViewerToken))
		assert.Equal(t, http.StatusOK, w.Code, "viewer should read %s", path)
	}
}

func TestRBACMiddleware_ViewerForbiddenOnWrites(t *testing.T) {
	mw := RBACMiddleware(testViewerToken, testAdminToken)(okHandler)
	cases := []struct{ method, path string }{
		{http.MethodPost, "/api/v1/alerts/abc/feedback"},
		{http.MethodPost, "/api/v1/rules/reload"},
		{http.MethodPut, "/api/v1/rules"},
		{http.MethodDelete, "/api/v1/alerts/abc"},
	}
	for _, tc := range cases {
		w := httptest.NewRecorder()
		mw.ServeHTTP(w, rbacRequest(tc.method, tc.path, testViewerToken))
		assert.Equal(t, http.StatusForbidden, w.Code, "viewer must be forbidden: %s %s", tc.method, tc.path)
	}
}

func TestRBACMiddleware_AdminCanWriteAll(t *testing.T) {
	mw := RBACMiddleware(testViewerToken, testAdminToken)(okHandler)
	cases := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/alerts"},
		{http.MethodPost, "/api/v1/alerts/abc/feedback"},
		{http.MethodPost, "/api/v1/rules/reload"},
		{http.MethodPut, "/api/v1/rules"},
		{http.MethodDelete, "/api/v1/alerts/abc"},
		{http.MethodGet, "/debug/state"},
	}
	for _, tc := range cases {
		w := httptest.NewRecorder()
		mw.ServeHTTP(w, rbacRequest(tc.method, tc.path, testAdminToken))
		assert.Equal(t, http.StatusOK, w.Code, "admin must access: %s %s", tc.method, tc.path)
	}
}

func TestRBACMiddleware_MalformedAuthHeader(t *testing.T) {
	mw := RBACMiddleware(testViewerToken, testAdminToken)(okHandler)

	cases := []string{
		"Basic dXNlcjpwYXNz", // wrong scheme
		testAdminToken,        // missing "Bearer " prefix
		"Bearer",              // missing token value
	}
	for _, header := range cases {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/alerts", nil)
		r.Header.Set("Authorization", header)
		w := httptest.NewRecorder()
		mw.ServeHTTP(w, r)
		assert.Equal(t, http.StatusUnauthorized, w.Code, "header: %q", header)
	}
}

// --- NewServerWithRBAC integration test ---

func TestNewServerWithRBAC_Integration(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	addr := listener.Addr().String()
	srv := NewServerWithRBAC(addr, "/metrics", "/health", false, false,
		testViewerToken, testAdminToken, true)
	srv.SetReady(true)

	go srv.server.Serve(listener)
	time.Sleep(30 * time.Millisecond)

	base := "http://" + addr
	client := &http.Client{}

	do := func(method, path, token string) int {
		req, _ := http.NewRequest(method, base+path, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		return resp.StatusCode
	}

	// Health is always public.
	assert.Equal(t, http.StatusOK, do(http.MethodGet, "/health/live", ""))
	assert.Equal(t, http.StatusOK, do(http.MethodGet, "/health/ready", ""))

	// Metrics: viewer can read, unauthenticated gets 401.
	assert.Equal(t, http.StatusOK, do(http.MethodGet, "/metrics", testViewerToken))
	assert.Equal(t, http.StatusOK, do(http.MethodGet, "/metrics", testAdminToken))
	assert.Equal(t, http.StatusUnauthorized, do(http.MethodGet, "/metrics", ""))

	// /api/v1/alerts: unauthenticated → 401; authenticated requests pass auth
	// and may return 503 because no alert store is set — that's fine for an RBAC test.
	assert.Equal(t, http.StatusUnauthorized, do(http.MethodGet, "/api/v1/alerts", ""))
	viewerAlertsStatus := do(http.MethodGet, "/api/v1/alerts", testViewerToken)
	assert.NotEqual(t, http.StatusUnauthorized, viewerAlertsStatus, "viewer should not get 401 on GET /alerts")
	assert.NotEqual(t, http.StatusForbidden, viewerAlertsStatus, "viewer should not get 403 on GET /alerts")
	adminAlertsStatus := do(http.MethodGet, "/api/v1/alerts", testAdminToken)
	assert.NotEqual(t, http.StatusUnauthorized, adminAlertsStatus, "admin should not get 401 on GET /alerts")
	assert.NotEqual(t, http.StatusForbidden, adminAlertsStatus, "admin should not get 403 on GET /alerts")

	// POST feedback: viewer → 403, admin passes auth (may 503 without store).
	assert.Equal(t, http.StatusForbidden, do(http.MethodPost, "/api/v1/alerts/x/feedback", testViewerToken))
	adminStatus := do(http.MethodPost, "/api/v1/alerts/x/feedback", testAdminToken)
	assert.NotEqual(t, http.StatusUnauthorized, adminStatus)
	assert.NotEqual(t, http.StatusForbidden, adminStatus)
}

// --- pprof auth enforcement ---

// TestPprofRequiresAdminToken verifies that /debug/pprof endpoints are gated
// behind RBAC: no token → 401, viewer token → 403, admin token → 200.
// This is the acceptance-criteria check for issue #217.
func TestPprofRequiresAdminToken(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	addr := listener.Addr().String()
	// enablePprof=true so the routes are registered.
	srv := NewServerWithRBAC(addr, "/metrics", "/health", true, false,
		testViewerToken, testAdminToken, true)
	srv.SetReady(true)
	go srv.server.Serve(listener)
	time.Sleep(30 * time.Millisecond)

	base := "http://" + addr
	client := &http.Client{}

	do := func(path, token string) int {
		req, _ := http.NewRequest(http.MethodGet, base+path, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		return resp.StatusCode
	}

	pprofPaths := []string{
		"/debug/pprof/",
		"/debug/pprof/heap",
		"/debug/pprof/goroutine",
		"/debug/pprof/allocs",
	}

	for _, path := range pprofPaths {
		// No token → 401.
		assert.Equal(t, http.StatusUnauthorized, do(path, ""),
			"pprof %s must be 401 without token", path)

		// Viewer token → 403 (pprof is admin-only).
		assert.Equal(t, http.StatusForbidden, do(path, testViewerToken),
			"pprof %s must be 403 with viewer token", path)

		// Admin token → 200.
		assert.Equal(t, http.StatusOK, do(path, testAdminToken),
			"pprof %s must be 200 with admin token", path)
	}
}

// TestPprofDisabledReturns404 verifies that /debug/pprof routes return 404
// when pprof is not enabled, even with a valid admin token.
func TestPprofDisabledReturns404(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	addr := listener.Addr().String()
	// enablePprof=false — routes are not registered.
	srv := NewServerWithRBAC(addr, "/metrics", "/health", false, false,
		testViewerToken, testAdminToken, true)
	srv.SetReady(true)
	go srv.server.Serve(listener)
	time.Sleep(30 * time.Millisecond)

	base := "http://" + addr
	client := &http.Client{}

	do := func(path, token string) int {
		req, _ := http.NewRequest(http.MethodGet, base+path, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		return resp.StatusCode
	}

	// Admin can authenticate fine, but pprof routes should not exist.
	assert.Equal(t, http.StatusNotFound, do("/debug/pprof/", testAdminToken),
		"pprof index must 404 when pprof is disabled")
	assert.Equal(t, http.StatusNotFound, do("/debug/pprof/heap", testAdminToken),
		"pprof heap must 404 when pprof is disabled")
}

// TestRBACMiddleware_PprofIsAdminOnly verifies the middleware logic directly
// without a real HTTP server: /debug/pprof paths are not in viewerPrefixes.
func TestRBACMiddleware_PprofIsAdminOnly(t *testing.T) {
	mw := RBACMiddleware(testViewerToken, testAdminToken)(okHandler)

	pprofPaths := []string{
		"/debug/pprof/",
		"/debug/pprof/heap",
		"/debug/pprof/goroutine",
		"/debug/pprof/profile",
		"/debug/pprof/allocs",
		"/debug/pprof/block",
		"/debug/pprof/mutex",
	}

	for _, path := range pprofPaths {
		// Viewer must be forbidden on any pprof path.
		w := httptest.NewRecorder()
		mw.ServeHTTP(w, rbacRequest(http.MethodGet, path, testViewerToken))
		assert.Equal(t, http.StatusForbidden, w.Code,
			"viewer must be forbidden on %s", path)

		// Admin must be allowed.
		w = httptest.NewRecorder()
		mw.ServeHTTP(w, rbacRequest(http.MethodGet, path, testAdminToken))
		assert.Equal(t, http.StatusOK, w.Code,
			"admin must be allowed on %s", path)

		// No token → unauthorized.
		w = httptest.NewRecorder()
		mw.ServeHTTP(w, rbacRequest(http.MethodGet, path, ""))
		assert.Equal(t, http.StatusUnauthorized, w.Code,
			"unauthenticated must be 401 on %s", path)
	}
}

// --- Backward compat: NewServerWithAuth still works as admin-only ---

func TestNewServerWithAuth_BackwardCompat(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	addr := listener.Addr().String()
	// Single legacy token → treated as admin.
	srv := NewServerWithAuth(addr, "/metrics", "/health", false, false, testAdminToken, true)
	go srv.server.Serve(listener)
	time.Sleep(30 * time.Millisecond)

	base := "http://" + addr
	client := &http.Client{}

	do := func(method, path, token string) int {
		req, _ := http.NewRequest(method, base+path, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		return resp.StatusCode
	}

	assert.Equal(t, http.StatusOK, do(http.MethodGet, "/health/live", ""))
	assert.Equal(t, http.StatusOK, do(http.MethodGet, "/metrics", testAdminToken))
	assert.Equal(t, http.StatusUnauthorized, do(http.MethodGet, "/metrics", "wrong"))
	assert.Equal(t, http.StatusUnauthorized, do(http.MethodGet, "/metrics", ""))
}
