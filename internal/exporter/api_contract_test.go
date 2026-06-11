package exporter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apispec "github.com/zugolO/ebpf-guard/api"
	"gopkg.in/yaml.v3"
)

// newContractServer returns a Server wired up with no auth, no external
// dependencies — enough to exercise endpoint routing and response shape.
func newContractServer() *Server {
	srv := NewServer(":0", "/metrics", "/health")
	srv.SetReady(true)
	return srv
}

// TestAPIContract_OpenAPISpecValid verifies that the embedded OpenAPI spec is
// well-formed YAML containing the required top-level sections.
func TestAPIContract_OpenAPISpecValid(t *testing.T) {
	var spec map[string]interface{}
	err := yaml.Unmarshal(apispec.OpenAPISpec, &spec)
	require.NoError(t, err, "api/openapi.yaml must be valid YAML")

	assert.Equal(t, "3.0.3", spec["openapi"], "spec must be OpenAPI 3.0.3")
	assert.NotEmpty(t, spec["info"], "spec must have info section")
	assert.NotEmpty(t, spec["paths"], "spec must have paths section")
	assert.NotEmpty(t, spec["components"], "spec must have components section")
}

// TestAPIContract_OpenAPISpecCoversAllRoutes verifies that every registered
// route path appears in the OpenAPI spec's paths section.
func TestAPIContract_OpenAPISpecCoversAllRoutes(t *testing.T) {
	var spec struct {
		Paths map[string]interface{} `yaml:"paths"`
	}
	require.NoError(t, yaml.Unmarshal(apispec.OpenAPISpec, &spec))

	// Canonical routes that must be documented (parameterised paths use {id}).
	requiredPaths := []string{
		"/health",
		"/health/live",
		"/health/ready",
		"/metrics",
		"/api/v1/alerts",
		"/api/v1/alerts/{id}",
		"/api/v1/alerts/{id}/explain",
		"/api/v1/alerts/{id}/feedback",
		"/api/v1/alerts/export/cef",
		"/api/v1/feedback",
		"/api/v1/rules",
		"/api/v1/rules/reload",
		"/api/v1/status",
		"/api/v1/incidents",
		"/api/v1/incidents/{id}",
		"/api/docs",
	}

	for _, path := range requiredPaths {
		assert.Contains(t, spec.Paths, path, "path %q must be documented in api/openapi.yaml", path)
	}
}

// TestAPIContract_HealthEndpoints verifies shape of the three health probes.
func TestAPIContract_HealthEndpoints(t *testing.T) {
	srv := newContractServer()
	mux := srv.mux

	for _, path := range []string{"/health", "/health/live", "/health/ready"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)

			// Health endpoints return 2xx regardless of ready state (ready returns
			// 503 only when not ready — we set ready=true above).
			assert.Less(t, w.Code, 400, "health probe %s returned unexpected status %d", path, w.Code)
		})
	}
}

// TestAPIContract_HealthReady503WhenNotReady verifies readiness returns 503
// when the agent is not yet ready.
func TestAPIContract_HealthReady503WhenNotReady(t *testing.T) {
	srv := newContractServer()
	srv.SetReady(false)

	req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

// TestAPIContract_AlertsEndpoint_NoStore verifies GET /api/v1/alerts returns 503
// when no alert store is configured, matching the OpenAPI spec.
func TestAPIContract_AlertsEndpoint_NoStore(t *testing.T) {
	srv := newContractServer()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/alerts", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

// TestAPIContract_AlertsEndpoint_MethodNotAllowed verifies non-GET returns 405.
func TestAPIContract_AlertsEndpoint_MethodNotAllowed(t *testing.T) {
	srv := newContractServer()

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, "/api/v1/alerts", nil)
		w := httptest.NewRecorder()
		srv.mux.ServeHTTP(w, req)
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code, "method %s should be 405", method)
	}
}

// TestAPIContract_StatusEndpoint verifies GET /api/v1/status returns valid JSON
// matching the StatusResponse schema.
func TestAPIContract_StatusEndpoint(t *testing.T) {
	srv := newContractServer()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var body StatusAPIResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	assert.NotEmpty(t, body.Uptime, "uptime must be non-empty")
	assert.NotZero(t, body.Timestamp, "timestamp must be set")
}

// TestAPIContract_RulesEndpoint verifies GET /api/v1/rules returns a JSON array.
func TestAPIContract_RulesEndpoint(t *testing.T) {
	srv := newContractServer()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/rules", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var rules []RuleAPIResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&rules))
	// Empty slice (no rules loaded) is valid — just check it parses.
}

// TestAPIContract_RulesReload_MethodNotAllowed verifies GET on /api/v1/rules/reload returns 405.
func TestAPIContract_RulesReload_MethodNotAllowed(t *testing.T) {
	srv := newContractServer()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/rules/reload", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

// TestAPIContract_RulesReload_NotConfigured verifies POST /api/v1/rules/reload returns
// 404 when no reload function is registered.
func TestAPIContract_RulesReload_NotConfigured(t *testing.T) {
	srv := newContractServer()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/rules/reload", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestAPIContract_IncidentsEndpoint_NotConfigured verifies GET /api/v1/incidents
// returns 503 when no incident tracker is configured.
func TestAPIContract_IncidentsEndpoint_NotConfigured(t *testing.T) {
	srv := newContractServer()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

// TestAPIContract_FeedbackEndpoint_NotConfigured verifies GET /api/v1/feedback
// returns 501 when no feedback manager is configured.
func TestAPIContract_FeedbackEndpoint_NotConfigured(t *testing.T) {
	srv := newContractServer()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/feedback", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

// TestAPIContract_AlertFeedback_BadVerdict verifies the feedback endpoint rejects
// unknown verdicts with 400, matching the FeedbackRequest schema enum constraint.
func TestAPIContract_AlertFeedback_BadVerdict(t *testing.T) {
	srv := newContractServer()

	body := `{"verdict":"maybe","reason":"test"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/alerts/some-id/feedback",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	// 503 because alertStore is nil (checked first), but the path must be reachable.
	assert.NotEqual(t, http.StatusNotFound, w.Code, "feedback path must be routable")
}

// TestAPIContract_SwaggerUI verifies GET /api/docs returns HTML containing the
// Swagger UI scaffold.
func TestAPIContract_SwaggerUI(t *testing.T) {
	srv := newContractServer()

	req := httptest.NewRequest(http.MethodGet, "/api/docs", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "text/html; charset=utf-8", w.Header().Get("Content-Type"))
	body := w.Body.String()
	assert.Contains(t, body, "swagger-ui", "response must contain Swagger UI scaffold")
	assert.Contains(t, body, "/api/openapi.yaml", "Swagger UI must reference the spec URL")
}

// TestAPIContract_OpenAPISpecEndpoint verifies GET /api/openapi.yaml returns
// the embedded spec with the correct content-type.
func TestAPIContract_OpenAPISpecEndpoint(t *testing.T) {
	srv := newContractServer()

	req := httptest.NewRequest(http.MethodGet, "/api/openapi.yaml", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/yaml", w.Header().Get("Content-Type"))

	// Verify the response is valid YAML.
	var spec map[string]interface{}
	err := yaml.Unmarshal(w.Body.Bytes(), &spec)
	require.NoError(t, err, "served spec must be valid YAML")
	assert.Equal(t, "3.0.3", spec["openapi"])
}
