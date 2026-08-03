// Package exporter provides HTTP server with optional authentication.
package exporter

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
)

// tokenScopeKey is the context key for storing the authenticated token's scope.
type tokenScopeKey struct{}

// TokenScope carries the authenticated token's role and namespace allowlist
// through the request context. Handlers call TokenScopeFromContext to retrieve it.
type TokenScope struct {
	Role       Role
	Namespaces []string // nil/empty = all namespaces
}

// TokenScopeFromContext extracts TokenScope from the request context.
// Returns false if no scope was set (e.g. auth is disabled).
func TokenScopeFromContext(ctx context.Context) (TokenScope, bool) {
	scope, ok := ctx.Value(tokenScopeKey{}).(TokenScope)
	return scope, ok
}

// AllowsNamespace returns true if the token scope permits access to ns.
// An empty Namespaces list (or a "*" entry) means all namespaces are allowed.
func (s TokenScope) AllowsNamespace(ns string) bool {
	if len(s.Namespaces) == 0 {
		return true
	}
	for _, n := range s.Namespaces {
		if n == "*" || n == ns {
			return true
		}
	}
	return false
}

// NamespacedToken is a runtime token descriptor used by MultiTenantRBACMiddleware.
type NamespacedToken struct {
	Token      string
	Role       Role
	Namespaces []string // empty = all namespaces
}

// Role represents an RBAC role for HTTP API access.
type Role string

const (
	RoleViewer Role = "viewer"
	RoleAdmin  Role = "admin"
)

// tokenPreview returns a short, non-sensitive prefix of a token suitable for
// correlating log lines without disclosing the secret. Tokens are 64 hex chars,
// so an 8-char prefix is not enough to brute-force.
func tokenPreview(token string) string {
	if len(token) <= 8 {
		return "********"
	}
	return token[:8] + "…"
}

// AuthConfig holds authentication configuration.
type AuthConfig struct {
	Enabled     bool
	BearerToken string
}

// GenerateRandomToken generates a cryptographically secure random 32-byte token.
// Returns the token as a hex-encoded string.
func GenerateRandomToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// SetupAuth configures authentication for the server.
// If auth is enabled but no token is provided, generates a random token.
// Returns the token to use (either configured or generated) and a bool indicating if auth is enabled.
func SetupAuth(authCfg AuthConfig, logger *slog.Logger) (string, bool) {
	if !authCfg.Enabled {
		logger.Info("auth: authentication disabled (not recommended for production)")
		return "", false
	}

	token := authCfg.BearerToken
	if token == "" {
		var err error
		token, err = GenerateRandomToken()
		if err != nil {
			logger.Error("auth: failed to generate random token, disabling auth", slog.Any("error", err))
			return "", false
		}
		// Do NOT put the secret in the structured logger — that stream is
		// typically shipped to a SIEM / log aggregator and persisted. Log only a
		// short, non-sensitive preview for correlation, and print the full token
		// once to stderr so the operator can copy it on first start.
		logger.Warn("auth: no bearer token configured, generated a random one",
			slog.String("token_preview", tokenPreview(token)),
			slog.String("note", "full token printed once to stderr; set alerting/auth token in config to suppress"))
		fmt.Fprintf(os.Stderr,
			"\n=== ebpf-guard: generated bearer token (shown once) ===\n%s\nUse this token for Prometheus scraping and API access. Configure it explicitly to stop auto-generation.\n\n",
			token)
	} else {
		logger.Info("auth: bearer token configured from config file")
	}

	return token, true
}

// BearerTokenMiddleware creates middleware that validates Bearer token.
// Kept for backward compatibility and simple single-token use cases.
func BearerTokenMiddleware(token string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip auth for health endpoints
			if strings.HasPrefix(r.URL.Path, "/health") {
				next.ServeHTTP(w, r)
				return
			}

			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "Unauthorized: missing Authorization header", http.StatusUnauthorized)
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				http.Error(w, "Unauthorized: invalid Authorization format", http.StatusUnauthorized)
				return
			}

			if subtle.ConstantTimeCompare([]byte(parts[1]), []byte(token)) != 1 {
				http.Error(w, "Unauthorized: invalid token", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// viewerPrefixes lists URL path prefixes that viewer-role tokens may access via GET.
// Static UI/doc assets are not listed here — they are served publicly (see
// publicAssetPrefixes / publicAssetPaths) so a browser can load the HTML shell
// before it has a token to attach. All alert *data* stays under /api/v1/*.
var viewerPrefixes = []string{
	"/metrics",
	"/api/v1/alerts",
	"/api/v1/rules",
	"/api/v1/status",
	"/api/v1/summary",
	"/api/v1/feedback",
	"/api/v1/incidents",
}

// publicAssetPrefixes lists path prefixes served WITHOUT authentication. These
// hold only static, data-free assets — the embedded dashboard (HTML/JS/CSS) and
// the Swagger UI bundle. A browser navigating to /ui/ cannot send an
// Authorization header on the initial navigation, so the shell must load
// unauthenticated; the JS then prompts for a token and attaches it to every
// /api/v1/* fetch, which remain behind auth.
var publicAssetPrefixes = []string{
	"/ui/",
	"/swaggerui/",
}

// publicAssetPaths lists exact paths served without authentication: the root
// redirect to /ui/, the bare /ui (redirected to /ui/ by the mux), and the
// OpenAPI docs page + spec, which contain no alert data.
var publicAssetPaths = map[string]struct{}{
	"/":                 {},
	"/ui":               {},
	"/api/docs":         {},
	"/api/openapi.yaml": {},
}

// isPublicAsset reports whether path may be served without a bearer token.
// Only static assets qualify; every /api/v1/* data endpoint stays authenticated.
func isPublicAsset(path string) bool {
	if _, ok := publicAssetPaths[path]; ok {
		return true
	}
	for _, prefix := range publicAssetPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// isViewerAllowed returns true when the viewer role may access the given method+path.
// Viewers are restricted to GET requests on the read-only endpoints listed in viewerPrefixes.
func isViewerAllowed(method, path string) bool {
	if method != http.MethodGet && method != http.MethodHead {
		return false
	}
	for _, prefix := range viewerPrefixes {
		if path == prefix || strings.HasPrefix(path, prefix+"/") || strings.HasPrefix(path, prefix+"?") {
			return true
		}
	}
	return false
}

// corsMiddleware adds CORS headers to the read-only /api/v1/* endpoints
// (status, summary, alerts, incidents, rules, feedback) so a fleet dashboard
// running on one agent's origin can poll other agents directly from the
// browser (issue #312). It never touches write endpoints — those stay
// same-origin only. Preflight OPTIONS requests are answered here, before the
// RBAC middleware runs, since a browser preflight never carries the
// Authorization header the RBAC check requires.
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isViewerAllowed(http.MethodGet, r.URL.Path) {
			s.applyCORSHeaders(w, r)
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// applyCORSHeaders sets Access-Control-Allow-Origin (and, when a header was
// set, the accompanying Allow-Methods/Allow-Headers) based on the configured
// allowlist. A request with no Origin header (same-origin, curl, Prometheus
// scraping) is left untouched.
func (s *Server) applyCORSHeaders(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return
	}
	s.mu.RLock()
	origins := s.corsAllowedOrigins
	s.mu.RUnlock()

	for _, allowed := range origins {
		if allowed == "*" {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			break
		}
		if allowed == origin {
			// Reflect the specific origin and add Vary: Origin to prevent
			// proxy cache poisoning when responses differ by origin.
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			break
		}
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	}
}

// extractBearerToken parses the Authorization header and returns the bearer token.
// Returns ("", false) if the header is missing or malformed.
func extractBearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", false
	}
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", false
	}
	return parts[1], true
}

// MultiTenantRBACMiddleware enforces namespace-scoped RBAC using a list of named tokens.
// Each token carries its own role and namespace allowlist. The resolved TokenScope is
// injected into the request context so downstream handlers can apply namespace filters.
//
// Health endpoints are always public. Returns 401 on missing/invalid token, 403 when
// the role is insufficient for the requested operation.
func MultiTenantRBACMiddleware(tokens []NamespacedToken) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path

			if strings.HasPrefix(path, "/health") {
				next.ServeHTTP(w, r)
				return
			}

			// Static UI/doc assets are public so a browser can load the shell
			// before it has a token; the data API below stays authenticated.
			if isPublicAsset(path) {
				next.ServeHTTP(w, r)
				return
			}

			bearerToken, ok := extractBearerToken(r)
			if !ok {
				http.Error(w, "Unauthorized: missing or malformed Authorization header", http.StatusUnauthorized)
				return
			}

			var matched *NamespacedToken
			for i := range tokens {
				if subtle.ConstantTimeCompare([]byte(bearerToken), []byte(tokens[i].Token)) == 1 {
					matched = &tokens[i]
					break
				}
			}
			if matched == nil {
				http.Error(w, "Unauthorized: invalid token", http.StatusUnauthorized)
				return
			}

			scope := TokenScope{Role: matched.Role, Namespaces: matched.Namespaces}

			if scope.Role != RoleAdmin && !isViewerAllowed(r.Method, path) {
				http.Error(w, "Forbidden: viewer role does not permit this operation", http.StatusForbidden)
				return
			}

			ctx := context.WithValue(r.Context(), tokenScopeKey{}, scope)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RBACMiddleware creates middleware that enforces two-role RBAC:
//   - viewer: GET /alerts, GET /rules, GET /health, GET /metrics (and sub-paths)
//   - admin:  all endpoints including write operations
//
// Health endpoints (/health, /health/ready, /health/live) are always public.
// Returns 401 when no valid token is present, 403 when the token's role is insufficient.
func RBACMiddleware(viewerToken, adminToken string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path

			// Health probes are always public — Kubernetes needs them without auth.
			if strings.HasPrefix(path, "/health") {
				next.ServeHTTP(w, r)
				return
			}

			// Static UI/doc assets are public so a browser can load the shell
			// before it has a token; the data API below stays authenticated.
			if isPublicAsset(path) {
				next.ServeHTTP(w, r)
				return
			}

			token, ok := extractBearerToken(r)
			if !ok {
				http.Error(w, "Unauthorized: missing or malformed Authorization header", http.StatusUnauthorized)
				return
			}

			// Determine role by constant-time token comparison.
			var role Role
			if adminToken != "" && subtle.ConstantTimeCompare([]byte(token), []byte(adminToken)) == 1 {
				role = RoleAdmin
			} else if viewerToken != "" && subtle.ConstantTimeCompare([]byte(token), []byte(viewerToken)) == 1 {
				role = RoleViewer
			} else {
				http.Error(w, "Unauthorized: invalid token", http.StatusUnauthorized)
				return
			}

			// Admin may access everything.
			if role == RoleAdmin {
				ctx := context.WithValue(r.Context(), tokenScopeKey{}, TokenScope{Role: RoleAdmin})
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// Viewer is restricted to read-only endpoints.
			if !isViewerAllowed(r.Method, path) {
				http.Error(w, "Forbidden: viewer role does not permit this operation", http.StatusForbidden)
				return
			}

			ctx := context.WithValue(r.Context(), tokenScopeKey{}, TokenScope{Role: RoleViewer})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
