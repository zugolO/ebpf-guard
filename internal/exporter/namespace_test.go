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

// --- TokenScope tests ---

func TestTokenScope_AllowsNamespace(t *testing.T) {
	cases := []struct {
		name       string
		namespaces []string
		query      string
		want       bool
	}{
		{"empty=all", nil, "any-ns", true},
		{"wildcard", []string{"*"}, "any-ns", true},
		{"exact match", []string{"team-a"}, "team-a", true},
		{"no match", []string{"team-a"}, "team-b", false},
		{"multi match first", []string{"team-a", "team-b"}, "team-a", true},
		{"multi match second", []string{"team-a", "team-b"}, "team-b", true},
		{"multi no match", []string{"team-a", "team-b"}, "team-c", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scope := TokenScope{Namespaces: tc.namespaces}
			assert.Equal(t, tc.want, scope.AllowsNamespace(tc.query))
		})
	}
}

func TestTokenScopeFromContext_Missing(t *testing.T) {
	_, ok := TokenScopeFromContext(context.Background())
	assert.False(t, ok)
}

func TestTokenScopeFromContext_Present(t *testing.T) {
	scope := TokenScope{Role: RoleViewer, Namespaces: []string{"team-a"}}
	ctx := context.WithValue(context.Background(), tokenScopeKey{}, scope)
	got, ok := TokenScopeFromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, scope, got)
}

// --- applyNamespaceScope tests ---

func TestApplyNamespaceScope_NoScope(t *testing.T) {
	filters := store.QueryFilters{Namespace: "team-x"}
	got, err := applyNamespaceScope(context.Background(), filters)
	require.NoError(t, err)
	assert.Equal(t, "team-x", got.Namespace)
}

func TestApplyNamespaceScope_GlobalToken(t *testing.T) {
	scope := TokenScope{Role: RoleAdmin, Namespaces: nil}
	ctx := context.WithValue(context.Background(), tokenScopeKey{}, scope)
	filters := store.QueryFilters{}
	got, err := applyNamespaceScope(ctx, filters)
	require.NoError(t, err)
	assert.Empty(t, got.Namespace)
	assert.Empty(t, got.Namespaces)
}

func TestApplyNamespaceScope_SingleNamespace_Injected(t *testing.T) {
	scope := TokenScope{Role: RoleViewer, Namespaces: []string{"team-a"}}
	ctx := context.WithValue(context.Background(), tokenScopeKey{}, scope)
	filters := store.QueryFilters{}
	got, err := applyNamespaceScope(ctx, filters)
	require.NoError(t, err)
	assert.Equal(t, "team-a", got.Namespace)
}

func TestApplyNamespaceScope_MultiNamespace_Injected(t *testing.T) {
	scope := TokenScope{Role: RoleViewer, Namespaces: []string{"team-a", "team-b"}}
	ctx := context.WithValue(context.Background(), tokenScopeKey{}, scope)
	filters := store.QueryFilters{}
	got, err := applyNamespaceScope(ctx, filters)
	require.NoError(t, err)
	assert.Empty(t, got.Namespace)
	assert.Equal(t, []string{"team-a", "team-b"}, got.Namespaces)
}

func TestApplyNamespaceScope_AllowedNamespaceRequested(t *testing.T) {
	scope := TokenScope{Role: RoleViewer, Namespaces: []string{"team-a", "team-b"}}
	ctx := context.WithValue(context.Background(), tokenScopeKey{}, scope)
	filters := store.QueryFilters{Namespace: "team-a"}
	got, err := applyNamespaceScope(ctx, filters)
	require.NoError(t, err)
	assert.Equal(t, "team-a", got.Namespace)
}

func TestApplyNamespaceScope_ForbiddenNamespaceRequested(t *testing.T) {
	scope := TokenScope{Role: RoleViewer, Namespaces: []string{"team-a"}}
	ctx := context.WithValue(context.Background(), tokenScopeKey{}, scope)
	filters := store.QueryFilters{Namespace: "team-b"}
	_, err := applyNamespaceScope(ctx, filters)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "team-b")
}

func TestApplyNamespaceScope_WildcardToken(t *testing.T) {
	scope := TokenScope{Role: RoleAdmin, Namespaces: []string{"*"}}
	ctx := context.WithValue(context.Background(), tokenScopeKey{}, scope)
	filters := store.QueryFilters{Namespace: "any-team"}
	got, err := applyNamespaceScope(ctx, filters)
	require.NoError(t, err)
	assert.Equal(t, "any-team", got.Namespace)
}

// --- MultiTenantRBACMiddleware tests ---

func TestMultiTenantRBAC_NoToken(t *testing.T) {
	tokens := []NamespacedToken{
		{Token: "tok-admin", Role: RoleAdmin},
	}
	mw := MultiTenantRBACMiddleware(tokens)(okHandler)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, rbacRequest(http.MethodGet, "/api/v1/alerts", ""))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMultiTenantRBAC_InvalidToken(t *testing.T) {
	tokens := []NamespacedToken{
		{Token: "tok-admin", Role: RoleAdmin},
	}
	mw := MultiTenantRBACMiddleware(tokens)(okHandler)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, rbacRequest(http.MethodGet, "/api/v1/alerts", "wrong"))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMultiTenantRBAC_HealthPublic(t *testing.T) {
	tokens := []NamespacedToken{{Token: "tok-admin", Role: RoleAdmin}}
	mw := MultiTenantRBACMiddleware(tokens)(okHandler)
	for _, path := range []string{"/health", "/health/ready", "/health/live"} {
		w := httptest.NewRecorder()
		mw.ServeHTTP(w, rbacRequest(http.MethodGet, path, ""))
		assert.Equal(t, http.StatusOK, w.Code, path)
	}
}

func TestMultiTenantRBAC_ViewerForbiddenOnWrite(t *testing.T) {
	tokens := []NamespacedToken{
		{Token: "tok-viewer", Role: RoleViewer, Namespaces: []string{"team-a"}},
	}
	mw := MultiTenantRBACMiddleware(tokens)(okHandler)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, rbacRequest(http.MethodPost, "/api/v1/rules/reload", "tok-viewer"))
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestMultiTenantRBAC_ScopeInjectedInContext(t *testing.T) {
	var capturedScope TokenScope
	var scopeOK bool
	capture := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedScope, scopeOK = TokenScopeFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	tokens := []NamespacedToken{
		{Token: "tok-viewer", Role: RoleViewer, Namespaces: []string{"team-a", "team-b"}},
	}
	mw := MultiTenantRBACMiddleware(tokens)(capture)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, rbacRequest(http.MethodGet, "/api/v1/alerts", "tok-viewer"))

	assert.Equal(t, http.StatusOK, w.Code)
	require.True(t, scopeOK)
	assert.Equal(t, RoleViewer, capturedScope.Role)
	assert.Equal(t, []string{"team-a", "team-b"}, capturedScope.Namespaces)
}

// --- Integration: GET /alerts with namespace enforcement ---

func TestHandleAlerts_NamespaceEnforcement(t *testing.T) {
	ms := store.NewMemoryStore()
	ctx := context.Background()

	// Store alerts from two namespaces.
	for _, ns := range []string{"team-a", "team-b"} {
		_ = ms.Store(ctx, types.Alert{
			ID:        "alert-" + ns,
			Timestamp: time.Now(),
			RuleID:    "rule_001",
			Severity:  types.SeverityWarning,
			Enrichment: types.EnrichmentInfo{Namespace: ns},
		})
	}

	// Token scoped to team-a only.
	tokens := []NamespacedToken{
		{Token: "tok-a", Role: RoleViewer, Namespaces: []string{"team-a"}},
		{Token: "tok-admin", Role: RoleAdmin},
	}
	srv := NewServerWithMultiTenant("", "/metrics", "/health", false, false, tokens, "", "", true)
	srv.SetAlertStore(ms)

	// Viewer token for team-a should return only team-a alert.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/alerts", nil)
	req.Header.Set("Authorization", "Bearer tok-a")
	// Inject scope manually (middleware would normally do this).
	req = req.WithContext(context.WithValue(req.Context(), tokenScopeKey{}, TokenScope{
		Role:       RoleViewer,
		Namespaces: []string{"team-a"},
	}))
	w := httptest.NewRecorder()
	srv.handleAlerts(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var alerts []types.Alert
	require.NoError(t, json.NewDecoder(w.Body).Decode(&alerts))
	require.Len(t, alerts, 1)
	assert.Equal(t, "team-a", alerts[0].Enrichment.Namespace)
}

func TestHandleAlerts_ForbiddenNamespaceParam(t *testing.T) {
	ms := store.NewMemoryStore()
	srv := NewServerWithMultiTenant("", "/metrics", "/health", false, false, nil, "", "", false)
	srv.SetAlertStore(ms)

	// Token scoped to team-a requesting team-b — should be 403.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/alerts?namespace=team-b", nil)
	req = req.WithContext(context.WithValue(req.Context(), tokenScopeKey{}, TokenScope{
		Role:       RoleViewer,
		Namespaces: []string{"team-a"},
	}))
	w := httptest.NewRecorder()
	srv.handleAlerts(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}
