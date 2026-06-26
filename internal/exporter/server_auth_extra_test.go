package exporter

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenPreview(t *testing.T) {
	assert.Equal(t, "********", tokenPreview("short"))
	assert.Equal(t, "abcdefgh…", tokenPreview("abcdefghijklmnop"))
}

func TestGenerateRandomToken(t *testing.T) {
	a, err := GenerateRandomToken()
	require.NoError(t, err)
	assert.Len(t, a, 64) // 32 bytes hex-encoded
	b, err := GenerateRandomToken()
	require.NoError(t, err)
	assert.NotEqual(t, a, b)
}

func TestSetupAuth(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Disabled.
	tok, enabled := SetupAuth(AuthConfig{Enabled: false}, logger)
	assert.Empty(t, tok)
	assert.False(t, enabled)

	// Enabled with explicit token.
	tok, enabled = SetupAuth(AuthConfig{Enabled: true, BearerToken: "secret"}, logger)
	assert.Equal(t, "secret", tok)
	assert.True(t, enabled)

	// Enabled without token → generated.
	tok, enabled = SetupAuth(AuthConfig{Enabled: true}, logger)
	assert.NotEmpty(t, tok)
	assert.True(t, enabled)
}

func TestBearerTokenMiddleware(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mw := BearerTokenMiddleware("good-token")(ok)

	cases := []struct {
		name   string
		path   string
		header string
		want   int
	}{
		{"health bypass", "/health", "", http.StatusOK},
		{"missing header", "/api/v1/alerts", "", http.StatusUnauthorized},
		{"bad format", "/api/v1/alerts", "Token xyz", http.StatusUnauthorized},
		{"wrong token", "/api/v1/alerts", "Bearer nope", http.StatusUnauthorized},
		{"correct token", "/api/v1/alerts", "Bearer good-token", http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			w := httptest.NewRecorder()
			mw.ServeHTTP(w, req)
			assert.Equal(t, tc.want, w.Code)
		})
	}
}

func TestIsViewerAllowed(t *testing.T) {
	assert.True(t, isViewerAllowed(http.MethodGet, "/api/v1/alerts"))
	assert.True(t, isViewerAllowed(http.MethodGet, "/api/v1/alerts/123"))
	assert.False(t, isViewerAllowed(http.MethodPost, "/api/v1/alerts"))
	assert.False(t, isViewerAllowed(http.MethodGet, "/api/v1/admin"))
}
