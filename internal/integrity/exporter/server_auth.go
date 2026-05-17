// Package exporter provides HTTP server with optional authentication.
package exporter

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

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
		logger.Warn("auth: no bearer token configured, generated random token",
			slog.String("token", token),
			slog.String("note", "use this token for Prometheus scraping and API access"))
	} else {
		logger.Info("auth: bearer token configured from config file")
	}

	return token, true
}

// BearerTokenMiddleware creates middleware that validates Bearer token.
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
