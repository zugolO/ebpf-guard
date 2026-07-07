//go:build !rego

package admission

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ── NewServer ─────────────────────────────────────────────────────────────────

func TestNewServer_Defaults(t *testing.T) {
	srv, err := NewServer(Config{}, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	if srv == nil {
		t.Fatal("NewServer returned nil server")
	}
	if srv.config.WebhookPath != "/admission" {
		t.Errorf("WebhookPath = %q, want /admission", srv.config.WebhookPath)
	}
	if srv.config.Mode != "warn" {
		t.Errorf("Mode = %q, want warn", srv.config.Mode)
	}
	if srv.config.BindAddress != ":8443" {
		t.Errorf("BindAddress = %q, want :8443", srv.config.BindAddress)
	}
	if srv.logger == nil {
		t.Error("logger should default to slog.Default() when nil is passed")
	}
}

func TestNewServer_PreservesExplicitConfig(t *testing.T) {
	cfg := Config{
		Mode:        "enforce",
		WebhookPath: "/custom",
		BindAddress: ":9443",
		RegoDir:     "/some/dir",
	}
	srv, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	if srv.config.WebhookPath != "/custom" {
		t.Errorf("WebhookPath = %q, want /custom", srv.config.WebhookPath)
	}
	if srv.config.Mode != "enforce" {
		t.Errorf("Mode = %q, want enforce", srv.config.Mode)
	}
	if srv.config.BindAddress != ":9443" {
		t.Errorf("BindAddress = %q, want :9443", srv.config.BindAddress)
	}
	if srv.config.RegoDir != "/some/dir" {
		t.Errorf("RegoDir = %q, want /some/dir", srv.config.RegoDir)
	}
}

// ── Start / Shutdown ──────────────────────────────────────────────────────────

func TestServer_Start_ReturnsError(t *testing.T) {
	srv, err := NewServer(Config{}, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}

	err = srv.Start(context.Background())
	if err == nil {
		t.Fatal("Start() should return an error in the stub build")
	}
}

func TestServer_Shutdown_NoOp(t *testing.T) {
	srv, err := NewServer(Config{}, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}

	if err := srv.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown() should always return nil, got: %v", err)
	}

	// Also verify Shutdown respects an already-cancelled context by still
	// returning nil (it never inspects the context in the stub).
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	<-ctx.Done()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() with expired context should still return nil, got: %v", err)
	}
}

// ── HandleAdmission ───────────────────────────────────────────────────────────

func TestServer_HandleAdmission_AlwaysAllows(t *testing.T) {
	srv, err := NewServer(Config{}, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/admission", nil)
	rec := httptest.NewRecorder()

	srv.HandleAdmission(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var review AdmissionReview
	if err := json.NewDecoder(rec.Body).Decode(&review); err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}
	if review.APIVersion != "admission.k8s.io/v1" {
		t.Errorf("APIVersion = %q, want admission.k8s.io/v1", review.APIVersion)
	}
	if review.Kind != "AdmissionReview" {
		t.Errorf("Kind = %q, want AdmissionReview", review.Kind)
	}
	if review.Response == nil {
		t.Fatal("Response should not be nil")
	}
	if !review.Response.Allowed {
		t.Error("stub HandleAdmission must always allow")
	}
	if review.Response.UID != "stub" {
		t.Errorf("Response.UID = %q, want stub", review.Response.UID)
	}
}

func TestServer_HandleAdmission_IgnoresMethodAndBody(t *testing.T) {
	// The stub does not even look at the request — verify it behaves the
	// same regardless of method or body content, unlike the real webhook.
	srv, err := NewServer(Config{}, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}

	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut} {
		req := httptest.NewRequest(method, "/admission", nil)
		rec := httptest.NewRecorder()
		srv.HandleAdmission(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("method %s: status = %d, want %d", method, rec.Code, http.StatusOK)
		}
	}
}

// ── HandleHealth ──────────────────────────────────────────────────────────────

func TestServer_HandleHealth(t *testing.T) {
	srv, err := NewServer(Config{}, nil)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	srv.HandleHealth(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	body := rec.Body.String()
	var parsed map[string]string
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("failed to decode health body %q: %v", body, err)
	}
	if parsed["status"] != "healthy" {
		t.Errorf("status field = %q, want healthy", parsed["status"])
	}
	if parsed["rego"] != "disabled" {
		t.Errorf("rego field = %q, want disabled", parsed["rego"])
	}
}
