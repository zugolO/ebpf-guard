//go:build !rego

// Package admission provides a stub admission webhook when the rego build tag is not set.
package admission

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
)

// AdmissionReview is a subset of the Kubernetes AdmissionReview API object.
type AdmissionReview struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Request    *AdmissionRequest `json:"request,omitempty"`
	Response   *AdmissionResponse `json:"response,omitempty"`
}

// AdmissionRequest contains the object to be admitted.
type AdmissionRequest struct {
	UID       string          `json:"uid"`
	Kind      GroupVersionKind `json:"kind"`
	Resource  GroupVersionResource `json:"resource"`
	Namespace string          `json:"namespace"`
	Operation string          `json:"operation"`
	Object    json.RawMessage `json:"object"`
}

// GroupVersionKind identifies a Kubernetes resource kind.
type GroupVersionKind struct {
	Group   string `json:"group"`
	Version string `json:"version"`
	Kind    string `json:"kind"`
}

// GroupVersionResource identifies a Kubernetes resource type.
type GroupVersionResource struct {
	Group    string `json:"group"`
	Version  string `json:"version"`
	Resource string `json:"resource"`
}

// AdmissionResponse carries the webhook decision.
type AdmissionResponse struct {
	UID     string `json:"uid"`
	Allowed bool   `json:"allowed"`
	Result  *Status `json:"status,omitempty"`
	// Warnings lists advisory messages returned to the client even when allowed.
	Warnings []string `json:"warnings,omitempty"`
}

// Status is a simplified Kubernetes Status object.
type Status struct {
	Code    int32  `json:"code"`
	Message string `json:"message"`
}

// Config holds admission webhook configuration.
type Config struct {
	Mode            string
	FailurePolicy   string
	TLSCertFile     string
	TLSKeyFile      string
	TLSAutoGenerate bool
	WebhookPath     string
	BindAddress     string
	RegoDir         string
}

// Server is a stub admission webhook server.
type Server struct {
	config Config
	logger *slog.Logger
}

// NewServer creates a stub admission server. Rego policy evaluation requires
// building with -tags rego. All admission requests are allowed.
func NewServer(cfg Config, logger *slog.Logger) (*Server, error) {
	if logger == nil {
		logger = slog.Default()
	}
	logger.Warn("admission: rego build tag not set — install with -tags rego for admission webhook support")
	if cfg.WebhookPath == "" {
		cfg.WebhookPath = "/admission"
	}
	if cfg.Mode == "" {
		cfg.Mode = "warn"
	}
	if cfg.BindAddress == "" {
		cfg.BindAddress = ":8443"
	}
	return &Server{config: cfg, logger: logger}, nil
}

// Start is a no-op in the stub.
func (s *Server) Start(_ context.Context) error {
	s.logger.Warn("admission: server start skipped — rego build tag not set, use -tags rego")
	return fmt.Errorf("admission: rego build tag not set, use -tags rego")
}

// Shutdown is a no-op in the stub.
func (s *Server) Shutdown(_ context.Context) error { return nil }

// HandleAdmission is a stub that always allows admission.
func (s *Server) HandleAdmission(w http.ResponseWriter, r *http.Request) {
	s.handleAdmission(w, r)
}

func (s *Server) handleAdmission(w http.ResponseWriter, _ *http.Request) {
	response := AdmissionReview{
		APIVersion: "admission.k8s.io/v1",
		Kind:       "AdmissionReview",
		Response: &AdmissionResponse{
			UID:     "stub",
			Allowed: true,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.logger.Error("admission: failed to encode response", slog.Any("error", err))
	}
}

// HandleHealth returns a stub health check.
func (s *Server) HandleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"healthy","rego":"disabled"}`))
}
