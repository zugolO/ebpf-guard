//go:build rego

// Package admission implements a Kubernetes ValidatingAdmissionWebhook server
// that evaluates pod specs against the same Rego policies used for runtime
// enforcement, providing a pre-deploy enforcement layer.
package admission

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/open-policy-agent/opa/rego"
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
	// Mode is "warn" (allow + annotate warnings) or "enforce" (deny on violations).
	Mode string
	// FailurePolicy controls behaviour when the webhook panics: "Ignore" or "Fail".
	// Note: This is surfaced in the ValidatingWebhookConfiguration, not here.
	FailurePolicy string
	// TLSCertFile is the path to the PEM TLS certificate.
	TLSCertFile string
	// TLSKeyFile is the path to the PEM private key.
	TLSKeyFile string
	// TLSAutoGenerate generates a self-signed cert when cert/key files are empty.
	TLSAutoGenerate bool
	// WebhookPath is the URL path for admission requests.
	WebhookPath string
	// BindAddress is the HTTPS listen address.
	BindAddress string
	// RegoDir is the directory containing Rego policy files.
	RegoDir string
}

// Server is the admission webhook HTTP server.
type Server struct {
	config  Config
	logger  *slog.Logger
	engine  *admissionEngine
	server  *http.Server
	healthy atomic.Bool

	requestsTotal  atomic.Uint64
	allowedTotal   atomic.Uint64
	deniedTotal    atomic.Uint64
	warningsTotal  atomic.Uint64
}

// NewServer creates an admission webhook server, compiling the Rego policies
// from config.RegoDir immediately so startup fails fast on policy errors.
func NewServer(cfg Config, logger *slog.Logger) (*Server, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.WebhookPath == "" {
		cfg.WebhookPath = "/admission"
	}
	if cfg.Mode == "" {
		cfg.Mode = "warn"
	}
	if cfg.BindAddress == "" {
		cfg.BindAddress = ":8443"
	}

	engine, err := newAdmissionEngine(cfg.RegoDir)
	if err != nil {
		return nil, fmt.Errorf("admission: load policies: %w", err)
	}

	s := &Server{
		config: cfg,
		logger: logger,
		engine: engine,
	}
	s.healthy.Store(true)
	return s, nil
}

// Start starts the HTTPS webhook server in the background.
// It returns immediately; use Shutdown to stop.
func (s *Server) Start(ctx context.Context) error {
	tlsCfg, err := s.buildTLS()
	if err != nil {
		return fmt.Errorf("admission: build TLS: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc(s.config.WebhookPath, s.handleAdmission)
	mux.HandleFunc("/healthz", s.handleHealth)

	s.server = &http.Server{
		Addr:         s.config.BindAddress,
		Handler:      mux,
		TLSConfig:    tlsCfg,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		s.logger.Info("admission webhook: starting HTTPS server", "addr", s.config.BindAddress, "mode", s.config.Mode)
		if err := s.server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			s.logger.Error("admission webhook: server error", "error", err)
			s.healthy.Store(false)
		}
	}()
	return nil
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.server == nil {
		return nil
	}
	return s.server.Shutdown(ctx)
}

// HandleAdmission processes an AdmissionReview request.
// Exported so tests and custom muxes can register the handler directly.
func (s *Server) HandleAdmission(w http.ResponseWriter, r *http.Request) {
	s.handleAdmission(w, r)
}

// handleAdmission processes an AdmissionReview request.
func (s *Server) handleAdmission(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var review AdmissionReview
	if err := json.NewDecoder(r.Body).Decode(&review); err != nil {
		http.Error(w, fmt.Sprintf("decode: %v", err), http.StatusBadRequest)
		return
	}
	if review.Request == nil {
		http.Error(w, "missing request", http.StatusBadRequest)
		return
	}

	s.requestsTotal.Add(1)

	resp := s.evaluate(r.Context(), review.Request)
	if resp.Allowed {
		s.allowedTotal.Add(1)
	} else {
		s.deniedTotal.Add(1)
	}
	if len(resp.Warnings) > 0 {
		s.warningsTotal.Add(uint64(len(resp.Warnings)))
	}

	review.Response = resp
	review.Request = nil

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(review); err != nil {
		s.logger.Error("admission webhook: encode response", "error", err)
	}
}

// evaluate runs Rego policies against the pod spec in the request.
func (s *Server) evaluate(ctx context.Context, req *AdmissionRequest) *AdmissionResponse {
	resp := &AdmissionResponse{UID: req.UID, Allowed: true}

	// Only evaluate Pod admission (CREATE and UPDATE).
	if req.Kind.Kind != "Pod" {
		return resp
	}
	if req.Operation != "CREATE" && req.Operation != "UPDATE" {
		return resp
	}

	var podObj map[string]interface{}
	if err := json.Unmarshal(req.Object, &podObj); err != nil {
		s.logger.Warn("admission webhook: unmarshal pod object", "error", err)
		return resp
	}

	input := map[string]interface{}{
		"request": map[string]interface{}{
			"uid":       req.UID,
			"kind":      req.Kind,
			"resource":  req.Resource,
			"namespace": req.Namespace,
			"operation": req.Operation,
			"object":    podObj,
		},
	}

	denials, warnings, err := s.engine.evaluate(ctx, input)
	if err != nil {
		s.logger.Error("admission webhook: policy eval", "error", err)
		// On eval error, allow through (consistent with failurePolicy: Ignore).
		return resp
	}

	resp.Warnings = warnings

	if len(denials) > 0 && strings.EqualFold(s.config.Mode, "enforce") {
		resp.Allowed = false
		resp.Result = &Status{
			Code:    403,
			Message: strings.Join(denials, "; "),
		}
		s.logger.Info("admission webhook: denied pod", "namespace", req.Namespace, "uid", req.UID, "reasons", denials)
	} else if len(denials) > 0 {
		// warn mode: allow but surface denials as warnings too
		resp.Warnings = append(resp.Warnings, denials...)
		s.logger.Info("admission webhook: warn-mode violation", "namespace", req.Namespace, "uid", req.UID, "reasons", denials)
	}

	return resp
}

// HandleHealth returns 200 OK for liveness probes.
// Exported so tests and custom muxes can register the handler directly.
func (s *Server) HandleHealth(w http.ResponseWriter, r *http.Request) {
	s.handleHealth(w, r)
}

// handleHealth returns 200 OK for liveness probes.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	if !s.healthy.Load() {
		http.Error(w, "unhealthy", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// buildTLS builds the TLS configuration from cert/key files or auto-generates.
func (s *Server) buildTLS() (*tls.Config, error) {
	if s.config.TLSAutoGenerate && s.config.TLSCertFile == "" {
		return s.autoGenerateTLS()
	}
	if s.config.TLSCertFile == "" || s.config.TLSKeyFile == "" {
		return nil, fmt.Errorf("tls_cert_file and tls_key_file are required (or set tls_auto_generate: true)")
	}
	cert, err := tls.LoadX509KeyPair(s.config.TLSCertFile, s.config.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS key pair: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// autoGenerateTLS generates a self-signed ECDSA P-256 certificate.
func (s *Server) autoGenerateTLS() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ebpf-guard-admission"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * 365 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// Optionally persist for inspection
	_ = os.WriteFile("/tmp/ebpf-guard-admission.crt", certPEM, 0o600)

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("build key pair: %w", err)
	}
	s.logger.Info("admission webhook: generated self-signed TLS certificate (development only)")
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// ---------------------------------------------------------------------------
// Rego engine
// ---------------------------------------------------------------------------

type admissionEngine struct {
	prepared *rego.PreparedEvalQuery
}

func newAdmissionEngine(regoDir string) (*admissionEngine, error) {
	entries, err := os.ReadDir(regoDir)
	if err != nil {
		if os.IsNotExist(err) {
			return &admissionEngine{}, nil
		}
		return nil, fmt.Errorf("read rego dir %s: %w", regoDir, err)
	}

	opts := []func(*rego.Rego){
		rego.Query("data.ebpf_guard.admission"),
	}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".rego") {
			continue
		}
		content, err := os.ReadFile(fmt.Sprintf("%s/%s", regoDir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", e.Name(), err)
		}
		opts = append(opts, rego.Module(e.Name(), string(content)))
	}

	if len(opts) == 1 {
		// No policy files found — allow all.
		return &admissionEngine{}, nil
	}

	pq, err := rego.New(opts...).PrepareForEval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("compile admission policies: %w", err)
	}
	return &admissionEngine{prepared: &pq}, nil
}

// evaluate returns (denials, warnings, error).
func (e *admissionEngine) evaluate(ctx context.Context, input map[string]interface{}) ([]string, []string, error) {
	if e.prepared == nil {
		return nil, nil, nil
	}

	rs, err := e.prepared.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, nil, err
	}

	var denials, warnings []string
	for _, result := range rs {
		for _, expr := range result.Expressions {
			if expr.Value == nil {
				continue
			}
			ns, ok := expr.Value.(map[string]interface{})
			if !ok {
				continue
			}
			denials = append(denials, extractStringSet(ns["deny"])...)
			warnings = append(warnings, extractStringSet(ns["warn"])...)
		}
	}
	return denials, warnings, nil
}

func extractStringSet(v interface{}) []string {
	if v == nil {
		return nil
	}
	var result []string
	switch typed := v.(type) {
	case []interface{}:
		for _, item := range typed {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
	case map[string]interface{}:
		// OPA sometimes returns sets as maps with empty struct values
		for k := range typed {
			result = append(result, k)
		}
	}
	return result
}
