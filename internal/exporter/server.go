// Package exporter provides Prometheus metrics and Alertmanager alerting.
package exporter

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/pprof"
	"sync"
	"time"

	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/internal/explainer"
	"github.com/zugolO/ebpf-guard/internal/feedback"
	"github.com/zugolO/ebpf-guard/internal/store"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// CollectorStatus tracks the status of a collector.
type CollectorStatus struct {
	Name    string `json:"name"`
	Healthy bool   `json:"healthy"`
	Error   string `json:"error,omitempty"`
}

// Server provides HTTP endpoints for metrics and health checks.
type Server struct {
	bindAddress string
	metricsPath string
	healthPath  string
	server      *http.Server
	mux         *http.ServeMux // retained for post-construction route registration
	mu          sync.RWMutex
	logger      *slog.Logger

	// Health state
	healthy            bool
	ready              bool
	startTime          time.Time
	collectorStatuses  map[string]CollectorStatus
	requiredCollectors map[string]bool // names that must be healthy for /health/ready → 200

	// Debug handler (optional)
	debugHandler *DebugHandler

	// Alert store for REST API
	alertStore store.AlertStore

	// Rules provider for REST API
	rulesProviderFn func() []correlator.Rule

	// Rules reload handler
	rulesReloadFn func() error

	// feedbackManager handles false-positive feedback from analysts (optional).
	feedbackManager *feedback.Manager

	// alertExplainer generates human-readable explanations for alerts (optional).
	alertExplainer *explainer.Explainer

	// incidentTracker exposes the engine's incident grouping state (optional).
	incidentTracker *correlator.IncidentTracker
}

// NewServer creates a new HTTP server for metrics and health.
func NewServer(bindAddress, metricsPath, healthPath string) *Server {
	return NewServerWithPprof(bindAddress, metricsPath, healthPath, false)
}

// NewServerWithPprof creates a new HTTP server with optional pprof endpoints.
func NewServerWithPprof(bindAddress, metricsPath, healthPath string, enablePprof bool) *Server {
	return NewServerWithOptions(bindAddress, metricsPath, healthPath, enablePprof, false)
}

// NewServerWithOptions creates a new HTTP server with optional pprof and debug endpoints.
func NewServerWithOptions(bindAddress, metricsPath, healthPath string, enablePprof, enableDebug bool) *Server {
	return NewServerWithAuth(bindAddress, metricsPath, healthPath, enablePprof, enableDebug, "", false)
}

// NewServerWithAuth creates a new HTTP server with authentication support.
// The provided authToken is treated as an admin token; viewer access is not separately restricted.
// For two-role RBAC use NewServerWithRBAC.
func NewServerWithAuth(bindAddress, metricsPath, healthPath string, enablePprof, enableDebug bool, authToken string, authEnabled bool) *Server {
	return NewServerWithRBAC(bindAddress, metricsPath, healthPath, enablePprof, enableDebug, "", authToken, authEnabled)
}

// NewServerWithMultiTenant creates a new HTTP server with namespace-scoped RBAC.
// Each token in the tokens slice carries its own role and namespace allowlist.
// The legacy viewerToken/adminToken are also accepted if non-empty.
// Pass authEnabled=false to skip auth entirely.
func NewServerWithMultiTenant(bindAddress, metricsPath, healthPath string, enablePprof, enableDebug bool, tokens []NamespacedToken, viewerToken, adminToken string, authEnabled bool) *Server {
	if metricsPath == "" {
		metricsPath = "/metrics"
	}
	if healthPath == "" {
		healthPath = "/health"
	}

	s := &Server{
		bindAddress:       bindAddress,
		metricsPath:       metricsPath,
		healthPath:        healthPath,
		healthy:           true,
		ready:             false,
		startTime:         time.Now(),
		collectorStatuses: make(map[string]CollectorStatus),
		logger:            slog.Default(),
	}

	mux := http.NewServeMux()
	s.mux = mux
	mux.Handle(metricsPath, promhttp.Handler())
	mux.HandleFunc(healthPath, s.handleHealth)
	mux.HandleFunc(healthPath+"/ready", s.handleReady)
	mux.HandleFunc(healthPath+"/live", s.handleLive)

	if enablePprof {
		slog.Info("exporter/server: enabling pprof endpoints at /debug/pprof")
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
		mux.Handle("/debug/pprof/allocs", pprof.Handler("allocs"))
		mux.Handle("/debug/pprof/block", pprof.Handler("block"))
		mux.Handle("/debug/pprof/goroutine", pprof.Handler("goroutine"))
		mux.Handle("/debug/pprof/heap", pprof.Handler("heap"))
		mux.Handle("/debug/pprof/mutex", pprof.Handler("mutex"))
		mux.Handle("/debug/pprof/threadcreate", pprof.Handler("threadcreate"))
	}

	if enableDebug {
		slog.Info("exporter/server: enabling debug endpoints at /debug/state")
		s.debugHandler = NewDebugHandler("dev", s)
		mux.HandleFunc("/debug/state", s.debugHandler.ServeHTTP)
	}

	s.RegisterAPIRoutes(mux)

	handler := http.Handler(mux)
	if authEnabled {
		// Build the combined token list from legacy tokens + namespaced tokens.
		all := make([]NamespacedToken, 0, len(tokens)+2)
		if adminToken != "" {
			all = append(all, NamespacedToken{Token: adminToken, Role: RoleAdmin})
		}
		if viewerToken != "" {
			all = append(all, NamespacedToken{Token: viewerToken, Role: RoleViewer})
		}
		all = append(all, tokens...)
		if len(all) > 0 {
			slog.Info("exporter/server: enabling multi-tenant RBAC",
				slog.Int("token_count", len(all)))
			handler = MultiTenantRBACMiddleware(all)(mux)
		}
	}

	s.server = &http.Server{
		Addr:         bindAddress,
		Handler:      handler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	return s
}

// NewServerWithRBAC creates a new HTTP server with two-role RBAC authentication:
//   - viewerToken: grants GET access to /alerts, /rules, /health, /metrics
//   - adminToken:  grants full access including write operations
//
// Pass empty strings to disable a role. Pass authEnabled=false to skip auth entirely.
func NewServerWithRBAC(bindAddress, metricsPath, healthPath string, enablePprof, enableDebug bool, viewerToken, adminToken string, authEnabled bool) *Server {
	if metricsPath == "" {
		metricsPath = "/metrics"
	}
	if healthPath == "" {
		healthPath = "/health"
	}

	s := &Server{
		bindAddress:       bindAddress,
		metricsPath:       metricsPath,
		healthPath:        healthPath,
		healthy:           true,
		ready:             false,
		startTime:         time.Now(),
		collectorStatuses: make(map[string]CollectorStatus),
		logger:            slog.Default(),
	}

	mux := http.NewServeMux()
	s.mux = mux
	mux.Handle(metricsPath, promhttp.Handler())
	mux.HandleFunc(healthPath, s.handleHealth)
	mux.HandleFunc(healthPath+"/ready", s.handleReady)
	mux.HandleFunc(healthPath+"/live", s.handleLive)

	// Register pprof endpoints if enabled
	if enablePprof {
		slog.Info("exporter/server: enabling pprof endpoints at /debug/pprof")
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
		mux.Handle("/debug/pprof/allocs", pprof.Handler("allocs"))
		mux.Handle("/debug/pprof/block", pprof.Handler("block"))
		mux.Handle("/debug/pprof/goroutine", pprof.Handler("goroutine"))
		mux.Handle("/debug/pprof/heap", pprof.Handler("heap"))
		mux.Handle("/debug/pprof/mutex", pprof.Handler("mutex"))
		mux.Handle("/debug/pprof/threadcreate", pprof.Handler("threadcreate"))
	}

	// Register debug endpoints if enabled
	if enableDebug {
		slog.Info("exporter/server: enabling debug endpoints at /debug/state")
		// Debug handler will be registered later via SetDebugHandler
		s.debugHandler = NewDebugHandler("dev", s)
		mux.HandleFunc("/debug/state", s.debugHandler.ServeHTTP)
	}

	// Register REST API routes
	s.RegisterAPIRoutes(mux)

	// Apply RBAC middleware if auth is enabled and at least one token is configured.
	handler := http.Handler(mux)
	if authEnabled && (viewerToken != "" || adminToken != "") {
		slog.Info("exporter/server: enabling RBAC authentication",
			slog.Bool("viewer_role", viewerToken != ""),
			slog.Bool("admin_role", adminToken != ""))
		handler = RBACMiddleware(viewerToken, adminToken)(mux)
	}

	s.server = &http.Server{
		Addr:         bindAddress,
		Handler:      handler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	return s
}

// RegisterGossipRoutes mounts the provided handler under /gossip/ on the
// server's internal mux. Must be called before Start.
func (s *Server) RegisterGossipRoutes(h http.Handler) {
	if s.mux == nil {
		return
	}
	s.mux.Handle("/gossip/", h)
}

// Start starts the HTTP server in a goroutine.
// It also launches the anomaly score cardinality cleanup goroutine so stale
// per-PID Prometheus label sets are removed before they cause OOM.
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	s.ready = true
	s.mu.Unlock()

	go StartAnomalyScoreCleanup(ctx, AnomalyScoreEvictionInterval, 30*time.Minute)
	
	errCh := make(chan error, 1)
	
	go func() {
		slog.Info("exporter/server: starting HTTP server",
			slog.String("address", s.bindAddress),
			slog.String("metrics", s.metricsPath),
			slog.String("health", s.healthPath))
		
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("exporter/server: HTTP server error: %w", err)
		}
	}()
	
	// Wait for context cancellation or server error
	select {
	case <-ctx.Done():
		return s.Shutdown(context.Background())
	case err := <-errCh:
		return err
	}
}

// Shutdown gracefully shuts down the HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.healthy = false
	s.ready = false
	s.mu.Unlock()
	
	slog.Info("exporter/server: shutting down HTTP server")
	
	shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	
	return s.server.Shutdown(shutdownCtx)
}

// SetHealthy sets the health status.
func (s *Server) SetHealthy(healthy bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.healthy = healthy
}

// SetReady sets the readiness status.
func (s *Server) SetReady(ready bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ready = ready
}

// SetCollectorStatus sets the status for a specific collector.
func (s *Server) SetCollectorStatus(status CollectorStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.collectorStatuses[status.Name] = status
}

// SetRequiredCollectors declares which collectors must be healthy for the
// /health/ready endpoint to return 200. Call before Start.
func (s *Server) SetRequiredCollectors(names []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requiredCollectors = make(map[string]bool, len(names))
	for _, n := range names {
		s.requiredCollectors[n] = true
	}
}

// SetRequired is an alias for SetRequiredCollectors.
func (s *Server) SetRequired(names []string) { s.SetRequiredCollectors(names) }

// SetAlertStore sets the alert store for REST API access.
func (s *Server) SetAlertStore(st store.AlertStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.alertStore = st
}

// SetFeedbackManager wires the feedback manager so POST /api/v1/alerts/{id}/feedback
// is handled. Must be called before the server starts.
func (s *Server) SetFeedbackManager(fm *feedback.Manager) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.feedbackManager = fm
}

// SetIncidentTracker wires the incident tracker so GET /api/v1/incidents is served.
func (s *Server) SetIncidentTracker(t *correlator.IncidentTracker) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.incidentTracker = t
}

// SetExplainer wires an Explainer so GET /api/v1/alerts/{id}/explain is served.
// Must be called before Start.
func (s *Server) SetExplainer(e *explainer.Explainer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.alertExplainer = e
}

// SetupExplainer creates an Explainer from templatesDir and wires it to the server.
// If templatesDir is empty or missing, the explainer falls back to built-in templates.
// Call before Start to enable GET /api/v1/alerts/{id}/explain.
func (s *Server) SetupExplainer(templatesDir string) error {
	var exp *explainer.Explainer
	var err error
	if templatesDir == "" {
		exp, err = explainer.NewWithDefaults()
	} else {
		exp, err = explainer.New(templatesDir)
	}
	if err != nil {
		return fmt.Errorf("exporter: create explainer: %w", err)
	}
	s.SetExplainer(exp)
	s.logger.Info("exporter/server: alert explainer configured",
		slog.String("templates_dir", templatesDir))
	return nil
}

// SetupFeedbackManager creates a feedback.Manager, loads any previously persisted
// suppressions from exportPath (empty = in-memory only), and wires it to the server.
// Call before Start to enable the feedback REST endpoints instead of returning 501.
func (s *Server) SetupFeedbackManager(exportPath string) error {
	fm := feedback.NewManager(exportPath, s.logger)
	if err := fm.LoadFromFile(); err != nil {
		return fmt.Errorf("exporter: load feedback records: %w", err)
	}
	s.SetFeedbackManager(fm)
	s.logger.Info("exporter/server: feedback manager configured",
		slog.String("export_path", exportPath))
	return nil
}

// GetCollectorStatuses returns a copy of all collector statuses.
func (s *Server) GetCollectorStatuses() []CollectorStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	statuses := make([]CollectorStatus, 0, len(s.collectorStatuses))
	for _, status := range s.collectorStatuses {
		statuses = append(statuses, status)
	}
	return statuses
}

// GetDebugHandler returns the debug handler (may be nil if not enabled).
func (s *Server) GetDebugHandler() *DebugHandler {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.debugHandler
}

// AllCollectorsHealthy returns true if all collectors are healthy.
func (s *Server) AllCollectorsHealthy() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	if len(s.collectorStatuses) == 0 {
		return true // No collectors registered yet
	}
	
	for _, status := range s.collectorStatuses {
		if !status.Healthy {
			return false
		}
	}
	return true
}

// handleHealth handles the /health endpoint (comprehensive health check).
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	status := s.getHealthStatus()
	
	w.Header().Set("Content-Type", "application/json")
	
	if !status.Healthy {
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	
	if err := json.NewEncoder(w).Encode(status); err != nil {
		slog.Error("exporter/server: failed to encode health status", slog.Any("error", err))
	}
}

// handleReady handles the /health/ready endpoint (readiness probe).
// Returns 503 only if a required collector is unhealthy or the store is unhealthy.
// Optional collectors may be unhealthy without affecting readiness.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	ready := s.ready
	statuses := make([]CollectorStatus, 0, len(s.collectorStatuses))
	for _, status := range s.collectorStatuses {
		statuses = append(statuses, status)
	}
	alertStore := s.alertStore
	required := s.requiredCollectors
	s.mu.RUnlock()

	// When no required set is configured, all registered collectors are required
	// (preserves the previous behaviour).
	var failedRequired []string
	for _, status := range statuses {
		if status.Healthy {
			continue
		}
		if len(required) == 0 || required[status.Name] {
			failedRequired = append(failedRequired, status.Name)
		}
	}

	// Check store health if configured.
	storeHealthy := true
	if alertStore != nil {
		storeHealthy = alertStore.Healthy(r.Context())
	}

	w.Header().Set("Content-Type", "application/json")

	if ready && len(failedRequired) == 0 && storeHealthy {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":     "ready",
			"collectors": statuses,
			"store":      "healthy",
		})
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		response := map[string]interface{}{
			"status":     "not ready",
			"collectors": statuses,
		}
		if !ready {
			response["reason"] = "server not ready"
		}
		if len(failedRequired) > 0 {
			// "failed_collectors" keeps backward compat; "failed_required_collectors"
			// disambiguates when a required list is explicitly configured.
			response["failed_collectors"] = failedRequired
			if len(required) > 0 {
				response["failed_required_collectors"] = failedRequired
			}
		}
		if !storeHealthy {
			response["store"] = "unhealthy"
		}
		json.NewEncoder(w).Encode(response)
	}
}

// handleLive handles the /health/live endpoint (liveness probe).
func (s *Server) handleLive(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	healthy := s.healthy
	s.mu.RUnlock()
	
	if healthy {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("alive\n"))
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("unhealthy\n"))
	}
}

// HealthStatus represents the health check response.
type HealthStatus struct {
	Healthy   bool          `json:"healthy"`
	Ready     bool          `json:"ready"`
	Uptime    time.Duration `json:"uptime"`
	Timestamp time.Time     `json:"timestamp"`
}

// getHealthStatus returns the current health status.
func (s *Server) getHealthStatus() HealthStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	return HealthStatus{
		Healthy:   s.healthy,
		Ready:     s.ready,
		Uptime:    time.Since(s.startTime),
		Timestamp: time.Now(),
	}
}
