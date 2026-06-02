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
	healthy           bool
	ready             bool
	startTime         time.Time
	collectorStatuses map[string]CollectorStatus

	// Debug handler (optional)
	debugHandler *DebugHandler

	// Alert store for REST API
	alertStore store.AlertStore

	// Rules provider for REST API
	rulesProviderFn func() []correlator.Rule

	// Rules reload handler
	rulesReloadFn func() error
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
func NewServerWithAuth(bindAddress, metricsPath, healthPath string, enablePprof, enableDebug bool, authToken string, authEnabled bool) *Server {
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

	// Apply auth middleware if enabled
	handler := http.Handler(mux)
	if authEnabled && authToken != "" {
		slog.Info("exporter/server: enabling bearer token authentication")
		handler = BearerTokenMiddleware(authToken)(mux)
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
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	s.ready = true
	s.mu.Unlock()
	
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

// SetAlertStore sets the alert store for REST API access.
func (s *Server) SetAlertStore(st store.AlertStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.alertStore = st
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
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	ready := s.ready
	statuses := make([]CollectorStatus, 0, len(s.collectorStatuses))
	for _, status := range s.collectorStatuses {
		statuses = append(statuses, status)
	}
	alertStore := s.alertStore
	s.mu.RUnlock()
	
	// Check if all collectors are healthy
	allHealthy := true
	var failedCollectors []string
	for _, status := range statuses {
		if !status.Healthy {
			allHealthy = false
			failedCollectors = append(failedCollectors, status.Name)
		}
	}
	
	// Check store health if configured
	storeHealthy := true
	if alertStore != nil {
		storeHealthy = alertStore.Healthy(r.Context())
	}
	
	w.Header().Set("Content-Type", "application/json")
	
	if ready && allHealthy && storeHealthy {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":     "ready",
			"collectors": statuses,
			"store":      "healthy",
		})
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		response := map[string]interface{}{
			"status": "not ready",
		}
		if !ready {
			response["reason"] = "server not ready"
		}
		if !allHealthy {
			response["failed_collectors"] = failedCollectors
			response["collectors"] = statuses
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
