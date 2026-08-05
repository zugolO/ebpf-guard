// Package exporter provides debug endpoints for operational visibility.
package exporter

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// DebugState represents the current operational state of the agent.
type DebugState struct {
	Timestamp       time.Time            `json:"timestamp"`
	Version         string               `json:"version"`
	Uptime          time.Duration        `json:"uptime"`
	Rules           []RuleState          `json:"rules"`
	ActiveSilences  []SilenceState       `json:"active_silences"`
	EngineStats     EngineStats          `json:"engine_stats"`
	ProfilerStats   ProfilerStats        `json:"profiler_stats"`
	CollectorStats  []CollectorStatus    `json:"collector_stats"`
	EnrichmentStats EnrichmentStats      `json:"enrichment_stats"`
	HardwareProfile HardwareProfileState `json:"hardware_profile"`
}

// HardwareProfileState reports how the hardware-aware tuning profile
// (lite/balanced/production, issue #287) was resolved at startup, and what
// it applied to BPF map sizes and profiler limits.
type HardwareProfileState struct {
	Profile         string `json:"profile"`
	Source          string `json:"source"` // "flag", "config", or "autodetect"
	Reason          string `json:"reason"`
	CPUs            int    `json:"cpus"`
	MemTotalMB      int    `json:"mem_total_mb"`
	EventsMap       int    `json:"bpf_events_map"`
	ProcessesMap    int    `json:"bpf_processes_map"`
	ConnectionsMap  int    `json:"bpf_connections_map"`
	MaxTrackedPIDs  int    `json:"profiler_max_tracked_pids"`
	SequenceEnabled bool   `json:"sequence_profiler_enabled"`
	LineageEnabled  bool   `json:"lineage_tracker_enabled"`
}

// RuleState represents a loaded rule.
type RuleState struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	EventType   string `json:"event_type"`
	Severity    string `json:"severity"`
	Action      string `json:"action"`
	Description string `json:"description,omitempty"`
}

// SilenceState represents an active silence.
type SilenceState struct {
	RuleID    string        `json:"rule_id"`
	Severity  string        `json:"severity,omitempty"`
	Duration  time.Duration `json:"duration"`
	CreatedAt time.Time     `json:"created_at"`
	ExpiresAt time.Time     `json:"expires_at"`
}

// EngineStats contains correlation engine statistics.
type EngineStats struct {
	TotalEvents uint64 `json:"total_events"`
	TotalAlerts uint64 `json:"total_alerts"`
	// AlertsDropped counts alerts the engine itself discarded (dedup/rate-limit/
	// feedback filter). Renamed from the misleading `dropped_events` (P1-10):
	// run #4 showed /debug/state's dropped_events=103867 against /metrics'
	// events_dropped_total=1155880 — an 11x gap that looked like a bug but was
	// two different counters (engine alert drops vs collector event drops) sold
	// under indistinguishable names. The JSON key is now `alerts_dropped` to
	// match its actual contents.
	AlertsDropped uint64 `json:"alerts_dropped"`
	RulesLoaded   int    `json:"rules_loaded"`
}

// ProfilerStats contains profiler learning statistics.
type ProfilerStats struct {
	LearningComplete    bool    `json:"learning_complete"`
	LearningProgress    float64 `json:"learning_progress"` // 0.0-1.0
	ProfilesActive      int     `json:"profiles_active"`
	AnomaliesTotal      uint64  `json:"anomalies_total"`
	LearningSampleCount uint64  `json:"learning_sample_count"`
}

// EnrichmentStats contains K8s enrichment statistics.
type EnrichmentStats struct {
	Enabled     bool   `json:"enabled"`
	CachedPods  int    `json:"cached_pods"`
	CacheSize   int    `json:"cache_size"`
	Enrichments uint64 `json:"enrichments_total"`
}

// DebugHandler provides debug endpoints.
type DebugHandler struct {
	mu               sync.RWMutex
	startTime        time.Time
	version          string
	rules            []RuleState
	silenceProvider  SilenceProvider
	engineProvider   EngineProvider
	profilerProvider ProfilerProvider
	enricherProvider EnricherProvider
	server           *Server
	hardwareProfile  HardwareProfileState
}

// SilenceProvider interface for getting active silences.
type SilenceProvider interface {
	GetActiveSilences() []SilenceState
}

// EngineProvider interface for getting engine stats.
type EngineProvider interface {
	GetStats() EngineStats
}

// ProfilerProvider interface for getting profiler stats.
type ProfilerProvider interface {
	GetStats() ProfilerStats
}

// EngineStatsFunc adapts a function to the EngineProvider interface. The
// function is called on every request so /debug/state reflects live counters
// rather than a snapshot taken at wiring time.
type EngineStatsFunc func() EngineStats

// GetStats returns the engine stats for the debug endpoint.
func (f EngineStatsFunc) GetStats() EngineStats { return f() }

// ProfilerStatsFunc adapts a function to the ProfilerProvider interface.
type ProfilerStatsFunc func() ProfilerStats

// GetStats returns the profiler stats for the debug endpoint.
func (f ProfilerStatsFunc) GetStats() ProfilerStats { return f() }

// EnricherProvider interface for getting enrichment stats.
type EnricherProvider interface {
	GetStats() EnrichmentStats
}

// NewDebugHandler creates a new debug handler.
func NewDebugHandler(version string, server *Server) *DebugHandler {
	return &DebugHandler{
		startTime: time.Now(),
		version:   version,
		rules:     make([]RuleState, 0),
		server:    server,
	}
}

// SetSilenceProvider sets the silence provider.
func (h *DebugHandler) SetSilenceProvider(provider SilenceProvider) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.silenceProvider = provider
}

// SetEngineProvider sets the engine provider.
func (h *DebugHandler) SetEngineProvider(provider EngineProvider) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.engineProvider = provider
}

// SetProfilerProvider sets the profiler provider.
func (h *DebugHandler) SetProfilerProvider(provider ProfilerProvider) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.profilerProvider = provider
}

// SetEnricherProvider sets the enricher provider.
func (h *DebugHandler) SetEnricherProvider(provider EnricherProvider) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.enricherProvider = provider
}

// SetRules updates the loaded rules state.
func (h *DebugHandler) SetRules(rules []RuleState) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.rules = rules
}

// SetHardwareProfile records how the lite/balanced/production tuning profile
// was resolved at startup, surfaced via /debug/state.
func (h *DebugHandler) SetHardwareProfile(state HardwareProfileState) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.hardwareProfile = state
}

// ServeHTTP implements http.Handler for /debug/state.
func (h *DebugHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	state := h.buildState()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(state); err != nil {
		slog.Error("exporter/debug: failed to encode debug state", slog.Any("error", err))
	}
}

// buildState constructs the current debug state.
func (h *DebugHandler) buildState() DebugState {
	h.mu.RLock()
	defer h.mu.RUnlock()

	state := DebugState{
		Timestamp:       time.Now(),
		Version:         h.version,
		Uptime:          time.Since(h.startTime),
		Rules:           h.rules,
		HardwareProfile: h.hardwareProfile,
	}

	// Get collector stats from server
	if h.server != nil {
		state.CollectorStats = h.server.GetCollectorStatuses()
	}

	// Get silences
	if h.silenceProvider != nil {
		state.ActiveSilences = h.silenceProvider.GetActiveSilences()
	}

	// Get engine stats
	if h.engineProvider != nil {
		state.EngineStats = h.engineProvider.GetStats()
	}

	// Get profiler stats
	if h.profilerProvider != nil {
		state.ProfilerStats = h.profilerProvider.GetStats()
	}

	// Get enrichment stats
	if h.enricherProvider != nil {
		state.EnrichmentStats = h.enricherProvider.GetStats()
	}

	return state
}

// RegisterRoutes registers debug endpoints with the provided mux.
func (h *DebugHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/debug/state", h.ServeHTTP)
}
