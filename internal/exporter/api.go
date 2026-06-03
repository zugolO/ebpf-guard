// Package exporter provides HTTP server, metrics, and REST API endpoints.
package exporter

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/internal/feedback"
	"github.com/zugolO/ebpf-guard/internal/store"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// RegisterAPIRoutes registers REST API routes on the given mux.
func (s *Server) RegisterAPIRoutes(mux *http.ServeMux) {
	// Alert endpoints
	mux.HandleFunc("/api/v1/alerts", s.handleAlerts)
	mux.HandleFunc("/api/v1/alerts/", s.handleAlertPath) // GET /{id} + POST /{id}/feedback
	mux.HandleFunc("/api/v1/alerts/export/cef", s.handleExportCEF)

	// Feedback list endpoint
	mux.HandleFunc("/api/v1/feedback", s.handleFeedbackList)

	// Status endpoint
	mux.HandleFunc("/api/v1/status", s.handleStatus)

	// Rules endpoints
	mux.HandleFunc("/api/v1/rules", s.handleRules)
	mux.HandleFunc("/api/v1/rules/reload", s.handleRulesReload)
}

// handleAlerts handles GET /api/v1/alerts with query parameter filters.
func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.alertStore == nil {
		http.Error(w, "Alert store not configured", http.StatusServiceUnavailable)
		return
	}

	filters := parseQueryFilters(r)

	ctx := r.Context()
	alerts, err := s.alertStore.Query(ctx, filters)
	if err != nil {
		s.logger.Error("failed to query alerts", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(alerts)
}

// handleAlertPath dispatches sub-paths under /api/v1/alerts/:
//
//	GET  /api/v1/alerts/{id}          → return single alert
//	POST /api/v1/alerts/{id}/feedback → record analyst feedback
func (s *Server) handleAlertPath(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/alerts/")
	if path == "" || path == r.URL.Path {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	// POST /api/v1/alerts/{id}/feedback
	if r.Method == http.MethodPost && strings.HasSuffix(path, "/feedback") {
		alertID := strings.TrimSuffix(path, "/feedback")
		if alertID == "" {
			http.Error(w, "Invalid alert ID", http.StatusBadRequest)
			return
		}
		s.submitAlertFeedback(w, r, alertID)
		return
	}

	// GET /api/v1/alerts/{id} — reject IDs containing slashes (reserved for sub-paths)
	if r.Method == http.MethodGet && !strings.Contains(path, "/") {
		if s.alertStore == nil {
			http.Error(w, "Alert store not configured", http.StatusServiceUnavailable)
			return
		}
		alert, err := s.alertStore.QueryByID(r.Context(), path)
		if err != nil {
			http.Error(w, "Alert not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(alert)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// submitAlertFeedback handles POST /api/v1/alerts/{id}/feedback.
func (s *Server) submitAlertFeedback(w http.ResponseWriter, r *http.Request, alertID string) {
	s.mu.RLock()
	fm := s.feedbackManager
	as := s.alertStore
	s.mu.RUnlock()

	if as == nil {
		http.Error(w, "Alert store not configured", http.StatusServiceUnavailable)
		return
	}
	if fm == nil {
		http.Error(w, "Feedback not configured", http.StatusNotImplemented)
		return
	}

	alert, err := as.QueryByID(r.Context(), alertID)
	if err != nil || alert == nil {
		http.Error(w, "Alert not found", http.StatusNotFound)
		return
	}

	var req feedback.Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Verdict != feedback.VerdictFalsePositive && req.Verdict != feedback.VerdictTruePositive {
		http.Error(w, "Invalid verdict: must be false_positive or true_positive", http.StatusBadRequest)
		return
	}

	resp, err := fm.Submit(*alert, req.Verdict, req.Reason)
	if err != nil {
		s.logger.Error("feedback: failed to persist", "err", err)
		// Still return 200 — feedback was recorded in memory even if file write failed.
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleFeedbackList handles GET /api/v1/feedback — returns all recorded feedback.
func (s *Server) handleFeedbackList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	fm := s.feedbackManager
	s.mu.RUnlock()

	if fm == nil {
		http.Error(w, "Feedback not configured", http.StatusNotImplemented)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(fm.Records())
}

// handleExportCEF handles GET /api/v1/alerts/export/cef for SIEM integration.
func (s *Server) handleExportCEF(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.alertStore == nil {
		http.Error(w, "Alert store not configured", http.StatusServiceUnavailable)
		return
	}

	filters := parseQueryFilters(r)

	ctx := r.Context()
	alerts, err := s.alertStore.Query(ctx, filters)
	if err != nil {
		s.logger.Error("failed to query alerts for export", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\"alerts.cef\"")

	for _, alert := range alerts {
		cefLine := formatCEF(alert)
		w.Write([]byte(cefLine + "\n"))
	}
}

// handleStatus handles GET /api/v1/status for agent status.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	status := HealthStatus{
		Healthy:   s.healthy,
		Ready:     s.ready,
		Uptime:    time.Since(s.startTime),
		Timestamp: time.Now(),
	}
	collectorStatuses := make([]CollectorStatus, 0, len(s.collectorStatuses))
	for _, cs := range s.collectorStatuses {
		collectorStatuses = append(collectorStatuses, cs)
	}
	alertStore := s.alertStore
	s.mu.RUnlock()

	// Check store health
	storeHealth := "not configured"
	if alertStore != nil {
		if alertStore.Healthy(r.Context()) {
			storeHealth = "healthy"
		} else {
			storeHealth = "unhealthy"
		}
	}

	response := StatusAPIResponse{
		Healthy:    status.Healthy,
		Ready:      status.Ready,
		Uptime:     status.Uptime.String(),
		Timestamp:  status.Timestamp,
		Collectors: collectorStatuses,
		Store:      storeHealth,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// StatusAPIResponse represents the status API response
type StatusAPIResponse struct {
	Healthy    bool              `json:"healthy"`
	Ready      bool              `json:"ready"`
	Uptime     string            `json:"uptime"`
	Timestamp  time.Time         `json:"timestamp"`
	Collectors []CollectorStatus `json:"collectors"`
	Store      string            `json:"store"`
}

// handleRules handles GET /api/v1/rules to list loaded rules.
func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get rules from the rules provider
	rules := s.getRules()

	// Convert to API response format
	response := make([]RuleAPIResponse, 0, len(rules))
	for _, rule := range rules {
		response = append(response, convertRuleToAPI(rule))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleRulesReload handles POST /api/v1/rules/reload to trigger rule reload.
func (s *Server) handleRulesReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.rulesReloadFn == nil {
		http.Error(w, "Rule reload not configured", http.StatusNotFound)
		return
	}

	// Trigger reload
	if err := s.rulesReloadFn(); err != nil {
		s.logger.Error("failed to reload rules", "error", err)
		http.Error(w, "Failed to reload rules: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "accepted",
		"message": "Rules reload triggered",
	})
}

// RuleAPIResponse represents a rule in the API response
type RuleAPIResponse struct {
	ID             string                 `json:"id"`
	Name           string                 `json:"name"`
	Description    string                 `json:"description"`
	EventType      string                 `json:"event_type"`
	Severity       string                 `json:"severity"`
	Action         string                 `json:"action"`
	Tags           []string               `json:"tags,omitempty"`
	Condition      RuleConditionResponse  `json:"condition,omitempty"`
	ConditionGroup *RuleConditionGroupResponse `json:"condition_group,omitempty"`
}

// RuleConditionResponse represents a condition in the API response
type RuleConditionResponse struct {
	Field  string   `json:"field"`
	Op     string   `json:"op"`
	Values []string `json:"values"`
}

// RuleConditionGroupResponse represents a condition group in the API response
type RuleConditionGroupResponse struct {
	Operator   string                  `json:"operator"`
	Conditions []RuleConditionResponse `json:"conditions"`
}

// convertRuleToAPI converts an internal Rule to API response format
func convertRuleToAPI(rule correlator.Rule) RuleAPIResponse {
	eventTypeStr := "unknown"
	switch rule.EventType {
	case types.EventSyscall:
		eventTypeStr = "syscall"
	case types.EventTCPConnect:
		eventTypeStr = "network"
	case types.EventFileAccess:
		eventTypeStr = "file"
	}

	resp := RuleAPIResponse{
		ID:          rule.ID,
		Name:        rule.Name,
		Description: rule.Description,
		EventType:   eventTypeStr,
		Severity:    string(rule.Severity),
		Action:      string(rule.Action),
		Tags:        rule.Tags,
		Condition: RuleConditionResponse{
			Field:  rule.Condition.Field,
			Op:     string(rule.Condition.Op),
			Values: rule.Condition.Values,
		},
	}

	if rule.ConditionGroup != nil {
		resp.ConditionGroup = convertConditionGroupToAPI(rule.ConditionGroup)
	}

	return resp
}

// convertConditionGroupToAPI converts a condition group to API format
func convertConditionGroupToAPI(group *correlator.RuleConditionGroup) *RuleConditionGroupResponse {
	if group == nil {
		return nil
	}

	resp := &RuleConditionGroupResponse{
		Operator:   group.Operator,
		Conditions: make([]RuleConditionResponse, 0, len(group.Conditions)),
	}

	for _, cond := range group.Conditions {
		resp.Conditions = append(resp.Conditions, RuleConditionResponse{
			Field:  cond.Field,
			Op:     string(cond.Op),
			Values: cond.Values,
		})
	}

	return resp
}

// getRules returns the currently loaded rules
// This is set via SetRulesProvider
func (s *Server) getRules() []correlator.Rule {
	s.mu.RLock()
	fn := s.rulesProviderFn
	s.mu.RUnlock()

	if fn != nil {
		return fn()
	}
	return nil
}

// SetRulesProvider sets the function that provides loaded rules
func (s *Server) SetRulesProvider(fn func() []correlator.Rule) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rulesProviderFn = fn
}

// SetRulesReloadHandler sets the function that triggers rule reload
func (s *Server) SetRulesReloadHandler(fn func() error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rulesReloadFn = fn
}

// parseQueryFilters extracts filters from HTTP query parameters.
func parseQueryFilters(r *http.Request) store.QueryFilters {
	filters := store.QueryFilters{}

	if since := r.URL.Query().Get("since"); since != "" {
		if d, err := time.ParseDuration(since); err == nil {
			filters.Since = time.Now().Add(-d)
		}
	}
	if until := r.URL.Query().Get("until"); until != "" {
		if d, err := time.ParseDuration(until); err == nil {
			filters.Until = time.Now().Add(-d)
		}
	}
	if pidStr := r.URL.Query().Get("pid"); pidStr != "" {
		if pid, err := strconv.ParseUint(pidStr, 10, 32); err == nil {
			filters.PIDs = []uint32{uint32(pid)}
		}
	}
	if severity := r.URL.Query().Get("severity"); severity != "" {
		filters.Severity = parseSeverityList(severity)
	}
	if ruleID := r.URL.Query().Get("rule_id"); ruleID != "" {
		filters.RuleIDs = strings.Split(ruleID, ",")
	}
	if podName := r.URL.Query().Get("pod"); podName != "" {
		filters.PodName = podName
	}
	if namespace := r.URL.Query().Get("namespace"); namespace != "" {
		filters.Namespace = namespace
	}
	if limit := r.URL.Query().Get("limit"); limit != "" {
		if n, err := strconv.Atoi(limit); err == nil {
			filters.Limit = n
		}
	}
	if offset := r.URL.Query().Get("offset"); offset != "" {
		if n, err := strconv.Atoi(offset); err == nil {
			filters.Offset = n
		}
	}

	return filters
}

// parseSeverityList parses a comma-separated severity list.
func parseSeverityList(s string) []types.Severity {
	var result []types.Severity
	for _, part := range strings.Split(s, ",") {
		switch strings.ToLower(strings.TrimSpace(part)) {
		case "warning":
			result = append(result, types.SeverityWarning)
		case "critical":
			result = append(result, types.SeverityCritical)
		}
	}
	return result
}

// formatCEF formats an alert as a CEF (Common Event Format) string.
// CEF:0|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
func formatCEF(alert types.Alert) string {
	// Map our severity to CEF severity (0-10)
	cefSeverity := "5" // Medium
	if alert.Severity == types.SeverityCritical {
		cefSeverity = "10" // High
	} else if alert.Severity == types.SeverityWarning {
		cefSeverity = "4" // Low-Medium
	}

	// Build extensions
	extensions := []string{
		"rt=" + strconv.FormatInt(alert.Timestamp.UnixMilli(), 10),
		"deviceProcessName=" + escapeCEF(alert.Comm),
		"dpid=" + strconv.FormatUint(uint64(alert.PID), 10),
		"cs1=" + escapeCEF(alert.RuleID),
		"cs1Label=rule_id",
	}

	if alert.Enrichment.PodName != "" {
		extensions = append(extensions, "dhost="+escapeCEF(alert.Enrichment.PodName))
	}
	if alert.Enrichment.Namespace != "" {
		extensions = append(extensions, "cs2="+escapeCEF(alert.Enrichment.Namespace))
		extensions = append(extensions, "cs2Label=namespace")
	}
	if alert.TraceID != "" {
		extensions = append(extensions, "cs3="+escapeCEF(alert.TraceID))
		extensions = append(extensions, "cs3Label=trace_id")
	}

	return "CEF:0|ebpf-guard|ebpf-guard|1.0|" +
		escapeCEF(alert.RuleID) + "|" +
		escapeCEF(alert.Message) + "|" +
		cefSeverity + "|" +
		strings.Join(extensions, " ")
}

// escapeCEF escapes special characters in CEF fields.
func escapeCEF(s string) string {
	// CEF requires escaping: \, |, =, \n, \r
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "=", "\\=")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	return s
}
