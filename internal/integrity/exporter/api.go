// Package exporter provides HTTP server, metrics, and REST API endpoints.
package exporter

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ebpf-guard/ebpf-guard/internal/correlator"
	"github.com/ebpf-guard/ebpf-guard/internal/explainer"
	"github.com/ebpf-guard/ebpf-guard/internal/store"
	"github.com/ebpf-guard/ebpf-guard/pkg/types"
)

// RegisterAPIRoutes registers REST API routes on the given mux.
func (s *Server) RegisterAPIRoutes(mux *http.ServeMux) {
	// Alert endpoints
	mux.HandleFunc("/api/v1/alerts", s.handleAlerts)
	mux.HandleFunc("/api/v1/alerts/", s.handleAlertWithPath)
	mux.HandleFunc("/api/v1/alerts/export/cef", s.handleExportCEF)

	// Status endpoint
	mux.HandleFunc("/api/v1/status", s.handleStatus)

	// Rules endpoints
	mux.HandleFunc("/api/v1/rules", s.handleRules)
	mux.HandleFunc("/api/v1/rules/reload", s.handleRulesReload)

	// Explain endpoint
	mux.HandleFunc("/api/v1/explain/", s.handleExplain)
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
	if err := json.NewEncoder(w).Encode(alerts); err != nil {
		s.logger.Error("failed to encode alerts response", "error", err)
	}
}

// handleAlertWithPath handles GET /api/v1/alerts/{id} and /api/v1/alerts/{id}/explain.
func (s *Server) handleAlertWithPath(w http.ResponseWriter, r *http.Request) {
	// Extract path after /api/v1/alerts/
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/alerts/")
	if path == "" || path == r.URL.Path {
		http.Error(w, "Invalid alert ID", http.StatusBadRequest)
		return
	}

	// Check if this is an explain request
	if strings.HasSuffix(path, "/explain") {
		alertID := strings.TrimSuffix(path, "/explain")
		s.handleExplainByID(w, r, alertID)
		return
	}

	// Regular alert lookup
	s.handleAlertByID(w, r, path)
}

// handleAlertByID handles GET /api/v1/alerts/{id}.
func (s *Server) handleAlertByID(w http.ResponseWriter, r *http.Request, alertID string) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.alertStore == nil {
		http.Error(w, "Alert store not configured", http.StatusServiceUnavailable)
		return
	}

	ctx := r.Context()
	alert, err := s.alertStore.QueryByID(ctx, alertID)
	if err != nil {
		http.Error(w, "Alert not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(alert); err != nil {
		s.logger.Error("failed to encode alert response", "error", err)
	}
}

// handleExplainByID handles GET /api/v1/alerts/{id}/explain.
func (s *Server) handleExplainByID(w http.ResponseWriter, r *http.Request, alertID string) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.alertStore == nil {
		http.Error(w, "Alert store not configured", http.StatusServiceUnavailable)
		return
	}

	ctx := r.Context()
	alert, err := s.alertStore.QueryByID(ctx, alertID)
	if err != nil {
		http.Error(w, "Alert not found", http.StatusNotFound)
		return
	}

	// Generate explanation
	exp, err := explainer.NewWithDefaults()
	if err != nil {
		s.logger.Error("failed to create explainer", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	explanation, err := exp.Explain(*alert)
	if err != nil {
		s.logger.Error("failed to explain alert", "error", err)
		http.Error(w, "Failed to generate explanation", http.StatusInternalServerError)
		return
	}

	response := struct {
		Alert       types.Alert            `json:"alert"`
		Explanation *explainer.Explanation `json:"explanation"`
	}{
		Alert:       *alert,
		Explanation: explanation,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.logger.Error("failed to encode explain response", "error", err)
	}
}

// handleExplain handles GET /api/v1/explain/{fingerprint} for direct explanation lookup.
func (s *Server) handleExplain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract fingerprint from path: /api/v1/explain/{fingerprint}
	fingerprint := strings.TrimPrefix(r.URL.Path, "/api/v1/explain/")
	if fingerprint == "" || fingerprint == r.URL.Path {
		http.Error(w, "Invalid fingerprint", http.StatusBadRequest)
		return
	}

	// For now, use the fingerprint as alert ID
	// In production, this would query by fingerprint field
	s.handleExplainByID(w, r, fingerprint)
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
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.logger.Error("failed to encode status response", "error", err)
	}
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
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.logger.Error("failed to encode rules response", "error", err)
	}
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
	if err := json.NewEncoder(w).Encode(map[string]string{
		"status":  "accepted",
		"message": "Rules reload triggered",
	}); err != nil {
		s.logger.Error("failed to encode reload response", "error", err)
	}
}

// RuleAPIResponse represents a rule in the API response
type RuleAPIResponse struct {
	ID             string                      `json:"id"`
	Name           string                      `json:"name"`
	Description    string                      `json:"description"`
	EventType      string                      `json:"event_type"`
	Severity       string                      `json:"severity"`
	Action         string                      `json:"action"`
	Tags           []string                    `json:"tags,omitempty"`
	Condition      RuleConditionResponse       `json:"condition,omitempty"`
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
