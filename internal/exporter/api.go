// Package exporter provides HTTP server, metrics, and REST API endpoints.
package exporter

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	apispec "github.com/zugolO/ebpf-guard/api"
	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/internal/exporter/dashboard"
	"github.com/zugolO/ebpf-guard/internal/exporter/swaggerui"
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

	// Summary endpoint (aggregates for the dashboard: top rules, severity, timeline)
	mux.HandleFunc("/api/v1/summary", s.handleSummary)

	// Rules endpoints
	mux.HandleFunc("/api/v1/rules", s.handleRules)
	mux.HandleFunc("/api/v1/rules/reload", s.handleRulesReload)

	// Incident endpoints
	mux.HandleFunc("/api/v1/incidents", s.handleIncidents)
	mux.HandleFunc("/api/v1/incidents/", s.handleIncidentByID)

	// BPF live-update endpoint (admin-only)
	mux.HandleFunc("/api/v1/bpf/reload", s.handleBPFReload)

	// Swagger UI — served without auth so API consumers can explore the spec.
	// Assets are embedded at build time to eliminate the unpkg.com CDN dependency.
	mux.Handle("/swaggerui/", swaggerui.Handler())
	mux.HandleFunc("/api/docs", s.handleAPIDocs)
	mux.HandleFunc("/api/openapi.yaml", s.handleOpenAPISpec)

	// Embedded read-only dashboard — self-contained, no external assets.
	// Subject to the same bearer auth as the rest of the read-only API (see viewerPrefixes).
	mux.Handle("/ui/", dashboard.Handler())
	mux.HandleFunc("/", s.handleDashboardRedirect)
}

// handleDashboardRedirect redirects the bare root path to the embedded dashboard.
// Any other unmatched path falls through to a 404, matching prior behavior.
func (s *Server) handleDashboardRedirect(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, "/ui/", http.StatusFound)
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
	restricted, err := applyNamespaceScope(ctx, filters)
	if err != nil {
		http.Error(w, "Forbidden: "+err.Error(), http.StatusForbidden)
		return
	}

	alerts, err := s.alertStore.Query(ctx, restricted)
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
//	GET  /api/v1/alerts/{id}/explain  → return human-readable explanation
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

	// GET /api/v1/alerts/{id}/explain
	if r.Method == http.MethodGet && strings.HasSuffix(path, "/explain") {
		alertID := strings.TrimSuffix(path, "/explain")
		if alertID == "" {
			http.Error(w, "Invalid alert ID", http.StatusBadRequest)
			return
		}
		s.explainAlert(w, r, alertID)
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

// explainAlert handles GET /api/v1/alerts/{id}/explain.
// Returns a human-readable explanation with MITRE ATT&CK mappings and mitigations.
func (s *Server) explainAlert(w http.ResponseWriter, r *http.Request, alertID string) {
	s.mu.RLock()
	exp := s.alertExplainer
	as := s.alertStore
	s.mu.RUnlock()

	if as == nil {
		http.Error(w, "Alert store not configured", http.StatusServiceUnavailable)
		return
	}
	if exp == nil {
		http.Error(w, "Explainer not configured", http.StatusNotImplemented)
		return
	}

	alert, err := as.QueryByID(r.Context(), alertID)
	if err != nil || alert == nil {
		http.Error(w, "Alert not found", http.StatusNotFound)
		return
	}

	explanation, err := exp.Explain(*alert)
	if err != nil {
		s.logger.Error("explainer: failed to explain alert",
			slog.String("alert_id", alertID), slog.Any("error", err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(explanation)
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
	restricted, err := applyNamespaceScope(ctx, filters)
	if err != nil {
		http.Error(w, "Forbidden: "+err.Error(), http.StatusForbidden)
		return
	}
	alerts, err := s.alertStore.Query(ctx, restricted)
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

// handleSummary handles GET /api/v1/summary — aggregate statistics for the
// dashboard: total count, severity distribution, top rules, and an hourly
// timeline. Accepts the same query filters as /api/v1/alerts, defaulting to
// a 24h window when "since" is not provided.
func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.alertStore == nil {
		http.Error(w, "Alert store not configured", http.StatusServiceUnavailable)
		return
	}

	filters := parseQueryFilters(r)
	if filters.Since.IsZero() && r.URL.Query().Get("since") == "" {
		filters.Since = time.Now().Add(-24 * time.Hour)
	}
	if filters.Limit == 0 {
		filters.Limit = 5000
	}

	ctx := r.Context()
	restricted, err := applyNamespaceScope(ctx, filters)
	if err != nil {
		http.Error(w, "Forbidden: "+err.Error(), http.StatusForbidden)
		return
	}

	alerts, err := s.alertStore.Query(ctx, restricted)
	if err != nil {
		s.logger.Error("failed to query alerts for summary", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(buildAlertSummary(alerts))
}

// AlertSummary is the aggregate response returned by /api/v1/summary.
type AlertSummary struct {
	Total      int              `json:"total"`
	BySeverity map[string]int   `json:"by_severity"`
	TopRules   []RuleCount      `json:"top_rules"`
	Timeline   []TimelineBucket `json:"timeline"`
}

// RuleCount pairs a rule ID with the number of alerts it produced.
type RuleCount struct {
	RuleID string `json:"rule_id"`
	Count  int    `json:"count"`
}

// TimelineBucket counts alerts within a single hour-wide bucket.
type TimelineBucket struct {
	Hour  string `json:"hour"`
	Count int    `json:"count"`
}

// buildAlertSummary aggregates a slice of alerts into severity counts, the
// top 10 rules by alert count, and an hourly timeline covering the observed
// range (oldest to newest alert, inclusive).
func buildAlertSummary(alerts []types.Alert) AlertSummary {
	summary := AlertSummary{
		Total:      len(alerts),
		BySeverity: map[string]int{},
	}
	if len(alerts) == 0 {
		return summary
	}

	ruleCounts := make(map[string]int)
	hourCounts := make(map[time.Time]int)
	var minHour, maxHour time.Time

	for _, a := range alerts {
		summary.BySeverity[string(a.Severity)]++
		ruleCounts[a.RuleID]++

		hour := a.Timestamp.UTC().Truncate(time.Hour)
		hourCounts[hour]++
		if minHour.IsZero() || hour.Before(minHour) {
			minHour = hour
		}
		if maxHour.IsZero() || hour.After(maxHour) {
			maxHour = hour
		}
	}

	summary.TopRules = make([]RuleCount, 0, len(ruleCounts))
	for ruleID, count := range ruleCounts {
		summary.TopRules = append(summary.TopRules, RuleCount{RuleID: ruleID, Count: count})
	}
	sort.Slice(summary.TopRules, func(i, j int) bool {
		if summary.TopRules[i].Count != summary.TopRules[j].Count {
			return summary.TopRules[i].Count > summary.TopRules[j].Count
		}
		return summary.TopRules[i].RuleID < summary.TopRules[j].RuleID
	})
	if len(summary.TopRules) > 10 {
		summary.TopRules = summary.TopRules[:10]
	}

	// Cap the timeline to a reasonable number of buckets so a wide "since"
	// window (e.g. months) doesn't produce an unbounded response.
	const maxBuckets = 500
	summary.Timeline = make([]TimelineBucket, 0)
	for h := minHour; !h.After(maxHour) && len(summary.Timeline) < maxBuckets; h = h.Add(time.Hour) {
		summary.Timeline = append(summary.Timeline, TimelineBucket{
			Hour:  h.Format(time.RFC3339),
			Count: hourCounts[h],
		})
	}

	return summary
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

// applyNamespaceScope restricts query filters to the namespaces allowed by the
// token embedded in ctx. Returns an error if the caller requested a namespace
// outside of their token's allowlist. No-op when auth is disabled (no scope).
func applyNamespaceScope(ctx context.Context, filters store.QueryFilters) (store.QueryFilters, error) {
	scope, ok := TokenScopeFromContext(ctx)
	if !ok || len(scope.Namespaces) == 0 {
		return filters, nil
	}

	if filters.Namespace != "" {
		if !scope.AllowsNamespace(filters.Namespace) {
			return filters, fmt.Errorf("namespace %q not in token scope", filters.Namespace)
		}
		return filters, nil
	}

	// No explicit namespace requested — restrict to the token's allowed set.
	// Single namespace: inject directly into the scalar Namespace field.
	// Multiple namespaces: populate the Namespaces slice for OR-based filtering.
	wildcard := false
	for _, ns := range scope.Namespaces {
		if ns == "*" {
			wildcard = true
			break
		}
	}
	if !wildcard {
		if len(scope.Namespaces) == 1 {
			filters.Namespace = scope.Namespaces[0]
		} else {
			filters.Namespaces = scope.Namespaces
		}
	}
	return filters, nil
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

// handleIncidents handles GET /api/v1/incidents.
//
// Query parameters:
//   - namespace: filter by Kubernetes namespace (empty = all namespaces)
//   - status: "open" | "closed" (empty = both)
//   - limit: maximum number of results (default unlimited)
func (s *Server) handleIncidents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.incidentTracker == nil {
		http.Error(w, "Incident tracking not configured", http.StatusServiceUnavailable)
		return
	}

	q := r.URL.Query()
	namespace := q.Get("namespace")
	status := q.Get("status")

	limit := 0
	if l := q.Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}

	// Enforce namespace scope from the authenticated token.
	scope, hasScopeCtx := TokenScopeFromContext(r.Context())
	if hasScopeCtx && len(scope.Namespaces) > 0 {
		if namespace != "" {
			if !scope.AllowsNamespace(namespace) {
				http.Error(w, fmt.Sprintf("Forbidden: namespace %q not in token scope", namespace), http.StatusForbidden)
				return
			}
		} else if len(scope.Namespaces) == 1 && scope.Namespaces[0] != "*" {
			namespace = scope.Namespaces[0]
		}
	}

	incidents := s.incidentTracker.GetAll(namespace, status, limit)
	if incidents == nil {
		incidents = []types.Incident{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(incidents)
}

// handleIncidentByID handles GET /api/v1/incidents/{id}.
func (s *Server) handleIncidentByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.incidentTracker == nil {
		http.Error(w, "Incident tracking not configured", http.StatusServiceUnavailable)
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/incidents/")
	if id == "" {
		http.Error(w, "Missing incident ID", http.StatusBadRequest)
		return
	}

	inc, ok := s.incidentTracker.GetByID(id)
	if !ok {
		http.Error(w, "Incident not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(inc)
}

// handleAPIDocs serves an interactive Swagger UI page for the ebpf-guard API.
// Assets are embedded at build time (swaggerui/ directory) — no CDN dependency.
// Content-Security-Policy restricts scripts and connections to same origin.
func (s *Server) handleAPIDocs(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; "+
			"script-src 'self'; "+
			"connect-src 'self'; "+
			"style-src 'self' 'unsafe-inline'; "+
			"img-src 'self' data:; "+
			"font-src 'self'; "+
			"frame-ancestors 'none'; "+
			"base-uri 'self'")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>ebpf-guard API</title>
  <link rel="stylesheet" href="/swaggerui/swagger-ui.css">
</head>
<body>
<div id="swagger-ui"></div>
<script src="/swaggerui/swagger-ui-bundle.js"></script>
<script>
  SwaggerUIBundle({
    url: "/api/openapi.yaml",
    dom_id: "#swagger-ui",
    presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
    layout: "BaseLayout",
    deepLinking: true,
  });
</script>
</body>
</html>`)
}

// handleOpenAPISpec serves the raw OpenAPI 3.0 YAML specification.
// The spec is embedded at build time so it is always in sync with the binary.
// CORS is restricted to the configured allowlist (default: "*" for backward compat).
func (s *Server) handleOpenAPISpec(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")

	origin := r.Header.Get("Origin")
	s.mu.RLock()
	origins := s.corsAllowedOrigins
	s.mu.RUnlock()

	if len(origins) > 0 && origin != "" {
		for _, allowed := range origins {
			if allowed == "*" {
				w.Header().Set("Access-Control-Allow-Origin", "*")
				break
			}
			if allowed == origin {
				// Reflect the specific origin and add Vary: Origin to prevent
				// proxy cache poisoning when responses differ by origin.
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
				break
			}
		}
	}

	w.Write(apispec.OpenAPISpec) //nolint:errcheck
}

// handleBPFReload triggers a live eBPF program replacement.
//
//	POST /api/v1/bpf/reload
//	Authorization: Bearer <admin-token>
//
// Response: {"status":"ok","programs_updated":N,"duration_ms":M}
// The endpoint is admin-only; viewers receive 403.
func (s *Server) handleBPFReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Require admin role when auth is enabled.
	if scope, ok := TokenScopeFromContext(r.Context()); ok && scope.Role != RoleAdmin {
		http.Error(w, "Forbidden: admin role required", http.StatusForbidden)
		return
	}

	s.mu.RLock()
	reloader := s.bpfReloader
	s.mu.RUnlock()

	if reloader == nil {
		http.Error(w, "BPF live update not configured", http.StatusServiceUnavailable)
		return
	}

	start := time.Now()
	if err := reloader(r.Context()); err != nil {
		s.logger.Error("BPF live reload failed", slog.Any("error", err))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "error",
			"error":  err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "ok",
		"duration_ms": time.Since(start).Milliseconds(),
	})
}
