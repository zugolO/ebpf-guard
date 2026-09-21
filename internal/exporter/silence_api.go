package exporter

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 6.3.L, ревизия item 2 (№414 → №420). №414 перевёл ключ сайленса на
// базовое имя и оставил открытым вопрос: «откуда аналитик возьмёт rule_id —
// из дашборда (имя Rego) или из rules/*.yaml (базовое)». Решать его было не
// на чем: AlertSilencer не был подключён НИ К ОДНОМУ хендлеру, НИ К ОДНОМУ
// вызову из main.go и не спрашивался ни на одном алерте — то есть починенный
// ключ жил в коде, которого нет в продукте, а метка 6.3L.2 могла вынести
// только НЕИЗМЕРИМ и делала критерий выхода волны недостижимым
// ([[verdict-line-that-can-only-say-unmeasurable]]).
//
// Решение: точка входа заводится, и вопрос об имени закрывается ТЕМ ЖЕ
// резолвером, что у исключений (item 1, №413) — аналитик подаёт имя, которое
// ВИДИТ, а ключи заводятся на каждое базовое правило, в которое оно
// разрешается. Расширение на «семью» имени Rego при этом перестаёт быть
// побочным эффектом и становится тем, что аналитик видит в ответе поимённо:
// ответ перечисляет КАЖДЫЙ заведённый ключ.

// SilenceRequest is the JSON body accepted by POST /api/v1/alerts/silence.
type SilenceRequest struct {
	// RuleID is the name the analyst sees — a YAML rule id, a Rego decision
	// name, or (when the two collide) both. Resolved the same way the tuning
	// endpoint resolves it.
	RuleID string `json:"rule_id"`
	// Severity scopes the silence; empty silences every severity tier that a
	// rule can produce, which is expressed as one key per tier.
	Severity string `json:"severity"`
	// Duration is a Go duration string ("30m", "2h"). Required.
	Duration string `json:"duration"`
	// Reason is recorded with the window and returned by GET.
	Reason string `json:"reason"`
}

// SilenceResponse is returned by POST /api/v1/alerts/silence.
type SilenceResponse struct {
	// Keys lists every silence key created, one per (base rule id, severity).
	// Listing them is the point: an analyst silencing a Rego name that several
	// base rules share must SEE that it covers all of them.
	Keys  []string  `json:"keys"`
	Until time.Time `json:"until"`
}

// silenceSeverities is the tier list used when a request names no severity.
var silenceSeverities = []types.Severity{
	types.SeverityInfo, types.SeverityWarning, types.SeverityCritical,
}

// handleAlertSilence handles POST (create) and GET (list) on
// /api/v1/alerts/silence. Admin-only for POST, the same contract as the
// tuning endpoint: silencing hides alerts from the forwarding path.
func (s *Server) handleAlertSilence(w http.ResponseWriter, r *http.Request) {
	silencer := s.AlertSilencer()
	if silencer == nil {
		http.Error(w, "alert silencer is not enabled on this agent", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		writeJSON(w, silencer.Windows())
		return
	case http.MethodPost:
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if scope, ok := TokenScopeFromContext(r.Context()); ok && scope.Role != RoleAdmin {
		http.Error(w, "Forbidden: admin role required to silence alerts", http.StatusForbidden)
		return
	}

	var req SilenceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	req.RuleID = strings.TrimSpace(req.RuleID)
	req.Duration = strings.TrimSpace(req.Duration)
	if req.RuleID == "" || req.Duration == "" {
		http.Error(w, "rule_id and duration are required", http.StatusBadRequest)
		return
	}
	dur, err := time.ParseDuration(req.Duration)
	if err != nil || dur <= 0 {
		http.Error(w, "duration must be a positive Go duration string (e.g. \"30m\")", http.StatusBadRequest)
		return
	}

	bases, bothMissed := s.resolveRuleIDToBaseIDs(req.RuleID)
	if len(bases) == 0 {
		if bothMissed {
			http.Error(w, fmt.Sprintf("rule %q not found: unknown both as a loaded rule id and as a Rego-renamed name", req.RuleID), http.StatusNotFound)
			return
		}
		http.Error(w, fmt.Sprintf("rule %q is known as a Rego rename, but none of its base rules are currently loaded", req.RuleID), http.StatusNotFound)
		return
	}

	tiers := silenceSeverities
	if sev := strings.TrimSpace(req.Severity); sev != "" {
		tiers = []types.Severity{types.Severity(sev)}
	}

	resp := SilenceResponse{Until: time.Now().Add(dur)}
	for _, base := range bases {
		for _, tier := range tiers {
			key := SilenceKey(base, tier)
			silencer.Silence(key, dur, req.Reason)
			resp.Keys = append(resp.Keys, key)
		}
	}
	writeJSON(w, resp)
}

// handleAlertSilenceByKey handles DELETE /api/v1/alerts/silence/{key}, lifting
// one window. Admin-only, like creating one.
func (s *Server) handleAlertSilenceByKey(w http.ResponseWriter, r *http.Request) {
	silencer := s.AlertSilencer()
	if silencer == nil {
		http.Error(w, "alert silencer is not enabled on this agent", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if scope, ok := TokenScopeFromContext(r.Context()); ok && scope.Role != RoleAdmin {
		http.Error(w, "Forbidden: admin role required to lift a silence", http.StatusForbidden)
		return
	}
	key := strings.TrimPrefix(r.URL.Path, "/api/v1/alerts/silence/")
	if key == "" {
		http.Error(w, "silence key is required", http.StatusBadRequest)
		return
	}
	silencer.RemoveSilence(key)
	w.WriteHeader(http.StatusNoContent)
}

// resolveRuleIDToBaseIDs maps a rule_id an analyst supplied onto the base rule
// ids it can stand for: itself when a loaded rule carries that id, plus every
// base id the Rego rename index knows it as. The union — not one or the other —
// for the reason spelled out in handleTuningExceptions: the two namespaces are
// not disjoint by construction.
//
// bothMissed distinguishes the two 404 causes: "no such name anywhere" from
// "a known rename whose base rules are not loaded right now".
func (s *Server) resolveRuleIDToBaseIDs(ruleID string) (bases []string, bothMissed bool) {
	renamed := BaseRuleIDsForRenamed(ruleID)
	wanted := make(map[string]struct{}, len(renamed)+1)
	wanted[ruleID] = struct{}{}
	for _, base := range renamed {
		wanted[base] = struct{}{}
	}
	for _, rule := range s.getRules() {
		if _, ok := wanted[rule.ID]; ok {
			bases = append(bases, rule.ID)
		}
	}
	return bases, len(bases) == 0 && len(renamed) == 0
}

// writeJSON writes v as the JSON body of a 200 response.
func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	// #nosec G104 -- encode error is not actionable once headers are written
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}
