// Package exporter provides the false-positive → exception generation cycle
// for issue #308: an operator who sees noise in the dashboard can suppress it
// in two clicks instead of hand-writing YAML.
package exporter

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/pkg/types"
	"gopkg.in/yaml.v3"
)

// TuningExceptionRequest is the JSON body accepted by
// POST /api/v1/tuning/exceptions.
type TuningExceptionRequest struct {
	RuleID string `json:"rule_id"`
	Name   string `json:"name"`
	// Comm suppresses alerts from this process name (comm).
	Comm string `json:"comm"`
	// PathPrefix additionally restricts the exception to file events whose
	// path starts with this prefix. Only meaningful for file-access rules;
	// ignored otherwise.
	PathPrefix string `json:"path_prefix,omitempty"`
	// Axis / AxisValue narrow by an IDENTITY field instead of comm — wave
	// 6.3.L.1, item 1 (№422). Required for rules the comm axis cannot carry:
	// a synthetic rule (anomaly_detection — the largest single source of
	// volume in the cluster, and the one that bypasses the rule layer
	// entirely), and any event type whose condition fields include no comm at
	// all. Axis must be one of correlator.IdentityFieldNames(); those are the
	// axes valid on EVERY event type and the only ones a synthetic rule's
	// exceptions accept (validateIdentityCondition).
	//
	// When both comm and axis are supplied the axis wins for rules that
	// cannot take comm, and comm is used for the rest — one request, one
	// exception per target rule, each on an axis that rule can actually hold.
	Axis      string `json:"axis,omitempty"`
	AxisValue string `json:"axis_value,omitempty"`
	// Persist writes the generated exception into the local-tuning overlay
	// file (admin-only, hot-reloaded). When false, the endpoint only returns
	// the YAML snippet for the operator to copy manually.
	Persist bool `json:"persist"`
}

// TuningAxisRefusal is the JSON body returned (HTTP 422) when the request
// resolved to a real rule but carries no axis that rule can be narrowed by.
//
// It exists because the bare 400 it replaces was indistinguishable from a
// malformed request and told the analyst nothing about what to send instead
// (№422): the largest source of noise in the cluster answered "exception
// generation is not supported for this rule's event type" and the dashboard
// had no next step. The refusal now NAMES the rule, the reason, and the axes
// that rule does accept, so the second request is a copy-paste away.
type TuningAxisRefusal struct {
	Error string `json:"error"`
	// Reason is a stable machine-readable token: "synthetic_rule_needs_identity_axis"
	// or "event_type_has_no_comm_field".
	Reason string `json:"reason"`
	RuleID string `json:"rule_id"`
	// Synthetic reports whether the rule is produced outside the rule-matching
	// path (profiler-synthesised), which is why comm is not an option for it.
	Synthetic bool `json:"synthetic"`
	// SupportedAxes lists the field names accepted in "axis" for this rule.
	SupportedAxes []string `json:"supported_axes"`
	Hint          string   `json:"hint"`
}

// TuningExceptionResponse is returned by POST /api/v1/tuning/exceptions.
type TuningExceptionResponse struct {
	// YAML is the ready-to-paste snippet for rules.local_tuning_path
	// (rules/local-tuning.yaml by default), scoped to just this rule_id.
	YAML string `json:"yaml"`
	// Persisted is true when the exception was written to the overlay file
	// on disk (Persist was requested, an admin token was used, and the write
	// succeeded).
	Persisted bool `json:"persisted"`
	// Axes names, per base rule id, the condition field the generated
	// exception was built on (wave 6.3.L.1, item 1). One renamed name can
	// resolve to several base rules of different event types — and, since
	// №422, to rules narrowed on DIFFERENT axes — so "what did this actually
	// narrow, and by what" must be readable from the response, not inferred
	// from the YAML by eye.
	Axes map[string]string `json:"axes,omitempty"`
}

// buildException constructs the RuleException for req against target. The axis
// is chosen in the order the analyst can actually verify:
//
//  1. an explicit identity axis (req.Axis), which is valid on every event type
//     and on synthetic rules — this is the only axis a synthetic rule accepts;
//  2. otherwise comm, on the field name the loader itself says this event type
//     carries (correlator.CommFieldForEventType — read from the loader's
//     allowlists, never from a second copy of the answer);
//  3. otherwise a REFUSAL that names the rule, the reason and the axes that
//     would work (wave 6.3.L.1, item 1, №422).
//
// A path prefix is only applied to file-access rules on the comm axis, where
// "file.path" is a valid condition field.
func buildException(req TuningExceptionRequest, target correlator.Rule) (correlator.RuleException, *TuningAxisRefusal) {
	if req.Axis != "" {
		return correlator.RuleException{
			Name:      req.Name,
			Condition: correlator.RuleCondition{Field: req.Axis, Op: correlator.OpEquals, Values: []string{req.AxisValue}},
		}, nil
	}

	if target.Synthetic {
		return correlator.RuleException{}, &TuningAxisRefusal{
			Error:         fmt.Sprintf("rule %q is synthetic: it is not produced by the rule-matching layer, and comm is not one of the axes it can be narrowed by", target.ID),
			Reason:        "synthetic_rule_needs_identity_axis",
			RuleID:        target.ID,
			Synthetic:     true,
			SupportedAxes: correlator.IdentityFieldNames(),
			Hint:          `re-send with {"axis":"proc.exe_path","axis_value":"/usr/bin/<binary>"} — a synthetic rule's exceptions are restricted to the identity axes, which is also why they cannot be spoofed by a forged comm`,
		}
	}

	field, ok := correlator.CommFieldForEventType(target.EventType)
	if !ok {
		return correlator.RuleException{}, &TuningAxisRefusal{
			Error:         fmt.Sprintf("rule %q has event type %d, whose condition fields carry no process name: comm cannot narrow it", target.ID, target.EventType),
			Reason:        "event_type_has_no_comm_field",
			RuleID:        target.ID,
			SupportedAxes: correlator.IdentityFieldNames(),
			Hint:          `re-send with {"axis":"<one of supported_axes>","axis_value":"..."}`,
		}
	}

	if req.Comm == "" {
		return correlator.RuleException{}, &TuningAxisRefusal{
			Error:         fmt.Sprintf("rule %q can be narrowed by comm, but no comm was supplied", target.ID),
			Reason:        "no_axis_supplied",
			RuleID:        target.ID,
			SupportedAxes: append([]string{field}, correlator.IdentityFieldNames()...),
			Hint:          `send "comm", or an explicit {"axis","axis_value"} pair`,
		}
	}

	commCond := correlator.RuleCondition{Field: field, Op: correlator.OpEquals, Values: []string{req.Comm}}

	if req.PathPrefix != "" && target.EventType == types.EventFileAccess {
		return correlator.RuleException{
			Name: req.Name,
			ConditionGroup: &correlator.RuleConditionGroup{
				Operator: "and",
				Conditions: []correlator.RuleCondition{
					commCond,
					{Field: "file.path", Op: correlator.OpPrefix, Values: []string{req.PathPrefix}},
				},
			},
		}, nil
	}

	return correlator.RuleException{Name: req.Name, Condition: commCond}, nil
}

// handleTuningExceptions handles POST /api/v1/tuning/exceptions. Admin-only
// when auth is enabled; a viewer role never reaches this handler because
// isViewerAllowed only permits GET/HEAD.
func (s *Server) handleTuningExceptions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if scope, ok := TokenScopeFromContext(r.Context()); ok && scope.Role != RoleAdmin {
		http.Error(w, "Forbidden: admin role required to persist exceptions", http.StatusForbidden)
		return
	}

	var req TuningExceptionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	req.RuleID = strings.TrimSpace(req.RuleID)
	req.Name = strings.TrimSpace(req.Name)
	req.Comm = strings.TrimSpace(req.Comm)
	req.Axis = strings.TrimSpace(req.Axis)
	req.AxisValue = strings.TrimSpace(req.AxisValue)
	if req.RuleID == "" || req.Name == "" {
		http.Error(w, "rule_id and name are required", http.StatusBadRequest)
		return
	}
	// comm OR an explicit identity axis (wave 6.3.L.1, item 1, №422): comm
	// alone cannot narrow a synthetic rule or an event type that carries no
	// process name, and refusing those with a bare 400 is what left the
	// largest source of volume unnarrowable.
	if req.Comm == "" && req.Axis == "" {
		http.Error(w, "comm, or an axis/axis_value pair, is required", http.StatusBadRequest)
		return
	}
	if req.Axis != "" {
		if req.AxisValue == "" {
			http.Error(w, "axis_value is required when axis is given", http.StatusBadRequest)
			return
		}
		known := false
		for _, f := range correlator.IdentityFieldNames() {
			if req.Axis == f {
				known = true
				break
			}
		}
		if !known {
			http.Error(w, fmt.Sprintf("axis %q is not an identity axis; valid axes: %v", req.Axis, correlator.IdentityFieldNames()), http.StatusBadRequest)
			return
		}
	}

	rules := s.getRules()
	// №413 (wave 6.3.L, item 1): req.RuleID is what the analyst SEES, and
	// after Rego enrichment that is the renamed name, not any YAML id — none
	// of the four live Rego-decision names appear in rules/*.yaml at all. So
	// the name is resolved on BOTH identities and the results are UNIONED:
	// as a loaded rule id, and through the reverse rename index (renameIndex,
	// fed live by RecordAlertRuleIDRename) as a Rego-visible name. The union
	// matters because the two namespaces are not disjoint by construction —
	// nothing stops a future Rego decision from reusing an existing YAML id,
	// and resolving only the direct hit would then leave the base rule that
	// actually fired untouched: №413 again, one indirection deeper. A 404 is
	// reserved for a name unknown as EITHER identity, and says which lookup
	// missed.
	bases := BaseRuleIDsForRenamed(req.RuleID)
	wanted := make(map[string]struct{}, len(bases)+1)
	wanted[req.RuleID] = struct{}{}
	for _, base := range bases {
		wanted[base] = struct{}{}
	}
	var targets []correlator.Rule
	for _, rule := range rules {
		if _, ok := wanted[rule.ID]; ok {
			targets = append(targets, rule)
		}
	}
	if len(targets) == 0 {
		if len(bases) == 0 {
			http.Error(w, fmt.Sprintf("rule %q not found: unknown both as a loaded rule id and as a Rego-renamed name", req.RuleID), http.StatusNotFound)
			return
		}
		http.Error(w, fmt.Sprintf("rule %q is known as a Rego rename of %v, but none of those base rules are currently loaded", req.RuleID, bases), http.StatusNotFound)
		return
	}
	// A renamed name can be shared by several base rules (wave 6.3.L input:
	// dns_dga_ngram and dns_dga_high_entropy both rename to dga_domain). The
	// exception is generated against every matching base rule, explicitly —
	// the analyst asked to suppress what the dashboard shows under this name,
	// and every rule capable of producing it must stop firing for the
	// exception to hold.
	overlay := &correlator.TuningOverlay{}
	axes := make(map[string]string, len(targets))
	for _, target := range targets {
		exc, refusal := buildException(req, target)
		if refusal != nil {
			// 422, not 400: the request was well-formed and the rule exists —
			// what is missing is an axis this particular rule can hold, and
			// the body says which ones it can (wave 6.3.L.1, №422). A 400
			// here was read by the analyst as "the API does not support
			// narrowing this", with no way to tell it from a typo.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnprocessableEntity)
			// #nosec G104 -- see the response encode note below
			json.NewEncoder(w).Encode(refusal) //nolint:errcheck
			return
		}
		overlay.Overlays = append(overlay.Overlays, correlator.RuleTuningOverlay{
			RuleID:     target.ID,
			Exceptions: []correlator.RuleException{exc},
		})
		if exc.ConditionGroup != nil {
			axes[target.ID] = exc.ConditionGroup.Conditions[0].Field
		} else {
			axes[target.ID] = exc.Condition.Field
		}
	}

	data, err := yaml.Marshal(overlay)
	if err != nil {
		s.logger.Error("tuning: failed to marshal exception snippet", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	resp := TuningExceptionResponse{YAML: string(data), Axes: axes}

	if req.Persist {
		// One load → validate → write → reload for the WHOLE overlay, not one
		// per target (wave 6.3.L review): a per-target loop rewrote the file and
		// re-read every rule N times for one request, and a failure on target
		// number two left target number one already persisted and hot-reloaded —
		// a half-applied exception nobody asked for and no response reported.
		persisted, perr := s.persistTuningExceptions(overlay.Overlays)
		if perr != nil {
			http.Error(w, "Failed to persist exception: "+perr.Error(), http.StatusInternalServerError)
			return
		}
		resp.Persisted = persisted
	}

	w.Header().Set("Content-Type", "application/json")
	// #nosec G104 -- response encode error is not actionable once headers are written; other handlers in this file follow the same pattern
	json.NewEncoder(w).Encode(resp) //nolint:errcheck
}

// persistTuningException appends exc to the rule_id entry in the local-tuning
// overlay file. Thin wrapper over persistTuningExceptions for the single-rule
// case; see there for the contract.
func (s *Server) persistTuningException(ruleID string, exc correlator.RuleException) (bool, error) {
	return s.persistTuningExceptions([]correlator.RuleTuningOverlay{
		{RuleID: ruleID, Exceptions: []correlator.RuleException{exc}},
	})
}

// persistTuningExceptions appends every exception in additions to its rule_id
// entry in the local-tuning overlay file (creating entries as needed),
// validates the RESULTING overlay against the currently loaded rules, and
// writes it back to disk — once, for all of them. Returns false without error
// if no overlay path is configured; the caller still gets the YAML snippet to
// copy manually.
//
// All-or-nothing on purpose (wave 6.3.L): one Rego-visible name can resolve to
// several base rules (№413), and an exception that landed on three of nine
// rules would suppress an arbitrary part of what the analyst asked about while
// the response reported a single boolean. Validation runs on the merged
// overlay, the file is written once, and the rules are reloaded once.
func (s *Server) persistTuningExceptions(additions []correlator.RuleTuningOverlay) (bool, error) {
	s.mu.RLock()
	path := s.localTuningPath
	s.mu.RUnlock()
	if path == "" {
		return false, nil
	}

	s.tuningWriteMu.Lock()
	defer s.tuningWriteMu.Unlock()

	overlay, err := correlator.LoadTuningOverlay(path)
	if err != nil {
		return false, fmt.Errorf("load existing overlay: %w", err)
	}
	if overlay == nil {
		overlay = &correlator.TuningOverlay{}
	}

	for _, add := range additions {
		found := false
		for i := range overlay.Overlays {
			if overlay.Overlays[i].RuleID == add.RuleID {
				overlay.Overlays[i].Exceptions = append(overlay.Overlays[i].Exceptions, add.Exceptions...)
				found = true
				break
			}
		}
		if !found {
			overlay.Overlays = append(overlay.Overlays, correlator.RuleTuningOverlay{
				RuleID:     add.RuleID,
				Exceptions: append([]correlator.RuleException(nil), add.Exceptions...),
			})
		}
	}

	// Validate against a deep copy of the live rules — ApplyTuningOverlay
	// appends into Rule.Exceptions, and GetRules only shallow-copies the
	// slice header, so validating against the copy-of-copy below avoids
	// aliasing into the engine's shared backing array.
	rules := s.getRules()
	validation := make([]correlator.Rule, len(rules))
	copy(validation, rules)
	for i := range validation {
		validation[i].Exceptions = append([]correlator.RuleException(nil), validation[i].Exceptions...)
	}
	if _, err := correlator.ApplyTuningOverlay(validation, overlay); err != nil {
		return false, fmt.Errorf("generated exception failed validation: %w", err)
	}

	data, err := yaml.Marshal(overlay)
	if err != nil {
		return false, fmt.Errorf("marshal overlay: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return false, fmt.Errorf("write overlay file: %w", err)
	}

	if s.rulesReloadFn != nil {
		if err := s.rulesReloadFn(); err != nil {
			s.logger.Warn("tuning: overlay written but rules reload failed", "error", err)
		}
	}

	return true, nil
}

// IncidentIngestStateResponse is the body of GET/POST
// /api/v1/tuning/incident-ingest.
type IncidentIngestStateResponse struct {
	// Enabled is the state AFTER the call.
	Enabled bool `json:"enabled"`
	// Changed reports whether this call flipped the state (false on a GET, and
	// on a POST that asked for the state it was already in) — an A/B window
	// must not record a transition that never happened.
	Changed bool `json:"changed"`
}

// handleIncidentIngest serves GET/POST /api/v1/tuning/incident-ingest — the
// runtime switch for the incident layer (wave 6.3.L.1, item 2, №423).
//
// The A/B it exists for: one binary, one node, two adjacent windows, three
// quantities (RSS, ring-buffer losses, alert volume). Restarting the agent
// between the windows would measure the restart — cleared baselines, re-grown
// heap, a fresh profiler — and not the layer ([[ab-toggle-measures-the-restart]]),
// so the state is flipped in place and the response says whether it actually
// moved.
//
// Admin-only, like every other write on this server; a GET is allowed for a
// viewer through the usual isViewerAllowed path.
func (s *Server) handleIncidentIngest(w http.ResponseWriter, r *http.Request) {
	s.serveRuntimeSwitch(w, r, "incident-ingest")
}

// handleAlertAggregation serves GET/POST /api/v1/tuning/alert-aggregation —
// the same runtime switch shape for the alert-aggregation layer (wave 6.3.L.1,
// item 4, №425).
//
// Why a switch and not the config file: the layer folds repeats in the STORE,
// so leaving it on for a whole run would move store-read quantities of every
// other criterion in the run. The pipeline turns it on for one dedicated
// window after the measured window has closed, takes the verdict there, and
// turns it back off.
func (s *Server) handleAlertAggregation(w http.ResponseWriter, r *http.Request) {
	s.serveRuntimeSwitch(w, r, "alert-aggregation")
}

func (s *Server) serveRuntimeSwitch(w http.ResponseWriter, r *http.Request, name string) {
	s.mu.RLock()
	sw, wired := s.runtimeSwitches[name]
	s.mu.RUnlock()
	if !wired || sw.get == nil || sw.set == nil {
		http.Error(w, fmt.Sprintf("runtime switch %q is not wired in this build", name), http.StatusServiceUnavailable)
		return
	}
	get, set := sw.get, sw.set

	switch r.Method {
	case http.MethodGet:
		writeJSON(w, IncidentIngestStateResponse{Enabled: get()})
	case http.MethodPost:
		if scope, ok := TokenScopeFromContext(r.Context()); ok && scope.Role != RoleAdmin {
			http.Error(w, "Forbidden: admin role required", http.StatusForbidden)
			return
		}
		var req struct {
			Enabled *bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.Enabled == nil {
			http.Error(w, `"enabled" (boolean) is required`, http.StatusBadRequest)
			return
		}
		before := get()
		set(*req.Enabled)
		after := get()
		s.logger.Warn("tuning: runtime switch flipped (wave 6.3.L.1 measurement switch)",
			"switch", name, "from", before, "to", after)
		writeJSON(w, IncidentIngestStateResponse{Enabled: after, Changed: before != after})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
