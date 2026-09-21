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
	// Persist writes the generated exception into the local-tuning overlay
	// file (admin-only, hot-reloaded). When false, the endpoint only returns
	// the YAML snippet for the operator to copy manually.
	Persist bool `json:"persist"`
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
}

// commFieldForEventType returns the rule-condition field name that carries
// the process name for eventType, and whether that event type supports a
// comm-based exception at all. Kept in sync with the field-name allowlists in
// rule_loader.go: "comm" for syscalls, "proc.comm" everywhere else that
// carries process enrichment.
//
//nolint:exhaustive // only syscall/network/file events carry a comm-bearing field usable in an exception condition; every other event type falls through to the default (unsupported).
func commFieldForEventType(eventType types.EventType) (string, bool) {
	switch eventType {
	case types.EventSyscall:
		return "comm", true
	case types.EventTCPConnect, types.EventFileAccess:
		return "proc.comm", true
	default:
		return "", false
	}
}

// buildException constructs the RuleException for req against the matching
// rule's event type. A path prefix is only applied to file-access rules,
// where "file.path" is a valid condition field.
func buildException(req TuningExceptionRequest, eventType types.EventType) (correlator.RuleException, error) {
	field, ok := commFieldForEventType(eventType)
	if !ok {
		return correlator.RuleException{}, fmt.Errorf("exception generation is not supported for this rule's event type")
	}

	commCond := correlator.RuleCondition{Field: field, Op: correlator.OpEquals, Values: []string{req.Comm}}

	if req.PathPrefix != "" && eventType == types.EventFileAccess {
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
	if req.RuleID == "" || req.Name == "" || req.Comm == "" {
		http.Error(w, "rule_id, name, and comm are required", http.StatusBadRequest)
		return
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
	for _, target := range targets {
		exc, err := buildException(req, target.EventType)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		overlay.Overlays = append(overlay.Overlays, correlator.RuleTuningOverlay{
			RuleID:     target.ID,
			Exceptions: []correlator.RuleException{exc},
		})
	}

	data, err := yaml.Marshal(overlay)
	if err != nil {
		s.logger.Error("tuning: failed to marshal exception snippet", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	resp := TuningExceptionResponse{YAML: string(data)}

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
