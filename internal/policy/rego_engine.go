// Package policy provides Rego/OPA policy-as-code evaluation for alerts.
package policy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/open-policy-agent/opa/rego"
)

// PolicyDecision represents the result of evaluating an alert against Rego policies.
type PolicyDecision struct {
	RuleID         string
	Severity       types.Severity
	Message        string
	Action         string
	MitreTechnique string
	Matched        bool
}

// RegoEngine evaluates alerts against Rego policies.
// It uses pre-compiled policies via PrepareForEval for optimal performance.
type RegoEngine struct {
	mu         sync.RWMutex
	prepared   *rego.PreparedEvalQuery // Pointer for atomic swap
	policies   map[string]string       // filename -> content
	rulesDir   string
	enabled    atomic.Bool

	// Metrics
	// evalDuration is called with the Evaluate latency when non-nil.
	// Use SetDurationObserver to wire up a prometheus.Observer or any callback.
	evalDuration  atomic.Value // stores DurationObserver
	evalTotal     atomic.Uint64
	evalErrors    atomic.Uint64
	reloadCounter atomic.Uint64
}

// DurationObserver is a callback that receives Evaluate latency measurements.
type DurationObserver func(time.Duration)

// RegoEngineConfig holds configuration for the Rego engine.
type RegoEngineConfig struct {
	Enabled  bool
	RulesDir string
}

// DefaultRegoEngineConfig returns a default configuration.
func DefaultRegoEngineConfig() RegoEngineConfig {
	return RegoEngineConfig{
		Enabled:  true,
		RulesDir: "rules/rego",
	}
}

// NewRegoEngine creates a new Rego engine and loads policies.
func NewRegoEngine(config RegoEngineConfig) (*RegoEngine, error) {
	engine := &RegoEngine{
		policies: make(map[string]string),
		rulesDir: config.RulesDir,
	}
	engine.enabled.Store(config.Enabled)

	if !config.Enabled {
		return engine, nil
	}

	if err := engine.loadPolicies(); err != nil {
		return nil, fmt.Errorf("policy/rego: load policies: %w", err)
	}

	if err := engine.compile(context.Background()); err != nil {
		return nil, fmt.Errorf("policy/rego: compile policies: %w", err)
	}

	return engine, nil
}

// loadPolicies reads all .rego files from the rules directory.
func (re *RegoEngine) loadPolicies() error {
	re.policies = make(map[string]string)

	entries, err := os.ReadDir(re.rulesDir)
	if err != nil {
		if os.IsNotExist(err) {
			// Rules directory doesn't exist, that's ok
			return nil
		}
		return fmt.Errorf("read rules dir %s: %w", re.rulesDir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".rego") {
			continue
		}
		if strings.HasSuffix(entry.Name(), "_test.rego") {
			continue
		}

		path := filepath.Join(re.rulesDir, entry.Name())
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read policy %s: %w", path, err)
		}

		re.policies[entry.Name()] = string(content)
	}

	return nil
}

// compile creates a prepared evaluation query from loaded policies.
// Accepts a context so callers can cancel a long-running compilation (e.g.
// during graceful shutdown or hot-reload with a deadline).
func (re *RegoEngine) compile(ctx context.Context) error {
	if len(re.policies) == 0 {
		// No policies loaded, clear prepared query
		re.mu.Lock()
		re.prepared = nil
		re.mu.Unlock()
		return nil
	}

	// Build rego options from loaded policies
	var opts []func(*rego.Rego)
	for filename, content := range re.policies {
		opts = append(opts, rego.Module(filename, content))
	}

	// Add query for data.ebpf_guard.allow and data.ebpf_guard.decisions
	opts = append(opts, rego.Query("data.ebpf_guard"))

	// Create rego instance and prepare for evaluation
	r := rego.New(opts...)
	prepared, err := r.PrepareForEval(ctx)
	if err != nil {
		return fmt.Errorf("prepare for eval: %w", err)
	}

	re.mu.Lock()
	re.prepared = &prepared
	re.mu.Unlock()

	return nil
}

// Evaluate runs the alert through Rego policies and returns decisions.
// This method is called ONLY on alerts (post-YAML-filter), never on raw events.
// Performance target: < 500µs p99 with pre-compiled policies.
func (re *RegoEngine) Evaluate(ctx context.Context, alert types.Alert) ([]PolicyDecision, error) {
	if !re.enabled.Load() {
		return nil, nil
	}

	re.mu.RLock()
	prepared := re.prepared
	re.mu.RUnlock()

	if prepared == nil {
		return nil, nil
	}

	start := time.Now()
	re.evalTotal.Add(1)

	// Convert alert to input for Rego
	input := alertToInput(alert)

	// Evaluate against prepared query
	rs, err := prepared.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		re.evalErrors.Add(1)
		return nil, fmt.Errorf("rego eval: %w", err)
	}

	if fn, ok := re.evalDuration.Load().(DurationObserver); ok {
		fn(time.Since(start))
	}

	// Extract decisions from results
	var decisions []PolicyDecision
	for _, result := range rs {
		for _, expr := range result.Expressions {
			if expr.Value == nil {
				continue
			}

			// Parse decisions from the result
			if decisionsData, ok := expr.Value.(map[string]interface{}); ok {
				if decisionsList, ok := decisionsData["decisions"].([]interface{}); ok {
					for _, d := range decisionsList {
						if decisionMap, ok := d.(map[string]interface{}); ok {
							decision := parseDecision(decisionMap)
							if decision.Matched {
								decisions = append(decisions, decision)
							}
						}
					}
				}
			}
		}
	}

	return decisions, nil
}

// alertToInput converts an Alert to a map for Rego input.
func alertToInput(alert types.Alert) map[string]interface{} {
	return map[string]interface{}{
		"id":       alert.ID,
		"rule_id":  alert.RuleID,
		"rule_name": alert.RuleName,
		"severity": string(alert.Severity),
		"pid":      alert.PID,
		"comm":     alert.Comm,
		"message":  alert.Message,
		"details":  alert.Details,
		"trace_id": alert.TraceID,
		"enrichment": map[string]interface{}{
			"pod_name":     alert.Enrichment.PodName,
			"namespace":    alert.Enrichment.Namespace,
			"pod_uid":      alert.Enrichment.PodUID,
			"node_name":    alert.Enrichment.NodeName,
			"labels":       alert.Enrichment.Labels,
			"annotations":  alert.Enrichment.Annotations,
			"container_id": alert.Enrichment.ContainerID,
		},
		"event": eventToInput(alert.Event),
	}
}

// eventToInput converts an Event to a map for Rego input.
func eventToInput(event types.Event) map[string]interface{} {
	result := map[string]interface{}{
		"type":        int(event.Type),
		"timestamp":   event.Timestamp,
		"pid":         event.PID,
		"tgid":        event.TGID,
		"ppid":        event.PPID,
		"uid":         event.UID,
		"comm":        string(trimNullBytes(event.Comm[:])),
		"parent_comm": string(trimNullBytes(event.ParentComm[:])),
	}

	if event.Syscall != nil {
		result["syscall"] = map[string]interface{}{
			"nr":   event.Syscall.Nr,
			"ret":  event.Syscall.Ret,
			"args": event.Syscall.Args,
		}
	}

	if event.Network != nil {
		result["network"] = map[string]interface{}{
			"saddr":  event.Network.Saddr,
			"daddr":  event.Network.Daddr,
			"sport":  event.Network.Sport,
			"dport":  event.Network.Dport,
			"proto":  event.Network.Proto,
			"family": int(event.Network.Family),
		}
	}

	if event.File != nil {
		result["file"] = map[string]interface{}{
			"filename": string(trimNullBytes(event.File.Filename[:])),
			"flags":    event.File.Flags,
			"mode":     event.File.Mode,
			"op":       event.File.Op,
		}
	}

	if event.TLS != nil {
		result["tls"] = map[string]interface{}{
			"direction": int(event.TLS.Direction),
			"data_len":  event.TLS.DataLen,
			"data":      string(trimNullBytes(event.TLS.Data[:])),
		}
	}

	if event.DNS != nil {
		result["dns"] = map[string]interface{}{
			"qname":        event.DNS.QName,
			"qtype":        event.DNS.QType,
			"rcode":        event.DNS.RCode,
			"direction":    int(event.DNS.Direction),
			"response_ips": event.DNS.ResponseIPs,
		}
	}

	return result
}

// trimNullBytes removes trailing null bytes from a byte slice.
func trimNullBytes(b []byte) []byte {
	for i, v := range b {
		if v == 0 {
			return b[:i]
		}
	}
	return b
}

// parseDecision converts a Rego result map to a PolicyDecision.
func parseDecision(m map[string]interface{}) PolicyDecision {
	d := PolicyDecision{
		Matched: false,
	}

	if matched, ok := m["matched"].(bool); ok {
		d.Matched = matched
	}
	if ruleID, ok := m["rule_id"].(string); ok {
		d.RuleID = ruleID
	}
	if severity, ok := m["severity"].(string); ok {
		d.Severity = types.Severity(severity)
	}
	if message, ok := m["message"].(string); ok {
		d.Message = message
	}
	if action, ok := m["action"].(string); ok {
		d.Action = action
	}
	if mitre, ok := m["mitre_technique"].(string); ok {
		d.MitreTechnique = mitre
	}

	return d
}

// Reload reloads policies from disk and recompiles using context.Background().
// Use ReloadWithContext when a deadline or cancellation is needed.
func (re *RegoEngine) Reload() error {
	return re.ReloadWithContext(context.Background())
}

// ReloadWithContext reloads policies from disk and recompiles.
// The supplied context can be used to cancel a slow compilation.
// Safe for concurrent use — the prepared query is swapped atomically.
func (re *RegoEngine) ReloadWithContext(ctx context.Context) error {
	if err := re.loadPolicies(); err != nil {
		return fmt.Errorf("reload policies: %w", err)
	}
	if err := re.compile(ctx); err != nil {
		return fmt.Errorf("recompile policies: %w", err)
	}
	re.reloadCounter.Add(1)
	return nil
}

// SetDurationObserver wires up a latency callback for Evaluate calls.
// Pass nil to disable. Thread-safe.
func (re *RegoEngine) SetDurationObserver(fn DurationObserver) {
	re.evalDuration.Store(fn)
}

// SetEnabled enables or disables the Rego engine.
func (re *RegoEngine) SetEnabled(enabled bool) {
	re.enabled.Store(enabled)
}

// IsEnabled returns whether the Rego engine is enabled.
func (re *RegoEngine) IsEnabled() bool {
	return re.enabled.Load()
}

// GetStats returns engine statistics.
func (re *RegoEngine) GetStats() RegoEngineStats {
	return RegoEngineStats{
		EvalTotal:     re.evalTotal.Load(),
		EvalErrors:    re.evalErrors.Load(),
		ReloadCounter: re.reloadCounter.Load(),
		PolicyCount:   len(re.policies),
	}
}

// RegoEngineStats holds Rego engine statistics.
type RegoEngineStats struct {
	EvalTotal     uint64
	EvalErrors    uint64
	ReloadCounter uint64
	PolicyCount   int
}
