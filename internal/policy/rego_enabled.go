//go:build rego

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

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Supported reports whether Rego/OPA evaluation is actually compiled into this
// binary. It is true here — built WITH the `rego` build tag: policies are loaded, compiled and evaluated.
//
// №389 (волна 6.3-up): without this constant the two build variants are
// indistinguishable at run time — NewRegoEngine succeeds either way, the stub
// silently answers "no decisions", and `policy.rego.enabled: true` reads as a
// working layer in the config while nothing evaluates. Callers use it to say so
// out loud rather than to change behaviour.
const Supported = true

// PolicyDecision represents the result of evaluating an alert against Rego policies.
type PolicyDecision struct {
	RuleID         string
	Severity       types.Severity
	Message        string
	Action         string
	MitreTechnique string
	Matched        bool
}

// regoPartitionModules maps a partition name to the list of .rego filenames that
// should be compiled for that partition.  base.rego is always included; the
// remaining filenames are the sub-packages relevant to that event class.
// Using a subset cuts OPA evaluation time by 2-4× compared to a monolithic query.
var regoPartitionModules = map[string][]string{
	"syscall": {"base.rego", "process_injection.rego", "lineage.rego"},
	"network": {"base.rego", "network.rego", "k8s.rego", "lineage.rego"},
	"file":    {"base.rego", "file.rego", "k8s.rego", "lineage.rego"},
	"dns":     {"base.rego", "dns.rego", "lineage.rego"},
	"full":    {"base.rego", "dns.rego", "file.rego", "k8s.rego", "lineage.rego", "network.rego", "process_injection.rego"},
}

// eventTypePartition maps an event type to its partition name so Evaluate picks
// the smallest PreparedEvalQuery that covers all rules for that event class.
func eventTypePartition(et types.EventType) string {
	switch et {
	case types.EventSyscall, types.EventPrivesc, types.EventKmodLoad, types.EventCgroupEsc:
		return "syscall"
	case types.EventTCPConnect, types.EventNetClose:
		return "network"
	case types.EventFileAccess:
		return "file"
	case types.EventDNS:
		return "dns"
	default:
		return "full"
	}
}

// decisionsPool recycles []PolicyDecision backing arrays across Evaluate calls.
var decisionsPool = sync.Pool{
	New: func() any { s := make([]PolicyDecision, 0, 8); return &s },
}

// RegoEngine evaluates alerts against Rego policies.
// It uses pre-compiled policies via PrepareForEval for optimal performance.
// Per-event-type partitioned queries reduce OPA evaluation time by 2-4× vs a
// monolithic full-namespace query.
type RegoEngine struct {
	mu          sync.RWMutex
	partitioned map[string]*lazyQuery // partition → targeted query, compiled on first use
	fallback    *lazyQuery            // full-namespace query for a partition that cannot compile
	policies    map[string]string     // filename -> content
	rulesDir    string
	enabled     atomic.Bool

	// Metrics
	// evalDuration is called with the Evaluate latency when non-nil.
	// Use SetDurationObserver to wire up a prometheus.Observer or any callback.
	evalDuration  atomic.Value // stores DurationObserver
	evalTotal     atomic.Uint64
	evalErrors    atomic.Uint64
	reloadCounter atomic.Uint64
}

// lazyQuery is a PreparedEvalQuery compiled on first use. OPA keeps a full
// compiler (all modules, indexes, type environment) behind every prepared
// query, ≈1.5 MiB each on the shipped policy set; alerts reach only some event
// classes, so a query nobody asks for is never built (wave 8.2, C4).
type lazyQuery struct {
	modules map[string]string // filename -> content
	once    sync.Once
	pq      *rego.PreparedEvalQuery
	err     error
}

func newLazyQuery(modules map[string]string) *lazyQuery {
	return &lazyQuery{modules: modules}
}

// get compiles the query on the first call; later calls return the same result.
func (lq *lazyQuery) get(ctx context.Context) (*rego.PreparedEvalQuery, error) {
	lq.once.Do(func() {
		opts := make([]func(*rego.Rego), 0, len(lq.modules)+1)
		for filename, content := range lq.modules {
			opts = append(opts, rego.Module(filename, content))
		}
		opts = append(opts, rego.Query("data.ebpf_guard.decisions"))
		// A cancelled caller context must not poison the cached result.
		pq, err := rego.New(opts...).PrepareForEval(context.WithoutCancel(ctx))
		if err != nil {
			lq.err = err
			return
		}
		lq.pq = &pq
		lq.modules = nil // the compiler owns the parsed modules now
	})
	return lq.pq, lq.err
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

// compile validates the loaded policies and installs lazily compiled queries:
// a full-namespace fallback and one per event-class partition (only modules
// that can fire for that class). Validation is a single throw-away compile of
// the full module set, so a broken policy still fails startup and hot-reload
// instead of the first alert; the validated compiler is garbage afterwards.
// Each query is then built by lazyQuery.get when an alert of its class first
// reaches Evaluate — an empty rules dir builds none.
// Accepts a context so callers can cancel a long-running validation (e.g.
// during graceful shutdown or hot-reload with a deadline).
func (re *RegoEngine) compile(ctx context.Context) error {
	if len(re.policies) == 0 {
		re.mu.Lock()
		re.fallback = nil
		re.partitioned = nil
		re.mu.Unlock()
		return nil
	}

	if _, err := ast.CompileModules(re.policies); err != nil {
		return fmt.Errorf("prepare for eval: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("prepare for eval: %w", err)
	}

	// OPA skips sub-packages that reference undefined documents (empty set
	// semantics), so a missing module simply produces no rules.
	partitioned := make(map[string]*lazyQuery, len(regoPartitionModules))
	for partition, filenames := range regoPartitionModules {
		mods := make(map[string]string, len(filenames))
		for _, fn := range filenames {
			if content, ok := re.policies[fn]; ok {
				mods[fn] = content
			}
		}
		if len(mods) == 0 {
			continue
		}
		partitioned[partition] = newLazyQuery(mods)
	}

	all := make(map[string]string, len(re.policies))
	for fn, content := range re.policies {
		all[fn] = content
	}

	re.mu.Lock()
	re.fallback = newLazyQuery(all)
	re.partitioned = partitioned
	re.mu.Unlock()

	return nil
}

// Evaluate runs the alert through Rego policies and returns decisions.
// This method is called ONLY on alerts (post-YAML-filter), never on raw events.
//
// Performance: per-event-type partitioned queries cut OPA evaluation time by
// 2-4× vs a full-namespace query by loading only the rule sub-packages that
// can fire for the given event class (e.g. dns.rego for DNS events only).
//
// Target: < 250 µs p99 for typed events (network/file/dns/syscall).
func (re *RegoEngine) Evaluate(ctx context.Context, alert types.Alert) ([]PolicyDecision, error) {
	if !re.enabled.Load() {
		return nil, nil
	}

	// Pick the smallest prepared query that covers this event type.
	partition := eventTypePartition(alert.Event.Type)

	re.mu.RLock()
	lq := re.partitioned[partition]
	fallback := re.fallback
	re.mu.RUnlock()

	if lq == nil {
		lq = fallback
	}
	if lq == nil {
		return nil, nil
	}
	prepared, err := lq.get(ctx)
	if err != nil && fallback != nil && lq != fallback {
		// A partition that cannot compile falls back to the full query.
		prepared, err = fallback.get(ctx)
	}
	if err != nil {
		re.evalErrors.Add(1)
		return nil, fmt.Errorf("rego compile: %w", err)
	}

	start := time.Now()
	re.evalTotal.Add(1)

	// Convert alert to input for Rego
	input := alertToInput(alert)

	// Evaluate against the selected (partitioned or full) query.
	// The query is "data.ebpf_guard.decisions" which returns the decisions set
	// directly — avoiding the overhead of serialising the entire ebpf_guard namespace.
	rs, err := prepared.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		re.evalErrors.Add(1)
		return nil, fmt.Errorf("rego eval: %w", err)
	}

	if fn, ok := re.evalDuration.Load().(DurationObserver); ok && fn != nil {
		fn(time.Since(start))
	}

	// Extract decisions from the result set.
	// The query returns data.ebpf_guard.decisions which is a Rego set; OPA
	// serialises sets as []interface{} in the Go bindings.
	decisionsPtr := decisionsPool.Get().(*[]PolicyDecision)
	decisions := (*decisionsPtr)[:0]

	for _, result := range rs {
		for _, expr := range result.Expressions {
			if expr.Value == nil {
				continue
			}
			decisionsList, ok := expr.Value.([]interface{})
			if !ok {
				continue
			}
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

	if len(decisions) == 0 {
		*decisionsPtr = decisions
		decisionsPool.Put(decisionsPtr)
		return nil, nil
	}

	// Detach from pool — caller owns the result until they discard it.
	out := make([]PolicyDecision, len(decisions))
	copy(out, decisions)
	decisions = decisions[:0]
	*decisionsPtr = decisions
	decisionsPool.Put(decisionsPtr)

	return out, nil
}

// alertToInput converts an Alert to a map for Rego input.
func alertToInput(alert types.Alert) map[string]interface{} {
	return map[string]interface{}{
		"id":        alert.ID,
		"rule_id":   alert.RuleID,
		"rule_name": alert.RuleName,
		"severity":  string(alert.Severity),
		"pid":       alert.PID,
		"comm":      alert.Comm,
		"message":   alert.Message,
		"details":   alert.Details,
		"trace_id":  alert.TraceID,
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
			"data":      string(trimNullBytes(event.TLS.CapturedData())),
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
