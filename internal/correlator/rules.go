// Package correlator provides event correlation and rule-based detection.
package correlator

import (
	"encoding/binary"
	"fmt"
	"hash"
	"hash/fnv"
	"math/rand"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/zugolO/ebpf-guard/internal/util"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Sampling metrics — only incremented when a rule has effective SampleRate < 1.0.
// Rules with SampleRate == 1.0 (default) never touch these counters.
var (
	ruleSampledTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_guard_rule_sampled_total",
			Help: "Events that passed the per-rule sampling gate and were evaluated against the rule condition",
		},
		[]string{"rule_id", "mode", "sample_rate"},
	)
	ruleSkippedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_guard_rule_skipped_total",
			Help: "Events dropped by the per-rule sampling gate without condition evaluation",
		},
		[]string{"rule_id", "mode", "sample_rate"},
	)
)

// alertsPool recycles the backing arrays of []types.Alert slices returned by
// Evaluate. Most calls match 0-2 rules; a capacity-4 slab covers the common
// case without reallocation while keeping per-call heap traffic to zero on
// the hot path (no match → put back immediately).
var alertsPool = sync.Pool{
	New: func() any { s := make([]types.Alert, 0, 4); return &s },
}

// fnvHasherPool recycles fnv.New32() hashers used by shouldSample on the
// deterministic code path (active only when rule.SampleRate < 1.0).
var fnvHasherPool = sync.Pool{
	New: func() any { return fnv.New32() },
}

// RuleConditionOperator defines the comparison operation for a rule condition.
type RuleConditionOperator string

const (
	// OpIn checks if field value is in the list of values.
	OpIn RuleConditionOperator = "in"
	// OpNotIn checks if field value is not in the list of values.
	OpNotIn RuleConditionOperator = "not_in"
	// OpEquals checks if field equals a value.
	OpEquals RuleConditionOperator = "equals"
	// OpNotEquals checks if field does not equal a value.
	OpNotEquals RuleConditionOperator = "not_equals"
	// OpPrefix checks if field starts with any of the prefixes.
	OpPrefix RuleConditionOperator = "prefix"
	// OpNotPrefix checks if field does not start with any of the given prefixes.
	OpNotPrefix RuleConditionOperator = "not_prefix"
	// OpRegex checks if field matches a regex pattern.
	OpRegex RuleConditionOperator = "regex"
	// OpGreaterThan checks if numeric field is greater than value.
	OpGreaterThan RuleConditionOperator = "gt"
	// OpLessThan checks if numeric field is less than value.
	OpLessThan RuleConditionOperator = "lt"
	// OpGreaterOrEqual checks if numeric field is greater than or equal to value.
	OpGreaterOrEqual RuleConditionOperator = "gte"
	// OpLessOrEqual checks if numeric field is less than or equal to value.
	OpLessOrEqual RuleConditionOperator = "lte"
	// OpInCIDR checks if IP address is within CIDR range.
	OpInCIDR RuleConditionOperator = "in_cidr"
	// OpNotInCIDR checks if IP address is not within CIDR range.
	OpNotInCIDR RuleConditionOperator = "not_in_cidr"
	// OpCapsGained checks if any of the named capabilities were gained (new &^ old).
	OpCapsGained RuleConditionOperator = "caps_gained"
	// OpCapsDropped checks if any of the named capabilities were dropped (old &^ new).
	OpCapsDropped RuleConditionOperator = "caps_dropped"
	// OpSuffix checks if the field value ends with any of the given suffixes.
	OpSuffix RuleConditionOperator = "suffix"
	// OpNotSuffix checks if the field value does not end with any of the given suffixes.
	OpNotSuffix RuleConditionOperator = "not_suffix"
	// OpContains checks if the field value contains any of the given substrings.
	OpContains RuleConditionOperator = "contains"
)

// condOpCode is a precomputed numeric code for a RuleConditionOperator.
// Replaces string switch statements with integer switch in the hot path,
// turning ~10 ns string comparisons into ~2 ns jump-table dispatch.
type condOpCode uint8

const (
	condOpUnknown    condOpCode = iota
	condOpIn                    // "in"
	condOpNotIn                 // "not_in"
	condOpEquals                // "equals"
	condOpNotEquals             // "not_equals"
	condOpPrefix                // "prefix"
	condOpNotPrefix             // "not_prefix"
	condOpSuffix                // "suffix"
	condOpNotSuffix             // "not_suffix"
	condOpContains              // "contains"
	condOpRegex                 // "regex"
	condOpGT                    // "gt"
	condOpLT                    // "lt"
	condOpGTE                   // "gte"
	condOpLTE                   // "lte"
	condOpInCIDR                // "in_cidr"
	condOpNotInCIDR             // "not_in_cidr"
	condOpCapsGained            // "caps_gained"
	condOpCapsDropped           // "caps_dropped"
)

// opCodeOf converts a RuleConditionOperator string to its numeric code.
// Called once at rule load time; the result is cached in RuleCondition.opCode.
func opCodeOf(op RuleConditionOperator) condOpCode {
	switch op {
	case OpIn:
		return condOpIn
	case OpNotIn:
		return condOpNotIn
	case OpEquals, "eq":
		return condOpEquals
	case OpNotEquals, "neq":
		return condOpNotEquals
	case OpPrefix:
		return condOpPrefix
	case OpNotPrefix:
		return condOpNotPrefix
	case OpSuffix:
		return condOpSuffix
	case OpNotSuffix:
		return condOpNotSuffix
	case OpContains:
		return condOpContains
	case OpRegex:
		return condOpRegex
	case OpGreaterThan:
		return condOpGT
	case OpLessThan:
		return condOpLT
	case OpGreaterOrEqual:
		return condOpGTE
	case OpLessOrEqual:
		return condOpLTE
	case OpInCIDR:
		return condOpInCIDR
	case OpNotInCIDR:
		return condOpNotInCIDR
	case OpCapsGained:
		return condOpCapsGained
	case OpCapsDropped:
		return condOpCapsDropped
	}
	return condOpUnknown
}

// RuleCondition defines a single condition for rule evaluation.
type RuleCondition struct {
	Field  string                `yaml:"field"`
	Op     RuleConditionOperator `yaml:"op"`
	Values []string              `yaml:"values"`
	// setKey is the pre-computed valueSetCache key for OpIn/OpNotIn conditions.
	// Populated by RuleEngine.compilePatterns; never serialized.
	setKey string
	// valueSet is a direct pointer to the pre-built membership set for OpIn/OpNotIn.
	// Eliminates the re.valueSetCache[key] map lookup on the hot path: one
	// map lookup instead of two. Set by compileCondPtr; never serialized.
	valueSet map[string]struct{}
	// opCode is the precomputed numeric code for Op. evaluateCondition switches
	// on this integer (jump-table, ~2 ns) instead of Op string (~10 ns).
	opCode condOpCode
}

// RuleConditionGroup allows combining multiple conditions with AND/OR logic.
type RuleConditionGroup struct {
	// Operator is "and" or "or"
	Operator string `yaml:"operator"`
	// Conditions to evaluate
	Conditions []RuleCondition `yaml:"conditions"`
	// SubGroups allows nested condition groups for complex logic
	SubGroups []RuleConditionGroup `yaml:"subgroups,omitempty"`
}

// RuleAction defines what to do when a rule matches.
type RuleAction string

const (
	// ActionAlert generates an alert when the rule matches.
	ActionAlert RuleAction = "alert"
	// ActionDrop silently drops the event (for filtering).
	ActionDrop RuleAction = "drop"
	// ActionBlock blocks matching network packets using eBPF TC/XDP.
	ActionBlock RuleAction = "block"
	// ActionKill sends SIGKILL to the offending process.
	ActionKill RuleAction = "kill"
	// ActionThrottle rate-limits the offending process via cgroups v2.
	ActionThrottle RuleAction = "throttle"
)

// Rule defines a detection rule.
type Rule struct {
	ID          string          `yaml:"id"`
	Name        string          `yaml:"name"`
	Description string          `yaml:"description"`
	EventType   types.EventType `yaml:"event_type"`
	// skipSampler is precomputed at load time: true when SampleRate is absent
	// or ≥ 1.0 (i.e. no static sampling configured). matchesTyped tests this
	// flag before acquiring the sampler lock, reducing lock traffic for the
	// overwhelmingly common case of fully-evaluated (rate=1.0) rules.
	// Not serialized; set by RuleEngine.buildTypeIndex.
	skipSampler bool
	// Condition is a single condition (for simple rules)
	Condition RuleCondition `yaml:"condition"`
	// ConditionGroup allows complex AND/OR logic (takes precedence over Condition)
	ConditionGroup *RuleConditionGroup `yaml:"condition_group,omitempty"`
	Severity       types.AlertSeverity `yaml:"severity"`
	Action         RuleAction          `yaml:"action"`
	// Tags are optional metadata for rule categorization and filtering
	Tags []string `yaml:"tags,omitempty"`
	// Sampling holds the nested per-rule sampling configuration.
	// Takes precedence over the flat SampleRate/SampleDeterministic fields if set.
	//
	//   sampling:
	//     rate: 0.1        # evaluate 10% of matching events
	//     mode: hash_pid   # "random" (default) or "hash_pid"
	Sampling *RuleSampling `yaml:"sampling,omitempty"`
	// SampleRate controls the fraction of matching events that are evaluated.
	// 1.0 (default) evaluates every event; 0.1 evaluates ~10%.
	// Validated to be in (0.0, 1.0]; missing or 0 is treated as 1.0.
	// Deprecated: prefer the nested sampling block.
	SampleRate float64 `yaml:"sample_rate,omitempty"`
	// SampleDeterministic uses FNV(PID || timestamp>>30) for sampling instead of
	// a random number, ensuring the same PID is consistently sampled within ~1s windows.
	// Deprecated: prefer sampling.mode: hash_pid.
	SampleDeterministic bool `yaml:"sample_deterministic,omitempty"`
}

// RuleSet contains all loaded rules.
type RuleSet struct {
	Rules []Rule `yaml:"rules"`
}

// globalDNSAnalyzer is the package-level DNS entropy/n-gram calculator used by
// getFieldValue to evaluate enriched DNS rule fields (qname_entropy, qname_dga_score,
// qname_length, qname_digit_ratio, qname_subdomain_count, qname_is_dga) on demand.
var globalDNSAnalyzer = NewDNSEntropyCalculator()

// syscallNrStrings is a pre-computed lookup table for syscall numbers 0–511.
// Eliminates strconv.FormatInt allocations on the hot path in getFieldValue.
var syscallNrStrings [512]string

// fileOpNames maps FileEvent.Op to a human-readable name. Package-level array
// avoids the []string{...} literal allocation that would otherwise occur on
// every file-access rule evaluation (once per file event × rules with op field).
var fileOpNames = [3]string{"open", "read", "write"}

// gpuOpNames maps GPUEvent.Op to a human-readable name.
var gpuOpNames = [6]string{"alloc", "free", "memcpy_htod", "memcpy_dtoh", "memcpy_dtod", "kernel_launch"}

func init() {
	for i := range syscallNrStrings {
		syscallNrStrings[i] = strconv.Itoa(i)
	}
}

// byTypeSize is the fixed size of the byType array. EventType values are 1–14;
// 24 leaves headroom for future event types without resizing.
const byTypeSize = 24

// RuleEngine evaluates events against rules.
type RuleEngine struct {
	rules []Rule
	// byType indexes rules by event type for O(1) array dispatch.
	// EventType values are 1–13; index 0 is unused. Array access avoids the
	// hash/compare overhead of a map lookup on the hot path.
	// Rebuilt on hot-reload via buildTypeIndex.
	byType [byTypeSize][]Rule
	// compiled regex patterns for performance
	regexCache map[string]*regexp.Regexp
	// compiled CIDR ranges
	cidrCache map[string]*net.IPNet
	// valueSetCache maps a canonical key (sorted joined values) → set for O(1) OpIn/OpNotIn lookup.
	// Built once in compilePatterns; never mutated after construction.
	valueSetCache map[string]map[string]struct{}
	// sampler manages per-rule sample rates including adaptive overrides.
	sampler *RuleSampler
	// mu protects the rules slice
	mu sync.RWMutex
	// compilePatternsError records any error encountered during compilePatterns.
	// Rules are validated before reaching NewRuleEngineWithCache, so this should
	// be nil in production; it is a defence-in-depth check so compile failures
	// cannot silently drop patterns from the cache.
	compilePatternsError error
}

// CompileErrors returns any pattern compilation error from the last compilePatterns call.
// Returns nil when all patterns compiled successfully.
func (re *RuleEngine) CompileErrors() error {
	return re.compilePatternsError
}

// NewRuleEngine creates a new rule engine with the given rules.
func NewRuleEngine(rules []Rule) *RuleEngine {
	return NewRuleEngineWithCache(rules, nil)
}

// NewRuleEngineWithCache creates a RuleEngine and inherits compiled patterns from a
// prior engine so that unchanged regex/CIDR/set entries are not recompiled on hot-reload.
// Pass nil prior for the initial load.
//
// Unlike the old behaviour (which blindly copied ALL entries from the prior cache),
// this method first scans the new rules to collect which patterns are actually
// referenced, then selectively copies only those entries. This prevents stale
// entries from removed rules from accumulating indefinitely across repeated reloads.
func NewRuleEngineWithCache(rules []Rule, prior *RuleEngine) *RuleEngine {
	re := &RuleEngine{
		rules:         rules,
		regexCache:    make(map[string]*regexp.Regexp),
		cidrCache:     make(map[string]*net.IPNet),
		valueSetCache: make(map[string]map[string]struct{}),
		sampler:       NewRuleSampler(rules),
	}
	if prior != nil {
		re.inheritCache(prior, rules)
	}
	if err := re.compilePatterns(); err != nil {
		re.compilePatternsError = err
	}
	re.buildTypeIndex()
	return re
}

// inheritCache selectively copies compiled entries from the prior engine that are
// still referenced by the new rule set. Stale entries (patterns from removed rules)
// are left behind in the prior engine to be garbage-collected.
func (re *RuleEngine) inheritCache(prior *RuleEngine, rules []Rule) {
	neededRe, neededCIDR, neededSets := collectRequiredPatterns(rules)

	prior.mu.RLock()
	defer prior.mu.RUnlock()

	for k := range neededRe {
		if v, ok := prior.regexCache[k]; ok {
			re.regexCache[k] = v
		}
	}
	for k := range neededCIDR {
		if v, ok := prior.cidrCache[k]; ok {
			re.cidrCache[k] = v
		}
	}
	for k := range neededSets {
		if v, ok := prior.valueSetCache[k]; ok {
			re.valueSetCache[k] = v
		}
	}
}

// collectRequiredPatterns walks all rules and returns the set of regex patterns,
// CIDR strings, and value-set keys that are referenced by any condition. These
// are the only entries that should be inherited from a prior engine's cache.
func collectRequiredPatterns(rules []Rule) (regexPats, cidrPats, setKeys map[string]struct{}) {
	regexPats = make(map[string]struct{})
	cidrPats = make(map[string]struct{})
	setKeys = make(map[string]struct{})

	for i := range rules {
		conds := extractAllRuleConditions(&rules[i])
		for _, cond := range conds {
			switch cond.Op {
			case OpRegex:
				for _, p := range cond.Values {
					regexPats[p] = struct{}{}
				}
			case OpInCIDR, OpNotInCIDR:
				for _, c := range cond.Values {
					cidrPats[c] = struct{}{}
				}
			case OpIn, OpNotIn:
				setKeys[valueSetKey(cond.Values)] = struct{}{}
			}
		}
	}
	return
}

// extractAllRuleConditions returns all RuleCondition entries from a rule,
// traversing both the top-level Condition and any ConditionGroup/subgroups.
func extractAllRuleConditions(rule *Rule) []RuleCondition {
	if rule.ConditionGroup != nil {
		return extractGroupConditions(rule.ConditionGroup)
	}
	return []RuleCondition{rule.Condition}
}

// extractGroupConditions recursively collects conditions from a group and its subgroups.
func extractGroupConditions(g *RuleConditionGroup) []RuleCondition {
	if g == nil {
		return nil
	}
	conds := make([]RuleCondition, 0, len(g.Conditions))
	conds = append(conds, g.Conditions...)
	for i := range g.SubGroups {
		conds = append(conds, extractGroupConditions(&g.SubGroups[i])...)
	}
	return conds
}

// Sampler returns the RuleSampler attached to this engine. The adaptive sampler
// can call Sampler() to obtain the target for rate overrides.
func (re *RuleEngine) Sampler() *RuleSampler { return re.sampler }

// buildTypeIndex builds the byType array from re.rules and precomputes per-rule
// hot-path flags. Called once at construction (and thus on every hot-reload via
// NewRuleEngineWithCache). Not thread-safe on its own — must be called before
// the engine is published to other goroutines.
func (re *RuleEngine) buildTypeIndex() {
	for i := range re.rules {
		r := &re.rules[i]
		// Precompute whether this rule needs sampler access on every event.
		// A rule with no configured rate (or rate ≥ 1.0) can skip the three
		// RLock acquisitions in HasSampling+Mode+ShouldEvaluate when no adaptive
		// override is active, reducing hot-path lock traffic to zero.
		r.skipSampler = r.SampleRate <= 0 || r.SampleRate >= 1.0
		if t := int(r.EventType); t > 0 && t < byTypeSize {
			re.byType[t] = append(re.byType[t], *r)
		}
	}
}

// GetRules returns a copy of the loaded rules.
func (re *RuleEngine) GetRules() []Rule {
	re.mu.RLock()
	defer re.mu.RUnlock()

	rulesCopy := make([]Rule, len(re.rules))
	copy(rulesCopy, re.rules)
	return rulesCopy
}

// compilePatterns pre-compiles regex, CIDR, and OpIn/OpNotIn value sets for
// performance. It uses index-based (pointer) access so that setKey is written
// into the actual RuleCondition structs stored in re.rules, not into copies.
// Returns an error if any regex or CIDR pattern fails to compile; callers should
// check CompileErrors() on the returned engine.
func (re *RuleEngine) compilePatterns() error {
	var errs []error
	for i := range re.rules {
		if err := re.compileCondPtr(&re.rules[i].Condition); err != nil {
			errs = append(errs, err)
		}
		if re.rules[i].ConditionGroup != nil {
			if err := re.compileGroupPatterns(re.rules[i].ConditionGroup); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("compilePatterns: %d error(s): %v", len(errs), errs)
	}
	return nil
}

// compileCondPtr compiles a single condition and, for OpIn/OpNotIn, writes the
// pre-computed cache key back into cond.setKey so the evaluation hot path can
// look up the set without calling the expensive valueSetKey function.
// Returns an error if a regex pattern or CIDR range fails to compile.
func (re *RuleEngine) compileCondPtr(cond *RuleCondition) error {
	switch cond.Op {
	case OpRegex:
		for _, pattern := range cond.Values {
			if _, exists := re.regexCache[pattern]; !exists {
				compiled, err := regexp.Compile(pattern)
				if err != nil {
					return fmt.Errorf("rule compile: invalid regex pattern %q: %w", pattern, err)
				}
				re.regexCache[pattern] = compiled
			}
		}
	case OpInCIDR, OpNotInCIDR:
		for _, cidr := range cond.Values {
			if _, exists := re.cidrCache[cidr]; !exists {
				_, ipnet, err := net.ParseCIDR(cidr)
				if err != nil {
					return fmt.Errorf("rule compile: invalid CIDR range %q: %w", cidr, err)
				}
				re.cidrCache[cidr] = ipnet
			}
		}
	case OpIn, OpNotIn:
		key := valueSetKey(cond.Values)
		cond.setKey = key // stored so evaluation never calls valueSetKey again
		if _, exists := re.valueSetCache[key]; !exists {
			set := make(map[string]struct{}, len(cond.Values))
			for _, v := range cond.Values {
				set[v] = struct{}{}
			}
			re.valueSetCache[key] = set
		}
		// Store direct pointer so evaluateCondition avoids the valueSetCache
		// map lookup on the hot path (one lookup instead of two).
		cond.valueSet = re.valueSetCache[key]
	}
	// Precompute the numeric opcode so evaluateCondition uses an integer switch
	// (jump table, ~2 ns) instead of switching on the Op string (~10 ns).
	cond.opCode = opCodeOf(cond.Op)
	return nil
}

// compileGroupPatterns recurses into a ConditionGroup, compiling each
// RuleCondition in place (by index, not by range-copy).
// Also normalizes Operator to lowercase once so the hot path avoids strings.ToLower.
func (re *RuleEngine) compileGroupPatterns(g *RuleConditionGroup) error {
	g.Operator = strings.ToLower(g.Operator)
	for i := range g.Conditions {
		if err := re.compileCondPtr(&g.Conditions[i]); err != nil {
			return err
		}
	}
	for i := range g.SubGroups {
		if err := re.compileGroupPatterns(&g.SubGroups[i]); err != nil {
			return err
		}
	}
	return nil
}

// valueSetKey returns a stable cache key for a values slice.
// Sorts a copy so the key is order-independent (rule YAML order must not matter).
func valueSetKey(values []string) string {
	cp := make([]string, len(values))
	copy(cp, values)
	sort.Strings(cp)
	return strings.Join(cp, "\x00")
}

// inSetLookup returns true if value is present in the pre-built set identified
// by key. key must be the setKey pre-computed by compilePatterns; it is never
// empty for valid OpIn/OpNotIn conditions loaded through the normal rule pipeline.
func (re *RuleEngine) inSetLookup(key, value string) bool {
	if set, ok := re.valueSetCache[key]; ok {
		_, found := set[value]
		return found
	}
	return false
}

// getAllConditions extracts all conditions from a rule, recursively traversing SubGroups.
func (re *RuleEngine) getAllConditions(rule Rule) []RuleCondition {
	if rule.ConditionGroup != nil {
		return collectConditions(rule.ConditionGroup)
	}
	return []RuleCondition{rule.Condition}
}

// collectConditions recursively collects all conditions from a group and its SubGroups.
func collectConditions(g *RuleConditionGroup) []RuleCondition {
	if g == nil {
		return nil
	}
	conds := append([]RuleCondition{}, g.Conditions...)
	for i := range g.SubGroups {
		conds = append(conds, collectConditions(&g.SubGroups[i])...)
	}
	return conds
}

// EvaluateInto evaluates rules and calls fn for each matching alert.
// This is the zero-alloc hot path: no slice is allocated regardless of match
// count. Prefer this over Evaluate when the caller processes alerts inline.
//
// No lock is acquired: re.byType and all condition caches are written exactly
// once during construction (NewRuleEngineWithCache) before the engine is
// published, so they are safe to read concurrently without synchronisation.
// re.sampler has its own internal lock for adaptive-rate updates.
func (re *RuleEngine) EvaluateInto(e types.Event, fn func(types.Alert)) {
	t := int(e.Type)
	if uint(t) >= byTypeSize {
		return
	}
	rules := re.byType[t]
	for i := range rules {
		rule := &rules[i] // pointer avoids copying the ~300-byte Rule struct
		if !re.matchesTyped(e, rule) {
			continue
		}
		if rule.Action == ActionDrop {
			continue
		}
		fn(types.Alert{
			Timestamp: time.Unix(0, int64(e.Timestamp)),
			RuleID:    rule.ID,
			RuleName:  rule.Name,
			Severity:  rule.Severity,
			Message:   rule.Description,
			PID:       e.PID,
			Comm:      util.BytesToString(e.Comm[:]),
			Event:     e,
			Action:    string(rule.Action),
		})
	}
}

// Evaluate checks an event against all rules and returns matching alerts.
// It allocates only when at least one rule matches (lazy nil slice).
// For the zero-alloc path, use EvaluateInto instead.
//
// No lock is acquired: see EvaluateInto for the reasoning.
func (re *RuleEngine) Evaluate(e types.Event) []types.Alert {
	t := int(e.Type)
	if uint(t) >= byTypeSize {
		return nil
	}

	// nil until first match — avoids the 2048 B allocation on the common
	// no-match path. alertsPool recycles backing arrays on match paths.
	var alerts []types.Alert

	rules := re.byType[t]
	for i := range rules {
		rule := &rules[i]
		if !re.matchesTyped(e, rule) {
			continue
		}
		if rule.Action == ActionDrop {
			continue
		}
		if alerts == nil {
			sp := alertsPool.Get().(*[]types.Alert)
			alerts = (*sp)[:0]
		}
		alerts = append(alerts, types.Alert{
			Timestamp: time.Unix(0, int64(e.Timestamp)),
			RuleID:    rule.ID,
			RuleName:  rule.Name,
			Severity:  rule.Severity,
			Message:   rule.Description,
			PID:       e.PID,
			Comm:      util.BytesToString(e.Comm[:]),
			Event:     e,
			Action:    string(rule.Action),
		})
	}

	return alerts
}

// ReleaseAlerts returns a slice obtained from Evaluate back to the pool.
// Call this after the caller is done reading the slice. Passing nil is safe.
func ReleaseAlerts(s []types.Alert) {
	if s == nil {
		return
	}
	s = s[:0]
	alertsPool.Put(&s)
}

// shouldSample reports whether an event should be evaluated against a rule
// given the configured sample rate. Called only when rule.SampleRate < 1.0.
//
// deterministic=true uses FNV-1 32-bit hash of (PID || timestamp>>30) so
// that the same PID is consistently sampled or skipped within ~1 second
// windows (2^30 ns ≈ 1.07 s). This avoids alert storms where a single
// hot PID is repeatedly sampled on every event.
//
// deterministic=false uses a uniform random draw — distribution is correct
// over time but individual PIDs may be over- or under-represented in any
// short window.
func shouldSample(pid uint32, ts uint64, rate float64, deterministic bool) bool {
	if deterministic {
		h := fnvHasherPool.Get().(hash.Hash32)
		var buf [12]byte
		binary.LittleEndian.PutUint32(buf[:4], pid)
		binary.LittleEndian.PutUint64(buf[4:], ts>>30)
		h.Write(buf[:])
		result := float64(h.Sum32()%1000) < rate*1000
		h.Reset()
		fnvHasherPool.Put(h)
		return result
	}
	return rand.Float64() < rate //nolint:gosec // non-crypto, performance-sensitive
}

// matches checks if an event matches a rule (including type check).
// Used by code that iterates re.rules directly (e.g. ReferencedSyscalls).
func (re *RuleEngine) matches(e types.Event, rule Rule) bool {
	if e.Type != rule.EventType {
		return false
	}
	return re.matchesTyped(e, &rule)
}

// matchesTyped checks if an event matches a rule, assuming e.Type == rule.EventType.
// Takes *Rule to avoid copying the ~300-byte Rule struct on the hot path.
// Called from EvaluateInto/Evaluate which already dispatch via byType.
func (re *RuleEngine) matchesTyped(e types.Event, rule *Rule) bool {
	// Per-rule sampling gate.
	// Fast path: rule.skipSampler (precomputed at load time) is true when no
	// static rate is configured, and entryCount is 0 when no adaptive override
	// is active. In the common no-sampling case both are satisfied and we skip
	// all three RLock/map-lookup/RUnlock cycles (HasSampling+Mode+ShouldEvaluate).
	// CheckSampling collapses those three calls into one lock acquisition.
	if !rule.skipSampler || re.sampler.entryCount.Load() > 0 {
		if active, skip, mode, rateStr := re.sampler.CheckSampling(rule.ID, e.PID, e.Timestamp); active {
			if skip {
				ruleSkippedTotal.WithLabelValues(rule.ID, mode, rateStr).Inc()
				return false
			}
			ruleSampledTotal.WithLabelValues(rule.ID, mode, rateStr).Inc()
		}
	}

	// Lazily compute DNS analysis once per rule evaluation so that multiple
	// enriched DNS fields (qname_entropy, qname_dga_score, qname_digit_ratio,
	// qname_subdomain_count, qname_is_dga) all share the same DomainAnalysis
	// result instead of calling AnalyzeDomain up to 5 times per event.
	var dnsAnalysis *DomainAnalysis
	if e.Type == types.EventDNS && e.DNS != nil {
		a := globalDNSAnalyzer.AnalyzeDomain(e.DNS.QName)
		dnsAnalysis = &a
	}

	// Use condition group if present, otherwise use single condition.
	if rule.ConditionGroup != nil {
		return re.evaluateConditionGroup(e, rule.ConditionGroup, dnsAnalysis)
	}

	return re.evaluateCondition(e, &rule.Condition, dnsAnalysis)
}

// evaluateConditionGroup evaluates a group of conditions with AND/OR logic, recursing into SubGroups.
// dnsAnalysis is precomputed by matchesTyped when the event type is DNS — it is nil for all
// other event types and passed through to evaluateCondition / getFieldValue to avoid calling
// AnalyzeDomain multiple times for the same QName in different enriched DNS fields.
func (re *RuleEngine) evaluateConditionGroup(e types.Event, group *RuleConditionGroup, dnsAnalysis *DomainAnalysis) bool {
	if len(group.Conditions) == 0 && len(group.SubGroups) == 0 {
		return true
	}

	switch group.Operator {
	case "or":
		for i := range group.Conditions {
			if re.evaluateCondition(e, &group.Conditions[i], dnsAnalysis) {
				return true
			}
		}
		for i := range group.SubGroups {
			if re.evaluateConditionGroup(e, &group.SubGroups[i], dnsAnalysis) {
				return true
			}
		}
		return false
	default: // "and" or ""
		for i := range group.Conditions {
			if !re.evaluateCondition(e, &group.Conditions[i], dnsAnalysis) {
				return false
			}
		}
		for i := range group.SubGroups {
			if !re.evaluateConditionGroup(e, &group.SubGroups[i], dnsAnalysis) {
				return false
			}
		}
		return true
	}
}

// fieldNotFound is a sentinel returned by getFieldValue when the field name
// does not exist for the event type. This lets evaluateCondition distinguish
// "field is missing" from "field exists but has an empty string value".
const fieldNotFound = "\x00__field_not_found__"

// evaluateCondition evaluates a single condition against an event.
// Takes *RuleCondition to avoid copying the ~80-byte struct on the hot path.
// Switches on cond.opCode (precomputed integer) instead of cond.Op (string)
// for jump-table dispatch (~2 ns vs ~10 ns for string switch).
// dnsAnalysis is precomputed by matchesTyped for DNS events — nil for other types.
func (re *RuleEngine) evaluateCondition(e types.Event, cond *RuleCondition, dnsAnalysis *DomainAnalysis) bool {
	// caps_gained / caps_dropped operate directly on the Privesc struct —
	// they don't go through getFieldValue.
	switch cond.opCode {
	case condOpCapsGained:
		return re.matchesCaps(e, cond.Values, true)
	case condOpCapsDropped:
		return re.matchesCaps(e, cond.Values, false)
	}

	// Get field value based on event type and field name.
	// fieldNotFound means the field name is unknown for this event type —
	// treat as no-match for all operators (rule is misconfigured but was
	// already rejected at load time via validateFieldName).
	value := re.getFieldValue(e, cond.Field, dnsAnalysis)
	if value == fieldNotFound {
		return false
	}
	code := cond.opCode
	if value == "" && code != condOpEquals && code != condOpNotEquals && code != condOpNotIn {
		return false
	}

	// Evaluate condition using precomputed integer opcode for jump-table dispatch.
	switch code {
	case condOpIn:
		// Small sets (≤ 8 elements): linear scan over the Values slice is faster
		// than a map lookup due to cache locality and no hash computation.
		// For most rules the condition set is tiny (2–5 syscall numbers, etc.).
		if len(cond.Values) <= 8 {
			for _, v := range cond.Values {
				if v == value {
					return true
				}
			}
			return false
		}
		// Large sets: use the pre-built map for O(1) lookup.
		if cond.valueSet != nil {
			_, found := cond.valueSet[value]
			return found
		}
		return re.inSetLookup(cond.setKey, value)
	case condOpNotIn:
		if len(cond.Values) <= 8 {
			for _, v := range cond.Values {
				if v == value {
					return false
				}
			}
			return true
		}
		if cond.valueSet != nil {
			_, found := cond.valueSet[value]
			return !found
		}
		return !re.inSetLookup(cond.setKey, value)
	case condOpEquals:
		return len(cond.Values) > 0 && value == cond.Values[0]
	case condOpNotEquals:
		return len(cond.Values) == 0 || value != cond.Values[0]
	case condOpPrefix:
		return hasPrefix(cond.Values, value)
	case condOpNotPrefix:
		return !hasPrefix(cond.Values, value)
	case condOpSuffix:
		for _, sfx := range cond.Values {
			if strings.HasSuffix(value, sfx) {
				return true
			}
		}
		return false
	case condOpNotSuffix:
		for _, sfx := range cond.Values {
			if strings.HasSuffix(value, sfx) {
				return false
			}
		}
		return true
	case condOpRegex:
		return re.matchesRegex(cond.Values, value)
	case condOpGT:
		return re.compareNumeric(value, cond.Values, func(a, b float64) bool { return a > b })
	case condOpLT:
		return re.compareNumeric(value, cond.Values, func(a, b float64) bool { return a < b })
	case condOpGTE:
		return re.compareNumeric(value, cond.Values, func(a, b float64) bool { return a >= b })
	case condOpLTE:
		return re.compareNumeric(value, cond.Values, func(a, b float64) bool { return a <= b })
	case condOpContains:
		for _, v := range cond.Values {
			if strings.Contains(value, v) {
				return true
			}
		}
		return false
	case condOpInCIDR:
		return re.matchesCIDR(value, cond.Values, true)
	case condOpNotInCIDR:
		return re.matchesCIDR(value, cond.Values, false)
	default:
		return false
	}
}

// matchesCaps evaluates caps_gained (gained=true) or caps_dropped (gained=false).
// cond.Values contains capability names like ["CAP_SYS_ADMIN", "CAP_NET_RAW"].
// Returns true if ANY of the listed caps appear in the relevant delta mask.
func (re *RuleEngine) matchesCaps(e types.Event, capNames []string, gained bool) bool {
	if e.Privesc == nil {
		return false
	}
	var delta uint64
	if gained {
		delta = e.Privesc.NewCaps &^ e.Privesc.OldCaps // bits set in new but not old
	} else {
		delta = e.Privesc.OldCaps &^ e.Privesc.NewCaps // bits set in old but not new
	}
	for _, name := range capNames {
		if bit, ok := capNameToBit(name); ok {
			if delta&(1<<bit) != 0 {
				return true
			}
		}
	}
	return false
}

// capNameToBit converts a capability name like "CAP_SYS_ADMIN" to its bit index.
var capBitByName = map[string]uint{
	"CAP_CHOWN": 0, "CAP_DAC_OVERRIDE": 1, "CAP_DAC_READ_SEARCH": 2,
	"CAP_FOWNER": 3, "CAP_FSETID": 4, "CAP_KILL": 5,
	"CAP_SETGID": 6, "CAP_SETUID": 7, "CAP_SETPCAP": 8,
	"CAP_LINUX_IMMUTABLE": 9, "CAP_NET_BIND_SERVICE": 10, "CAP_NET_BROADCAST": 11,
	"CAP_NET_ADMIN": 12, "CAP_NET_RAW": 13, "CAP_IPC_LOCK": 14,
	"CAP_IPC_OWNER": 15, "CAP_SYS_MODULE": 16, "CAP_SYS_RAWIO": 17,
	"CAP_SYS_CHROOT": 18, "CAP_SYS_PTRACE": 19, "CAP_SYS_PACCT": 20,
	"CAP_SYS_ADMIN": 21, "CAP_SYS_BOOT": 22, "CAP_SYS_NICE": 23,
	"CAP_SYS_RESOURCE": 24, "CAP_SYS_TIME": 25, "CAP_SYS_TTY_CONFIG": 26,
	"CAP_MKNOD": 27, "CAP_LEASE": 28, "CAP_AUDIT_WRITE": 29,
	"CAP_AUDIT_CONTROL": 30, "CAP_SETFCAP": 31, "CAP_MAC_OVERRIDE": 32,
	"CAP_MAC_ADMIN": 33, "CAP_SYSLOG": 34, "CAP_WAKE_ALARM": 35,
	"CAP_BLOCK_SUSPEND": 36, "CAP_AUDIT_READ": 37, "CAP_PERFMON": 38,
	"CAP_BPF": 39, "CAP_CHECKPOINT_RESTORE": 40,
}

func capNameToBit(name string) (uint, bool) {
	bit, ok := capBitByName[strings.ToUpper(name)]
	return bit, ok
}

// getFieldValue extracts a field value from an event based on field name.
// Returns fieldNotFound if the field name is not valid for the event type.
// Hot path: uses strconv instead of fmt.Sprintf for numeric fields to avoid
// interface boxing allocations. dnsAnalysis is precomputed once per rule
// evaluation (in matchesTyped) so that multiple enriched DNS fields
// (qname_entropy, qname_dga_score, qname_digit_ratio, qname_subdomain_count,
// qname_is_dga) all reuse the same DomainAnalysis without recomputing entropy,
// n-gram scores, and digit ratio for the same QName.
// normaliseFieldName maps dotted-name aliases used in rule YAML files to their
// canonical single-word field names expected by getFieldValue.
// Aliases: file.path→filename, file.op→op, proc.comm→comm, network.dport→dport,
// syscall.nr→nr, etc.
func normaliseFieldName(field string) string {
	switch field {
	case "file.path":
		return "filename"
	case "file.op":
		return "op"
	case "file.flags":
		return "flags"
	case "file.mode":
		return "mode"
	case "file.directory":
		return "directory"
	case "file.extension":
		return "extension"
	case "proc.comm":
		return "comm"
	case "network.dport":
		return "dport"
	case "network.sport":
		return "sport"
	case "network.daddr":
		return "daddr"
	case "network.saddr":
		return "saddr"
	case "network.proto":
		return "proto"
	case "network.family":
		return "family"
	case "syscall.nr":
		return "nr"
	case "syscall.ret":
		return "ret"
	case "syscall.arg0":
		return "arg0"
	case "syscall.arg1":
		return "arg1"
	case "syscall.arg2":
		return "arg2"
	case "syscall.arg3":
		return "arg3"
	case "syscall.arg4":
		return "arg4"
	case "syscall.arg5":
		return "arg5"
	default:
		return field
	}
}

func (re *RuleEngine) getFieldValue(e types.Event, field string, dnsAnalysis *DomainAnalysis) string {
	// Normalise dotted-name aliases (file.path → filename, proc.comm → comm, etc.)
	// to the canonical field names expected by the rest of getFieldValue.
	field = normaliseFieldName(field)

	switch e.Type {
	case types.EventTCPConnect:
		if e.Network == nil {
			return ""
		}
		switch field {
		case "dport":
			return strconv.FormatUint(uint64(e.Network.Dport), 10)
		case "sport":
			return strconv.FormatUint(uint64(e.Network.Sport), 10)
		case "daddr":
			return util.FormatIP(e.Network.Daddr[:], e.Network.Family)
		case "saddr":
			return util.FormatIP(e.Network.Saddr[:], e.Network.Family)
		case "proto":
			return strconv.FormatUint(uint64(e.Network.Proto), 10)
		case "family":
			if e.Network.Family == types.AFInet6 {
				return "ipv6"
			}
			return "ipv4"
		case "proc.args":
			return e.ProcArgs
		case "proc.args_truncated":
			if e.ProcArgsTruncated {
				return "true"
			}
			return "false"
		case "comm":
			return util.BytesToString(e.Comm[:])
		case "uid":
			return strconv.FormatUint(uint64(e.UID), 10)
		}
	case types.EventFileAccess:
		if e.File == nil {
			return ""
		}
		switch field {
		case "filename":
			return util.BytesToString(e.File.Filename[:])
		case "fd.name":
			return e.File.FDPath
		case "fd.name_truncated":
			if e.File.FDPathTruncated {
				return "true"
			}
			return "false"
		case "flags":
			return strconv.FormatInt(int64(e.File.Flags), 10)
		case "mode":
			return strconv.FormatUint(uint64(e.File.Mode), 10)
		case "op":
			if int(e.File.Op) < len(fileOpNames) {
				return fileOpNames[e.File.Op]
			}
			return strconv.FormatUint(uint64(e.File.Op), 10)
		case "directory":
			p := util.BytesToString(e.File.Filename[:])
			if idx := strings.LastIndexByte(p, '/'); idx >= 0 {
				return p[:idx]
			}
			return "/"
		case "extension":
			p := util.BytesToString(e.File.Filename[:])
			if idx := strings.LastIndexByte(p, '.'); idx >= 0 {
				return p[idx:]
			}
			return ""
		case "proc.args":
			return e.ProcArgs
		case "proc.args_truncated":
			if e.ProcArgsTruncated {
				return "true"
			}
			return "false"
		case "comm":
			return util.BytesToString(e.Comm[:])
		case "uid":
			return strconv.FormatUint(uint64(e.UID), 10)
		}
	case types.EventSyscall:
		if e.Syscall == nil {
			return ""
		}
		switch field {
		case "nr":
			if nr := e.Syscall.Nr; nr >= 0 && nr < 512 {
				return syscallNrStrings[nr]
			}
			return strconv.FormatInt(e.Syscall.Nr, 10)
		case "ret":
			return strconv.FormatInt(e.Syscall.Ret, 10)
		case "uid":
			return strconv.FormatUint(uint64(e.UID), 10)
		case "comm":
			return util.BytesToString(e.Comm[:])
		case "arg0":
			return strconv.FormatUint(e.Syscall.Args[0], 10)
		case "arg1":
			return strconv.FormatUint(e.Syscall.Args[1], 10)
		case "arg2":
			return strconv.FormatUint(e.Syscall.Args[2], 10)
		case "arg3":
			return strconv.FormatUint(e.Syscall.Args[3], 10)
		case "arg4":
			return strconv.FormatUint(e.Syscall.Args[4], 10)
		case "arg5":
			return strconv.FormatUint(e.Syscall.Args[5], 10)
		case "fd.name":
			// fd.name for syscall events is populated at collection time by the
			// fileaccess collector via BPF fd_path_map lookup on arg0 (the fd).
			if e.File != nil {
				return e.File.FDPath
			}
			return ""
		case "proc.args":
			return e.ProcArgs
		case "proc.args_truncated":
			if e.ProcArgsTruncated {
				return "true"
			}
			return "false"
		}
	case types.EventDNS:
		if e.DNS == nil {
			return ""
		}
		switch field {
		case "qname", "dns.qname":
			return e.DNS.QName
		case "qtype":
			return strconv.FormatUint(uint64(e.DNS.QType), 10)
		case "rcode":
			return strconv.FormatUint(uint64(e.DNS.RCode), 10)
		case "direction":
			return strconv.FormatUint(uint64(e.DNS.Direction), 10)
		case "qname_length":
			return strconv.Itoa(len(e.DNS.QName))
		// ── Enriched DNS fields — use precomputed DomainAnalysis from matchesTyped ──
		case "qname_entropy":
			if dnsAnalysis != nil {
				return strconv.FormatFloat(dnsAnalysis.Entropy, 'f', 4, 64)
			}
			a := globalDNSAnalyzer.AnalyzeDomain(e.DNS.QName)
			return strconv.FormatFloat(a.Entropy, 'f', 4, 64)
		case "qname_dga_score":
			if dnsAnalysis != nil {
				return strconv.FormatFloat(dnsAnalysis.NgramScore, 'f', 4, 64)
			}
			a := globalDNSAnalyzer.AnalyzeDomain(e.DNS.QName)
			return strconv.FormatFloat(a.NgramScore, 'f', 4, 64)
		case "qname_digit_ratio":
			if dnsAnalysis != nil {
				return strconv.FormatFloat(dnsAnalysis.DigitRatio, 'f', 4, 64)
			}
			a := globalDNSAnalyzer.AnalyzeDomain(e.DNS.QName)
			return strconv.FormatFloat(a.DigitRatio, 'f', 4, 64)
		case "qname_subdomain_count":
			if dnsAnalysis != nil {
				return strconv.Itoa(dnsAnalysis.SubdomainCount)
			}
			a := globalDNSAnalyzer.AnalyzeDomain(e.DNS.QName)
			return strconv.Itoa(a.SubdomainCount)
		case "qname_is_dga":
			var a DomainAnalysis
			if dnsAnalysis != nil {
				a = *dnsAnalysis
			} else {
				a = globalDNSAnalyzer.AnalyzeDomain(e.DNS.QName)
			}
			if a.IsDGA || a.NgramScore >= DefaultNgramDGADetector().threshold {
				return "true"
			}
			return "false"
		}
	case types.EventTLS:
		if e.TLS == nil {
			return ""
		}
		switch field {
		case "tls_data", "data":
			l := e.TLS.DataLen
			if l > uint32(len(e.TLS.Data)) {
				l = uint32(len(e.TLS.Data))
			}
			return string(e.TLS.Data[:l])
		case "direction":
			return strconv.FormatUint(uint64(e.TLS.Direction), 10)
		case "data_len":
			return strconv.FormatUint(uint64(e.TLS.DataLen), 10)
		case "ja3":
			return e.TLS.JA3
		case "ja4":
			return e.TLS.JA4
		case "ja3s":
			return e.TLS.JA3S
		}
	case types.EventHTTPPlaintext:
		if e.HTTPPlaintext == nil {
			return ""
		}
		switch field {
		case "http_data", "data":
			l := e.HTTPPlaintext.DataLen
			if l > uint32(len(e.HTTPPlaintext.Data)) {
				l = uint32(len(e.HTTPPlaintext.Data))
			}
			return string(e.HTTPPlaintext.Data[:l])
		case "direction":
			return strconv.FormatUint(uint64(e.HTTPPlaintext.Direction), 10)
		case "data_len":
			return strconv.FormatUint(uint64(e.HTTPPlaintext.DataLen), 10)
		case "comm":
			return util.BytesToString(e.Comm[:])
		}
	case types.EventPrivesc:
		// caps_gained / caps_dropped are handled before getFieldValue.
		// Common process fields are also accessible.
		switch field {
		case "uid":
			return strconv.FormatUint(uint64(e.UID), 10)
		case "comm":
			return util.BytesToString(e.Comm[:])
		case "caps":
			if e.Privesc != nil {
				return "0x" + strconv.FormatUint(e.Privesc.NewCaps, 16)
			}
			return "0x0"
		}
	case types.EventNetClose:
		if e.NetClose == nil {
			return ""
		}
		switch field {
		case "dport":
			return strconv.FormatUint(uint64(e.NetClose.Dport), 10)
		case "sport":
			return strconv.FormatUint(uint64(e.NetClose.Sport), 10)
		case "daddr":
			return util.FormatIP(e.NetClose.Daddr[:], e.NetClose.Family)
		case "saddr":
			return util.FormatIP(e.NetClose.Saddr[:], e.NetClose.Family)
		case "family":
			if e.NetClose.Family == types.AFInet6 {
				return "ipv6"
			}
			return "ipv4"
		case "duration_sec":
			return strconv.FormatInt(int64(e.NetClose.Duration.Seconds()), 10)
		case "duration_ms":
			return strconv.FormatInt(e.NetClose.Duration.Milliseconds(), 10)
		}
	case types.EventGPU:
		if e.GPU == nil {
			return ""
		}
		switch field {
		case "gpu_op":
			if int(e.GPU.Op) < len(gpuOpNames) {
				return gpuOpNames[e.GPU.Op]
			}
			return strconv.FormatUint(uint64(e.GPU.Op), 10)
		case "gpu_size":
			return strconv.FormatUint(e.GPU.Size, 10)
		case "gpu_dev_ptr":
			return "0x" + strconv.FormatUint(e.GPU.DevPtr, 16)
		case "gpu_host_ptr":
			return "0x" + strconv.FormatUint(e.GPU.HostPtr, 16)
		case "comm":
			return util.BytesToString(e.Comm[:])
		case "uid":
			return strconv.FormatUint(uint64(e.UID), 10)
		}
	case types.EventCloudAudit:
		if e.CloudAudit == nil {
			return ""
		}
		switch field {
		case "cloud.provider":
			return e.CloudAudit.Provider
		case "cloud.service":
			return e.CloudAudit.Service
		case "cloud.action":
			return e.CloudAudit.Action
		case "cloud.principal":
			return e.CloudAudit.Principal
		case "cloud.resource":
			return e.CloudAudit.ResourceARN
		case "cloud.source_ip":
			return e.CloudAudit.SourceIP
		case "cloud.user_agent":
			return e.CloudAudit.UserAgent
		case "cloud.error_code":
			return e.CloudAudit.ErrorCode
		case "cloud.region":
			return e.CloudAudit.Region
		case "cloud.event_id":
			return e.CloudAudit.EventID
		}
	case types.EventKmodLoad:
		if e.Kmod == nil {
			return ""
		}
		switch field {
		case "name":
			return e.Kmod.ModName
		case "filename":
			return e.Kmod.ModName
		case "from_tmpfs":
			if e.Kmod.FromTmpfs {
				return "true"
			}
			return "false"
		case "comm":
			return util.BytesToString(e.Comm[:])
		case "parent_comm":
			return util.BytesToString(e.ParentComm[:])
		case "uid":
			return strconv.FormatUint(uint64(e.UID), 10)
		case "fingerprint":
			return ""
		}
	case types.EventIOUring:
		if e.IOUring == nil {
			return ""
		}
		switch field {
		case "op":
			if e.IOUring.Op == 0 {
				return "setup"
			}
			return "enter"
		case "flags":
			return strconv.FormatUint(uint64(e.IOUring.Flags), 10)
		case "fd":
			return strconv.FormatInt(int64(e.IOUring.Fd), 10)
		case "to_submit":
			return strconv.FormatUint(uint64(e.IOUring.ToSubmit), 10)
		case "comm":
			return util.BytesToString(e.Comm[:])
		case "uid":
			return strconv.FormatUint(uint64(e.UID), 10)
		}
	case types.EventBPFProgram:
		if e.BPFProgram == nil {
			return ""
		}
		switch field {
		case "cmd":
			return types.BPFCmdName(e.BPFProgram.Cmd)
		case "cmd_nr":
			return strconv.FormatUint(uint64(e.BPFProgram.Cmd), 10)
		case "prog_type":
			return types.BPFProgTypeName(e.BPFProgram.ProgType)
		case "prog_type_nr":
			return strconv.FormatUint(uint64(e.BPFProgram.ProgType), 10)
		case "ret":
			return strconv.FormatInt(int64(e.BPFProgram.Ret), 10)
		case "uid":
			return strconv.FormatUint(uint64(e.UID), 10)
		case "comm":
			return util.BytesToString(e.Comm[:])
		}
	}
	return fieldNotFound
}

// matchesRegex checks if value matches any of the regex patterns.
func (re *RuleEngine) matchesRegex(patterns []string, value string) bool {
	for _, pattern := range patterns {
		if re, exists := re.regexCache[pattern]; exists {
			if re.MatchString(value) {
				return true
			}
		}
	}
	return false
}

// compareNumeric parses numeric values and compares them.
func (re *RuleEngine) compareNumeric(value string, thresholds []string, cmp func(a, b float64) bool) bool {
	if len(thresholds) == 0 {
		return false
	}
	val, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return false
	}
	threshold, err := strconv.ParseFloat(thresholds[0], 64)
	if err != nil {
		return false
	}
	return cmp(val, threshold)
}

// matchesCIDR checks if IP address matches any CIDR range.
func (re *RuleEngine) matchesCIDR(ipStr string, cidrs []string, expectMatch bool) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for _, cidr := range cidrs {
		if ipnet, exists := re.cidrCache[cidr]; exists {
			if ipnet.Contains(ip) {
				return expectMatch
			}
		}
	}
	return !expectMatch
}

// ReferencedSyscalls returns the set of syscall numbers explicitly referenced
// by loaded rules that target EventSyscall events and constrain the "nr" field
// with an equality or set-membership operator (eq / in).
//
// The result is merged with DefaultMonitoredSyscalls so that the critical
// security-baseline syscalls are always forwarded, even when no rule names them.
//
// Rules without an explicit "nr" constraint will still receive events for any
// syscall that is present in the returned set — they are not excluded, but they
// may miss syscalls that are neither in an explicit rule condition nor in the
// default list.  This is an intentional trade-off to achieve the 60-80%
// ring-buffer reduction for typical mixed-syscall workloads.
func (re *RuleEngine) ReferencedSyscalls() []uint32 {
	re.mu.RLock()
	defer re.mu.RUnlock()

	seen := make(map[uint32]struct{})

	for _, rule := range re.rules {
		if rule.EventType != types.EventSyscall {
			continue
		}
		conds := re.getAllConditions(rule)
		for _, cond := range conds {
			if cond.Field != "nr" {
				continue
			}
			// Only eq and in operators name specific syscall numbers.
			if cond.Op != OpEquals && cond.Op != OpIn {
				continue
			}
			for _, v := range cond.Values {
				n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
				if err != nil || n < 0 || n >= 512 {
					continue
				}
				seen[uint32(n)] = struct{}{}
			}
		}
	}

	// Always include the security-baseline defaults.
	for _, n := range defaultMonitoredSyscallsU32() {
		seen[n] = struct{}{}
	}

	out := make([]uint32, 0, len(seen))
	for nr := range seen {
		out = append(out, nr)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// defaultMonitoredSyscallsU32 returns the default monitored syscall list as
// []uint32 so it can be used without importing the bpf package.
func defaultMonitoredSyscallsU32() []uint32 {
	return []uint32{
		59, 322, 101, 126, 308, 272, 319, 165, 166, 155, 161, 311, 310, 241,
		321, // bpf(2) — always forward so ebpf-subversion rules fire even without an explicit rule
	}
}

// contains checks if a string slice contains a value.
func contains(slice []string, value string) bool {
	for _, s := range slice {
		if s == value {
			return true
		}
	}
	return false
}

// hasPrefix checks if value starts with any of the prefixes.
func hasPrefix(prefixes []string, value string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

