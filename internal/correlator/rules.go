// Package correlator provides event correlation and rule-based detection.
package correlator

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zugolO/ebpf-guard/internal/util"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

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
)

// RuleCondition defines a single condition for rule evaluation.
type RuleCondition struct {
	Field  string                `yaml:"field"`
	Op     RuleConditionOperator `yaml:"op"`
	Values []string              `yaml:"values"`
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
	// Condition is a single condition (for simple rules)
	Condition RuleCondition `yaml:"condition"`
	// ConditionGroup allows complex AND/OR logic (takes precedence over Condition)
	ConditionGroup *RuleConditionGroup `yaml:"condition_group,omitempty"`
	Severity       types.AlertSeverity `yaml:"severity"`
	Action         RuleAction          `yaml:"action"`
	// Tags are optional metadata for rule categorization and filtering
	Tags []string `yaml:"tags,omitempty"`
}

// RuleSet contains all loaded rules.
type RuleSet struct {
	Rules []Rule `yaml:"rules"`
}

// globalDNSAnalyzer is the package-level DNS entropy/n-gram calculator used by
// getFieldValue to evaluate enriched DNS rule fields (qname_entropy, qname_dga_score,
// qname_length, qname_digit_ratio, qname_subdomain_count, qname_is_dga) on demand.
var globalDNSAnalyzer = NewDNSEntropyCalculator()

// RuleEngine evaluates events against rules.
type RuleEngine struct {
	rules []Rule
	// compiled regex patterns for performance
	regexCache map[string]*regexp.Regexp
	// compiled CIDR ranges
	cidrCache map[string]*net.IPNet
	// valueSetCache maps a canonical key (sorted joined values) → set for O(1) OpIn/OpNotIn lookup.
	// Built once in compilePatterns; never mutated after construction.
	valueSetCache map[string]map[string]struct{}
	// mu protects the rules slice
	mu sync.RWMutex
}

// NewRuleEngine creates a new rule engine with the given rules.
func NewRuleEngine(rules []Rule) *RuleEngine {
	re := &RuleEngine{
		rules:         rules,
		regexCache:    make(map[string]*regexp.Regexp),
		cidrCache:     make(map[string]*net.IPNet),
		valueSetCache: make(map[string]map[string]struct{}),
	}
	re.compilePatterns()
	return re
}

// GetRules returns a copy of the loaded rules.
func (re *RuleEngine) GetRules() []Rule {
	re.mu.RLock()
	defer re.mu.RUnlock()

	rulesCopy := make([]Rule, len(re.rules))
	copy(rulesCopy, re.rules)
	return rulesCopy
}

// compilePatterns pre-compiles regex, CIDR, and OpIn/OpNotIn value sets for performance.
func (re *RuleEngine) compilePatterns() {
	for _, rule := range re.rules {
		conditions := re.getAllConditions(rule)
		for _, cond := range conditions {
			switch cond.Op {
			case OpRegex:
				for _, pattern := range cond.Values {
					if _, exists := re.regexCache[pattern]; !exists {
						if compiled, err := regexp.Compile(pattern); err == nil {
							re.regexCache[pattern] = compiled
						}
					}
				}
			case OpInCIDR, OpNotInCIDR:
				for _, cidr := range cond.Values {
					if _, exists := re.cidrCache[cidr]; !exists {
						if _, ipnet, err := net.ParseCIDR(cidr); err == nil {
							re.cidrCache[cidr] = ipnet
						}
					}
				}
			case OpIn, OpNotIn:
				key := valueSetKey(cond.Values)
				if _, exists := re.valueSetCache[key]; !exists {
					set := make(map[string]struct{}, len(cond.Values))
					for _, v := range cond.Values {
						set[v] = struct{}{}
					}
					re.valueSetCache[key] = set
				}
			}
		}
	}
}

// valueSetKey returns a stable cache key for a values slice.
// Sorts a copy so the key is order-independent (rule YAML order must not matter).
func valueSetKey(values []string) string {
	cp := make([]string, len(values))
	copy(cp, values)
	sort.Strings(cp)
	return strings.Join(cp, "\x00")
}

// inSetLookup returns true if value is present in the pre-built set for values.
// Falls back to linear scan if no set was cached (should not happen after compilePatterns).
func (re *RuleEngine) inSetLookup(values []string, value string) bool {
	key := valueSetKey(values)
	if set, ok := re.valueSetCache[key]; ok {
		_, found := set[value]
		return found
	}
	return contains(values, value)
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

// Evaluate checks an event against all rules and returns matching alerts.
func (re *RuleEngine) Evaluate(e types.Event) []types.Alert {
	re.mu.RLock()
	defer re.mu.RUnlock()

	var alerts []types.Alert

	for _, rule := range re.rules {
		if !re.matches(e, rule) {
			continue
		}

		// Rule matched - check action
		if rule.Action == ActionDrop {
			continue // Silently drop
		}

		// Generate alert — ID intentionally omitted; set by CorrelationEngine.Ingest
		// with a monotonic sequence number to guarantee uniqueness.
		alert := types.Alert{
			Timestamp: time.Unix(0, int64(e.Timestamp)),
			RuleID:    rule.ID,
			RuleName:  rule.Name,
			Severity:  rule.Severity,
			Message:   rule.Description,
			PID:       e.PID,
			Comm:      util.BytesToString(e.Comm[:]),
			Event:     e,
			Action:    string(rule.Action),
		}
		alerts = append(alerts, alert)
	}

	return alerts
}

// matches checks if an event matches a rule.
func (re *RuleEngine) matches(e types.Event, rule Rule) bool {
	// Check event type
	if e.Type != rule.EventType {
		return false
	}

	// Use condition group if present, otherwise use single condition
	if rule.ConditionGroup != nil {
		return re.evaluateConditionGroup(e, rule.ConditionGroup)
	}

	return re.evaluateCondition(e, rule.Condition)
}

// evaluateConditionGroup evaluates a group of conditions with AND/OR logic, recursing into SubGroups.
func (re *RuleEngine) evaluateConditionGroup(e types.Event, group *RuleConditionGroup) bool {
	if len(group.Conditions) == 0 && len(group.SubGroups) == 0 {
		return true
	}

	switch strings.ToLower(group.Operator) {
	case "or":
		for _, cond := range group.Conditions {
			if re.evaluateCondition(e, cond) {
				return true
			}
		}
		for i := range group.SubGroups {
			if re.evaluateConditionGroup(e, &group.SubGroups[i]) {
				return true
			}
		}
		return false
	default: // "and" or ""
		for _, cond := range group.Conditions {
			if !re.evaluateCondition(e, cond) {
				return false
			}
		}
		for i := range group.SubGroups {
			if !re.evaluateConditionGroup(e, &group.SubGroups[i]) {
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
func (re *RuleEngine) evaluateCondition(e types.Event, cond RuleCondition) bool {
	// caps_gained / caps_dropped operate directly on the Privesc struct —
	// they don't go through getFieldValue.
	switch cond.Op {
	case OpCapsGained:
		return re.matchesCaps(e, cond.Values, true)
	case OpCapsDropped:
		return re.matchesCaps(e, cond.Values, false)
	}

	// Get field value based on event type and field name.
	// fieldNotFound means the field name is unknown for this event type —
	// treat as no-match for all operators (rule is misconfigured but was
	// already rejected at load time via validateFieldName).
	value := re.getFieldValue(e, cond.Field)
	if value == fieldNotFound {
		return false
	}
	if value == "" && cond.Op != OpEquals && cond.Op != OpNotEquals && cond.Op != OpNotIn {
		return false
	}

	// Evaluate condition
	switch cond.Op {
	case OpIn:
		return re.inSetLookup(cond.Values, value)
	case OpNotIn:
		return !re.inSetLookup(cond.Values, value)
	case OpEquals:
		return len(cond.Values) > 0 && value == cond.Values[0]
	case OpNotEquals:
		return len(cond.Values) == 0 || value != cond.Values[0]
	case OpPrefix:
		return hasPrefix(cond.Values, value)
	case OpSuffix:
		for _, sfx := range cond.Values {
			if strings.HasSuffix(value, sfx) {
				return true
			}
		}
		return false
	case OpRegex:
		return re.matchesRegex(cond.Values, value)
	case OpGreaterThan:
		return re.compareNumeric(value, cond.Values, func(a, b float64) bool { return a > b })
	case OpLessThan:
		return re.compareNumeric(value, cond.Values, func(a, b float64) bool { return a < b })
	case OpGreaterOrEqual:
		return re.compareNumeric(value, cond.Values, func(a, b float64) bool { return a >= b })
	case OpLessOrEqual:
		return re.compareNumeric(value, cond.Values, func(a, b float64) bool { return a <= b })
	case OpInCIDR:
		return re.matchesCIDR(value, cond.Values, true)
	case OpNotInCIDR:
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
// interface boxing allocations. DNS enriched fields are computed at most once
// per call via a lazy local variable.
func (re *RuleEngine) getFieldValue(e types.Event, field string) string {
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
		}
	case types.EventFileAccess:
		if e.File == nil {
			return ""
		}
		switch field {
		case "filename":
			return util.BytesToString(e.File.Filename[:])
		case "flags":
			return strconv.FormatInt(int64(e.File.Flags), 10)
		case "mode":
			return strconv.FormatUint(uint64(e.File.Mode), 10)
		case "op":
			ops := []string{"open", "read", "write"}
			if int(e.File.Op) < len(ops) {
				return ops[e.File.Op]
			}
			return strconv.FormatUint(uint64(e.File.Op), 10)
		}
	case types.EventSyscall:
		if e.Syscall == nil {
			return ""
		}
		switch field {
		case "nr":
			return strconv.FormatInt(e.Syscall.Nr, 10)
		case "ret":
			return strconv.FormatInt(e.Syscall.Ret, 10)
		}
	case types.EventDNS:
		if e.DNS == nil {
			return ""
		}
		switch field {
		case "qname":
			return e.DNS.QName
		case "qtype":
			return strconv.FormatUint(uint64(e.DNS.QType), 10)
		case "rcode":
			return strconv.FormatUint(uint64(e.DNS.RCode), 10)
		case "direction":
			return strconv.FormatUint(uint64(e.DNS.Direction), 10)
		case "qname_length":
			return strconv.Itoa(len(e.DNS.QName))
		// ── Enriched DNS fields — AnalyzeDomain is called lazily and at most once ──
		case "qname_entropy":
			a := globalDNSAnalyzer.AnalyzeDomain(e.DNS.QName)
			return strconv.FormatFloat(a.Entropy, 'f', 4, 64)
		case "qname_dga_score":
			a := globalDNSAnalyzer.AnalyzeDomain(e.DNS.QName)
			return strconv.FormatFloat(a.NgramScore, 'f', 4, 64)
		case "qname_digit_ratio":
			a := globalDNSAnalyzer.AnalyzeDomain(e.DNS.QName)
			return strconv.FormatFloat(a.DigitRatio, 'f', 4, 64)
		case "qname_subdomain_count":
			a := globalDNSAnalyzer.AnalyzeDomain(e.DNS.QName)
			return strconv.Itoa(a.SubdomainCount)
		case "qname_is_dga":
			a := globalDNSAnalyzer.AnalyzeDomain(e.DNS.QName)
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
		case "tls_data":
			l := e.TLS.DataLen
			if l > uint32(len(e.TLS.Data)) {
				l = uint32(len(e.TLS.Data))
			}
			return string(e.TLS.Data[:l])
		case "direction":
			return strconv.FormatUint(uint64(e.TLS.Direction), 10)
		case "data_len":
			return strconv.FormatUint(uint64(e.TLS.DataLen), 10)
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
				return fmt.Sprintf("0x%x", e.Privesc.NewCaps)
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
			ops := []string{"alloc", "free", "memcpy_htod", "memcpy_dtoh", "memcpy_dtod", "kernel_launch"}
			if int(e.GPU.Op) < len(ops) {
				return ops[e.GPU.Op]
			}
			return strconv.FormatUint(uint64(e.GPU.Op), 10)
		case "gpu_size":
			return strconv.FormatUint(e.GPU.Size, 10)
		case "gpu_dev_ptr":
			return fmt.Sprintf("0x%x", e.GPU.DevPtr)
		case "gpu_host_ptr":
			return fmt.Sprintf("0x%x", e.GPU.HostPtr)
		case "comm":
			return util.BytesToString(e.Comm[:])
		case "uid":
			return strconv.FormatUint(uint64(e.UID), 10)
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

