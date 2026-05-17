// Package correlator provides event correlation and rule-based detection.
package correlator

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ebpf-guard/ebpf-guard/pkg/types"
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

// RuleEngine evaluates events against rules.
type RuleEngine struct {
	rules []Rule
	// compiled regex patterns for performance
	regexCache map[string]*regexp.Regexp
	// compiled CIDR ranges
	cidrCache map[string]*net.IPNet
	// mu protects the rules slice
	mu sync.RWMutex
}

// NewRuleEngine creates a new rule engine with the given rules.
func NewRuleEngine(rules []Rule) *RuleEngine {
	re := &RuleEngine{
		rules:      rules,
		regexCache: make(map[string]*regexp.Regexp),
		cidrCache:  make(map[string]*net.IPNet),
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

// compilePatterns pre-compiles regex and CIDR patterns for performance.
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
			}
		}
	}
}

// getAllConditions extracts all conditions from a rule (handles both Condition and ConditionGroup).
func (re *RuleEngine) getAllConditions(rule Rule) []RuleCondition {
	if rule.ConditionGroup != nil {
		return rule.ConditionGroup.Conditions
	}
	return []RuleCondition{rule.Condition}
}

// Evaluate checks an event against all rules and returns matching alerts.
func (re *RuleEngine) Evaluate(e types.Event) []types.Alert {
	var alerts []types.Alert

	for _, rule := range re.rules {
		if !re.matches(e, rule) {
			continue
		}

		// Rule matched - check action
		if rule.Action == ActionDrop {
			continue // Silently drop
		}

		// Generate alert
		alert := types.Alert{
			ID:        fmt.Sprintf("%s-%d-%d", rule.ID, e.Timestamp, e.PID),
			Timestamp: time.Unix(0, int64(e.Timestamp)),
			RuleID:    rule.ID,
			RuleName:  rule.Name,
			Severity:  rule.Severity,
			Message:   rule.Description,
			PID:       e.PID,
			Comm:      string(e.Comm[:]),
			Event:     e,
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

// evaluateConditionGroup evaluates a group of conditions with AND/OR logic.
func (re *RuleEngine) evaluateConditionGroup(e types.Event, group *RuleConditionGroup) bool {
	if len(group.Conditions) == 0 {
		return true
	}

	switch strings.ToLower(group.Operator) {
	case "or":
		// OR: at least one condition must match
		for _, cond := range group.Conditions {
			if re.evaluateCondition(e, cond) {
				return true
			}
		}
		return false
	case "and", "":
		// AND: all conditions must match (default)
		for _, cond := range group.Conditions {
			if !re.evaluateCondition(e, cond) {
				return false
			}
		}
		return true
	default:
		// Unknown operator, default to AND
		for _, cond := range group.Conditions {
			if !re.evaluateCondition(e, cond) {
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
	if value == "" && cond.Op != OpEquals && cond.Op != OpNotEquals {
		return false
	}

	// Evaluate condition
	switch cond.Op {
	case OpIn:
		return contains(cond.Values, value)
	case OpNotIn:
		return !contains(cond.Values, value)
	case OpEquals:
		return len(cond.Values) > 0 && value == cond.Values[0]
	case OpNotEquals:
		return len(cond.Values) == 0 || value != cond.Values[0]
	case OpPrefix:
		return hasPrefix(cond.Values, value)
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
func (re *RuleEngine) getFieldValue(e types.Event, field string) string {
	switch e.Type {
	case types.EventTCPConnect:
		if e.Network == nil {
			return ""
		}
		switch field {
		case "dport":
			return fmt.Sprintf("%d", e.Network.Dport)
		case "sport":
			return fmt.Sprintf("%d", e.Network.Sport)
		case "daddr":
			return formatIP(e.Network.Daddr[:], e.Network.Family)
		case "saddr":
			return formatIP(e.Network.Saddr[:], e.Network.Family)
		case "proto":
			return fmt.Sprintf("%d", e.Network.Proto)
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
			return string(bytesToString(e.File.Filename[:]))
		case "flags":
			return fmt.Sprintf("%d", e.File.Flags)
		case "mode":
			return fmt.Sprintf("%d", e.File.Mode)
		case "op":
			ops := []string{"open", "read", "write"}
			if int(e.File.Op) < len(ops) {
				return ops[e.File.Op]
			}
			return fmt.Sprintf("%d", e.File.Op)
		}
	case types.EventSyscall:
		if e.Syscall == nil {
			return ""
		}
		switch field {
		case "nr":
			return fmt.Sprintf("%d", e.Syscall.Nr)
		case "ret":
			return fmt.Sprintf("%d", e.Syscall.Ret)
		}
	case types.EventDNS:
		if e.DNS == nil {
			return ""
		}
		switch field {
		case "qname":
			return e.DNS.QName
		case "qtype":
			return fmt.Sprintf("%d", e.DNS.QType)
		case "rcode":
			return fmt.Sprintf("%d", e.DNS.RCode)
		case "direction":
			return fmt.Sprintf("%d", e.DNS.Direction)
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
			return fmt.Sprintf("%d", e.TLS.Direction)
		case "data_len":
			return fmt.Sprintf("%d", e.TLS.DataLen)
		}
	case types.EventPrivesc:
		// caps_gained / caps_dropped are handled before getFieldValue.
		// Common process fields are also accessible.
		switch field {
		case "uid":
			return fmt.Sprintf("%d", e.UID)
		case "comm":
			return bytesToString(e.Comm[:])
		case "caps":
			// Return hex bitmask of new caps for generic comparisons.
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
			return fmt.Sprintf("%d", e.NetClose.Dport)
		case "sport":
			return fmt.Sprintf("%d", e.NetClose.Sport)
		case "daddr":
			return formatIP(e.NetClose.Daddr[:], e.NetClose.Family)
		case "saddr":
			return formatIP(e.NetClose.Saddr[:], e.NetClose.Family)
		case "family":
			if e.NetClose.Family == types.AFInet6 {
				return "ipv6"
			}
			return "ipv4"
		case "duration_sec":
			return fmt.Sprintf("%d", int64(e.NetClose.Duration.Seconds()))
		case "duration_ms":
			return fmt.Sprintf("%d", e.NetClose.Duration.Milliseconds())
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

// bytesToString converts a byte slice to string, stopping at first null byte.
func bytesToString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// formatIP formats an IP address based on address family.
// For IPv4, uses the first 4 bytes; for IPv6, uses all 16 bytes.
func formatIP(addr []byte, family types.AddressFamily) string {
	if family == types.AFInet6 {
		// IPv6 address
		return net.IP(addr).String()
	}
	// IPv4 address - only use first 4 bytes
	return fmt.Sprintf("%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3])
}
