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
	Severity    types.AlertSeverity `yaml:"severity"`
	Action      RuleAction      `yaml:"action"`
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
			ID:        rule.ID + "-" + strconv.FormatUint(e.Timestamp, 10) + "-" + strconv.Itoa(int(e.PID)),
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

// evaluateCondition evaluates a single condition against an event.
func (re *RuleEngine) evaluateCondition(e types.Event, cond RuleCondition) bool {
	// Get field value based on event type and field name
	value := re.getFieldValue(e, cond.Field)
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

// getFieldValue extracts a field value from an event based on field name.
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
	}
	return ""
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
