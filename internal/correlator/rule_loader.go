// Package correlator provides event correlation and rule-based detection.
package correlator

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"gopkg.in/yaml.v3"
)

// Valid field names for each event type. These are the single source of truth
// for field name validation — keep in sync with getFieldValue in rules.go.
var (
	validNetworkFields = map[string]bool{
		"dport": true, "sport": true, "daddr": true, "saddr": true, "proto": true, "family": true,
	}
	validFileFields = map[string]bool{
		"filename": true, "flags": true, "mode": true, "op": true, "directory": true, "extension": true,
	}
	validSyscallFields = map[string]bool{
		"nr": true, "ret": true,
	}
	validDNSFields = map[string]bool{
		"qname": true, "qtype": true, "rcode": true, "direction": true,
		// Enriched fields computed on demand from qname
		"qname_length": true, "qname_entropy": true, "qname_dga_score": true,
		"qname_digit_ratio": true, "qname_subdomain_count": true, "qname_is_dga": true,
	}
	validTLSFields = map[string]bool{
		"tls_data": true, "direction": true, "data_len": true,
	}
	// caps_gained / caps_dropped use the OpCapsGained / OpCapsDropped operators
	// (not standard value comparison), so their only meaningful field is "caps".
	validPrivescFields = map[string]bool{
		"caps": true, "uid": true, "comm": true,
	}
	validNetCloseFields = map[string]bool{
		"dport": true, "sport": true, "daddr": true, "saddr": true,
		"family": true, "duration_sec": true, "duration_ms": true,
	}
)

// Ensure RuleConditionGroup has SubGroups field for recursive validation.
// This is defined in rules.go but we need to reference it here.

// LoadRulesFromFile loads rules from a YAML file with full validation.
func LoadRulesFromFile(path string) ([]Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("correlator: read rules file: %w", err)
	}

	var ruleSet RuleSet
	if err := yaml.Unmarshal(data, &ruleSet); err != nil {
		return nil, fmt.Errorf("correlator: unmarshal rules: %w", err)
	}

	// Validate rules
	for i, rule := range ruleSet.Rules {
		if err := validateRule(&rule); err != nil {
			return nil, fmt.Errorf("correlator: validate rule %d (%s): %w", i, rule.ID, err)
		}
	}

	return ruleSet.Rules, nil
}

// LoadRulesFromDir loads all .yaml/.yml files from a directory.
func LoadRulesFromDir(dir string) ([]Rule, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("correlator: read rules directory: %w", err)
	}

	var allRules []Rule
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		rules, err := LoadRulesFromFile(path)
		if err != nil {
			return nil, fmt.Errorf("correlator: load rules from %s: %w", path, err)
		}

		allRules = append(allRules, rules...)
	}

	return allRules, nil
}

// validateRule validates a single rule including regex, CIDR, and field names.
func validateRule(rule *Rule) error {
	if rule.ID == "" {
		return fmt.Errorf("rule ID is required")
	}
	if rule.Name == "" {
		return fmt.Errorf("rule name is required")
	}
	if rule.EventType == 0 {
		return fmt.Errorf("event type is required")
	}
	if rule.Action == "" {
		rule.Action = ActionAlert // Default action
	}
	if rule.Severity == "" {
		rule.Severity = "warning" // Default severity
	}

	// Reject empty condition_group (Н-4): would silently match every event.
	if rule.ConditionGroup != nil && len(rule.ConditionGroup.Conditions) == 0 && len(rule.ConditionGroup.SubGroups) == 0 {
		return fmt.Errorf("rule %s: condition_group has no conditions or subgroups", rule.ID)
	}

	// Validate conditions
	conditions := getAllConditions(rule)
	for _, cond := range conditions {
		if err := validateCondition(&cond, rule.EventType); err != nil {
			return fmt.Errorf("condition validation failed: %w", err)
		}
	}

	return nil
}

// getAllConditions extracts all conditions from a rule, recursively traversing SubGroups.
func getAllConditions(rule *Rule) []RuleCondition {
	if rule.ConditionGroup != nil {
		return getConditionsFromGroup(rule.ConditionGroup)
	}
	return []RuleCondition{rule.Condition}
}

// getConditionsFromGroup recursively extracts conditions from a RuleConditionGroup and its SubGroups.
func getConditionsFromGroup(group *RuleConditionGroup) []RuleCondition {
	if group == nil {
		return nil
	}

	var conditions []RuleCondition

	// Add direct conditions
	conditions = append(conditions, group.Conditions...)

	// Recursively process subgroups
	for i := range group.SubGroups {
		conditions = append(conditions, getConditionsFromGroup(&group.SubGroups[i])...)
	}

	return conditions
}

// validateCondition validates a single condition including regex, CIDR, and field names.
func validateCondition(cond *RuleCondition, eventType types.EventType) error {
	// Validate field name is valid for the event type
	if err := validateFieldName(cond.Field, eventType); err != nil {
		return err
	}

	// Validate operator-specific requirements
	switch cond.Op {
	case OpRegex:
		if err := validateRegexPatterns(cond.Values); err != nil {
			return fmt.Errorf("regex validation failed for field %s: %w", cond.Field, err)
		}
	case OpInCIDR, OpNotInCIDR:
		if err := validateCIDRPatterns(cond.Values); err != nil {
			return fmt.Errorf("CIDR validation failed for field %s: %w", cond.Field, err)
		}
		// CIDR only valid for IP address fields
		if cond.Field != "daddr" && cond.Field != "saddr" {
			return fmt.Errorf("CIDR operator %s can only be used with daddr/saddr fields, not %s", cond.Op, cond.Field)
		}
	case OpIn, OpNotIn, OpEquals, OpNotEquals, OpPrefix, OpSuffix,
		OpGreaterThan, OpLessThan, OpGreaterOrEqual, OpLessOrEqual,
		OpCapsGained, OpCapsDropped:
		// These operators don't need pre-validation
	default:
		return fmt.Errorf("unknown operator: %s", cond.Op)
	}

	return nil
}

// validateFieldName checks if a field name is valid for the given event type.
func validateFieldName(field string, eventType types.EventType) error {
	if field == "" {
		return fmt.Errorf("field name is required")
	}

	var validFields map[string]bool
	switch eventType {
	case types.EventTCPConnect:
		validFields = validNetworkFields
	case types.EventFileAccess:
		validFields = validFileFields
	case types.EventSyscall:
		validFields = validSyscallFields
	case types.EventDNS:
		validFields = validDNSFields
	case types.EventTLS:
		validFields = validTLSFields
	case types.EventPrivesc:
		validFields = validPrivescFields
	case types.EventNetClose:
		validFields = validNetCloseFields
	default:
		return fmt.Errorf("unknown event type: %d", eventType)
	}

	if !validFields[field] {
		// Get list of valid fields for error message
		var validList []string
		for f := range validFields {
			validList = append(validList, f)
		}
		return fmt.Errorf("invalid field name %q for event type %d, valid fields: %v", field, eventType, validList)
	}

	return nil
}

// validateRegexPatterns compiles and validates all regex patterns.
func validateRegexPatterns(patterns []string) error {
	if len(patterns) == 0 {
		return fmt.Errorf("regex operator requires at least one pattern")
	}
	for _, pattern := range patterns {
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("invalid regex pattern %q: %w", pattern, err)
		}
	}
	return nil
}

// validateCIDRPatterns parses and validates all CIDR ranges.
func validateCIDRPatterns(cidrs []string) error {
	if len(cidrs) == 0 {
		return fmt.Errorf("CIDR operator requires at least one CIDR range")
	}
	for _, cidr := range cidrs {
		_, _, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("invalid CIDR range %q: %w", cidr, err)
		}
	}
	return nil
}
