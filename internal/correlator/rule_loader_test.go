package correlator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetAllConditionsRecursive verifies that getAllConditions properly
// recurses into nested SubGroups to extract all conditions.
func TestGetAllConditionsRecursive(t *testing.T) {
	tests := []struct {
		name       string
		rule       Rule
		wantCount  int
		wantFields []string
	}{
		{
			name: "simple condition",
			rule: Rule{
				ID:        "test_001",
				Name:      "Simple rule",
				EventType: types.EventTCPConnect,
				Condition: RuleCondition{
					Field:  "dport",
					Op:     "equals",
					Values: []string{"80"},
				},
			},
			wantCount:  1,
			wantFields: []string{"dport"},
		},
		{
			name: "single level condition group",
			rule: Rule{
				ID:        "test_002",
				Name:      "Group rule",
				EventType: types.EventTCPConnect,
				ConditionGroup: &RuleConditionGroup{
					Operator: "and",
					Conditions: []RuleCondition{
						{Field: "dport", Op: "equals", Values: []string{"80"}},
						{Field: "daddr", Op: "prefix", Values: []string{"10.0."}},
					},
				},
			},
			wantCount:  2,
			wantFields: []string{"dport", "daddr"},
		},
		{
			name: "nested subgroups",
			rule: Rule{
				ID:        "test_003",
				Name:      "Nested rule",
				EventType: types.EventFileAccess,
				ConditionGroup: &RuleConditionGroup{
					Operator: "and",
					Conditions: []RuleCondition{
						{Field: "filename", Op: "prefix", Values: []string{"/etc/"}},
					},
					SubGroups: []RuleConditionGroup{
						{
							Operator: "or",
							Conditions: []RuleCondition{
								{Field: "extension", Op: "equals", Values: []string{".conf"}},
								{Field: "extension", Op: "equals", Values: []string{".key"}},
							},
						},
					},
				},
			},
			wantCount:  3,
			wantFields: []string{"filename", "extension", "extension"},
		},
		{
			name: "deeply nested subgroups",
			rule: Rule{
				ID:        "test_004",
				Name:      "Deep nested rule",
				EventType: types.EventSyscall,
				ConditionGroup: &RuleConditionGroup{
					Operator: "and",
					Conditions: []RuleCondition{
						{Field: "nr", Op: "gt", Values: []string{"0"}},
					},
					SubGroups: []RuleConditionGroup{
						{
							Operator: "or",
							Conditions: []RuleCondition{
								{Field: "nr", Op: "lt", Values: []string{"100"}},
							},
							SubGroups: []RuleConditionGroup{
								{
									Operator: "and",
									Conditions: []RuleCondition{
										{Field: "ret", Op: "equals", Values: []string{"0"}},
									},
								},
							},
						},
					},
				},
			},
			wantCount:  3,
			wantFields: []string{"nr", "nr", "ret"},
		},
		{
			name: "multiple subgroups at same level",
			rule: Rule{
				ID:        "test_005",
				Name:      "Multiple subgroups",
				EventType: types.EventTCPConnect,
				ConditionGroup: &RuleConditionGroup{
					Operator: "and",
					SubGroups: []RuleConditionGroup{
						{
							Operator: "or",
							Conditions: []RuleCondition{
								{Field: "dport", Op: "equals", Values: []string{"80"}},
								{Field: "dport", Op: "equals", Values: []string{"443"}},
							},
						},
						{
							Operator: "or",
							Conditions: []RuleCondition{
								{Field: "proto", Op: "equals", Values: []string{"6"}},
								{Field: "proto", Op: "equals", Values: []string{"17"}},
							},
						},
					},
				},
			},
			wantCount:  4,
			wantFields: []string{"dport", "dport", "proto", "proto"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conditions := getAllConditions(&tt.rule)
			assert.Len(t, conditions, tt.wantCount, "expected %d conditions, got %d", tt.wantCount, len(conditions))

			for i, field := range tt.wantFields {
				if i < len(conditions) {
					assert.Equal(t, field, conditions[i].Field, "condition %d field mismatch", i)
				}
			}
		})
	}
}

// TestNestedConditionGroupValidation verifies that invalid regex in nested
// SubGroups is properly rejected at load time.
func TestNestedConditionGroupValidation(t *testing.T) {
	// Create a temporary rule file with nested invalid regex
	ruleContent := `
rules:
  - id: nested_invalid_regex
    name: "Test nested invalid regex"
    description: "This rule has invalid regex in a nested subgroup"
    event_type: 3
    condition_group:
      operator: AND
      conditions:
        - field: filename
          op: prefix
          values: ["/etc/"]
      subgroups:
        - operator: OR
          conditions:
            - field: extension
              op: regex
              values: ["[invalid(regex"]
`
	tmpDir := t.TempDir()
	ruleFile := filepath.Join(tmpDir, "test_rules.yaml")
	err := os.WriteFile(ruleFile, []byte(ruleContent), 0644)
	require.NoError(t, err)

	// Attempt to load the rules - should fail due to invalid regex
	_, err = LoadRulesFromFile(ruleFile)
	require.Error(t, err, "expected error for invalid regex in nested subgroup")
	assert.Contains(t, err.Error(), "regex", "error should mention regex validation")
}

// TestValidateRegexPatterns_LengthLimit verifies that patterns exceeding
// maxRegexPatternLen are rejected to guard against excessive compilation cost.
func TestValidateRegexPatterns_LengthLimit(t *testing.T) {
	// Pattern within the allowed limit — should compile fine.
	short := strings.Repeat("a", maxRegexPatternLen)
	err := validateRegexPatterns([]string{short})
	require.NoError(t, err)

	// Pattern one byte over the limit — should be rejected.
	long := strings.Repeat("a", maxRegexPatternLen+1)
	err = validateRegexPatterns([]string{long})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "maximum length")
}

// TestNestedInvalidFieldName verifies that invalid field names in nested
// SubGroups are properly rejected at load time.
func TestNestedInvalidFieldName(t *testing.T) {
	ruleContent := `
rules:
  - id: nested_invalid_field
    name: "Test nested invalid field"
    description: "This rule has invalid field name in a nested subgroup"
    event_type: 2
    condition_group:
      operator: AND
      conditions:
        - field: dport
          op: equals
          values: ["80"]
      subgroups:
        - operator: OR
          conditions:
            - field: invalid_field_name
              op: equals
              values: ["test"]
`
	tmpDir := t.TempDir()
	ruleFile := filepath.Join(tmpDir, "test_rules.yaml")
	err := os.WriteFile(ruleFile, []byte(ruleContent), 0644)
	require.NoError(t, err)

	_, err = LoadRulesFromFile(ruleFile)
	require.Error(t, err, "expected error for invalid field name in nested subgroup")
	assert.Contains(t, err.Error(), "field", "error should mention field validation")
}

// TestNestedCIDRValidation verifies that invalid CIDR in nested SubGroups
// is properly rejected at load time.
func TestNestedCIDRValidation(t *testing.T) {
	ruleContent := `
rules:
  - id: nested_invalid_cidr
    name: "Test nested invalid CIDR"
    description: "This rule has invalid CIDR in a nested subgroup"
    event_type: 2
    condition_group:
      operator: AND
      conditions:
        - field: dport
          op: equals
          values: ["80"]
      subgroups:
        - operator: OR
          conditions:
            - field: daddr
              op: in_cidr
              values: ["invalid-cidr"]
`
	tmpDir := t.TempDir()
	ruleFile := filepath.Join(tmpDir, "test_rules.yaml")
	err := os.WriteFile(ruleFile, []byte(ruleContent), 0644)
	require.NoError(t, err)

	_, err = LoadRulesFromFile(ruleFile)
	require.Error(t, err, "expected error for invalid CIDR in nested subgroup")
	assert.Contains(t, err.Error(), "CIDR", "error should mention CIDR validation")
}

// TestValidNestedRules verifies that valid nested rules load successfully.
func TestValidNestedRules(t *testing.T) {
	ruleContent := `
rules:
  - id: valid_nested
    name: "Valid nested rule"
    description: "This is a valid rule with nested subgroups"
    event_type: 3
    condition_group:
      operator: AND
      conditions:
        - field: filename
          op: prefix
          values: ["/etc/", "/var/"]
      subgroups:
        - operator: OR
          conditions:
            - field: extension
              op: regex
              values: ["^\\.conf$", "^\\.key$"]
        - operator: OR
          conditions:
            - field: directory
              op: prefix
              values: ["/etc/ssl/", "/etc/ssh/"]
`
	tmpDir := t.TempDir()
	ruleFile := filepath.Join(tmpDir, "test_rules.yaml")
	err := os.WriteFile(ruleFile, []byte(ruleContent), 0644)
	require.NoError(t, err)

	rules, err := LoadRulesFromFile(ruleFile)
	require.NoError(t, err, "valid nested rules should load successfully")
	assert.Len(t, rules, 1)
	assert.Equal(t, "valid_nested", rules[0].ID)
}

// TestGetConditionsFromGroupEdgeCases tests edge cases for getConditionsFromGroup.
func TestGetConditionsFromGroupEdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		group     *RuleConditionGroup
		wantCount int
	}{
		{
			name:      "nil group",
			group:     nil,
			wantCount: 0,
		},
		{
			name: "empty group",
			group: &RuleConditionGroup{
				Operator:   "and",
				Conditions: []RuleCondition{},
				SubGroups:  []RuleConditionGroup{},
			},
			wantCount: 0,
		},
		{
			name: "group with empty subgroup",
			group: &RuleConditionGroup{
				Operator: "and",
				Conditions: []RuleCondition{
					{Field: "dport", Op: "equals", Values: []string{"80"}},
				},
				SubGroups: []RuleConditionGroup{
					{
						Operator:   "or",
						Conditions: []RuleCondition{},
					},
				},
			},
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conditions := getConditionsFromGroup(tt.group)
			assert.Len(t, conditions, tt.wantCount)
		})
	}
}

// TestLoadRulesFromDirWithNestedRules verifies that loading rules from a
// directory properly validates nested conditions.
func TestLoadRulesFromDirWithNestedRules(t *testing.T) {
	tmpDir := t.TempDir()

	// Valid rule file
	validRule := `
rules:
  - id: valid_rule
    name: "Valid rule"
    event_type: network
    condition:
      field: dport
      op: equals
      values: ["80"]
`
	err := os.WriteFile(filepath.Join(tmpDir, "valid.yaml"), []byte(validRule), 0644)
	require.NoError(t, err)

	// Invalid rule file with nested invalid regex
	invalidRule := `
rules:
  - id: invalid_rule
    name: "Invalid rule"
    event_type: 3
    condition_group:
      operator: AND
      subgroups:
        - operator: OR
          conditions:
            - field: filename
              op: regex
              values: ["[invalid"]
`
	err = os.WriteFile(filepath.Join(tmpDir, "invalid.yaml"), []byte(invalidRule), 0644)
	require.NoError(t, err)

	// Should fail due to invalid rule
	_, err = LoadRulesFromDir(tmpDir)
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "invalid.yaml"), "error should mention the invalid file")
}

// TestRuleTagsLoading verifies that tags are properly loaded from YAML rules.
func TestRuleTagsLoading(t *testing.T) {
	ruleContent := `
rules:
  - id: tagged_rule
    name: "Rule with tags"
    description: "This rule has tags for categorization"
    event_type: 3
    condition:
      field: filename
      op: prefix
      values: ["/etc/"]
    severity: critical
    action: alert
    tags: [owasp, path-traversal, a01-broken-access-control]
`
	tmpDir := t.TempDir()
	ruleFile := filepath.Join(tmpDir, "tagged_rules.yaml")
	err := os.WriteFile(ruleFile, []byte(ruleContent), 0644)
	require.NoError(t, err)

	rules, err := LoadRulesFromFile(ruleFile)
	require.NoError(t, err)
	require.Len(t, rules, 1)

	rule := rules[0]
	assert.Equal(t, "tagged_rule", rule.ID)
	assert.Equal(t, []string{"owasp", "path-traversal", "a01-broken-access-control"}, rule.Tags)
}

// TestRuleTagsFiltering verifies that rules can be filtered by tags.
func TestRuleTagsFiltering(t *testing.T) {
	rules := []Rule{
		{
			ID:        "rule_001",
			Name:      "OWASP Path Traversal",
			EventType: types.EventFileAccess,
			Tags:      []string{"owasp", "path-traversal", "a01"},
		},
		{
			ID:        "rule_002",
			Name:      "Container Escape",
			EventType: types.EventSyscall,
			Tags:      []string{"container-escape", "privilege-escalation"},
		},
		{
			ID:        "rule_003",
			Name:      "CIS Benchmark",
			EventType: types.EventSyscall,
			Tags:      []string{"cis", "compliance"},
		},
		{
			ID:        "rule_004",
			Name:      "No tags rule",
			EventType: types.EventSyscall,
			Tags:      nil,
		},
	}

	// Test filtering by single tag
	owaspRules := filterRulesByTag(rules, "owasp")
	assert.Len(t, owaspRules, 1)
	assert.Equal(t, "rule_001", owaspRules[0].ID)

	// Test filtering by container-escape tag
	escapeRules := filterRulesByTag(rules, "container-escape")
	assert.Len(t, escapeRules, 1)
	assert.Equal(t, "rule_002", escapeRules[0].ID)

	// Test filtering by non-existent tag
	noRules := filterRulesByTag(rules, "non-existent")
	assert.Len(t, noRules, 0)

	// Test filtering with empty tag (should return all)
	allRules := filterRulesByTag(rules, "")
	assert.Len(t, allRules, 4)
}

// TestRuleTagsEmpty verifies that rules without tags load correctly.
func TestRuleTagsEmpty(t *testing.T) {
	ruleContent := `
rules:
  - id: no_tags_rule
    name: "Rule without tags"
    description: "This rule has no tags field"
    event_type: 3
    condition:
      field: filename
      op: prefix
      values: ["/etc/"]
    severity: warning
    action: alert
`
	tmpDir := t.TempDir()
	ruleFile := filepath.Join(tmpDir, "no_tags.yaml")
	err := os.WriteFile(ruleFile, []byte(ruleContent), 0644)
	require.NoError(t, err)

	rules, err := LoadRulesFromFile(ruleFile)
	require.NoError(t, err)
	require.Len(t, rules, 1)

	rule := rules[0]
	assert.Equal(t, "no_tags_rule", rule.ID)
	assert.Nil(t, rule.Tags)
	assert.Empty(t, rule.Tags)
}

// TestRuleTagsFromOWASPRules verifies that OWASP rules with tags load correctly.
func TestRuleTagsFromOWASPRules(t *testing.T) {
	// Use numeric event_type values (3 = file, 2 = network)
	ruleContent := `
rules:
  - id: owasp_path_traversal
    name: "OWASP: Path traversal attempt"
    description: "Process accessed file with path traversal pattern"
    event_type: 3
    condition:
      field: filename
      op: regex
      values: ["\\.\\./"]
    severity: critical
    action: alert
    tags: [owasp, path-traversal, a01-broken-access-control]
  - id: owasp_ssrf
    name: "OWASP: SSRF attempt"
    description: "Web server accessing cloud metadata"
    event_type: 2
    condition:
      field: daddr
      op: in
      values: ["169.254.169.254"]
    severity: critical
    action: alert
    tags: [owasp, ssrf, a10-ssrf, metadata, cloud]
`
	tmpDir := t.TempDir()
	ruleFile := filepath.Join(tmpDir, "owasp_rules.yaml")
	err := os.WriteFile(ruleFile, []byte(ruleContent), 0644)
	require.NoError(t, err)

	rules, err := LoadRulesFromFile(ruleFile)
	require.NoError(t, err)
	require.Len(t, rules, 2)

	// Check first rule tags
	assert.Equal(t, []string{"owasp", "path-traversal", "a01-broken-access-control"}, rules[0].Tags)

	// Check second rule tags
	assert.Equal(t, []string{"owasp", "ssrf", "a10-ssrf", "metadata", "cloud"}, rules[1].Tags)

	// Test filtering
	owaspRules := filterRulesByTag(rules, "owasp")
	assert.Len(t, owaspRules, 2)

	ssrfRules := filterRulesByTag(rules, "ssrf")
	assert.Len(t, ssrfRules, 1)
	assert.Equal(t, "owasp_ssrf", ssrfRules[0].ID)
}

// TestRuleLoaderRejectsUnknownField verifies that a rule referencing a
// non-existent field name is rejected at load time (Sprint 27.0 Part C).
func TestRuleLoaderRejectsUnknownField(t *testing.T) {
	tmpDir := t.TempDir()

	yamlContent := `rules:
  - id: bad_field_rule
    name: Bad Field Rule
    event_type: 2
    condition:
      field: "unknwon_typo"
      op: equals
      values: ["8080"]
    severity: warning
    action: alert
`
	path := filepath.Join(tmpDir, "bad.yaml")
	require.NoError(t, os.WriteFile(path, []byte(yamlContent), 0644))

	_, err := LoadRulesFromFile(path)
	require.Error(t, err, "rule with unknown field should be rejected")
	assert.Contains(t, err.Error(), "unknwon_typo", "error should mention the bad field name")
}

// TestEvaluateConditionEmptyLegitValue verifies that a field with a real empty
// string value is handled differently from a completely missing field, so that
// legitimate empty-value matches still work (Sprint 27.0 Part C).
func TestEvaluateConditionEmptyLegitValue(t *testing.T) {
	// A rule that checks dport equals "0" — a legitimate (if unusual) zero port.
	rule := Rule{
		ID:        "zero_port",
		Name:      "Zero Port Rule",
		EventType: types.EventTCPConnect,
		Condition: RuleCondition{Field: "dport", Op: OpEquals, Values: []string{"0"}},
		Severity:  types.SeverityWarning,
		Action:    ActionAlert,
	}
	engine := NewRuleEngine([]Rule{rule})
	event := types.Event{
		Type:    types.EventTCPConnect,
		Network: &types.NetworkEvent{Dport: 0},
	}
	// "0" is a non-empty string — the rule must match.
	alerts := engine.Evaluate(event)
	assert.Len(t, alerts, 1, "rule for dport==0 must match event with Dport=0")
}

// filterRulesByTag is a helper function to filter rules by a specific tag.
func filterRulesByTag(rules []Rule, tag string) []Rule {
	if tag == "" {
		return rules
	}
	var filtered []Rule
	for _, rule := range rules {
		for _, t := range rule.Tags {
			if t == tag {
				filtered = append(filtered, rule)
				break
			}
		}
	}
	return filtered
}
