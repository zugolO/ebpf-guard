// Package correlator provides event correlation and rule-based detection.
package correlator

import (
	"fmt"
	"testing"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRuleEngine_Evaluate(t *testing.T) {
	tests := []struct {
		name     string
		rules    []Rule
		event    types.Event
		expected int
	}{
		{
			name:     "empty ruleset",
			rules:    []Rule{},
			event:    types.Event{Type: types.EventTCPConnect},
			expected: 0,
		},
		{
			name: "network rule - dport equals",
			rules: []Rule{
				{
					ID:        "net_001",
					Name:      "Port 8080 Rule",
					EventType: types.EventTCPConnect,
					Condition: RuleCondition{Field: "dport", Op: OpEquals, Values: []string{"8080"}},
					Severity:  types.SeverityWarning,
					Action:    ActionAlert,
				},
			},
			event: types.Event{
				Type:    types.EventTCPConnect,
				Network: &types.NetworkEvent{Dport: 8080},
			},
			expected: 1,
		},
		{
			name: "network rule - dport not equals",
			rules: []Rule{
				{
					ID:        "net_001",
					Name:      "Port 8080 Rule",
					EventType: types.EventTCPConnect,
					Condition: RuleCondition{Field: "dport", Op: OpEquals, Values: []string{"8080"}},
					Severity:  types.SeverityWarning,
					Action:    ActionAlert,
				},
			},
			event: types.Event{
				Type:    types.EventTCPConnect,
				Network: &types.NetworkEvent{Dport: 9090},
			},
			expected: 0,
		},
		{
			name: "network rule - dport in list",
			rules: []Rule{
				{
					ID:        "net_002",
					Name:      "Allowed Ports",
					EventType: types.EventTCPConnect,
					Condition: RuleCondition{Field: "dport", Op: OpIn, Values: []string{"80", "443", "53"}},
					Severity:  types.SeverityWarning,
					Action:    ActionAlert,
				},
			},
			event: types.Event{
				Type:    types.EventTCPConnect,
				Network: &types.NetworkEvent{Dport: 443},
			},
			expected: 1,
		},
		{
			name: "network rule - dport not_in list",
			rules: []Rule{
				{
					ID:        "net_003",
					Name:      "Unexpected Egress",
					EventType: types.EventTCPConnect,
					Condition: RuleCondition{Field: "dport", Op: OpNotIn, Values: []string{"80", "443", "53"}},
					Severity:  types.SeverityWarning,
					Action:    ActionAlert,
				},
			},
			event: types.Event{
				Type:    types.EventTCPConnect,
				Network: &types.NetworkEvent{Dport: 8080},
			},
			expected: 1,
		},
		{
			name: "file rule - filename prefix",
			rules: []Rule{
				{
					ID:        "file_001",
					Name:      "Sensitive File Access",
					EventType: types.EventFileAccess,
					Condition: RuleCondition{Field: "filename", Op: OpPrefix, Values: []string{"/etc/shadow", "/etc/passwd"}},
					Severity:  types.SeverityCritical,
					Action:    ActionAlert,
				},
			},
			event: types.Event{
				Type: types.EventFileAccess,
				File: &types.FileEvent{
					Filename: stringToByteArray("/etc/shadow"),
				},
			},
			expected: 1,
		},
		{
			name: "file rule - filename no match",
			rules: []Rule{
				{
					ID:        "file_001",
					Name:      "Sensitive File Access",
					EventType: types.EventFileAccess,
					Condition: RuleCondition{Field: "filename", Op: OpPrefix, Values: []string{"/etc/shadow"}},
					Severity:  types.SeverityCritical,
					Action:    ActionAlert,
				},
			},
			event: types.Event{
				Type: types.EventFileAccess,
				File: &types.FileEvent{
					Filename: stringToByteArray("/tmp/test"),
				},
			},
			expected: 0,
		},
		{
			name: "wrong event type",
			rules: []Rule{
				{
					ID:        "net_001",
					Name:      "Network Rule",
					EventType: types.EventTCPConnect,
					Condition: RuleCondition{Field: "dport", Op: OpEquals, Values: []string{"8080"}},
					Severity:  types.SeverityWarning,
					Action:    ActionAlert,
				},
			},
			event: types.Event{
				Type: types.EventSyscall,
			},
			expected: 0,
		},
		{
			name: "multiple rules - one matches",
			rules: []Rule{
				{
					ID:        "rule_001",
					Name:      "Port 80",
					EventType: types.EventTCPConnect,
					Condition: RuleCondition{Field: "dport", Op: OpEquals, Values: []string{"80"}},
					Severity:  types.SeverityWarning,
					Action:    ActionAlert,
				},
				{
					ID:        "rule_002",
					Name:      "Port 8080",
					EventType: types.EventTCPConnect,
					Condition: RuleCondition{Field: "dport", Op: OpEquals, Values: []string{"8080"}},
					Severity:  types.SeverityWarning,
					Action:    ActionAlert,
				},
			},
			event: types.Event{
				Type:    types.EventTCPConnect,
				Network: &types.NetworkEvent{Dport: 8080},
			},
			expected: 1,
		},
		{
			name: "multiple rules - both match",
			rules: []Rule{
				{
					ID:        "rule_001",
					Name:      "Any Port",
					EventType: types.EventTCPConnect,
					Condition: RuleCondition{Field: "dport", Op: OpNotIn, Values: []string{}},
					Severity:  types.SeverityWarning,
					Action:    ActionAlert,
				},
				{
					ID:        "rule_002",
					Name:      "Port 8080",
					EventType: types.EventTCPConnect,
					Condition: RuleCondition{Field: "dport", Op: OpEquals, Values: []string{"8080"}},
					Severity:  types.SeverityCritical,
					Action:    ActionAlert,
				},
			},
			event: types.Event{
				Type:    types.EventTCPConnect,
				Network: &types.NetworkEvent{Dport: 8080},
			},
			expected: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := NewRuleEngine(tt.rules)
			alerts := engine.Evaluate(tt.event)
			assert.Len(t, alerts, tt.expected)
		})
	}
}

func TestRuleEngine_AlertContent(t *testing.T) {
	rules := []Rule{
		{
			ID:          "test_001",
			Name:        "Test Alert",
			Description: "This is a test alert",
			EventType:   types.EventTCPConnect,
			Condition:   RuleCondition{Field: "dport", Op: OpEquals, Values: []string{"8080"}},
			Severity:    types.SeverityCritical,
			Action:      ActionAlert,
		},
	}

	engine := NewRuleEngine(rules)
	event := types.Event{
		Type:      types.EventTCPConnect,
		PID:       1234,
		Timestamp: 1234567890,
		Network:   &types.NetworkEvent{Dport: 8080},
	}

	alerts := engine.Evaluate(event)
	require.Len(t, alerts, 1)

	alert := alerts[0]
	// ID is intentionally empty from Evaluate — Ingest assigns the canonical monotonic ID.
	assert.Empty(t, alert.ID)
	assert.Equal(t, "test_001", alert.RuleID)
	assert.Equal(t, "Test Alert", alert.RuleName)
	assert.Equal(t, "This is a test alert", alert.Message)
	assert.Equal(t, types.SeverityCritical, alert.Severity)
	assert.Equal(t, uint32(1234), alert.PID)
	assert.Equal(t, uint32(1234), alert.Event.PID)
}

func TestRuleEngine_RegexOperator(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		value    string
		expected bool
	}{
		{"simple match", "^test.*", "test123", true},
		{"no match", "^test.*", "nottest", false},
		{"port pattern", ":(80|443)$", "192.168.1.1:80", true},
		{"port pattern no match", ":(80|443)$", "192.168.1.1:8080", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules := []Rule{
				{
					ID:        "regex_test",
					Name:      "Regex Test",
					EventType: types.EventFileAccess,
					Condition: RuleCondition{
						Field:  "filename",
						Op:     OpRegex,
						Values: []string{tt.pattern},
					},
					Severity: types.SeverityWarning,
					Action:   ActionAlert,
				},
			}

			engine := NewRuleEngine(rules)
			event := types.Event{
				Type: types.EventFileAccess,
				File: &types.FileEvent{
					Filename: stringToByteArray(tt.value),
				},
			}

			alerts := engine.Evaluate(event)
			if tt.expected {
				assert.Len(t, alerts, 1)
			} else {
				assert.Len(t, alerts, 0)
			}
		})
	}
}

func TestRuleEngine_NumericOperators(t *testing.T) {
	tests := []struct {
		name      string
		op        RuleConditionOperator
		value     uint16
		threshold string
		expected  bool
	}{
		{"gt - greater", OpGreaterThan, 100, "50", true},
		{"gt - equal", OpGreaterThan, 100, "100", false},
		{"gt - less", OpGreaterThan, 50, "100", false},
		{"lt - less", OpLessThan, 50, "100", true},
		{"lt - equal", OpLessThan, 100, "100", false},
		{"lt - greater", OpLessThan, 100, "50", false},
		{"gte - greater", OpGreaterOrEqual, 100, "50", true},
		{"gte - equal", OpGreaterOrEqual, 100, "100", true},
		{"gte - less", OpGreaterOrEqual, 50, "100", false},
		{"lte - less", OpLessOrEqual, 50, "100", true},
		{"lte - equal", OpLessOrEqual, 100, "100", true},
		{"lte - greater", OpLessOrEqual, 100, "50", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules := []Rule{
				{
					ID:        "numeric_test",
					Name:      "Numeric Test",
					EventType: types.EventTCPConnect,
					Condition: RuleCondition{
						Field:  "dport",
						Op:     tt.op,
						Values: []string{tt.threshold},
					},
					Severity: types.SeverityWarning,
					Action:   ActionAlert,
				},
			}

			engine := NewRuleEngine(rules)
			event := types.Event{
				Type:    types.EventTCPConnect,
				Network: &types.NetworkEvent{Dport: tt.value},
			}

			alerts := engine.Evaluate(event)
			if tt.expected {
				assert.Len(t, alerts, 1)
			} else {
				assert.Len(t, alerts, 0)
			}
		})
	}
}

func TestRuleEngine_CIDROperators(t *testing.T) {
	tests := []struct {
		name     string
		op       RuleConditionOperator
		ip       string
		cidrs    []string
		expected bool
	}{
		{"in_cidr - match", OpInCIDR, "192.168.1.100", []string{"192.168.1.0/24"}, true},
		{"in_cidr - no match", OpInCIDR, "10.0.0.1", []string{"192.168.1.0/24"}, false},
		{"in_cidr - multiple match", OpInCIDR, "10.0.0.1", []string{"192.168.1.0/24", "10.0.0.0/8"}, true},
		{"not_in_cidr - match", OpNotInCIDR, "10.0.0.1", []string{"192.168.1.0/24"}, true},
		{"not_in_cidr - no match", OpNotInCIDR, "192.168.1.100", []string{"192.168.1.0/24"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules := []Rule{
				{
					ID:        "cidr_test",
					Name:      "CIDR Test",
					EventType: types.EventTCPConnect,
					Condition: RuleCondition{
						Field:  "daddr",
						Op:     tt.op,
						Values: tt.cidrs,
					},
					Severity: types.SeverityWarning,
					Action:   ActionAlert,
				},
			}

			engine := NewRuleEngine(rules)
			ipBytes := ipToBytes(tt.ip)
			event := types.Event{
				Type: types.EventTCPConnect,
				Network: &types.NetworkEvent{
					Daddr:  ipBytes,
					Family: types.AFInet,
				},
			}

			alerts := engine.Evaluate(event)
			if tt.expected {
				assert.Len(t, alerts, 1)
			} else {
				assert.Len(t, alerts, 0)
			}
		})
	}
}

func TestRuleEngine_ConditionGroupAND(t *testing.T) {
	rules := []Rule{
		{
			ID:        "and_test",
			Name:      "AND Test",
			EventType: types.EventTCPConnect,
			ConditionGroup: &RuleConditionGroup{
				Operator: "and",
				Conditions: []RuleCondition{
					{Field: "dport", Op: OpEquals, Values: []string{"8080"}},
					{Field: "daddr", Op: OpEquals, Values: []string{"192.168.1.1"}},
				},
			},
			Severity: types.SeverityWarning,
			Action:   ActionAlert,
		},
	}

	engine := NewRuleEngine(rules)

	// Both conditions match
	event1 := types.Event{
		Type: types.EventTCPConnect,
		Network: &types.NetworkEvent{
			Dport:  8080,
			Daddr:  ipToBytes("192.168.1.1"),
			Family: types.AFInet,
		},
	}
	alerts := engine.Evaluate(event1)
	assert.Len(t, alerts, 1)

	// Only one condition matches
	event2 := types.Event{
		Type: types.EventTCPConnect,
		Network: &types.NetworkEvent{
			Dport:  8080,
			Daddr:  ipToBytes("10.0.0.1"),
			Family: types.AFInet,
		},
	}
	alerts = engine.Evaluate(event2)
	assert.Len(t, alerts, 0)
}

func TestRuleEngine_ConditionGroupOR(t *testing.T) {
	rules := []Rule{
		{
			ID:        "or_test",
			Name:      "OR Test",
			EventType: types.EventTCPConnect,
			ConditionGroup: &RuleConditionGroup{
				Operator: "or",
				Conditions: []RuleCondition{
					{Field: "dport", Op: OpEquals, Values: []string{"8080"}},
					{Field: "dport", Op: OpEquals, Values: []string{"9090"}},
				},
			},
			Severity: types.SeverityWarning,
			Action:   ActionAlert,
		},
	}

	engine := NewRuleEngine(rules)

	// First condition matches
	event1 := types.Event{
		Type:    types.EventTCPConnect,
		Network: &types.NetworkEvent{Dport: 8080},
	}
	alerts := engine.Evaluate(event1)
	assert.Len(t, alerts, 1)

	// Second condition matches
	event2 := types.Event{
		Type:    types.EventTCPConnect,
		Network: &types.NetworkEvent{Dport: 9090},
	}
	alerts = engine.Evaluate(event2)
	assert.Len(t, alerts, 1)

	// Neither condition matches
	event3 := types.Event{
		Type:    types.EventTCPConnect,
		Network: &types.NetworkEvent{Dport: 3000},
	}
	alerts = engine.Evaluate(event3)
	assert.Len(t, alerts, 0)
}

func TestRuleEngine_NotEqualsOperator(t *testing.T) {
	rules := []Rule{
		{
			ID:        "not_equals_test",
			Name:      "Not Equals Test",
			EventType: types.EventTCPConnect,
			Condition: RuleCondition{
				Field:  "dport",
				Op:     OpNotEquals,
				Values: []string{"80"},
			},
			Severity: types.SeverityWarning,
			Action:   ActionAlert,
		},
	}

	engine := NewRuleEngine(rules)

	// Port is not 80 - should match
	event1 := types.Event{
		Type:    types.EventTCPConnect,
		Network: &types.NetworkEvent{Dport: 8080},
	}
	alerts := engine.Evaluate(event1)
	assert.Len(t, alerts, 1)

	// Port is 80 - should not match
	event2 := types.Event{
		Type:    types.EventTCPConnect,
		Network: &types.NetworkEvent{Dport: 80},
	}
	alerts = engine.Evaluate(event2)
	assert.Len(t, alerts, 0)
}

func TestContains(t *testing.T) {
	tests := []struct {
		slice    []string
		value    string
		expected bool
	}{
		{[]string{"a", "b", "c"}, "b", true},
		{[]string{"a", "b", "c"}, "d", false},
		{[]string{}, "a", false},
		{[]string{"a"}, "a", true},
	}

	for _, tt := range tests {
		result := contains(tt.slice, tt.value)
		assert.Equal(t, tt.expected, result)
	}
}

func TestHasPrefix(t *testing.T) {
	tests := []struct {
		prefixes []string
		value    string
		expected bool
	}{
		{[]string{"/etc/", "/var/"}, "/etc/passwd", true},
		{[]string{"/etc/", "/var/"}, "/var/log", true},
		{[]string{"/etc/", "/var/"}, "/tmp/test", false},
		{[]string{}, "/etc/passwd", false},
		{[]string{"/etc/"}, "/etc/", true},
	}

	for _, tt := range tests {
		result := hasPrefix(tt.prefixes, tt.value)
		assert.Equal(t, tt.expected, result)
	}
}

// Helper function to convert string to fixed-size byte array
func stringToByteArray(s string) [256]byte {
	var arr [256]byte
	copy(arr[:], s)
	return arr
}

// Helper function to convert IP string to 16-byte array (IPv4 in first 4 bytes)
func ipToBytes(ip string) [16]byte {
	var result [16]byte
	parts := []byte(ip)
	// Simple parsing for test IPs like "192.168.1.1"
	// In real code, use net.ParseIP
	var nums [4]int
	var idx int
	var current int
	for _, b := range parts {
		if b == '.' {
			nums[idx] = current
			idx++
			current = 0
		} else {
			current = current*10 + int(b-'0')
		}
	}
	nums[idx] = current
	for i := 0; i < 4; i++ {
		result[i] = byte(nums[i])
	}
	return result
}

// TestValidateRule_FieldValidation tests field name validation for different event types.
func TestValidateRule_FieldValidation(t *testing.T) {
	tests := []struct {
		name      string
		rule      Rule
		wantError string
	}{
		{
			name: "valid network field - dport",
			rule: Rule{
				ID:        "test_001",
				Name:      "Test Rule",
				EventType: types.EventTCPConnect,
				Condition: RuleCondition{Field: "dport", Op: OpEquals, Values: []string{"80"}},
			},
			wantError: "",
		},
		{
			name: "valid network field - daddr",
			rule: Rule{
				ID:        "test_002",
				Name:      "Test Rule",
				EventType: types.EventTCPConnect,
				Condition: RuleCondition{Field: "daddr", Op: OpEquals, Values: []string{"192.168.1.1"}},
			},
			wantError: "",
		},
		{
			name: "invalid network field",
			rule: Rule{
				ID:        "test_003",
				Name:      "Test Rule",
				EventType: types.EventTCPConnect,
				Condition: RuleCondition{Field: "filename", Op: OpEquals, Values: []string{"test"}},
			},
			wantError: "invalid field name",
		},
		{
			name: "valid file field - filename",
			rule: Rule{
				ID:        "test_004",
				Name:      "Test Rule",
				EventType: types.EventFileAccess,
				Condition: RuleCondition{Field: "filename", Op: OpPrefix, Values: []string{"/etc/"}},
			},
			wantError: "",
		},
		{
			name: "valid file field - flags",
			rule: Rule{
				ID:        "test_005",
				Name:      "Test Rule",
				EventType: types.EventFileAccess,
				Condition: RuleCondition{Field: "flags", Op: OpEquals, Values: []string{"0"}},
			},
			wantError: "",
		},
		{
			name: "invalid file field",
			rule: Rule{
				ID:        "test_006",
				Name:      "Test Rule",
				EventType: types.EventFileAccess,
				Condition: RuleCondition{Field: "dport", Op: OpEquals, Values: []string{"80"}},
			},
			wantError: "invalid field name",
		},
		{
			name: "valid syscall field - nr",
			rule: Rule{
				ID:        "test_007",
				Name:      "Test Rule",
				EventType: types.EventSyscall,
				Condition: RuleCondition{Field: "nr", Op: OpEquals, Values: []string{"1"}},
			},
			wantError: "",
		},
		{
			name: "invalid syscall field",
			rule: Rule{
				ID:        "test_008",
				Name:      "Test Rule",
				EventType: types.EventSyscall,
				Condition: RuleCondition{Field: "filename", Op: OpEquals, Values: []string{"test"}},
			},
			wantError: "invalid field name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRule(&tt.rule)
			if tt.wantError == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tt.wantError)
			}
		})
	}
}

// TestValidateRule_RegexValidation tests regex pattern validation.
func TestValidateRule_RegexValidation(t *testing.T) {
	tests := []struct {
		name      string
		condition RuleCondition
		wantError string
	}{
		{
			name:      "valid regex",
			condition: RuleCondition{Field: "filename", Op: OpRegex, Values: []string{`.*\.conf$`, `/etc/.*`}},
			wantError: "",
		},
		{
			name:      "invalid regex",
			condition: RuleCondition{Field: "filename", Op: OpRegex, Values: []string{`[invalid`}},
			wantError: "invalid regex pattern",
		},
		{
			name:      "empty regex list",
			condition: RuleCondition{Field: "filename", Op: OpRegex, Values: []string{}},
			wantError: "requires at least one pattern",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := Rule{
				ID:        "test_regex",
				Name:      "Test Rule",
				EventType: types.EventFileAccess,
				Condition: tt.condition,
			}
			err := validateRule(&rule)
			if tt.wantError == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tt.wantError)
			}
		})
	}
}

// TestValidateRule_CIDRValidation tests CIDR range validation.
func TestValidateRule_CIDRValidation(t *testing.T) {
	tests := []struct {
		name      string
		condition RuleCondition
		wantError string
	}{
		{
			name:      "valid CIDR",
			condition: RuleCondition{Field: "daddr", Op: OpInCIDR, Values: []string{"192.168.0.0/16", "10.0.0.0/8"}},
			wantError: "",
		},
		{
			name:      "invalid CIDR",
			condition: RuleCondition{Field: "daddr", Op: OpInCIDR, Values: []string{"invalid-cidr"}},
			wantError: "invalid CIDR range",
		},
		{
			name:      "empty CIDR list",
			condition: RuleCondition{Field: "daddr", Op: OpInCIDR, Values: []string{}},
			wantError: "requires at least one CIDR range",
		},
		{
			name:      "CIDR on wrong field",
			condition: RuleCondition{Field: "dport", Op: OpInCIDR, Values: []string{"192.168.0.0/16"}},
			wantError: "CIDR operator",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := Rule{
				ID:        "test_cidr",
				Name:      "Test Rule",
				EventType: types.EventTCPConnect,
				Condition: tt.condition,
			}
			err := validateRule(&rule)
			if tt.wantError == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tt.wantError)
			}
		})
	}
}

// TestSubGroupNestedANDOR verifies two-level AND(OR(c1, c2), c3) SubGroup evaluation.
func TestSubGroupNestedANDOR(t *testing.T) {
	// AND( OR(dport==80, dport==443), daddr==192.168.1.1 )
	rule := Rule{
		ID:        "subgroup_001",
		Name:      "SubGroup AND/OR Test",
		EventType: types.EventTCPConnect,
		ConditionGroup: &RuleConditionGroup{
			Operator: "and",
			Conditions: []RuleCondition{
				{Field: "daddr", Op: OpEquals, Values: []string{"192.168.1.1"}},
			},
			SubGroups: []RuleConditionGroup{
				{
					Operator: "or",
					Conditions: []RuleCondition{
						{Field: "dport", Op: OpEquals, Values: []string{"80"}},
						{Field: "dport", Op: OpEquals, Values: []string{"443"}},
					},
				},
			},
		},
		Severity: types.SeverityWarning,
		Action:   ActionAlert,
	}
	engine := NewRuleEngine([]Rule{rule})

	// Both outer cond and subgroup OR match → should alert
	ev1 := types.Event{
		Type: types.EventTCPConnect,
		Network: &types.NetworkEvent{
			Dport:  443,
			Daddr:  ipToBytes("192.168.1.1"),
			Family: types.AFInet,
		},
	}
	assert.Len(t, engine.Evaluate(ev1), 1, "AND(OR(80,443), daddr match) should alert")

	// Outer cond matches but subgroup OR does not → no alert
	ev2 := types.Event{
		Type: types.EventTCPConnect,
		Network: &types.NetworkEvent{
			Dport:  8080,
			Daddr:  ipToBytes("192.168.1.1"),
			Family: types.AFInet,
		},
	}
	assert.Len(t, engine.Evaluate(ev2), 0, "AND(OR no match, daddr match) should not alert")

	// SubGroup OR matches but outer cond does not → no alert
	ev3 := types.Event{
		Type: types.EventTCPConnect,
		Network: &types.NetworkEvent{
			Dport:  80,
			Daddr:  ipToBytes("10.0.0.1"),
			Family: types.AFInet,
		},
	}
	assert.Len(t, engine.Evaluate(ev3), 0, "AND(OR match, daddr no match) should not alert")
}

// TestSubGroupRegexPatternCompiled verifies regex inside a SubGroup is compiled and matches.
func TestSubGroupRegexPatternCompiled(t *testing.T) {
	rule := Rule{
		ID:        "subgroup_regex",
		Name:      "SubGroup Regex Test",
		EventType: types.EventFileAccess,
		ConditionGroup: &RuleConditionGroup{
			Operator: "and",
			Conditions: []RuleCondition{
				{Field: "op", Op: OpEquals, Values: []string{"open"}},
			},
			SubGroups: []RuleConditionGroup{
				{
					Operator: "or",
					Conditions: []RuleCondition{
						{Field: "filename", Op: OpRegex, Values: []string{`^/etc/.*\.key$`}},
					},
				},
			},
		},
		Severity: types.SeverityWarning,
		Action:   ActionAlert,
	}
	engine := NewRuleEngine([]Rule{rule})

	// Matches regex in subgroup
	ev1 := types.Event{
		Type: types.EventFileAccess,
		File: &types.FileEvent{
			Op:       0,
			Filename: stringToByteArray("/etc/ssl/private.key"),
		},
	}
	assert.Len(t, engine.Evaluate(ev1), 1, "regex in subgroup should match")

	// Does not match regex
	ev2 := types.Event{
		Type: types.EventFileAccess,
		File: &types.FileEvent{
			Op:       0,
			Filename: stringToByteArray("/etc/ssl/cert.pem"),
		},
	}
	assert.Len(t, engine.Evaluate(ev2), 0, "regex in subgroup should not match")
}

// TestSubGroupCIDRCondition verifies CIDR condition inside a SubGroup matches IP.
func TestSubGroupCIDRCondition(t *testing.T) {
	rule := Rule{
		ID:        "subgroup_cidr",
		Name:      "SubGroup CIDR Test",
		EventType: types.EventTCPConnect,
		ConditionGroup: &RuleConditionGroup{
			Operator: "and",
			Conditions: []RuleCondition{
				{Field: "dport", Op: OpEquals, Values: []string{"443"}},
			},
			SubGroups: []RuleConditionGroup{
				{
					Operator: "or",
					Conditions: []RuleCondition{
						{Field: "daddr", Op: OpInCIDR, Values: []string{"10.0.0.0/8"}},
					},
				},
			},
		},
		Severity: types.SeverityWarning,
		Action:   ActionAlert,
	}
	engine := NewRuleEngine([]Rule{rule})

	evMatch := types.Event{
		Type: types.EventTCPConnect,
		Network: &types.NetworkEvent{
			Dport:  443,
			Daddr:  ipToBytes("10.1.2.3"),
			Family: types.AFInet,
		},
	}
	assert.Len(t, engine.Evaluate(evMatch), 1, "CIDR in subgroup should match")

	evNoMatch := types.Event{
		Type: types.EventTCPConnect,
		Network: &types.NetworkEvent{
			Dport:  443,
			Daddr:  ipToBytes("192.168.1.1"),
			Family: types.AFInet,
		},
	}
	assert.Len(t, engine.Evaluate(evNoMatch), 0, "CIDR in subgroup should not match out-of-range IP")
}

// TestOpNotInEmptyFieldValue verifies OpNotIn with empty field and non-empty values list returns true.
func TestOpNotInEmptyFieldValue(t *testing.T) {
	// DNS event with empty qname — OpNotIn should return true (empty is not in the list)
	rule := Rule{
		ID:        "opnotin_empty",
		Name:      "OpNotIn Empty Field Test",
		EventType: types.EventDNS,
		Condition: RuleCondition{
			Field:  "qname",
			Op:     OpNotIn,
			Values: []string{"evil.com", "malware.net"},
		},
		Severity: types.SeverityWarning,
		Action:   ActionAlert,
	}
	engine := NewRuleEngine([]Rule{rule})

	evEmptyQName := types.Event{
		Type: types.EventDNS,
		DNS:  &types.DNSEvent{QName: ""},
	}
	// Empty string is not in ["evil.com", "malware.net"] → OpNotIn should be true → alert fires
	assert.Len(t, engine.Evaluate(evEmptyQName), 1, "OpNotIn with empty field value should return true")

	evMatchingQName := types.Event{
		Type: types.EventDNS,
		DNS:  &types.DNSEvent{QName: "evil.com"},
	}
	// "evil.com" IS in the list → OpNotIn should be false → no alert
	assert.Len(t, engine.Evaluate(evMatchingQName), 0, "OpNotIn with matching value should return false")
}

// TestRuleLoaderEmptyConditionGroup verifies that loading a rule with an empty
// condition_group returns a validation error.
func TestRuleLoaderEmptyConditionGroup(t *testing.T) {
	rule := &Rule{
		ID:        "empty_group",
		Name:      "Empty Group Rule",
		EventType: types.EventTCPConnect,
		ConditionGroup: &RuleConditionGroup{
			Operator:   "and",
			Conditions: []RuleCondition{},
			SubGroups:  []RuleConditionGroup{},
		},
		Severity: types.SeverityWarning,
		Action:   ActionAlert,
	}
	err := validateRule(rule)
	require.Error(t, err, "empty condition_group should fail validation")
	assert.Contains(t, err.Error(), "condition_group has no conditions or subgroups")
}

// BenchmarkOpInLargeSet measures O(1) map lookup vs O(n) linear scan for a 1000-element set.
func BenchmarkOpInLargeSet(b *testing.B) {
	// Build a 1000-element values list
	values := make([]string, 1000)
	for i := range values {
		values[i] = fmt.Sprintf("value-%d", i)
	}
	rule := Rule{
		ID:        "bench_in",
		Name:      "Bench OpIn",
		EventType: types.EventDNS,
		Condition: RuleCondition{Field: "qname", Op: OpIn, Values: values},
		Severity:  types.SeverityWarning,
		Action:    ActionAlert,
	}
	engine := NewRuleEngine([]Rule{rule})
	// Use a value that is NOT in the list — worst case for linear scan.
	event := types.Event{
		Type: types.EventDNS,
		DNS:  &types.DNSEvent{QName: "not-in-list"},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.Evaluate(event)
	}
}

// BenchmarkAlertIDGeneration measures allocations for Alert ID generation.
// Target: 1 alloc/op (fmt.Sprintf) instead of 4 (string concatenation).
// Results: fmt.Sprintf("%s-%d-%d", ruleID, ts, pid) = 1 alloc/op
func BenchmarkAlertIDGeneration(b *testing.B) {
	rules := []Rule{
		{
			ID:        "rule_bench_001",
			Name:      "Benchmark Rule",
			EventType: types.EventTCPConnect,
			Condition: RuleCondition{Field: "dport", Op: OpEquals, Values: []string{"8080"}},
			Severity:  types.SeverityWarning,
			Action:    ActionAlert,
		},
	}
	engine := NewRuleEngine(rules)
	event := types.Event{
		Type:      types.EventTCPConnect,
		Timestamp: 1234567890123456789,
		PID:       12345,
		Network:   &types.NetworkEvent{Dport: 8080},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		alerts := engine.Evaluate(event)
		if len(alerts) == 0 {
			b.Fatal("expected alert")
		}
		_ = alerts[0].ID
	}
}

// TestFDEnrichment verifies that fd.name and fd.name_truncated fields work
// correctly for file access events (issue #47).
func TestFDEnrichment(t *testing.T) {
	writeRule := Rule{
		ID:        "fd_001",
		Name:      "Sensitive Write via fd",
		EventType: types.EventFileAccess,
		Condition: RuleCondition{
			Field:  "fd.name",
			Op:     OpPrefix,
			Values: []string{"/etc/passwd"},
		},
		Severity: types.SeverityCritical,
		Action:   ActionAlert,
	}

	engine := NewRuleEngine([]Rule{writeRule})

	t.Run("write event with resolved fd.name fires rule", func(t *testing.T) {
		event := types.Event{
			Type: types.EventFileAccess,
			File: &types.FileEvent{
				Op:     2, // FILE_OP_WRITE
				FDPath: "/etc/passwd",
			},
		}
		alerts := engine.Evaluate(event)
		require.Len(t, alerts, 1)
		assert.Equal(t, "fd_001", alerts[0].RuleID)
	})

	t.Run("write event with non-matching fd.name does not fire", func(t *testing.T) {
		event := types.Event{
			Type: types.EventFileAccess,
			File: &types.FileEvent{
				Op:     2, // FILE_OP_WRITE
				FDPath: "/tmp/harmless.txt",
			},
		}
		alerts := engine.Evaluate(event)
		assert.Empty(t, alerts)
	})

	t.Run("write event with empty fd.name does not fire", func(t *testing.T) {
		event := types.Event{
			Type: types.EventFileAccess,
			File: &types.FileEvent{
				Op:     2, // FILE_OP_WRITE
				FDPath: "",
			},
		}
		alerts := engine.Evaluate(event)
		assert.Empty(t, alerts)
	})

	t.Run("fd.name_truncated field returns correct value", func(t *testing.T) {
		truncRule := Rule{
			ID:        "fd_002",
			Name:      "Truncated path",
			EventType: types.EventFileAccess,
			Condition: RuleCondition{
				Field:  "fd.name_truncated",
				Op:     OpEquals,
				Values: []string{"true"},
			},
			Severity: types.SeverityWarning,
			Action:   ActionAlert,
		}
		eng := NewRuleEngine([]Rule{truncRule})

		truncEvent := types.Event{
			Type: types.EventFileAccess,
			File: &types.FileEvent{
				Op:              1, // FILE_OP_READ
				FDPath:          "/very/long/path",
				FDPathTruncated: true,
			},
		}
		alerts := eng.Evaluate(truncEvent)
		require.Len(t, alerts, 1)

		noTruncEvent := types.Event{
			Type: types.EventFileAccess,
			File: &types.FileEvent{
				Op:              1,
				FDPath:          "/short/path",
				FDPathTruncated: false,
			},
		}
		alerts = eng.Evaluate(noTruncEvent)
		assert.Empty(t, alerts)
	})

	t.Run("open event uses fd.name same as filename", func(t *testing.T) {
		var fname [256]byte
		copy(fname[:], "/etc/passwd")
		event := types.Event{
			Type: types.EventFileAccess,
			File: &types.FileEvent{
				Op:       0, // FILE_OP_OPEN
				Filename: fname,
				FDPath:   "/etc/passwd",
			},
		}
		alerts := engine.Evaluate(event)
		require.Len(t, alerts, 1)
	})
}

// TestFDEnrichmentValidation verifies that fd.name and fd.name_truncated are
// accepted field names during rule validation for file and syscall event types.
func TestFDEnrichmentValidation(t *testing.T) {
	t.Run("fd.name valid for file events", func(t *testing.T) {
		rule := &Rule{
			ID:        "v_001",
			Name:      "test",
			EventType: types.EventFileAccess,
			Condition: RuleCondition{Field: "fd.name", Op: OpPrefix, Values: []string{"/etc/"}},
			Severity:  types.SeverityWarning,
			Action:    ActionAlert,
		}
		err := validateRule(rule)
		require.NoError(t, err)
	})

	t.Run("fd.name_truncated valid for file events", func(t *testing.T) {
		rule := &Rule{
			ID:        "v_002",
			Name:      "test",
			EventType: types.EventFileAccess,
			Condition: RuleCondition{Field: "fd.name_truncated", Op: OpEquals, Values: []string{"true"}},
			Severity:  types.SeverityWarning,
			Action:    ActionAlert,
		}
		err := validateRule(rule)
		require.NoError(t, err)
	})

	t.Run("fd.name valid for syscall events", func(t *testing.T) {
		rule := &Rule{
			ID:        "v_003",
			Name:      "test",
			EventType: types.EventSyscall,
			Condition: RuleCondition{Field: "fd.name", Op: OpPrefix, Values: []string{"/etc/"}},
			Severity:  types.SeverityWarning,
			Action:    ActionAlert,
		}
		err := validateRule(rule)
		require.NoError(t, err)
	})
}
