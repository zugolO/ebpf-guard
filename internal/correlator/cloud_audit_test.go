package correlator

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

func TestCloudAuditFieldExtraction(t *testing.T) {
	re := NewRuleEngine(nil)

	event := types.Event{
		Type: types.EventCloudAudit,
		CloudAudit: &types.CloudAuditEvent{
			Provider:    "aws",
			Service:     "iam",
			Action:      "AssumeRole",
			Principal:   "arn:aws:iam::123456789:user/admin",
			ResourceARN: "arn:aws:iam::123456789:role/dev-role",
			SourceIP:    "203.0.113.42",
			UserAgent:   "aws-cli/2.0",
			ErrorCode:   "AccessDenied",
			Region:      "us-east-1",
			EventID:     "event-001",
		},
	}

	tests := []struct {
		field string
		want  string
	}{
		{"cloud.provider", "aws"},
		{"cloud.service", "iam"},
		{"cloud.action", "AssumeRole"},
		{"cloud.principal", "arn:aws:iam::123456789:user/admin"},
		{"cloud.resource", "arn:aws:iam::123456789:role/dev-role"},
		{"cloud.source_ip", "203.0.113.42"},
		{"cloud.user_agent", "aws-cli/2.0"},
		{"cloud.error_code", "AccessDenied"},
		{"cloud.region", "us-east-1"},
		{"cloud.event_id", "event-001"},
	}
	for _, tt := range tests {
		got := re.getFieldValue(event, tt.field, nil)
		assert.Equal(t, tt.want, got, "field=%q", tt.field)
	}
}

func TestCloudAuditNilPayload(t *testing.T) {
	re := NewRuleEngine(nil)
	event := types.Event{
		Type:       types.EventCloudAudit,
		CloudAudit: nil,
	}
	got := re.getFieldValue(event, "cloud.action", nil)
	assert.Equal(t, "", got)
}

func TestCloudAuditUnknownField(t *testing.T) {
	re := NewRuleEngine(nil)
	event := types.Event{
		Type:       types.EventCloudAudit,
		CloudAudit: &types.CloudAuditEvent{Action: "AssumeRole"},
	}
	got := re.getFieldValue(event, "cloud.nonexistent", nil)
	assert.Equal(t, fieldNotFound, got)
}

func TestCloudAuditRuleMatchesAssumeRole(t *testing.T) {
	rules := []Rule{
		{
			ID:        "cloud_001",
			EventType: types.EventCloudAudit,
			Condition: RuleCondition{
				Field:  "cloud.action",
				Op:     OpIn,
				Values: []string{"AssumeRole", "AssumeRoleWithWebIdentity"},
			},
			Severity: types.SeverityWarning,
			Action:   ActionAlert,
		},
	}
	re := NewRuleEngine(rules)

	event := types.Event{
		Type: types.EventCloudAudit,
		CloudAudit: &types.CloudAuditEvent{
			Provider: "aws",
			Action:   "AssumeRole",
			SourceIP: "203.0.113.42",
		},
	}

	alerts := re.Evaluate(event)
	require.Len(t, alerts, 1)
	assert.Equal(t, "cloud_001", alerts[0].RuleID)
}

func TestCloudAuditRuleNoMatchWrongProvider(t *testing.T) {
	rules := []Rule{
		{
			ID:        "cloud_005",
			EventType: types.EventCloudAudit,
			ConditionGroup: &RuleConditionGroup{
				Operator: "and",
				Conditions: []RuleCondition{
					{Field: "cloud.provider", Op: OpEquals, Values: []string{"aws"}},
					{Field: "cloud.action", Op: OpEquals, Values: []string{"CreateAccessKey"}},
				},
			},
			Severity: types.SeverityWarning,
			Action:   ActionAlert,
		},
	}
	re := NewRuleEngine(rules)

	// GCP event — should not match AWS-specific rule.
	event := types.Event{
		Type: types.EventCloudAudit,
		CloudAudit: &types.CloudAuditEvent{
			Provider: "gcp",
			Action:   "CreateAccessKey",
		},
	}
	alerts := re.Evaluate(event)
	assert.Empty(t, alerts)
}

func TestCloudAuditRuleErrorCode(t *testing.T) {
	rules := []Rule{
		{
			ID:        "cloud_007",
			EventType: types.EventCloudAudit,
			Condition: RuleCondition{
				Field:  "cloud.error_code",
				Op:     OpIn,
				Values: []string{"AccessDenied", "AccessDeniedException", "PERMISSION_DENIED"},
			},
			Severity: types.SeverityWarning,
			Action:   ActionAlert,
		},
	}
	re := NewRuleEngine(rules)

	tests := []struct {
		errorCode string
		wantAlert bool
	}{
		{"AccessDenied", true},
		{"PERMISSION_DENIED", true},
		{"", false},
		{"Throttling", false},
	}
	for _, tt := range tests {
		event := types.Event{
			Type:       types.EventCloudAudit,
			CloudAudit: &types.CloudAuditEvent{ErrorCode: tt.errorCode},
		}
		alerts := re.Evaluate(event)
		if tt.wantAlert {
			assert.Len(t, alerts, 1, "errorCode=%q should alert", tt.errorCode)
		} else {
			assert.Empty(t, alerts, "errorCode=%q should not alert", tt.errorCode)
		}
	}
}

func TestLoadCloudAuditFieldNames(t *testing.T) {
	// Verify all cloud.* fields are accepted at rule-load time.
	for field := range validCloudAuditFields {
		err := validateFieldName(field, types.EventCloudAudit)
		assert.NoError(t, err, "field %q should be valid", field)
	}
}

func TestCloudAuditEventTypeNames(t *testing.T) {
	names := []string{"cloud_audit", "cloud"}
	for _, name := range names {
		var et types.EventType
		require.NoError(t, parseEventTypeName(t, name, &et))
		assert.Equal(t, types.EventCloudAudit, et)
	}
}

// parseEventTypeName loads a minimal rule YAML via a temp file to exercise
// the full event_type unmarshal path.
func parseEventTypeName(t *testing.T, name string, et *types.EventType) error {
	t.Helper()
	content := `rules:
  - id: test
    name: test rule
    event_type: ` + name + `
    condition:
      field: cloud.action
      op: equals
      values: ["AssumeRole"]
    severity: warning
    action: alert
`
	f, err := os.CreateTemp(t.TempDir(), "rules-*.yaml")
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		return err
	}
	rules, err := LoadRulesFromFile(f.Name())
	if err != nil {
		return err
	}
	if len(rules) > 0 {
		*et = rules[0].EventType
	}
	return nil
}
