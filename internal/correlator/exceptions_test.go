// Package correlator provides event correlation and rule-based detection.
package correlator

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

func syscallEventWithComm(comm string) types.Event {
	e := types.Event{
		Type: types.EventSyscall,
		Syscall: &types.SyscallEvent{
			Nr: 2,
		},
	}
	copy(e.Comm[:], comm)
	return e
}

func TestRuleException_SuppressesMatchingAlert(t *testing.T) {
	rule := Rule{
		ID:        "container_escape_proc_write",
		Name:      "proc write",
		EventType: types.EventSyscall,
		Condition: RuleCondition{Field: "nr", Op: OpEquals, Values: []string{"2"}},
		Severity:  types.SeverityCritical,
		Action:    ActionAlert,
		Exceptions: []RuleException{
			{
				Name:      "systemd-sysctl",
				Condition: RuleCondition{Field: "comm", Op: OpIn, Values: []string{"systemd", "systemd-sysctl"}},
			},
		},
	}
	engine := NewRuleEngine([]Rule{rule})
	require.NoError(t, engine.CompileErrors())

	before := testutil.ToFloat64(ruleExceptionsTotal.WithLabelValues(rule.ID, "systemd-sysctl"))

	alerts := engine.Evaluate(syscallEventWithComm("systemd-sysctl"))
	assert.Empty(t, alerts, "event matching an exception must not raise an alert")

	after := testutil.ToFloat64(ruleExceptionsTotal.WithLabelValues(rule.ID, "systemd-sysctl"))
	assert.Equal(t, before+1, after, "suppression must increment ebpf_guard_rule_exceptions_total")
}

func TestRuleException_NonMatchingExceptionStillAlerts(t *testing.T) {
	rule := Rule{
		ID:        "container_escape_proc_write",
		Name:      "proc write",
		EventType: types.EventSyscall,
		Condition: RuleCondition{Field: "nr", Op: OpEquals, Values: []string{"2"}},
		Severity:  types.SeverityCritical,
		Action:    ActionAlert,
		Exceptions: []RuleException{
			{
				Name:      "systemd-sysctl",
				Condition: RuleCondition{Field: "comm", Op: OpIn, Values: []string{"systemd", "systemd-sysctl"}},
			},
		},
	}
	engine := NewRuleEngine([]Rule{rule})
	require.NoError(t, engine.CompileErrors())

	alerts := engine.Evaluate(syscallEventWithComm("attacker"))
	require.Len(t, alerts, 1)
	assert.Equal(t, rule.ID, alerts[0].RuleID)
}

func TestRuleException_ConditionGroup(t *testing.T) {
	rule := Rule{
		ID:        "fim_library_replaced",
		Name:      "library replaced",
		EventType: types.EventSyscall,
		Condition: RuleCondition{Field: "nr", Op: OpEquals, Values: []string{"2"}},
		Severity:  types.SeverityWarning,
		Action:    ActionAlert,
		Exceptions: []RuleException{
			{
				Name: "ldconfig",
				ConditionGroup: &RuleConditionGroup{
					Operator: "and",
					Conditions: []RuleCondition{
						{Field: "comm", Op: OpEquals, Values: []string{"ldconfig.real"}},
						{Field: "uid", Op: OpEquals, Values: []string{"0"}},
					},
				},
			},
		},
	}
	engine := NewRuleEngine([]Rule{rule})
	require.NoError(t, engine.CompileErrors())

	e := syscallEventWithComm("ldconfig.real")
	e.UID = 0
	assert.Empty(t, engine.Evaluate(e))

	e.UID = 1000
	assert.Len(t, engine.Evaluate(e), 1)
}

func TestValidateRule_Exceptions(t *testing.T) {
	tests := []struct {
		name      string
		rule      Rule
		wantError string
	}{
		{
			name: "valid exception",
			rule: Rule{
				ID:        "r1",
				Name:      "r1",
				EventType: types.EventSyscall,
				Condition: RuleCondition{Field: "nr", Op: OpEquals, Values: []string{"1"}},
				Exceptions: []RuleException{
					{Name: "ok", Condition: RuleCondition{Field: "comm", Op: OpEquals, Values: []string{"systemd"}}},
				},
			},
			wantError: "",
		},
		{
			name: "missing exception name",
			rule: Rule{
				ID:        "r2",
				Name:      "r2",
				EventType: types.EventSyscall,
				Condition: RuleCondition{Field: "nr", Op: OpEquals, Values: []string{"1"}},
				Exceptions: []RuleException{
					{Condition: RuleCondition{Field: "comm", Op: OpEquals, Values: []string{"systemd"}}},
				},
			},
			wantError: "missing required 'name'",
		},
		{
			name: "unknown field in exception condition",
			rule: Rule{
				ID:        "r3",
				Name:      "r3",
				EventType: types.EventSyscall,
				Condition: RuleCondition{Field: "nr", Op: OpEquals, Values: []string{"1"}},
				Exceptions: []RuleException{
					{Name: "bad", Condition: RuleCondition{Field: "filename", Op: OpEquals, Values: []string{"x"}}},
				},
			},
			wantError: "invalid field name",
		},
		{
			name: "empty exception condition_group",
			rule: Rule{
				ID:        "r4",
				Name:      "r4",
				EventType: types.EventSyscall,
				Condition: RuleCondition{Field: "nr", Op: OpEquals, Values: []string{"1"}},
				Exceptions: []RuleException{
					{Name: "bad", ConditionGroup: &RuleConditionGroup{Operator: "and"}},
				},
			},
			wantError: "condition_group has no conditions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRule(&tt.rule)
			if tt.wantError == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			}
		})
	}
}
