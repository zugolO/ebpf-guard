// Package correlator provides event correlation and rule-based detection.
package correlator

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

func writeTuningFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "local-tuning.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	return path
}

func TestLoadTuningOverlay_MissingFileIsNoOp(t *testing.T) {
	overlay, err := LoadTuningOverlay(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	require.NoError(t, err)
	assert.Nil(t, overlay)
}

func TestLoadTuningOverlay_EmptyPathIsNoOp(t *testing.T) {
	overlay, err := LoadTuningOverlay("")
	require.NoError(t, err)
	assert.Nil(t, overlay)
}

func TestLoadTuningOverlay_ParsesAndValidates(t *testing.T) {
	path := writeTuningFile(t, `
overlays:
  - rule_id: container_escape_proc_write
    exceptions:
      - name: systemd-sysctl
        condition:
          field: comm
          op: in
          values: [systemd, systemd-sysctl]
`)
	overlay, err := LoadTuningOverlay(path)
	require.NoError(t, err)
	require.NotNil(t, overlay)
	require.Len(t, overlay.Overlays, 1)
	assert.Equal(t, "container_escape_proc_write", overlay.Overlays[0].RuleID)
	require.Len(t, overlay.Overlays[0].Exceptions, 1)
	assert.Equal(t, "systemd-sysctl", overlay.Overlays[0].Exceptions[0].Name)
}

func TestLoadTuningOverlay_RejectsMissingRuleID(t *testing.T) {
	path := writeTuningFile(t, `
overlays:
  - exceptions:
      - name: x
        condition: {field: comm, op: eq, values: [a]}
`)
	_, err := LoadTuningOverlay(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing rule_id")
}

func TestLoadTuningOverlay_RejectsMissingExceptionName(t *testing.T) {
	path := writeTuningFile(t, `
overlays:
  - rule_id: some_rule
    exceptions:
      - condition: {field: comm, op: eq, values: [a]}
`)
	_, err := LoadTuningOverlay(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing name")
}

func TestApplyTuningOverlay_MergesByRuleID(t *testing.T) {
	rules := []Rule{
		{
			ID:        "container_escape_proc_write",
			Name:      "proc write",
			EventType: types.EventSyscall,
			Condition: RuleCondition{Field: "nr", Op: OpEquals, Values: []string{"2"}},
			Action:    ActionAlert,
		},
	}
	overlay := &TuningOverlay{
		Overlays: []RuleTuningOverlay{
			{
				RuleID: "container_escape_proc_write",
				Exceptions: []RuleException{
					{Name: "systemd", Condition: RuleCondition{Field: "comm", Op: OpEquals, Values: []string{"systemd"}}},
				},
			},
		},
	}

	unknown, err := ApplyTuningOverlay(rules, overlay)
	require.NoError(t, err)
	assert.Empty(t, unknown)
	require.Len(t, rules[0].Exceptions, 1)
	assert.Equal(t, "systemd", rules[0].Exceptions[0].Name)

	engine := NewRuleEngine(rules)
	require.NoError(t, engine.CompileErrors())
	assert.Empty(t, engine.Evaluate(syscallEventWithComm("systemd")))
	assert.Len(t, engine.Evaluate(syscallEventWithComm("attacker")), 1)
}

func TestApplyTuningOverlay_UnknownRuleIDIsSoftError(t *testing.T) {
	rules := []Rule{
		{ID: "rule_a", Name: "a", EventType: types.EventSyscall, Condition: RuleCondition{Field: "nr", Op: OpEquals, Values: []string{"1"}}},
	}
	overlay := &TuningOverlay{
		Overlays: []RuleTuningOverlay{
			{RuleID: "rule_does_not_exist", Exceptions: []RuleException{
				{Name: "x", Condition: RuleCondition{Field: "comm", Op: OpEquals, Values: []string{"a"}}},
			}},
		},
	}

	unknown, err := ApplyTuningOverlay(rules, overlay)
	require.NoError(t, err)
	assert.Equal(t, []string{"rule_does_not_exist"}, unknown)
	assert.Empty(t, rules[0].Exceptions)
}

func TestApplyTuningOverlay_InvalidFieldNameErrors(t *testing.T) {
	rules := []Rule{
		{ID: "rule_a", Name: "a", EventType: types.EventSyscall, Condition: RuleCondition{Field: "nr", Op: OpEquals, Values: []string{"1"}}},
	}
	overlay := &TuningOverlay{
		Overlays: []RuleTuningOverlay{
			{RuleID: "rule_a", Exceptions: []RuleException{
				{Name: "x", Condition: RuleCondition{Field: "filename", Op: OpEquals, Values: []string{"a"}}},
			}},
		},
	}

	_, err := ApplyTuningOverlay(rules, overlay)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid field name")
}

func TestApplyTuningOverlay_NilOverlayIsNoOp(t *testing.T) {
	rules := []Rule{{ID: "rule_a"}}
	unknown, err := ApplyTuningOverlay(rules, nil)
	require.NoError(t, err)
	assert.Nil(t, unknown)
}
