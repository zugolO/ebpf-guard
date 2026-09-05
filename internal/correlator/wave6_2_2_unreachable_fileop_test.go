package correlator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Wave 6.2.2, open question 7. Found while closing №234: a file rule may name
// an op no hook produces, and nothing catches it — "op" is a valid field name,
// so rule_loader.go passes it, and the rule is simply never matched by
// anything. That is the file-axis twin of findings #2/#39 on the syscall axis,
// and it is reported the same way, at startup, instead of decaying unnoticed.

func TestWave6_2_2_UnreachableFileOpRules_FlagsImpossibleOps(t *testing.T) {
	mk := func(id string, values []string) Rule {
		return Rule{
			ID: id, EventType: types.EventFileAccess, Severity: types.SeverityWarning, Action: ActionAlert,
			ConditionGroup: &RuleConditionGroup{
				Operator: "and",
				Conditions: []RuleCondition{
					{Field: "file.path", Op: OpPrefix, Values: []string{"/var/log/"}},
					{Field: "file.op", Op: OpIn, Values: values},
				},
			},
		}
	}
	engine := NewRuleEngine([]Rule{
		mk("dead_unlink_only", []string{"unlink", "truncate", "rename"}),
		mk("live_write", []string{"write"}),
		mk("live_mixed", []string{"unlink", "write"}),
		{ID: "no_op_condition", EventType: types.EventFileAccess, Severity: types.SeverityWarning, Action: ActionAlert,
			Condition: RuleCondition{Field: "filename", Op: OpPrefix, Values: []string{"/etc/"}}},
	})

	assert.Equal(t, []string{"dead_unlink_only"}, engine.UnreachableFileOpRules(),
		"only a rule whose every op value is unproducible is unreachable")
}

// The shipped ruleset is checked too, so the four known dead rules stay
// visible until someone either adds the hook or rewrites the condition — and
// so that a NEW rule with the same defect is caught by CI rather than by the
// next node measurement.
func TestWave6_2_2_UnreachableFileOpRules_ShippedRuleset(t *testing.T) {
	rules, err := LoadRulesFromDir("../../rules")
	require.NoError(t, err)

	unreachable := NewRuleEngine(rules).UnreachableFileOpRules()
	t.Logf("file rules unreachable by op (%d): %v", len(unreachable), unreachable)

	// Known set as of wave 6.2.2. fileaccess.bpf.c hooks openat/read/write/
	// chmod only; these four ask for unlink/truncate/rename/rmdir. Fixing them
	// is an owner decision (a new BPF hook, or narrowing to "write" and
	// accepting that every ordinary write to /var/log/ and /etc/ then matches)
	// recorded in plan.md, not something to paper over here.
	assert.ElementsMatch(t, []string{
		"defense_evasion_journald_log_clear",
		"evasion_log_clear",
		"impact_mass_file_deletion_critical",
		"ransomware_log_wipe",
	}, unreachable,
		"the set of op-unreachable rules changed: add the new one here after deciding what to do with it, or remove one that was fixed")
}
