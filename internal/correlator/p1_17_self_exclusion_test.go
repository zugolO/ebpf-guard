package correlator_test

import (
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/internal/canary"
	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

func p117Comm(s string) [16]byte {
	var c [16]byte
	copy(c[:], s)
	return c
}

func p117FileEvent(pid uint32, procComm, path string, op uint8) types.Event {
	e := types.Event{
		Type: types.EventFileAccess,
		PID:  pid,
		Comm: p117Comm(procComm),
		File: &types.FileEvent{Op: op},
	}
	copy(e.File.Filename[:], path)
	return e
}

// TestP1_17_SelfExclusion is the regression test for P1-17 ("Агент алертит на
// самого себя"). For every rule that fired on the agent's own activity during
// the 9-hour idle run, it asserts three things that must hold together:
//
//  1. the agent's own benign access is suppressed by the ebpf-guard-self
//     exception;
//  2. the same access from any other process still alerts;
//  3. an attacker-primitive path is NOT suppressed even when the process
//     claims comm == "ebpf-guard".
//
// (2) and (3) are the important ones. An exception that silences the rule
// outright would satisfy (1) alone — that is the "fixed the silence by going
// blind" failure mode. (3) specifically enforces that every self-exception is
// bound to comm AND path: a comm-only exception makes a compromised binary
// that renames itself "ebpf-guard" completely invisible on that rule.
func TestP1_17_SelfExclusion(t *testing.T) {
	selfPID := uint32(os.Getpid()) /* #nosec G115 -- test PID fits uint32 */

	const opOpen = 0 // op code emitted by the fileaccess collector for open

	testCases := []struct {
		name     string
		ruleFile string
		ruleID   string
		// benignPath is what the agent legitimately touches — must be suppressed.
		benignPath string
		// attackPath is an attacker primitive covered by the same rule — must
		// alert even when comm is spoofed to "ebpf-guard".
		attackPath string
		op         uint8
		// foreignComm is the non-agent process used for assertions (2) and (3).
		// Defaults to "nc". Rules scoped to a process role by closed question 9
		// need a comm inside that role, otherwise the case would assert the Q9
		// scoping instead of the self-exception this test is about.
		foreignComm string
	}{
		{"sigma_cpu_info_access", "../../rules/sigma-linux.yaml", "sigma_cpu_info_access",
			"/proc/cpuinfo", "/proc/sys/kernel/osrelease", opOpen, ""},
		{"cred_proc_maps_mass_read", "../../rules/credential-access.yaml", "cred_proc_maps_mass_read",
			"/proc/1234/maps", "/proc/1234/mem", opOpen, ""},
		{"mitre_sandbox_detect_proc_read", "../../rules/mitre-additional.yaml", "mitre_sandbox_detect_proc_read",
			"/proc/self/cgroup", "/proc/1/environ", opOpen, ""},
		{"container_escape_init_proc", "../../rules/container-escape.yaml", "container_escape_init_proc",
			"/proc/1/cgroup", "/proc/1/environ", opOpen, ""},
		// Q9 scoped this rule to web-server processes, so the foreign process
		// here must be one — a bare "nc" would no longer match the rule at all
		// and the case would silently stop testing the self-exception.
		{"owasp_web_sensitive_file_read", "../../rules/owasp-web.yaml", "owasp_web_sensitive_file_read",
			"/etc/passwd.canary", "/etc/shadow", opOpen, "nginx"},
		{"sigma_sensitive_file_chmod", "../../rules/sigma-linux.yaml", "sigma_sensitive_file_chmod",
			"/etc/shadow.canary", "/etc/sudoers", opOpen, ""},
		{"sigma_sensitive_dir_listing", "../../rules/sigma-linux.yaml", "sigma_sensitive_dir_listing",
			"/root/.ssh/id_rsa.canary", "/root/.ssh/id_rsa", opOpen, ""},
		{"drift_new_file_dir_sensitive", "../../rules/drift-rules.yaml", "drift_new_file_dir_sensitive",
			"/root/.ssh/id_rsa.canary", "/etc/cron.d/backdoor", opOpen, ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rules, err := correlator.LoadRulesFromFile(tc.ruleFile)
			require.NoError(t, err)

			var target *correlator.Rule
			for i := range rules {
				if rules[i].ID == tc.ruleID {
					target = &rules[i]
					break
				}
			}
			require.NotNil(t, target, "rule %s not found in %s", tc.ruleID, tc.ruleFile)

			var selfExc *correlator.RuleException
			for i := range target.Exceptions {
				if target.Exceptions[i].Name == "ebpf-guard-self" {
					selfExc = &target.Exceptions[i]
					break
				}
			}
			require.NotNil(t, selfExc, "rule %s must have an 'ebpf-guard-self' exception", tc.ruleID)

			// The exception must bind comm AND a path — never comm alone.
			require.NotNil(t, selfExc.ConditionGroup,
				"rule %s: self-exception must be a condition_group binding comm AND path; "+
					"a bare comm match would hide any process that renames itself 'ebpf-guard'",
				tc.ruleID)
			assert.GreaterOrEqual(t, len(selfExc.ConditionGroup.Conditions), 2,
				"rule %s: self-exception must constrain both comm and path", tc.ruleID)

			// Evaluate the single rule under test so a match is unambiguous.
			engine := correlator.NewRuleEngine([]correlator.Rule{*target})

			// (1) the agent's own benign access is suppressed.
			assert.Empty(t, engine.Evaluate(p117FileEvent(selfPID, "ebpf-guard", tc.benignPath, tc.op)),
				"rule %s must not alert on ebpf-guard's own access to %s", tc.ruleID, tc.benignPath)

			foreignComm := tc.foreignComm
			if foreignComm == "" {
				foreignComm = "nc"
			}

			// (2) the same access from a foreign process still alerts.
			assert.NotEmpty(t, engine.Evaluate(p117FileEvent(4242, foreignComm, tc.benignPath, tc.op)),
				"rule %s went blind: it no longer alerts on %s from a foreign process (%s) — "+
					"the self-exception must narrow the rule, not disable it",
				tc.ruleID, tc.benignPath, foreignComm)

			// (3) comm spoofing does not buy invisibility on attacker paths.
			//
			// For a rule Q9 scoped to a process role, spoofing comm='ebpf-guard'
			// puts the process outside the rule's scope entirely, so this rule
			// alone cannot answer the question. The property still has to hold
			// somewhere, so it is asserted against the whole catalog below —
			// weakening it to "this rule is scoped now" would drop exactly the
			// guarantee the case exists for.
			spoofEvent := p117FileEvent(4242, "ebpf-guard", tc.attackPath, tc.op)
			if tc.foreignComm == "" {
				assert.NotEmpty(t, engine.Evaluate(spoofEvent),
					"rule %s: a process spoofing comm='ebpf-guard' was able to access %s "+
						"undetected — the self-exception is not bound to a path", tc.ruleID, tc.attackPath)
				return
			}

			catalog, err := correlator.LoadRulesFromDir("../../rules")
			require.NoError(t, err)
			assert.NotEmpty(t, correlator.NewRuleEngine(catalog).Evaluate(spoofEvent),
				"rule %s is Q9-scoped, and no rule in the catalog alerts on %s from a "+
					"process spoofing comm='ebpf-guard' — comm spoofing must not grant "+
					"invisibility on an attacker path", tc.ruleID, tc.attackPath)
		})
	}
}

// TestP1_17_PIDFieldAvailable verifies that the "pid" field resolves for file
// events, which is what the canary self-exception matches on.
func TestP1_17_PIDFieldAvailable(t *testing.T) {
	rule := correlator.Rule{
		ID:        "test_pid_exception",
		Name:      "Test PID exception",
		EventType: types.EventFileAccess,
		Condition: correlator.RuleCondition{
			Field:  "filename",
			Op:     correlator.OpPrefix,
			Values: []string{"/tmp/"},
		},
		Exceptions: []correlator.RuleException{{
			Name: "exclude-self-pid",
			Condition: correlator.RuleCondition{
				Field:  "pid",
				Op:     correlator.OpEquals,
				Values: []string{"1"},
			},
		}},
		Severity: types.SeverityWarning,
		Action:   correlator.ActionAlert,
	}

	engine := correlator.NewRuleEngine([]correlator.Rule{rule})

	assert.Empty(t, engine.Evaluate(p117FileEvent(1, "pid1", "/tmp/test", 0)),
		"PID 1 must be excluded by the exception")
	assert.NotEmpty(t, engine.Evaluate(p117FileEvent(999, "pid999", "/tmp/test", 0)),
		"PID 999 must not be excluded by the exception")
}

// TestP1_17_CanarySelfPIDException verifies the canary rules carry a PID-based
// exception for the agent, and that a foreign process still trips the trap.
func TestP1_17_CanarySelfPIDException(t *testing.T) {
	const canaryPath = "/tmp/test.canary"
	mgr := canary.New(canary.Config{
		Enabled:       true,
		AlertSeverity: "critical",
		Files:         []string{canaryPath},
	})
	rules := mgr.Rules()
	require.Len(t, rules, 1)

	rule := rules[0]
	assert.Equal(t, "canary_001", rule.ID)
	require.NotEmpty(t, rule.Exceptions, "canary rule must have exceptions")

	var found bool
	for _, exc := range rule.Exceptions {
		if exc.Name == "ebpf-guard-self" {
			found = true
			assert.Equal(t, "pid", exc.Condition.Field)
			assert.Equal(t, correlator.OpEquals, exc.Condition.Op)
			require.Len(t, exc.Condition.Values, 1)
			assert.Equal(t, strconv.FormatUint(uint64(mgr.SelfPID()), 10), exc.Condition.Values[0])
			break
		}
	}
	assert.True(t, found, "canary rule must have an 'ebpf-guard-self' PID exception")

	engine := correlator.NewRuleEngine(rules)

	assert.Empty(t, engine.Evaluate(p117FileEvent(mgr.SelfPID(), "ebpf-guard", canaryPath, 0)),
		"canary must not fire on the agent's own verification read")
	assert.NotEmpty(t, engine.Evaluate(p117FileEvent(4242, "cat", canaryPath, 0)),
		"canary must still fire on a foreign process — the trap is the product's "+
			"highest-confidence detector and must not be disabled by the self-exception")
}

// BenchmarkP1_17_ExceptionEvaluation measures the hot-path cost of a PID-based
// exception.
func BenchmarkP1_17_ExceptionEvaluation(b *testing.B) {
	selfPID := uint32(os.Getpid()) /* #nosec G115 -- benchmark PID fits uint32 */

	rule := correlator.Rule{
		ID:        "test_pid_exception_bench",
		Name:      "Test PID exception benchmark",
		EventType: types.EventFileAccess,
		Condition: correlator.RuleCondition{
			Field:  "filename",
			Op:     correlator.OpPrefix,
			Values: []string{"/etc/"},
		},
		Exceptions: []correlator.RuleException{{
			Name: "ebpf-guard-self",
			Condition: correlator.RuleCondition{
				Field:  "pid",
				Op:     correlator.OpEquals,
				Values: []string{strconv.FormatUint(uint64(selfPID), 10)},
			},
		}},
		Severity: types.SeverityCritical,
		Action:   correlator.ActionAlert,
	}

	engine := correlator.NewRuleEngine([]correlator.Rule{rule})
	event := p117FileEvent(selfPID, "ebpf-guard", "/etc/passwd", 0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.Evaluate(event)
	}
}
