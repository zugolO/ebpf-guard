package correlator_test

import (
	"os"
	"strconv"
	"testing"
	"time"

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
		// cred_proc_maps_mass_read is NOT in this table (5.9.9.Fa): the rule now
		// carries a threshold (count: 5), and this table's single-Evaluate-call
		// shape cannot reach a burst gate. See
		// TestP1_17_CredProcMapsMassRead_NumericPID below for its dedicated,
		// threshold-aware coverage.
		{"mitre_sandbox_detect_proc_read", "../../rules/mitre-additional.yaml", "mitre_sandbox_detect_proc_read",
			"/proc/self/cgroup", "/proc/1/environ", opOpen, ""},
		{"container_escape_init_proc", "../../rules/container-escape.yaml", "container_escape_init_proc",
			"/proc/1/cgroup", "/proc/1/environ", opOpen, ""},
		// Q9 scoped this rule to web-server processes, so the foreign process
		// here must be one — a bare "nc" would no longer match the rule at all
		// and the case would silently stop testing the self-exception.
		{"owasp_web_sensitive_file_read", "../../rules/owasp-web.yaml", "owasp_web_sensitive_file_read",
			"/etc/passwd.canary", "/etc/shadow", opOpen, "nginx"},
		// sigma_sensitive_file_chmod was removed from this table by 5.9d: it
		// moved from event_type: file to event_type: syscall (the collector
		// never hooks chmod/fchmod/fchmodat at the file layer at all, so the
		// rule could never observe a genuine chmod there — see rules/sigma-linux.yaml).
		// Syscall args are raw pointers, not resolved paths, so a comm+path
		// self-exception is no longer possible for this rule; the agent's own
		// canary chmods are now covered only by the PID-tree self-exclusion
		// filter (correlator.self_exclude, 5.8e), applied before rule
		// evaluation rather than per-rule.
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

// TestP1_17_CredProcMapsMassRead_NumericPID is the regression test for
// 5.9.9.Fa (finding #107): cred_proc_maps_mass_read used to match via
// prefix("/proc/") + suffix("/maps","/mem","/environ"), which matches
// /proc/self/maps — the reading process's own memory, never another
// process's — and produced 44 false criticals per run across three
// consecutive measurements. The rule now gates on a numeric-PID regex and
// carries threshold{count: 5, group_by: chain}, so it needs dedicated,
// threshold-aware coverage rather than a row in the single-Evaluate-call
// table in TestP1_17_SelfExclusion above.
func TestP1_17_CredProcMapsMassRead_NumericPID(t *testing.T) {
	rules, err := correlator.LoadRulesFromFile("../../rules/credential-access.yaml")
	require.NoError(t, err)

	var target *correlator.Rule
	for i := range rules {
		if rules[i].ID == "cred_proc_maps_mass_read" {
			target = &rules[i]
			break
		}
	}
	require.NotNil(t, target, "cred_proc_maps_mass_read not found in credential-access.yaml")
	require.NotNil(t, target.Threshold, "cred_proc_maps_mass_read must carry a threshold (5.9.9.Fa)")
	require.Equal(t, 5, target.Threshold.Count)

	var selfExc *correlator.RuleException
	for i := range target.Exceptions {
		if target.Exceptions[i].Name == "ebpf-guard-self" {
			selfExc = &target.Exceptions[i]
			break
		}
	}
	require.NotNil(t, selfExc, "cred_proc_maps_mass_read must keep its 'ebpf-guard-self' exception (5.9.9.Fa leaves it unchanged)")

	const opOpen = 0
	nextPID := uint32(960000)
	pidFor := func() uint32 {
		nextPID++
		return nextPID
	}

	// fireN evaluates n events for the same (pid, comm, path) in sequence,
	// close enough in time to stay inside the rule's 10s burst window, and
	// returns the alerts from the last event.
	fireN := func(engine *correlator.RuleEngine, pid uint32, comm, path string, n int) []types.Alert {
		base := time.Now()
		var alerts []types.Alert
		for i := 0; i < n; i++ {
			e := p117FileEvent(pid, comm, path, opOpen)
			e.Timestamp = uint64(base.Add(time.Duration(i) * time.Millisecond).UnixNano())
			alerts = engine.Evaluate(e)
		}
		return alerts
	}

	t.Run("proc self maps never alerts, even past the threshold count", func(t *testing.T) {
		engine := correlator.NewRuleEngine([]correlator.Rule{*target})
		alerts := fireN(engine, pidFor(), "grep", "/proc/self/maps", 10)
		assert.Empty(t, alerts, "cred_proc_maps_mass_read must never match /proc/self/maps (finding #107)")
	})

	t.Run("numeric PID maps does not alert below the threshold count", func(t *testing.T) {
		engine := correlator.NewRuleEngine([]correlator.Rule{*target})
		alerts := fireN(engine, pidFor(), "nc", "/proc/1234/maps", 4)
		assert.Empty(t, alerts, "must not alert before the burst threshold is reached")
	})

	t.Run("numeric PID maps alerts once the threshold count is reached", func(t *testing.T) {
		engine := correlator.NewRuleEngine([]correlator.Rule{*target})
		alerts := fireN(engine, pidFor(), "nc", "/proc/1234/maps", 5)
		assert.NotEmpty(t, alerts, "must alert once the burst threshold is reached")
	})

	t.Run("numeric PID mem alerts once the threshold count is reached", func(t *testing.T) {
		engine := correlator.NewRuleEngine([]correlator.Rule{*target})
		alerts := fireN(engine, pidFor(), "nc", "/proc/1234/mem", 5)
		assert.NotEmpty(t, alerts, "must alert on /proc/<pid>/mem past the threshold")
	})

	t.Run("numeric PID task tid mem alerts once the threshold count is reached", func(t *testing.T) {
		engine := correlator.NewRuleEngine([]correlator.Rule{*target})
		alerts := fireN(engine, pidFor(), "nc", "/proc/1234/task/5678/mem", 5)
		assert.NotEmpty(t, alerts, "must alert on /proc/<pid>/task/<tid>/mem past the threshold")
	})

	// The live positive control (run_cred_proc_maps_positive_control,
	// run-all-attacks.sh, 5.9.9.Fa) reads another process's /proc/<pid>/maps
	// eight times from one process named "credscrape". Asserting its exact
	// shape here means a rename of that step, or a comm that happens to land
	// in the rule's not_in list, fails offline instead of showing up as a
	// silent rule on the stand — the failure mode finding #57 is about.
	t.Run("the live positive control's own shape fires the rule", func(t *testing.T) {
		engine := correlator.NewRuleEngine([]correlator.Rule{*target})
		alerts := fireN(engine, pidFor(), "credscrape", "/proc/4242/maps", 8)
		assert.NotEmpty(t, alerts, "run_cred_proc_maps_positive_control must raise cred_proc_maps_mass_read")
	})

	t.Run("ebpf-guard-self exception still suppresses comm=ebpf-guard maps reads past the threshold", func(t *testing.T) {
		engine := correlator.NewRuleEngine([]correlator.Rule{*target})
		alerts := fireN(engine, pidFor(), "ebpf-guard", "/proc/1234/maps", 10)
		assert.Empty(t, alerts, "the uprobe attacher's own /proc/<pid>/maps reads must stay excepted")
	})

	t.Run("comm spoofing does not buy invisibility on /proc/<pid>/mem past the threshold", func(t *testing.T) {
		engine := correlator.NewRuleEngine([]correlator.Rule{*target})
		alerts := fireN(engine, pidFor(), "ebpf-guard", "/proc/1234/mem", 5)
		assert.NotEmpty(t, alerts, "a process spoofing comm='ebpf-guard' must still alert on /proc/<pid>/mem — "+
			"the exception is scoped to the maps suffix only")
	})
}

// TestP1_17_ProcSelfNarrowingIsRuleLocal is the other half of 5.9.9.Fa, and it
// exists to make a PROHIBITION fail loudly instead of silently. 5.9.9.Fa
// narrowed cred_proc_maps_mass_read away from /proc/self/ because that rule is
// about scraping ANOTHER process's memory. plan.md ("Что в волну 5.9.9.F
// намеренно не входит") then forbids the symmetric edit across the rest of the
// /proc family: owasp_web_sensitive_file_read keeps
// /proc/self/{maps,mem,environ,cmdline} on purpose — a web worker reading its
// own memory IS the LFI/SSRF primitive, and the rule is already narrowed by
// web-worker comm instead — and mitre_sandbox_detect_proc_read keeps
// /proc/self/cgroup for the same reason. Generalising "self is never
// interesting" into those rules would be finding #57 inverted (silently
// narrowing detection), and until this test existed nothing would have caught
// it: the 5.9.9.Fa cases only assert what must STOP matching.
func TestP1_17_ProcSelfNarrowingIsRuleLocal(t *testing.T) {
	const opOpen = 0

	loadRule := func(t *testing.T, file, id string) correlator.Rule {
		t.Helper()
		rules, err := correlator.LoadRulesFromFile(file)
		require.NoError(t, err)
		for i := range rules {
			if rules[i].ID == id {
				return rules[i]
			}
		}
		t.Fatalf("rule %s not found in %s", id, file)
		return correlator.Rule{}
	}

	t.Run("owasp_web_sensitive_file_read still covers /proc/self from a web worker", func(t *testing.T) {
		rule := loadRule(t, "../../rules/owasp-web.yaml", "owasp_web_sensitive_file_read")
		engine := correlator.NewRuleEngine([]correlator.Rule{rule})

		for _, path := range []string{
			"/proc/self/maps",
			"/proc/self/mem",
			"/proc/self/environ",
			"/proc/self/cmdline",
		} {
			assert.NotEmpty(t, engine.Evaluate(p117FileEvent(4242, "nginx", path, opOpen)),
				"owasp_web_sensitive_file_read must keep alerting on %s from a web worker: "+
					"5.9.9.Fa narrowed cred_proc_maps_mass_read only, and plan.md forbids "+
					"carrying that narrowing into this rule", path)
		}
	})

	t.Run("that coverage is comm-scoped, not path-scoped", func(t *testing.T) {
		// The reason the rule can afford to keep /proc/self at all: Q9 already
		// bounds it to web-worker comms, so it never sees the idle-host churn
		// that made cred_proc_maps_mass_read fire 44 times a run. If this ever
		// starts alerting, the rule lost its comm bound and the /proc/self
		// paths become the noise source 5.9.9.Fa removed.
		rule := loadRule(t, "../../rules/owasp-web.yaml", "owasp_web_sensitive_file_read")
		engine := correlator.NewRuleEngine([]correlator.Rule{rule})
		assert.Empty(t, engine.Evaluate(p117FileEvent(4242, "grep", "/proc/self/maps", opOpen)),
			"owasp_web_sensitive_file_read must stay bound to web-worker comm (Q9)")
	})

	t.Run("mitre_sandbox_detect_proc_read still covers /proc/self/cgroup", func(t *testing.T) {
		rule := loadRule(t, "../../rules/mitre-additional.yaml", "mitre_sandbox_detect_proc_read")
		engine := correlator.NewRuleEngine([]correlator.Rule{rule})
		assert.NotEmpty(t, engine.Evaluate(p117FileEvent(4242, "nc", "/proc/self/cgroup", opOpen)),
			"mitre_sandbox_detect_proc_read must keep /proc/self/cgroup: reading one's own "+
				"cgroup IS the container-detection primitive, unlike reading one's own memory")
	})

	t.Run("cred_proc_maps_mass_read stays silent on /proc/self even from a web worker", func(t *testing.T) {
		// The two halves must hold simultaneously: the same /proc/self/maps
		// read is covered by owasp_web_sensitive_file_read (above) and NOT by
		// cred_proc_maps_mass_read (5.9.9.Fa). Asserted here on the whole
		// catalog rather than the single rule so that "the /proc/self read is
		// still seen by SOMETHING" and "it is no longer seen by THIS rule" are
		// one statement.
		catalog, err := correlator.LoadRulesFromDir("../../rules")
		require.NoError(t, err)
		engine := correlator.NewRuleEngine(catalog)

		var fired []types.Alert
		base := time.Now()
		for i := 0; i < 10; i++ {
			e := p117FileEvent(970001, "nginx", "/proc/self/maps", opOpen)
			e.Timestamp = uint64(base.Add(time.Duration(i) * time.Millisecond).UnixNano())
			fired = append(fired, engine.Evaluate(e)...)
		}

		sawOWASP := false
		for _, a := range fired {
			assert.NotEqual(t, "cred_proc_maps_mass_read", a.RuleID,
				"cred_proc_maps_mass_read must not match /proc/self/maps (finding #107)")
			if a.RuleID == "owasp_web_sensitive_file_read" {
				sawOWASP = true
			}
		}
		assert.True(t, sawOWASP,
			"a web worker reading /proc/self/maps must still be covered by "+
				"owasp_web_sensitive_file_read after 5.9.9.Fa")
	})
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
