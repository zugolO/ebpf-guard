package correlator

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/internal/bpf"
	"github.com/zugolO/ebpf-guard/pkg/types"
	"gopkg.in/yaml.v3"
)

// ─────────────────────────────────────────────────────────────────────────────
// normaliseFieldName — full alias table
// ─────────────────────────────────────────────────────────────────────────────

func TestNormaliseFieldName_AllAliases(t *testing.T) {
	cases := map[string]string{
		"file.path":       "filename",
		"file.op":         "op",
		"file.flags":      "flags",
		"file.mode":       "mode",
		"file.directory":  "directory",
		"file.extension":  "extension",
		"proc.comm":       "comm",
		"network.dport":   "dport",
		"network.sport":   "sport",
		"network.daddr":   "daddr",
		"network.saddr":   "saddr",
		"network.proto":   "proto",
		"network.family":  "family",
		"syscall.nr":      "nr",
		"syscall.ret":     "ret",
		"syscall.arg0":    "arg0",
		"syscall.arg1":    "arg1",
		"syscall.arg2":    "arg2",
		"syscall.arg3":    "arg3",
		"syscall.arg4":    "arg4",
		"syscall.arg5":    "arg5",
		"unaliased_field": "unaliased_field",
	}
	for in, want := range cases {
		assert.Equal(t, want, normaliseFieldName(in), "normaliseFieldName(%q)", in)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// opCodeOf — full operator table
// ─────────────────────────────────────────────────────────────────────────────

func TestOpCodeOf_AllOperators(t *testing.T) {
	cases := map[RuleConditionOperator]condOpCode{
		OpIn:                           condOpIn,
		OpNotIn:                        condOpNotIn,
		OpEquals:                       condOpEquals,
		"eq":                           condOpEquals,
		OpNotEquals:                    condOpNotEquals,
		"neq":                          condOpNotEquals,
		OpPrefix:                       condOpPrefix,
		OpNotPrefix:                    condOpNotPrefix,
		OpSuffix:                       condOpSuffix,
		OpNotSuffix:                    condOpNotSuffix,
		OpContains:                     condOpContains,
		OpRegex:                        condOpRegex,
		OpGreaterThan:                  condOpGT,
		OpLessThan:                     condOpLT,
		OpGreaterOrEqual:               condOpGTE,
		OpLessOrEqual:                  condOpLTE,
		OpInCIDR:                       condOpInCIDR,
		OpNotInCIDR:                    condOpNotInCIDR,
		OpCapsGained:                   condOpCapsGained,
		OpCapsDropped:                  condOpCapsDropped,
		RuleConditionOperator("bogus"): condOpUnknown,
	}
	for op, want := range cases {
		assert.Equal(t, want, opCodeOf(op), "opCodeOf(%q)", op)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// CompileErrors / Sampler / inSetLookup
// ─────────────────────────────────────────────────────────────────────────────

func TestCompileErrors_NilWhenAllValid(t *testing.T) {
	re := NewRuleEngine([]Rule{
		{ID: "r1", EventType: types.EventSyscall, Condition: RuleCondition{Field: "nr", Op: OpEquals, Values: []string{"1"}}, Action: ActionAlert},
	})
	assert.NoError(t, re.CompileErrors())
}

func TestCompileErrors_SetOnInvalidRegex(t *testing.T) {
	re := NewRuleEngine([]Rule{
		{ID: "r1", EventType: types.EventDNS, Condition: RuleCondition{Field: "qname", Op: OpRegex, Values: []string{"("}}, Action: ActionAlert},
	})
	require.Error(t, re.CompileErrors())
	assert.Contains(t, re.CompileErrors().Error(), "compilePatterns")
}

func TestCompileErrors_SetOnInvalidCIDR(t *testing.T) {
	re := NewRuleEngine([]Rule{
		{ID: "r1", EventType: types.EventTCPConnect, Condition: RuleCondition{Field: "daddr", Op: OpInCIDR, Values: []string{"not-a-cidr"}}, Action: ActionAlert},
	})
	require.Error(t, re.CompileErrors())
}

func TestSampler_ReturnsAttachedSampler(t *testing.T) {
	re := NewRuleEngine(nil)
	assert.NotNil(t, re.Sampler())
}

func TestInSetLookup(t *testing.T) {
	re := NewRuleEngine([]Rule{
		{ID: "r1", EventType: types.EventSyscall, Condition: RuleCondition{Field: "comm", Op: OpIn, Values: []string{"evil", "bad"}}, Action: ActionAlert},
	})
	key := valueSetKey([]string{"evil", "bad"})
	assert.True(t, re.inSetLookup(key, "evil"))
	assert.False(t, re.inSetLookup(key, "good"))
	// Unknown key → false.
	assert.False(t, re.inSetLookup("no-such-key", "evil"))
}

// ─────────────────────────────────────────────────────────────────────────────
// getAllConditions / collectConditions / extractGroupConditions — nested groups
// ─────────────────────────────────────────────────────────────────────────────

func TestGetAllConditions_SimpleCondition(t *testing.T) {
	re := NewRuleEngine(nil)
	rule := Rule{Condition: RuleCondition{Field: "comm", Op: OpEquals, Values: []string{"evil"}}}
	conds := re.getAllConditions(rule)
	require.Len(t, conds, 1)
	assert.Equal(t, "comm", conds[0].Field)
}

func TestGetAllConditions_NestedGroups(t *testing.T) {
	re := NewRuleEngine(nil)
	rule := Rule{
		ConditionGroup: &RuleConditionGroup{
			Operator:   "and",
			Conditions: []RuleCondition{{Field: "comm", Op: OpEquals, Values: []string{"evil"}}},
			SubGroups: []RuleConditionGroup{
				{
					Operator:   "or",
					Conditions: []RuleCondition{{Field: "uid", Op: OpEquals, Values: []string{"0"}}},
					SubGroups: []RuleConditionGroup{
						{Conditions: []RuleCondition{{Field: "nr", Op: OpEquals, Values: []string{"59"}}}},
					},
				},
			},
		},
	}
	conds := re.getAllConditions(rule)
	require.Len(t, conds, 3)

	fields := make([]string, len(conds))
	for i, c := range conds {
		fields[i] = c.Field
	}
	assert.ElementsMatch(t, []string{"comm", "uid", "nr"}, fields)
}

func TestExtractGroupConditions_NilGroup(t *testing.T) {
	assert.Nil(t, extractGroupConditions(nil))
}

func TestExtractGroupConditions_NestedSubgroups(t *testing.T) {
	g := &RuleConditionGroup{
		Conditions: []RuleCondition{{Field: "a"}},
		SubGroups: []RuleConditionGroup{
			{Conditions: []RuleCondition{{Field: "b"}}},
			{Conditions: []RuleCondition{{Field: "c"}}, SubGroups: []RuleConditionGroup{
				{Conditions: []RuleCondition{{Field: "d"}}},
			}},
		},
	}
	conds := extractGroupConditions(g)
	fields := make([]string, len(conds))
	for i, c := range conds {
		fields[i] = c.Field
	}
	assert.ElementsMatch(t, []string{"a", "b", "c", "d"}, fields)
}

func TestCollectConditions_NilGroup(t *testing.T) {
	assert.Nil(t, collectConditions(nil))
}

// ─────────────────────────────────────────────────────────────────────────────
// NewRuleEngineWithCache / inheritCache — hot-reload pattern inheritance
// ─────────────────────────────────────────────────────────────────────────────

func TestNewRuleEngineWithCache_InheritsUnchangedPatterns(t *testing.T) {
	rules := []Rule{
		{ID: "r1", EventType: types.EventDNS, Condition: RuleCondition{Field: "qname", Op: OpRegex, Values: []string{"^evil"}}, Action: ActionAlert},
		{ID: "r2", EventType: types.EventTCPConnect, Condition: RuleCondition{Field: "daddr", Op: OpInCIDR, Values: []string{"10.0.0.0/8"}}, Action: ActionAlert},
		{ID: "r3", EventType: types.EventSyscall, Condition: RuleCondition{Field: "comm", Op: OpIn, Values: []string{"evil", "bad"}}, Action: ActionAlert},
	}
	prior := NewRuleEngine(rules)
	require.NoError(t, prior.CompileErrors())

	// Reload with the same rules: everything should be inherited without recompiling.
	reloaded := NewRuleEngineWithCache(rules, prior)
	require.NoError(t, reloaded.CompileErrors())

	assert.Same(t, prior.regexCache["^evil"], reloaded.regexCache["^evil"], "regex pattern should be inherited, not recompiled")
	assert.Same(t, prior.cidrCache["10.0.0.0/8"], reloaded.cidrCache["10.0.0.0/8"], "CIDR should be inherited")
}

func TestNewRuleEngineWithCache_DropsStaleEntries(t *testing.T) {
	rules := []Rule{
		{ID: "r1", EventType: types.EventDNS, Condition: RuleCondition{Field: "qname", Op: OpRegex, Values: []string{"^evil"}}, Action: ActionAlert},
	}
	prior := NewRuleEngine(rules)

	// Reload with a completely different rule set — the old pattern must not
	// leak into the new cache.
	newRules := []Rule{
		{ID: "r2", EventType: types.EventDNS, Condition: RuleCondition{Field: "qname", Op: OpRegex, Values: []string{"^good"}}, Action: ActionAlert},
	}
	reloaded := NewRuleEngineWithCache(newRules, prior)
	_, stalePresent := reloaded.regexCache["^evil"]
	assert.False(t, stalePresent, "stale pattern from removed rule must not be inherited")
	_, freshPresent := reloaded.regexCache["^good"]
	assert.True(t, freshPresent)
}

// ─────────────────────────────────────────────────────────────────────────────
// ReleaseAlerts / matches
// ─────────────────────────────────────────────────────────────────────────────

func TestReleaseAlerts_NilIsSafe(t *testing.T) {
	assert.NotPanics(t, func() { ReleaseAlerts(nil) })
}

func TestReleaseAlerts_RecyclesSlice(t *testing.T) {
	re := NewRuleEngine([]Rule{
		{ID: "r1", EventType: types.EventSyscall, Condition: RuleCondition{Field: "nr", Op: OpEquals, Values: []string{"59"}}, Action: ActionAlert},
	})
	alerts := re.Evaluate(types.Event{Type: types.EventSyscall, Syscall: &types.SyscallEvent{Nr: 59}})
	require.Len(t, alerts, 1)
	assert.NotPanics(t, func() { ReleaseAlerts(alerts) })
}

func TestMatches(t *testing.T) {
	re := NewRuleEngine(nil)
	rule := Rule{
		EventType: types.EventSyscall,
		Condition: RuleCondition{Field: "nr", Op: OpEquals, Values: []string{"59"}},
	}
	re.compileCondPtr(&rule.Condition)

	assert.True(t, re.matches(types.Event{Type: types.EventSyscall, Syscall: &types.SyscallEvent{Nr: 59}}, rule))
	assert.False(t, re.matches(types.Event{Type: types.EventSyscall, Syscall: &types.SyscallEvent{Nr: 1}}, rule))
	// Wrong event type entirely → false without even checking the condition.
	assert.False(t, re.matches(types.Event{Type: types.EventDNS}, rule))
}

// ─────────────────────────────────────────────────────────────────────────────
// compareNumeric / matchesCIDR — edge cases
// ─────────────────────────────────────────────────────────────────────────────

func TestCompareNumeric_EdgeCases(t *testing.T) {
	re := NewRuleEngine(nil)
	gt := func(a, b float64) bool { return a > b }

	assert.False(t, re.compareNumeric("5", nil, gt), "no thresholds")
	assert.False(t, re.compareNumeric("not-a-number", []string{"1"}, gt), "unparseable value")
	assert.False(t, re.compareNumeric("5", []string{"not-a-number"}, gt), "unparseable threshold")
	assert.True(t, re.compareNumeric("5", []string{"1"}, gt), "valid comparison")
}

func TestMatchesCIDR_EdgeCases(t *testing.T) {
	re := NewRuleEngine([]Rule{
		{ID: "r1", EventType: types.EventTCPConnect, Condition: RuleCondition{Field: "daddr", Op: OpInCIDR, Values: []string{"10.0.0.0/8"}}, Action: ActionAlert},
	})

	assert.False(t, re.matchesCIDR("not-an-ip", []string{"10.0.0.0/8"}, true), "invalid IP")
	assert.True(t, re.matchesCIDR("10.1.2.3", []string{"10.0.0.0/8"}, true), "in range, expect match")
	assert.False(t, re.matchesCIDR("10.1.2.3", []string{"10.0.0.0/8"}, false), "in range, expect no-match (not_in_cidr)")
	assert.False(t, re.matchesCIDR("172.16.0.1", []string{"10.0.0.0/8"}, true), "out of range, expect match")
	assert.True(t, re.matchesCIDR("172.16.0.1", []string{"10.0.0.0/8"}, false), "out of range, expect no-match")
	// CIDR not present in cache at all (never compiled) → falls through to !expectMatch.
	assert.True(t, re.matchesCIDR("1.2.3.4", []string{"192.168.0.0/16"}, false))
}

// ─────────────────────────────────────────────────────────────────────────────
// ReferencedSyscalls
// ─────────────────────────────────────────────────────────────────────────────

func TestReferencedSyscalls(t *testing.T) {
	rules := []Rule{
		{ID: "r1", EventType: types.EventSyscall, Condition: RuleCondition{Field: "nr", Op: OpEquals, Values: []string{"257"}}, Action: ActionAlert},
		{ID: "r2", EventType: types.EventSyscall, Condition: RuleCondition{Field: "nr", Op: OpIn, Values: []string{"258", "259", "not-a-number", "-1", "9999"}}, Action: ActionAlert},
		// Non-"nr" field on a syscall rule must be ignored.
		{ID: "r3", EventType: types.EventSyscall, Condition: RuleCondition{Field: "comm", Op: OpEquals, Values: []string{"evil"}}, Action: ActionAlert},
		// prefix/regex ops on "nr" must be ignored (only eq/in name specific numbers).
		{ID: "r4", EventType: types.EventSyscall, Condition: RuleCondition{Field: "nr", Op: OpGreaterThan, Values: []string{"500"}}, Action: ActionAlert},
		// Non-syscall event type must be skipped entirely.
		{ID: "r5", EventType: types.EventDNS, Condition: RuleCondition{Field: "qname", Op: OpEquals, Values: []string{"evil.com"}}, Action: ActionAlert},
		// nr via a ConditionGroup.
		{ID: "r6", EventType: types.EventSyscall, ConditionGroup: &RuleConditionGroup{
			Operator:   "or",
			Conditions: []RuleCondition{{Field: "nr", Op: OpEquals, Values: []string{"260"}}},
		}, Action: ActionAlert},
	}
	re := NewRuleEngine(rules)
	syscalls := re.ReferencedSyscalls()

	assertContainsU32 := func(want uint32) {
		t.Helper()
		for _, n := range syscalls {
			if n == want {
				return
			}
		}
		t.Errorf("expected ReferencedSyscalls() to contain %d, got %v", want, syscalls)
	}
	assertContainsU32(257)
	assertContainsU32(258)
	assertContainsU32(259)
	assertContainsU32(260)
	// Out-of-range (9999 >= 512) and non-numeric ("not-a-number") must be excluded.
	for _, n := range syscalls {
		assert.NotEqual(t, uint32(9999), n)
	}
	// Default monitored syscalls are always merged in.
	assertContainsU32(59)
}

// ─────────────────────────────────────────────────────────────────────────────
// UnreachableSyscallRules (wave 5.9.2b, finding #39)
// ─────────────────────────────────────────────────────────────────────────────

func TestUnreachableSyscallRules(t *testing.T) {
	rules := []Rule{
		// nr entirely outside the allowlist -> unreachable.
		{ID: "unreachable_single", EventType: types.EventSyscall, Condition: RuleCondition{Field: "nr", Op: OpEquals, Values: []string{"999"}}, Action: ActionAlert},
		// nr set with a partial hit -> reachable, not reported.
		{ID: "partially_reachable", EventType: types.EventSyscall, Condition: RuleCondition{Field: "nr", Op: OpIn, Values: []string{"59", "999"}}, Action: ActionAlert},
		// nr fully inside the allowlist -> reachable.
		{ID: "reachable", EventType: types.EventSyscall, Condition: RuleCondition{Field: "nr", Op: OpEquals, Values: []string{"59"}}, Action: ActionAlert},
		// No numeric "nr" condition at all (e.g. drift's string-valued nr) -> not reported,
		// since there's nothing to intersect against the allowlist.
		{ID: "non_numeric_nr", EventType: types.EventSyscall, Condition: RuleCondition{Field: "nr", Op: OpEquals, Values: []string{"ptrace"}}, Action: ActionAlert},
		// Not a syscall rule -> ignored regardless of nr.
		{ID: "not_syscall", EventType: types.EventDNS, Condition: RuleCondition{Field: "qname", Op: OpEquals, Values: []string{"evil.com"}}, Action: ActionAlert},
		// Unreachable nr via a ConditionGroup, not a top-level Condition.
		{ID: "unreachable_group", EventType: types.EventSyscall, ConditionGroup: &RuleConditionGroup{
			Operator:   "or",
			Conditions: []RuleCondition{{Field: "nr", Op: OpIn, Values: []string{"998"}}},
		}, Action: ActionAlert},
	}
	re := NewRuleEngine(rules)
	allowlist := []int{59, 322, 101}

	unreachable := re.UnreachableSyscallRules(allowlist)

	assert.ElementsMatch(t, []string{"unreachable_single", "unreachable_group"}, unreachable)
}

// TestUnreachableSyscallRules_RepoRuleCount is a regression guard for finding
// #39: it loads the real rules/*.yaml tree and fails if the count of
// syscall rules with no reachable "nr" grows past the wave 5.9.2b ceiling
// (started at 27, capped at ≤20 by that wave) without a matching
// intentional-loss.txt entry, or if the mechanism itself stops flagging an
// obviously-unmonitored syscall number.
//
// The allowlist is RESOLVED THE WAY main.go RESOLVES IT, for every config the
// project actually runs — not restated here, and not read from one file only.
// Both mistakes have already been made: the wave found the same list in three
// places with a 241/298 mismatch between them, and then measured "11 mute
// rules" against config/config.yaml while the test stand runs
// config-test.yaml, which sets no monitored_syscalls at all and therefore
// falls back to DefaultMonitoredSyscalls() — a different, shorter list that
// leaves 13 rules mute. A test that reads one file keeps passing against
// numbers the agent never uses.
func TestUnreachableSyscallRules_RepoRuleCount(t *testing.T) {
	rules, err := LoadRulesFromDir("../../rules")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	re := NewRuleEngine(rules)
	recorded := intentionalLossRuleIDs(t, "../../deploy/docker-test-setup/attacks/intentional-loss.txt")

	configs := []struct {
		name string
		path string
	}{
		{"config.yaml (shipped default)", "../../config/config.yaml"},
		{"config-test.yaml (the measurement stand)", "../../deploy/docker-test-setup/config-test.yaml"},
	}

	for _, cfg := range configs {
		t.Run(cfg.name, func(t *testing.T) {
			allowlist := effectiveAllowlist(t, cfg.path)
			require.NotEmpty(t, allowlist, "an empty effective allowlist would make every syscall rule mute")

			unreachable := re.UnreachableSyscallRules(allowlist)
			if len(unreachable) > 20 {
				t.Errorf("wave 5.9.2b ceiling exceeded: %d syscall rules have no reachable nr "+
					"(want <=20, rules must either get their nr opened in the allowlist or be "+
					"recorded in deploy/docker-test-setup/attacks/intentional-loss.txt): %v",
					len(unreachable), unreachable)
			}

			// Criterion 5.9.2b is "≤20 AND every survivor has a line in
			// intentional-loss.txt with a reason" — the count alone was checked
			// here, the second half only by hand. Checking it by hand is what let
			// 27 rules accumulate unnoticed in the first place.
			for _, id := range unreachable {
				assert.Contains(t, recorded, id,
					"rule %q has no reachable nr under %s and no line in intentional-loss.txt: "+
						"either open its syscall (and add an attack step) or record why it cannot fire",
					id, cfg.path)
			}
		})
	}

	// The mechanism itself must still catch an obviously unmonitored syscall,
	// so the ceiling check above can't silently pass because the detector broke.
	augmented := append(append([]Rule{}, rules...), Rule{
		ID:        "zz_canary_unmonitored_nr",
		EventType: types.EventSyscall,
		Condition: RuleCondition{Field: "nr", Op: OpEquals, Values: []string{"9001"}},
		Action:    ActionAlert,
	})
	canaryUnreachable := NewRuleEngine(augmented).UnreachableSyscallRules(bpf.DefaultMonitoredSyscalls())
	assert.Contains(t, canaryUnreachable, "zz_canary_unmonitored_nr")
}

// ─────────────────────────────────────────────────────────────────────────────
// ContextEmptySyscallRules (wave 5.9.3c, finding #47)
// ─────────────────────────────────────────────────────────────────────────────

func TestContextEmptySyscallRules(t *testing.T) {
	rules := []Rule{
		// nr-only condition -> context-empty.
		{ID: "bare_nr", EventType: types.EventSyscall, Condition: RuleCondition{Field: "nr", Op: OpIn, Values: []string{"59"}}, Action: ActionAlert},
		// nr-only via the syscall.nr alias -> still context-empty after normalisation.
		{ID: "bare_nr_alias", EventType: types.EventSyscall, Condition: RuleCondition{Field: "syscall.nr", Op: OpEquals, Values: []string{"59"}}, Action: ActionAlert},
		// nr plus a comm exclusion -> has context, not reported.
		{ID: "nr_with_comm", EventType: types.EventSyscall, ConditionGroup: &RuleConditionGroup{
			Operator: "and",
			Conditions: []RuleCondition{
				{Field: "nr", Op: OpIn, Values: []string{"59"}},
				{Field: "comm", Op: OpNotIn, Values: []string{"sshd"}},
			},
		}, Action: ActionAlert},
		// nr plus an arg constraint -> has context, not reported.
		{ID: "nr_with_arg", EventType: types.EventSyscall, ConditionGroup: &RuleConditionGroup{
			Operator: "and",
			Conditions: []RuleCondition{
				{Field: "nr", Op: OpIn, Values: []string{"10"}},
				{Field: "arg2", Op: OpIn, Values: []string{"4"}},
			},
		}, Action: ActionAlert},
		// Not a syscall rule -> ignored regardless of field.
		{ID: "not_syscall", EventType: types.EventDNS, Condition: RuleCondition{Field: "qname", Op: OpEquals, Values: []string{"evil.com"}}, Action: ActionAlert},
	}
	re := NewRuleEngine(rules)

	got := re.ContextEmptySyscallRules()

	assert.ElementsMatch(t, []string{"bare_nr", "bare_nr_alias"}, got)
}

// TestContextEmptySyscallRules_RepoRuleCount is the 5.9.3c acceptance check:
// it loads the real rules/*.yaml tree and fails if the count of context-empty
// syscall rules grows past the wave's ≤5 ceiling, or if a rule leaves that
// ceiling without a documented reason here. wave 5.9.3b closed 6 of these
// (the ones event_type:syscall with only "nr"; the other 5 of the "11
// rules" mentioned in plan.md 5.9.3b use comm/proc.comm, not nr, so they were
// never counted by this check) and wave 5.9.3c closed 29 more, from 39 down
// to the 4 below — one under the ≤5 target.
//
// The 4 that remain use only "nr" because the real distinguishing signal —
// whether the memfd/anon-fd this syscall touches is later exec'd, or whether
// the chmod target path was under /tmp — needs correlation across multiple
// events (fd lifecycle, path resolution at the syscall layer) that a single
// condition on a single event cannot express. Giving them a comm/parent_comm
// allowlist would not add real context: memfd_create and chmod are used by
// enough ordinary software (browsers, systemd, package managers) that an
// allowlist would either chase an ever-growing list or exclude away most of
// the signal. See plan.md wave 5.9.3c for the full writeup.
var contextEmptySyscallRulesRemainder = map[string]string{
	"integrity_proc_self_exe_exec": "memfd_create/memfd_secret alone; the actual signal (exec of that fd) needs fd-lifecycle correlation, not a single-event field",
	"proc_inject_memfd_create":     "same memfd_create limitation as integrity_proc_self_exe_exec — pervasive legitimate use (browsers, systemd, JVM), no single-event field distinguishes staging from routine anonymous-file use",
	"sigma_memfd_create_anonymous": "duplicate of the same memfd_create limitation, different rule file",
	"sigma_chmod_executable_tmp":   "documented in the rule's own description (5.9d, finding #27): the collector cannot resolve the chmod target path at the syscall layer, so it cannot be scoped to /tmp despite the rule id",
}

func TestContextEmptySyscallRules_RepoRuleCount(t *testing.T) {
	rules, err := LoadRulesFromDir("../../rules")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	re := NewRuleEngine(rules)

	got := re.ContextEmptySyscallRules()
	// Logged, not just asserted: замер №2.9.3 requires this number by name in
	// the run's own report (п.5), and a passing test that prints nothing
	// forces whoever reads the protocol to take the count on trust.
	t.Logf("контекстно-пустых syscall-правил: %d (потолок 5): %v", len(got), got)
	if len(got) > 5 {
		t.Errorf("wave 5.9.3c ceiling exceeded: %d syscall rules constrain only \"nr\" "+
			"(want <=5, each documented in contextEmptySyscallRulesRemainder): %v", len(got), got)
	}
	for _, id := range got {
		assert.Contains(t, contextEmptySyscallRulesRemainder, id,
			"rule %q has no context beyond nr and no documented reason in "+
				"contextEmptySyscallRulesRemainder: either give it comm/parent_comm/argN "+
				"context or document why that's not possible", id)
	}

	// The mechanism itself must still catch an obviously context-empty rule,
	// so the ceiling check above can't silently pass because the detector broke.
	augmented := append(append([]Rule{}, rules...), Rule{
		ID:        "zz_canary_context_empty",
		EventType: types.EventSyscall,
		Condition: RuleCondition{Field: "nr", Op: OpEquals, Values: []string{"9001"}},
		Action:    ActionAlert,
	})
	canary := NewRuleEngine(augmented).ContextEmptySyscallRules()
	assert.Contains(t, canary, "zz_canary_context_empty")
}

// effectiveAllowlist resolves a config file the way cmd/ebpf-guard/main.go
// does: the explicit bpf.kernel_filter.monitored_syscalls list when it is set,
// and DefaultMonitoredSyscalls() when it is not. Reproducing that fallback is
// the point — config-test.yaml omits the key entirely, so a test that only
// read the file would have measured against an empty list.
func effectiveAllowlist(t *testing.T, path string) []int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	var doc struct {
		BPF struct {
			KernelFilter struct {
				MonitoredSyscalls []int `yaml:"monitored_syscalls"`
			} `yaml:"kernel_filter"`
		} `yaml:"bpf"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if len(doc.BPF.KernelFilter.MonitoredSyscalls) == 0 {
		return bpf.DefaultMonitoredSyscalls()
	}
	return doc.BPF.KernelFilter.MonitoredSyscalls
}

// intentionalLossRuleIDs reads the bare rule_id lines out of
// intentional-loss.txt. The file's format is one rule_id per line with no
// trailing text — run-gate.sh compares it against detected rule IDs with
// `comm -12`, so anything after the id would break the match there.
func intentionalLossRuleIDs(t *testing.T, path string) map[string]struct{} {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	ids := map[string]struct{}{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ids[line] = struct{}{}
	}
	return ids
}
