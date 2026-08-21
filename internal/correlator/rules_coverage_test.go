package correlator

import (
	"os"
	"strconv"
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

// silentRulesRegistry parses silent-rules.txt's "<rule_id> <category>"
// format (see the file's own header). Unlike intentionalLossRuleIDs' bare
// one-id-per-line format, each line here carries a category token — kept as
// a separate parser rather than overloading intentionalLossRuleIDs, whose
// callers all rely on its "whole trimmed line is the id" behavior.
func silentRulesRegistry(t *testing.T, path string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	reg := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		require.Lenf(t, fields, 2, "%s: malformed line %q — expected exactly \"<rule_id> <category>\"", path, line)
		id, cat := fields[0], fields[1]
		if prev, ok := reg[id]; ok {
			require.Equalf(t, prev, cat, "%s: rule %q recorded twice with different categories (%q vs %q) — a rule cannot be both \"silent by construction\" and \"silent because of environment\"", path, id, prev, cat)
		}
		reg[id] = cat
	}
	return reg
}

// TestExplanationRegistries_ReferenceRealRules is the machine gate wave
// 5.9.5d (finding №63) promises: background-rules.txt, intentional-loss.txt
// and silent-rules.txt are read by run-gate.sh criterion 6 and its
// 5.9.4h section purely by rule_id string match (comm -12 / awk), with no
// check that the id still names a loaded rule. A renamed or deleted rule
// left behind in one of these files would silently stop being "explained"
// (or worse, silently keep matching a coincidentally-reused id) and nobody
// would notice — this test catches that at review time instead of on a live
// gate run.
func TestExplanationRegistries_ReferenceRealRules(t *testing.T) {
	rules, err := LoadRulesFromDir("../../rules")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	validIDs := make(map[string]struct{}, len(rules)+1)
	for _, r := range rules {
		validIDs[r.ID] = struct{}{}
	}
	// "anomaly_detection" is not a YAML rule — it's the synthetic RuleID the
	// profiler stamps on EWMA anomaly alerts (internal/correlator/engine.go,
	// internal/feedback/manager.go's anomalyRuleID). background-rules.txt
	// legitimately explains it the same way it explains any other rule_id.
	validIDs["anomaly_detection"] = struct{}{}

	checkBareList := func(path string) {
		for id := range intentionalLossRuleIDs(t, path) {
			assert.Containsf(t, validIDs, id, "%s: rule_id %q does not name any loaded rule under rules/ — stale or misspelled entry", path, id)
		}
	}
	checkBareList("../../deploy/docker-test-setup/attacks/background-rules.txt")
	checkBareList("../../deploy/docker-test-setup/attacks/intentional-loss.txt")

	silentPath := "../../deploy/docker-test-setup/attacks/silent-rules.txt"
	for id := range silentRulesRegistry(t, silentPath) {
		assert.Containsf(t, validIDs, id, "%s: rule_id %q does not name any loaded rule under rules/ — stale or misspelled entry", silentPath, id)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// DestructiveRulesWithoutArgCondition — wave 5.9.4b, finding №53
// ─────────────────────────────────────────────────────────────────────────────

func TestDestructiveRulesWithoutArgCondition(t *testing.T) {
	rules := []Rule{
		// kill + comm-only exclusion -> flagged: nothing looks at what happened,
		// only who the caller claims to be.
		{ID: "kill_comm_only", EventType: types.EventSyscall, Condition: RuleCondition{Field: "comm", Op: OpNotIn, Values: []string{"trusted"}}, Action: ActionKill},
		// kill + comm plus a real arg condition -> not flagged.
		{ID: "kill_comm_and_arg", EventType: types.EventSyscall, ConditionGroup: &RuleConditionGroup{
			Operator: "and",
			Conditions: []RuleCondition{
				{Field: "comm", Op: OpNotIn, Values: []string{"trusted"}},
				{Field: "arg0", Op: OpIn, Values: []string{"9"}},
			},
		}, Action: ActionKill},
		// block on a real field (not comm) -> not flagged.
		{ID: "block_on_field", EventType: types.EventCgroupEsc, Condition: RuleCondition{Field: "new_cgroup_id", Op: OpEquals, Values: []string{"1"}}, Action: ActionBlock},
		// throttle with no condition at all -> flagged.
		{ID: "throttle_bare", EventType: types.EventSyscall, Action: ActionThrottle},
		// alert action -> out of scope regardless of condition shape.
		{ID: "alert_comm_only", EventType: types.EventSyscall, Condition: RuleCondition{Field: "comm", Op: OpNotIn, Values: []string{"trusted"}}, Action: ActionAlert},
		// drop action -> also out of scope.
		{ID: "drop_comm_only", EventType: types.EventSyscall, Condition: RuleCondition{Field: "comm", Op: OpNotIn, Values: []string{"trusted"}}, Action: ActionDrop},
	}
	re := NewRuleEngine(rules)

	got := re.DestructiveRulesWithoutArgCondition()

	assert.ElementsMatch(t, []string{"kill_comm_only", "throttle_bare"}, got)
}

// TestDestructiveRulesInventory_RepoRules is the machine inventory required
// by wave 5.9.4b (#53): every loaded rule with action kill/block/throttle
// must have a real argument/value condition, or be named in
// destructive-actions.txt with a reason. Logged, not just asserted — the
// measurement report for №2.9.4 needs this count and list by name (5.9.4b
// criterion), and a passing test that prints nothing would put that back on
// trust the way the missing inventory did before finding №53.
func TestDestructiveRulesInventory_RepoRules(t *testing.T) {
	rules, err := LoadRulesFromDir("../../rules")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	re := NewRuleEngine(rules)
	recorded := intentionalLossRuleIDs(t, "../../deploy/docker-test-setup/attacks/destructive-actions.txt")

	got := re.DestructiveRulesWithoutArgCondition()
	t.Logf("разрушительных правил (kill/block/throttle) без условия на аргумент: %d: %v", len(got), got)

	for _, id := range got {
		assert.Contains(t, recorded, id,
			"rule %q has action kill/block/throttle, no condition beyond comm, and no line in "+
				"destructive-actions.txt: either give it a real argument/value condition or record "+
				"why that isn't possible", id)
	}

	// The mechanism itself must still catch an obviously unguarded destructive
	// rule, so a clean inventory above can't silently pass because the
	// detector broke.
	augmented := append(append([]Rule{}, rules...), Rule{
		ID:        "zz_canary_destructive_no_arg",
		EventType: types.EventSyscall,
		Condition: RuleCondition{Field: "comm", Op: OpNotIn, Values: []string{"trusted"}},
		Action:    ActionKill,
	})
	canary := NewRuleEngine(augmented).DestructiveRulesWithoutArgCondition()
	assert.Contains(t, canary, "zz_canary_destructive_no_arg")
}

// TestKillScenarioControlRule_ActionIsKill guards the rule wave 5.9.5a
// designated as the live positive control for run-gate.sh criterion 17 (the
// kill-scenario in run_kill_scenario, deploy/docker-test-setup/attacks/
// run-all-attacks.sh): ebpf_subversion_detach_nonroot is the only repo rule
// with action: kill, and the scenario relies on it having no comm condition
// (so a non-root child of the harness — not a comm-whitelisted binary — can
// trigger it) and firing on nr=321 (bpf syscall) with arg0 one of the
// destructive bpf(2) commands and uid>0.
//
// If a future edit downgrades this rule's action away from kill, or narrows
// it with a comm condition, criterion 17 stops proving anything the moment
// it starts passing vacuously again (finding №62) — this test is the machine
// check destructive-actions.txt (5.9.5a block) promises exists.
func TestKillScenarioControlRule_ActionIsKill(t *testing.T) {
	rules, err := LoadRulesFromDir("../../rules")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}

	var kills []Rule
	var control *Rule
	for i := range rules {
		if rules[i].Action != ActionKill {
			continue
		}
		kills = append(kills, rules[i])
		if rules[i].ID == "ebpf_subversion_detach_nonroot" {
			control = &rules[i]
		}
	}

	var killIDs []string
	for _, r := range kills {
		killIDs = append(killIDs, r.ID)
	}
	require.NotNilf(t, control, "kill-scenario control rule ebpf_subversion_detach_nonroot not found among kill-action rules %v — 5.9.5a's positive control has no target left", killIDs)
	require.Equal(t, []string{"ebpf_subversion_detach_nonroot"}, killIDs,
		"kill-scenario control rule assumes it is the ONLY kill-action rule in the repo; a new one changes what criterion 17's pairing check actually proves and needs its own review")

	require.NotNil(t, control.ConditionGroup, "control rule must use condition_group (nr+arg0+uid), not a single condition")
	var sawComm, sawNR, sawArg0, sawUID bool
	for _, c := range control.ConditionGroup.Conditions {
		switch c.Field {
		case "comm":
			sawComm = true
		case "nr":
			sawNR = true
			assert.Contains(t, c.Values, "321", "control rule must match bpf(2), nr=321")
		case "arg0":
			sawArg0 = true
			assert.Contains(t, c.Values, "3", "control rule must accept BPF_MAP_DELETE_ELEM=3 — that's what run_kill_scenario invokes")
		case "uid":
			sawUID = true
			assert.Equal(t, OpGreaterThan, c.Op, "control rule must require uid>0 — the scenario runs as a non-root harness child")
		}
	}
	assert.False(t, sawComm, "control rule must NOT gate on comm — that's what makes it immune to attacker-comm exclusions, unlike ebpf_subversion_unauthorized_caller")
	assert.True(t, sawNR && sawArg0 && sawUID, "control rule must condition on nr, arg0 and uid — run_kill_scenario's bpf(BPF_MAP_DELETE_ELEM) call satisfies exactly these")
}

// TestDNSLongLabelControlRules_MatchOnQNameLengthAlone guards the four rules
// wave 5.9.5c (findings №64/№65) designated as the live positive control for
// run_dns_long_label_attack (run-all-attacks.sh): dns_tunneling_long_domain,
// exfil_dns_txt_long_label, netintr_dns_long_label and
// webshell_dns_exfil_long_subdomain all fire on qname_length alone, with no
// comm condition — which is exactly what lets one long-label query satisfy
// all four regardless of which process resolves it (the attack step uses
// dig, none of these rules name it; qname_length is measured on the full
// dotted name, so the step spends its length on several labels rather than
// one over-long one).
//
// On замер №2.9.4 these four were silent for the whole agent uptime with no
// scenario ever having exercised them, and it could not be told apart from a
// DNS-parse regression. If a future edit adds a comm condition, or raises a
// threshold past what the attack step's label satisfies (a single label
// built from two 60-char filler labels plus a run-scoped marker label,
// comfortably over the highest threshold here — netintr_dns_long_label's
// 100), the positive
// control stops proving anything the moment it starts passing vacuously
// again — this test is the machine check finding №64's "не нет сценария"
// conclusion depends on.
func TestDNSLongLabelControlRules_MatchOnQNameLengthAlone(t *testing.T) {
	rules, err := LoadRulesFromDir("../../rules")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}

	byID := make(map[string]*Rule, len(rules))
	for i := range rules {
		byID[rules[i].ID] = &rules[i]
	}

	cases := []struct {
		id     string
		thresh int // expected qname_length threshold, reviewed against the attack step's label
	}{
		{"dns_tunneling_long_domain", 50},
		{"exfil_dns_txt_long_label", 60},
		{"netintr_dns_long_label", 100},
		{"webshell_dns_exfil_long_subdomain", 60},
	}

	// The attack step builds a MULTI-LABEL name, not one long label: RFC 1035
	// caps a single label at 63 octets and dig refuses to send a query that
	// breaks it, so the length that clears these thresholds has to come from
	// several labels — filler(60) + "." + filler(60) + "." +
	// "ebpfguard-5951c-" + TIMESTAMP(>=15) + ".dns-tunnel-canary.invalid"(26),
	// i.e. >= 60+1+60+1+16+15+26 = 179 chars, every label under 63 and the
	// whole name under the 253-octet limit. 150 keeps a safety margin without
	// this test having to reproduce run-all-attacks.sh's exact TIMESTAMP format.
	const attackLabelMinLength = 150

	for _, c := range cases {
		r, ok := byID[c.id]
		require.Truef(t, ok, "control rule %q not found among loaded rules — 5.9.5c's positive control has no target left", c.id)
		assert.Equalf(t, types.EventDNS, r.EventType, "%s must be event_type: dns", c.id)
		require.Nilf(t, r.ConditionGroup, "%s must use a single condition (field: qname_length), not condition_group — a condition_group could hide a comm gate the attack step doesn't satisfy", c.id)
		assert.Equalf(t, "qname_length", r.Condition.Field, "%s must condition on qname_length alone", c.id)
		assert.Equalf(t, OpGreaterThan, r.Condition.Op, "%s must use op: gt", c.id)
		require.Len(t, r.Condition.Values, 1)
		thresh, convErr := strconv.Atoi(r.Condition.Values[0])
		require.NoError(t, convErr)
		assert.Equalf(t, c.thresh, thresh, "%s threshold changed from the value 5.9.5c reviewed — re-check it against run_dns_long_label_attack's label before updating this constant", c.id)
		assert.Lessf(t, thresh, attackLabelMinLength, "%s threshold %d must stay below the attack label's guaranteed length (%d) or the control stops proving anything", c.id, thresh, attackLabelMinLength)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ExclusionsCollidingWithAttackerComms — wave 5.9.4e, finding №56
// ─────────────────────────────────────────────────────────────────────────────

// knownAttackerComms is the set of process names the attack scripts under
// deploy/docker-test-setup/attacks actually run as.
//
// The first group is attack-manifest.json's own contents: the record_manifest
// calls in sqlmap-attacks.sh, bruteforce-attacks.sh, ssrf-attacks.sh and
// ldap-csrf-attacks.sh, plus the inline manifest entries in run-all-attacks.sh
// (docker-proxy transit, chmod, log_tamper/tee).
//
// The second group is the reason this list is not just the manifest: several
// attack steps in run-all-attacks.sh execute a tool directly without recording
// a manifest entry for it, and finding №56 was exactly one of those — the
// bpftool step (5.9.2b). A check built only from the manifest would have stayed
// green on the defect it was written to catch, and would stay green if a
// `comm not_in [bpftool]` were reintroduced tomorrow. These names are read off
// the attack steps themselves: run_bpf_attack runs bpftool, run_kmod_attack
// runs insmod, run_setuid_attack runs python3.
var knownAttackerComms = map[string]bool{
	// in attack-manifest.json
	"sqlmap":       true,
	"curl":         true,
	"docker-proxy": true,
	"chmod":        true,
	"tee":          true,
	// direct attack steps in run-all-attacks.sh, not in the manifest
	"bpftool": true, // run_bpf_attack (5.9.2b/5.9.4e) — the finding-№56 comm itself
	"insmod":  true, // run_kmod_attack
	"python3": true, // run_setuid_attack
	"dig":     true, // run_dns_long_label_attack (5.9.5c, findings №64/№65)
	// The DNS event's comm is NOT "dig": it comes from bpf_get_current_comm in
	// the sendmsg/sendto context, i.e. the name of the calling THREAD, and
	// modern dig (bind9 9.18+, libuv) sends from "isc-net-0000". Verified on
	// the stand 2026-08-21: the four long-label rules fired with comm=
	// isc-net-0000. Listing only "dig" would leave this step's real comm
	// unprotected — a future `comm not_in [isc-net-0000]` exclusion would
	// blind the 5.9.5c positive control and this check would stay green,
	// which is finding №56 all over again.
	"isc-net-0000": true, // run_dns_long_label_attack, actual event comm
}

func TestExclusionsCollidingWithAttackerComms(t *testing.T) {
	re := NewRuleEngine([]Rule{
		// comm not_in excludes an attacker comm -> flagged: this rule can
		// never fire on that attack step.
		{ID: "excludes_attacker", EventType: types.EventSyscall, ConditionGroup: &RuleConditionGroup{
			Operator: "and",
			Conditions: []RuleCondition{
				{Field: "nr", Op: OpIn, Values: []string{"321"}},
				{Field: "comm", Op: OpNotIn, Values: []string{"ebpf-guard", "curl"}},
			},
		}},
		// comm not_in excludes only non-attacker names -> not flagged.
		{ID: "clean_exclusion", EventType: types.EventSyscall, Condition: RuleCondition{Field: "comm", Op: OpNotIn, Values: []string{"ebpf-guard"}}},
		// comm in (not not_in) mentioning an attacker comm is a different
		// shape (allowlist, not exclusion) -> not flagged.
		{ID: "comm_allowlist", EventType: types.EventSyscall, Condition: RuleCondition{Field: "comm", Op: OpIn, Values: []string{"curl"}}},
	})

	got := re.ExclusionsCollidingWithAttackerComms(knownAttackerComms)
	assert.Equal(t, []string{"excludes_attacker"}, got)
}

// TestExclusionsCollidingWithAttackerComms_RepoRules is the machine check
// required by wave 5.9.4e criterion: "исключение × манифест атак" must run
// against every loaded rule and print how many it checked. A rule found here
// silently blinds its own positive control the way rootkit_bpf_prog_load_suspicious
// and rootkit_bpf_map_create_suspicious did against bpftool before this wave.
func TestExclusionsCollidingWithAttackerComms_RepoRules(t *testing.T) {
	rules, err := LoadRulesFromDir("../../rules")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	re := NewRuleEngine(rules)
	recorded := intentionalLossRuleIDs(t, "../../deploy/docker-test-setup/attacks/attacker-comm-exclusions.txt")
	// 5.9.5h (finding №69): a rule already recorded in intentional-loss.txt
	// ("no scenario on this stand") has zero positive control regardless of
	// which comm is excluded — the comm-exclusion collision can't be the
	// thing blinding it, because nothing reaches its other conditions
	// either. Accepting this registry too, instead of requiring the same
	// rule_id to also carry a redundant entry in attacker-comm-exclusions.txt,
	// keeps each silence explained exactly once — see
	// TestIntentionalLossAndCommExclusionsDontDoubleBook below for the
	// invariant that enforces "exactly once" going forward.
	noScenario := intentionalLossRuleIDs(t, "../../deploy/docker-test-setup/attacks/intentional-loss.txt")

	got := re.ExclusionsCollidingWithAttackerComms(knownAttackerComms)
	t.Logf("правил проверено на пересечение исключения по comm с манифестом атак: %d, найдено коллизий: %d %v",
		len(rules), len(got), got)

	for _, id := range got {
		_, inExclusions := recorded[id]
		_, inNoScenario := noScenario[id]
		assert.Truef(t, inExclusions || inNoScenario,
			"rule %q excludes a comm that an attack script actually runs as — it can never fire "+
				"on that attack step: either give it a real argument/value condition (the way "+
				"5.9.4e fixed rootkit_bpf_prog_load_suspicious/rootkit_bpf_map_create_suspicious, "+
				"finding №56) or record why the collision isn't a coverage gap in "+
				"attacker-comm-exclusions.txt (or in intentional-loss.txt, if the rule has no "+
				"scenario on this stand at all)", id)
	}
}

// TestIntentionalLossAndCommExclusionsDontDoubleBook is the machine check
// wave 5.9.5h added for finding №69: exfil_large_http_post was recorded in
// BOTH intentional-loss.txt ("no scenario" — nothing on this stand ever
// makes a large POST to the tracked non-standard ports, full stop) AND
// attacker-comm-exclusions.txt (its comm not_in list excludes python3,
// which does run as an attack step). Two reasons for one silence is worse
// than one: a reader trusts whichever registry they open first, and the
// two can drift independently. A rule with a genuine "no scenario" entry
// can never be additionally blinded by a comm exclusion — nothing reaches
// that condition either way — so the comm-collision entry is always
// redundant once "no scenario" is recorded, never a second real cause.
func TestIntentionalLossAndCommExclusionsDontDoubleBook(t *testing.T) {
	noScenario := intentionalLossRuleIDs(t, "../../deploy/docker-test-setup/attacks/intentional-loss.txt")
	commExclusions := intentionalLossRuleIDs(t, "../../deploy/docker-test-setup/attacks/attacker-comm-exclusions.txt")

	for id := range noScenario {
		assert.NotContainsf(t, commExclusions, id,
			"rule %q is recorded in both intentional-loss.txt (\"no scenario\") and "+
				"attacker-comm-exclusions.txt (comm collision) — a rule with no scenario on this "+
				"stand can't be separately blinded by a comm exclusion; consolidate to the single "+
				"intentional-loss.txt entry and drop the attacker-comm-exclusions.txt one (5.9.5h, "+
				"finding №69)", id)
	}
}
