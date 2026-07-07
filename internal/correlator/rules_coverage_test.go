package correlator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
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
