package correlator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

func TestCheckSampling_UnknownRule(t *testing.T) {
	s := NewRuleSampler(nil)
	active, skip, mode, rateStr := s.CheckSampling("no-such-rule", 1, 0)
	assert.False(t, active)
	assert.False(t, skip)
	assert.Equal(t, "", mode)
	assert.Equal(t, "", rateStr)
}

func TestCheckSampling_FullRateIsNotActive(t *testing.T) {
	rules := []Rule{{ID: "r1", SampleRate: 1.0}}
	s := NewRuleSampler(rules)
	active, _, _, _ := s.CheckSampling("r1", 1, 0)
	assert.False(t, active, "rate >= 1.0 means no sampling gate is active")
}

func TestCheckSampling_PartialRateReportsSampledAndDropped(t *testing.T) {
	rules := []Rule{{ID: "r1", SampleRate: 0.5, SampleDeterministic: true}}
	s := NewRuleSampler(rules)

	sampledAtLeastOnce, droppedAtLeastOnce := false, false
	for pid := uint32(0); pid < 200; pid++ {
		active, skip, mode, rateStr := s.CheckSampling("r1", pid, 0)
		assert.True(t, active)
		assert.Equal(t, "hash_pid", mode)
		assert.NotEmpty(t, rateStr)
		if skip {
			droppedAtLeastOnce = true
		} else {
			sampledAtLeastOnce = true
		}
	}
	assert.True(t, sampledAtLeastOnce, "expected at least one PID to be sampled")
	assert.True(t, droppedAtLeastOnce, "expected at least one PID to be dropped")
}

func TestRuleSampler_Mode_UnknownRuleDefaultsToRandom(t *testing.T) {
	s := NewRuleSampler(nil)
	assert.Equal(t, SamplingModeRandom, s.Mode("no-such-rule"))
}

func TestRuleSampler_Mode_EmptyModeDefaultsToRandom(t *testing.T) {
	rules := []Rule{{ID: "r1", SampleRate: 0.5}} // no explicit mode
	s := NewRuleSampler(rules)
	assert.Equal(t, SamplingModeRandom, s.Mode("r1"))
}

func TestRuleSampler_HasSampling_UnknownRule(t *testing.T) {
	s := NewRuleSampler(nil)
	assert.False(t, s.HasSampling("no-such-rule"))
}

func TestRuleSampler_ShouldEvaluate_UnknownRuleAlwaysTrue(t *testing.T) {
	s := NewRuleSampler(nil)
	assert.True(t, s.ShouldEvaluate("no-such-rule", 1, 0))
}

// TestRuleEngine_MatchesTyped_UsesCheckSampling exercises the hot-path wiring
// in matchesTyped (rules.go) that funnels through RuleSampler.CheckSampling.
func TestRuleEngine_MatchesTyped_UsesCheckSampling(t *testing.T) {
	re := NewRuleEngine([]Rule{
		{
			ID:                  "sampled",
			EventType:           types.EventSyscall,
			Condition:           RuleCondition{Field: "nr", Op: OpEquals, Values: []string{"1"}},
			Action:              ActionAlert,
			SampleRate:          0.5,
			SampleDeterministic: true,
		},
	})

	matchCount, skipCount := 0, 0
	for pid := uint32(0); pid < 200; pid++ {
		ev := types.Event{Type: types.EventSyscall, PID: pid, Syscall: &types.SyscallEvent{Nr: 1}}
		if len(re.Evaluate(ev)) > 0 {
			matchCount++
		} else {
			skipCount++
		}
	}
	assert.Greater(t, matchCount, 0)
	assert.Greater(t, skipCount, 0)
}
