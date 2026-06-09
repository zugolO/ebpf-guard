package correlator

import (
	"testing"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// newSyscallRule builds a minimal syscall rule for benchmarking.
func newSyscallRule(id string, op RuleConditionOperator, values []string) Rule {
	return Rule{
		ID:        id,
		Name:      id,
		EventType: types.EventSyscall,
		Condition: RuleCondition{Field: "nr", Op: op, Values: values},
		Severity:  types.SeverityWarning,
		Action:    ActionAlert,
	}
}

// BenchmarkRuleEval_NoMatchByType measures EvaluateInto when the event type has
// no rules registered. byType returns a nil slice immediately — this is the floor.
//
// Target: < 5 ns/op, 0 allocs/op.
func BenchmarkRuleEval_NoMatchByType(b *testing.B) {
	rule := newSyscallRule("bench_nomatch_type", OpIn, []string{"1", "2", "3"})
	engine := NewRuleEngine([]Rule{rule})
	// Network event — no rules registered for this type.
	ev := types.Event{
		Type:    types.EventTCPConnect,
		PID:     1234,
		Network: &types.NetworkEvent{Dport: 443},
	}
	fn := func(types.Alert) {}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.EvaluateInto(ev, fn)
	}
}

// BenchmarkRuleEval_NoMatchByCond measures EvaluateInto on the no-match path:
// event type matches, but the "nr" value is not in the rule's set.
// This is the overwhelmingly common production case.
//
// Target: < 20 ns/op, 0 allocs/op.
func BenchmarkRuleEval_NoMatchByCond(b *testing.B) {
	rule := newSyscallRule("bench_nomatch_cond", OpIn, []string{"1", "2", "3"})
	engine := NewRuleEngine([]Rule{rule})
	ev := syscallEvent(1234, 59) // nr=59 is NOT in {1,2,3}
	fn := func(types.Alert) {}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.EvaluateInto(ev, fn)
	}
}

// BenchmarkRuleEval_NoMatchByCond_Equals measures the equals operator no-match path.
func BenchmarkRuleEval_NoMatchByCond_Equals(b *testing.B) {
	rule := newSyscallRule("bench_nomatch_eq", OpEquals, []string{"1"})
	engine := NewRuleEngine([]Rule{rule})
	ev := syscallEvent(1234, 59) // nr=59 != "1"
	fn := func(types.Alert) {}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.EvaluateInto(ev, fn)
	}
}

// BenchmarkRuleEval_Match measures EvaluateInto when a rule fires and fn is called.
// Includes the time.Unix conversion and alert struct construction.
func BenchmarkRuleEval_Match(b *testing.B) {
	rule := newSyscallRule("bench_match", OpIn, []string{"59", "60", "61"})
	engine := NewRuleEngine([]Rule{rule})
	ev := syscallEvent(1234, 59) // matches
	fn := func(types.Alert) {}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.EvaluateInto(ev, fn)
	}
}

// BenchmarkRuleEval_MultiRule measures EvaluateInto with 10 rules registered
// for the same event type — all non-matching.
func BenchmarkRuleEval_MultiRule(b *testing.B) {
	rules := make([]Rule, 10)
	for i := range rules {
		rules[i] = newSyscallRule("bench_multi_"+string(rune('a'+i)), OpEquals, []string{"999"})
	}
	engine := NewRuleEngine(rules)
	ev := syscallEvent(1234, 59) // no rule matches nr=59 against "999"
	fn := func(types.Alert) {}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.EvaluateInto(ev, fn)
	}
}
