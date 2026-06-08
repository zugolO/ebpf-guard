package correlator

import (
	"testing"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// BenchmarkMatches_NoSampling is the baseline: sample_rate 1.0 (default).
// Every event is evaluated — this is the existing behaviour.
func BenchmarkMatches_NoSampling(b *testing.B) {
	rule := Rule{
		ID:         "bench_no_sample",
		Name:       "No sampling",
		EventType:  types.EventSyscall,
		Condition:  RuleCondition{Field: "nr", Op: OpEquals, Values: []string{"59"}},
		Severity:   types.SeverityWarning,
		Action:     ActionAlert,
		SampleRate: 1.0,
	}
	engine := NewRuleEngine([]Rule{rule})
	event := types.Event{
		Type:    types.EventSyscall,
		PID:     1234,
		TGID:    1234,
		Syscall: &types.SyscallEvent{Nr: 59},
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = engine.Evaluate(event)
	}
}

// BenchmarkMatches_Sampled10pct shows that sample_rate: 0.1 (random) reduces
// condition evaluation work to ~10% vs the NoSampling baseline.
func BenchmarkMatches_Sampled10pct(b *testing.B) {
	rule := Rule{
		ID:         "bench_sampled_10pct",
		Name:       "10pct random sampling",
		EventType:  types.EventSyscall,
		Condition:  RuleCondition{Field: "nr", Op: OpEquals, Values: []string{"59"}},
		Severity:   types.SeverityWarning,
		Action:     ActionAlert,
		SampleRate: 0.1,
	}
	engine := NewRuleEngine([]Rule{rule})
	event := types.Event{
		Type:    types.EventSyscall,
		PID:     1234,
		TGID:    1234,
		Syscall: &types.SyscallEvent{Nr: 59},
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = engine.Evaluate(event)
	}
}

// BenchmarkMatches_Sampled10pct_Deterministic shows the cost of the FNV hash
// path (sample_deterministic: true) at 10% rate.
func BenchmarkMatches_Sampled10pct_Deterministic(b *testing.B) {
	rule := Rule{
		ID:                  "bench_det_10pct",
		Name:                "10pct deterministic sampling",
		EventType:           types.EventSyscall,
		Condition:           RuleCondition{Field: "nr", Op: OpEquals, Values: []string{"59"}},
		Severity:            types.SeverityWarning,
		Action:              ActionAlert,
		SampleRate:          0.1,
		SampleDeterministic: true,
	}
	engine := NewRuleEngine([]Rule{rule})
	event := types.Event{
		Type:    types.EventSyscall,
		PID:     1234,
		TGID:    1234,
		Syscall: &types.SyscallEvent{Nr: 59},
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = engine.Evaluate(event)
	}
}

// BenchmarkShouldSample_Deterministic benchmarks the FNV hash directly
// to isolate the cost of the sampling gate itself.
func BenchmarkShouldSample_Deterministic(b *testing.B) {
	pid := uint32(1234)
	ts := uint64(1_700_000_000_000_000_000)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = shouldSample(pid, ts+uint64(i), 0.1, true)
	}
}

// BenchmarkShouldSample_Random benchmarks the random path.
func BenchmarkShouldSample_Random(b *testing.B) {
	pid := uint32(1234)
	ts := uint64(1_700_000_000_000_000_000)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = shouldSample(pid, ts+uint64(i), 0.1, false)
	}
}
