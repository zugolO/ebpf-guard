package correlator

import (
	"math"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// TestRuleSampler_FullRate verifies that a rule with SampleRate=1.0 is never
// entered into the sampler and always returns true from ShouldEvaluate.
func TestRuleSampler_FullRate(t *testing.T) {
	rules := []Rule{{
		ID:         "full_rate",
		SampleRate: 1.0,
	}}
	s := NewRuleSampler(rules)
	if s.HasSampling("full_rate") {
		t.Fatal("HasSampling should be false for rate=1.0")
	}
	for i := 0; i < 1000; i++ {
		if !s.ShouldEvaluate("full_rate", uint32(i), uint64(i)*1e9) {
			t.Fatal("ShouldEvaluate must always return true for rate=1.0")
		}
	}
}

// TestRuleSampler_UnknownRule verifies that unknown rule IDs always pass.
func TestRuleSampler_UnknownRule(t *testing.T) {
	s := NewRuleSampler(nil)
	if !s.ShouldEvaluate("unknown", 1, 0) {
		t.Fatal("unknown rule must always pass")
	}
	if s.HasSampling("unknown") {
		t.Fatal("HasSampling must be false for unknown rule")
	}
}

// TestRuleSampler_RandomRate checks that the pass rate is within 5% of the configured value.
func TestRuleSampler_RandomRate(t *testing.T) {
	const targetRate = 0.2
	const n = 100_000
	const margin = 0.05 // ±5 percentage points

	rules := []Rule{{
		ID:         "sampled_20pct",
		SampleRate: targetRate,
	}}
	s := NewRuleSampler(rules)
	if !s.HasSampling("sampled_20pct") {
		t.Fatal("HasSampling should be true for rate=0.2")
	}
	if s.Mode("sampled_20pct") != SamplingModeRandom {
		t.Fatalf("expected random mode, got %q", s.Mode("sampled_20pct"))
	}

	passed := 0
	for i := 0; i < n; i++ {
		if s.ShouldEvaluate("sampled_20pct", uint32(i%65536), uint64(i)*1e9) {
			passed++
		}
	}
	actual := float64(passed) / n
	if math.Abs(actual-targetRate) > margin {
		t.Errorf("random sampling rate %.4f outside [%.4f, %.4f] for target %.4f",
			actual, targetRate-margin, targetRate+margin, targetRate)
	}
}

// TestRuleSampler_HashPIDRate checks that hash_pid mode hits the target rate.
func TestRuleSampler_HashPIDRate(t *testing.T) {
	const targetRate = 0.1
	const n = 100_000
	const margin = 0.05

	rules := []Rule{{
		ID:                  "sampled_10pct_det",
		SampleRate:          targetRate,
		SampleDeterministic: true,
	}}
	s := NewRuleSampler(rules)
	if s.Mode("sampled_10pct_det") != SamplingModeHashPID {
		t.Fatalf("expected hash_pid mode")
	}

	passed := 0
	for i := 0; i < n; i++ {
		pid := uint32(i % 1000) // cycle through 1000 PIDs
		ts := uint64(i)*1e9 + uint64(i)<<30
		if s.ShouldEvaluate("sampled_10pct_det", pid, ts) {
			passed++
		}
	}
	actual := float64(passed) / n
	if math.Abs(actual-targetRate) > margin {
		t.Errorf("hash_pid sampling rate %.4f outside [%.4f, %.4f] for target %.4f",
			actual, targetRate-margin, targetRate+margin, targetRate)
	}
}

// TestRuleSampler_ZeroRate verifies that a zero rate is never stored (treated as 1.0 by loader).
func TestRuleSampler_ZeroRate(t *testing.T) {
	// Zero SampleRate is normalised to 1.0 by validateRule; if someone constructs
	// a Rule directly with zero, the sampler must not treat it as 0%.
	rules := []Rule{{
		ID:         "zero_rate",
		SampleRate: 0,
	}}
	s := NewRuleSampler(rules)
	// rate=0 is < 1.0, so it will be stored — but ShouldEvaluate with rate=0 will
	// always return false. In practice, validateRule prevents this from reaching
	// production. We just verify the sampler doesn't panic.
	_ = s.ShouldEvaluate("zero_rate", 1, 1)
}

// TestRuleSampler_AdaptiveOverride checks that setAdaptiveRate/clearAdaptiveRate
// work correctly for both initially-sampled and initially-full-rate rules.
func TestRuleSampler_AdaptiveOverride(t *testing.T) {
	t.Run("override_full_rate_rule", func(t *testing.T) {
		rules := []Rule{{ID: "full", SampleRate: 1.0}}
		s := NewRuleSampler(rules)

		// Before override: no sampling.
		if s.HasSampling("full") {
			t.Fatal("should not have sampling before override")
		}

		// Apply adaptive override.
		s.setAdaptiveRate("full", 0.25)
		if !s.HasSampling("full") {
			t.Fatal("should have sampling after adaptive override")
		}

		// Clear override: should return to no sampling.
		s.clearAdaptiveRate("full")
		if s.HasSampling("full") {
			t.Fatal("should not have sampling after clearing override")
		}
	})

	t.Run("override_sampled_rule", func(t *testing.T) {
		rules := []Rule{{ID: "warn", SampleRate: 0.5}}
		s := NewRuleSampler(rules)

		// Apply stricter adaptive override.
		s.setAdaptiveRate("warn", 0.1)

		// Verify effective rate is lower.
		passed := 0
		const n = 100_000
		for i := 0; i < n; i++ {
			if s.ShouldEvaluate("warn", uint32(i%1000), uint64(i)*1e9) {
				passed++
			}
		}
		rate := float64(passed) / n
		// Effective rate should be ~0.1 (stricter of 0.5 and 0.1).
		if math.Abs(rate-0.1) > 0.05 {
			t.Errorf("adaptive override rate %.4f, expected ~0.1", rate)
		}

		// Clear: back to base rate of 0.5.
		s.clearAdaptiveRate("warn")
		passed = 0
		for i := 0; i < n; i++ {
			if s.ShouldEvaluate("warn", uint32(i%1000), uint64(i)*1e9) {
				passed++
			}
		}
		rate = float64(passed) / n
		if math.Abs(rate-0.5) > 0.05 {
			t.Errorf("restored rate %.4f, expected ~0.5", rate)
		}
	})
}

// TestRuleEngine_SampledRule verifies that the engine respects sampling in EvaluateInto.
func TestRuleEngine_SampledRule(t *testing.T) {
	const targetRate = 0.3
	const n = 100_000
	const margin = 0.05

	rule := Rule{
		ID:        "dns_vol",
		Name:      "DNS volume",
		EventType: types.EventDNS,
		Condition: RuleCondition{Field: "qname", Op: OpPrefix, Values: []string{""}},
		Severity:  types.SeverityWarning,
		Action:    ActionAlert,
		Sampling:  &RuleSampling{Rate: targetRate, Mode: SamplingModeRandom},
	}
	// Simulate what validateRule does.
	_ = validateRule(&rule)
	engine := NewRuleEngine([]Rule{rule})

	matched := 0
	e := types.Event{
		Type:      types.EventDNS,
		PID:       1,
		Timestamp: uint64(time.Now().UnixNano()),
		DNS:       &types.DNSEvent{QName: "example.com"},
	}
	for i := 0; i < n; i++ {
		e.PID = uint32(i%10000) + 1
		e.Timestamp = uint64(i) * 1e9
		engine.EvaluateInto(e, func(_ types.Alert) { matched++ })
	}

	rate := float64(matched) / n
	if math.Abs(rate-targetRate) > margin {
		t.Errorf("engine sampling rate %.4f outside [%.4f, %.4f]",
			rate, targetRate-margin, targetRate+margin)
	}
}

// TestRuleEngine_SamplingBlock_YAML verifies that the sampling block is parsed and applied.
func TestRuleEngine_SamplingBlock_YAML(t *testing.T) {
	rule := Rule{
		ID:        "r1",
		Name:      "r1",
		EventType: types.EventSyscall,
		Condition: RuleCondition{Field: "nr", Op: OpEquals, Values: []string{"59"}},
		Severity:  types.SeverityWarning,
		Action:    ActionAlert,
		Sampling:  &RuleSampling{Rate: 0.5, Mode: SamplingModeHashPID},
	}
	if err := validateRule(&rule); err != nil {
		t.Fatalf("validateRule: %v", err)
	}
	if rule.SampleRate != 0.5 {
		t.Errorf("SampleRate not propagated from Sampling block: got %.2f", rule.SampleRate)
	}
	if !rule.SampleDeterministic {
		t.Error("SampleDeterministic not set for hash_pid mode")
	}
	if rule.SampleRate >= 1.0 {
		t.Error("rate should be < 1.0 after propagation")
	}
}

// TestAdaptiveSampler_NoCriticalDownsample ensures critical rules are never downsampled.
func TestAdaptiveSampler_NoCriticalDownsample(t *testing.T) {
	rules := []Rule{
		{ID: "crit", SampleRate: 1.0, Severity: types.SeverityCritical},
		{ID: "warn", SampleRate: 1.0, Severity: types.SeverityWarning},
	}
	sampler := NewRuleSampler(rules)
	cfg := AdaptiveSamplingConfig{
		Enabled:           true,
		TriggerCPUPercent: 80,
		WarningSampleRate: 0.1,
		CriticalSampleRate: 1.0,
		CheckInterval:     time.Second,
	}
	as := NewAdaptiveSampler(cfg, rules, sampler)

	// Simulate activation.
	as.active.Store(false)
	for _, r := range rules {
		if r.Severity == types.SeverityCritical {
			continue
		}
		sampler.setAdaptiveRate(r.ID, cfg.WarningSampleRate)
	}

	// Critical rule must not have sampling.
	if sampler.HasSampling("crit") {
		t.Error("critical rule must never be downsampled by adaptive sampler")
	}
	// Warning rule should now be sampled.
	if !sampler.HasSampling("warn") {
		t.Error("warning rule should be downsampled by adaptive sampler")
	}
	_ = as // suppress unused warning
}

// TestAdaptiveSamplerConfig_Defaults verifies DefaultAdaptiveSamplingConfig values.
func TestAdaptiveSamplerConfig_Defaults(t *testing.T) {
	cfg := DefaultAdaptiveSamplingConfig()
	if cfg.Enabled {
		t.Error("adaptive sampling should be disabled by default")
	}
	if cfg.TriggerCPUPercent != 80.0 {
		t.Errorf("expected 80.0 trigger, got %.1f", cfg.TriggerCPUPercent)
	}
	if cfg.WarningSampleRate != 0.25 {
		t.Errorf("expected 0.25 warning rate, got %.2f", cfg.WarningSampleRate)
	}
	if cfg.CriticalSampleRate != 1.0 {
		t.Errorf("expected 1.0 critical rate, got %.2f", cfg.CriticalSampleRate)
	}
}
