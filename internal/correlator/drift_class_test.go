package correlator

import (
	"context"
	"testing"

	"github.com/zugolO/ebpf-guard/internal/profiler"
	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRule_EffectiveClass(t *testing.T) {
	var unset Rule
	assert.Equal(t, ClassThreat, unset.EffectiveClass())

	drift := Rule{Class: ClassDrift}
	assert.Equal(t, ClassDrift, drift.EffectiveClass())

	threat := Rule{Class: ClassThreat}
	assert.Equal(t, ClassThreat, threat.EffectiveClass())
}

func TestValidateRule_RejectsUnknownClass(t *testing.T) {
	rules := []Rule{{
		ID:        "bad_class",
		Name:      "Bad class",
		EventType: types.EventTCPConnect,
		Condition: RuleCondition{Field: "dport", Op: OpEquals, Values: []string{"80"}},
		Class:     RuleClass("bogus"),
	}}
	err := ValidateFull(rules)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown class")
}

func TestEvaluateInto_PropagatesRuleClassToAlert(t *testing.T) {
	rules := []Rule{
		{
			ID:        "threat_rule",
			Name:      "Threat",
			EventType: types.EventTCPConnect,
			Condition: RuleCondition{Field: "dport", Op: OpEquals, Values: []string{"80"}},
			Severity:  types.SeverityWarning,
			Action:    ActionAlert,
		},
		{
			ID:        "drift_rule",
			Name:      "Drift",
			EventType: types.EventTCPConnect,
			Condition: RuleCondition{Field: "dport", Op: OpEquals, Values: []string{"443"}},
			Severity:  types.SeverityWarning,
			Action:    ActionAlert,
			Class:     ClassDrift,
		},
	}
	re := NewRuleEngine(rules)

	var got []types.Alert
	re.EvaluateInto(types.Event{Type: types.EventTCPConnect, Network: &types.NetworkEvent{Dport: 80}}, func(a types.Alert) {
		got = append(got, a)
	})
	require.Len(t, got, 1)
	assert.Equal(t, "", got[0].Class, "unclassified rule leaves Alert.Class empty")

	got = nil
	re.EvaluateInto(types.Event{Type: types.EventTCPConnect, Network: &types.NetworkEvent{Dport: 443}}, func(a types.Alert) {
		got = append(got, a)
	})
	require.Len(t, got, 1)
	assert.Equal(t, string(ClassDrift), got[0].Class)
}

// TestCorrelationEngine_DriftClassSuppressedDuringLearning verifies the full
// wiring (issue #286): a class: drift rule match is routed through the
// configured DriftBaselineProfiler instead of alerting directly. While the
// workload is learning, no alert is produced; a signature the profiler never
// saw during learning is allowed through as a genuine deviation once the
// workload has switched to enforcing.
func TestCorrelationEngine_DriftClassSuppressedDuringLearning(t *testing.T) {
	driftRule := Rule{
		ID:        "drift_new_dir",
		Name:      "Drift: new directory",
		EventType: types.EventFileAccess,
		Condition: RuleCondition{Field: "filename", Op: OpPrefix, Values: []string{"/etc/"}},
		Severity:  types.SeverityWarning,
		Action:    ActionAlert,
		Class:     ClassDrift,
	}

	driftProfiler := profiler.NewDriftBaselineProfiler(profiler.DriftBaselineConfig{
		Enabled:        true,
		LearningPeriod: 0, // learning completes as soon as MinSamples is reached
		MinSamples:     2,
		PerWorkload:    true,
	}, nil)

	cfg := DefaultCorrelationEngineConfig()
	cfg.Rules = []Rule{driftRule}
	cfg.EnableAnomaly = false
	cfg.EnableRateLimit = false
	cfg.EnableDedup = false
	cfg.DriftBaselineProfiler = driftProfiler
	ce := NewCorrelationEngineWithConfig(cfg)
	defer ce.Close()

	ctx := context.Background()
	fileEvent := func(comm string, path string) types.Event {
		var filename [256]byte
		copy(filename[:], path)
		var commBytes [16]byte
		copy(commBytes[:], comm)
		return types.Event{
			Type: types.EventFileAccess,
			Comm: commBytes,
			File: &types.FileEvent{Filename: filename},
		}
	}

	// Learning phase: same signature observed twice, never alerted.
	alerts := ce.Ingest(ctx, fileEvent("sshd", "/etc/ssh/sshd_config"))
	assert.Empty(t, alerts, "drift match during learning must not alert")
	alerts = ce.Ingest(ctx, fileEvent("sshd", "/etc/ssh/sshd_config"))
	assert.Empty(t, alerts, "drift match during learning must not alert")

	// Enforcing phase now: the same signature is known baseline, suppressed.
	alerts = ce.Ingest(ctx, fileEvent("sshd", "/etc/ssh/sshd_config"))
	assert.Empty(t, alerts, "known baseline signature must stay suppressed")

	// A path never observed during learning is a genuine deviation.
	alerts = ce.Ingest(ctx, fileEvent("sshd", "/etc/cron.d/malicious"))
	require.Len(t, alerts, 1, "novel signature after learning must alert")
	assert.Equal(t, "drift_new_dir", alerts[0].RuleID)
}

// TestCorrelationEngine_DriftClassAlertsWhenProfilerNotConfigured verifies
// backward compatibility: without a DriftBaselineProfiler wired in, class:
// drift rules alert exactly like class: threat rules (no behavior change for
// existing deployments that don't opt into the feature).
func TestCorrelationEngine_DriftClassAlertsWhenProfilerNotConfigured(t *testing.T) {
	driftRule := Rule{
		ID:        "drift_new_dir",
		Name:      "Drift: new directory",
		EventType: types.EventFileAccess,
		Condition: RuleCondition{Field: "filename", Op: OpPrefix, Values: []string{"/etc/"}},
		Severity:  types.SeverityWarning,
		Action:    ActionAlert,
		Class:     ClassDrift,
	}

	cfg := DefaultCorrelationEngineConfig()
	cfg.Rules = []Rule{driftRule}
	cfg.EnableAnomaly = false
	cfg.EnableRateLimit = false
	cfg.EnableDedup = false
	ce := NewCorrelationEngineWithConfig(cfg)
	defer ce.Close()

	var filename [256]byte
	copy(filename[:], "/etc/passwd")
	alerts := ce.Ingest(context.Background(), types.Event{
		Type: types.EventFileAccess,
		File: &types.FileEvent{Filename: filename},
	})
	require.Len(t, alerts, 1)
	assert.Equal(t, "drift_new_dir", alerts[0].RuleID)
}
