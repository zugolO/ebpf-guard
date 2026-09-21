package exporter

import (
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestAlertSilencer_Silence(t *testing.T) {
	silencer := NewAlertSilencer()
	
	// Silence a rule
	silencer.Silence("rule_001:critical", 1*time.Hour, "maintenance window")
	
	// Check if silenced
	alert := types.Alert{
		RuleID:   "rule_001",
		Severity: types.SeverityCritical,
	}
	
	assert.True(t, silencer.IsSilenced(alert))
	
	// Different severity should not be silenced
	alert2 := types.Alert{
		RuleID:   "rule_001",
		Severity: types.SeverityWarning,
	}
	assert.False(t, silencer.IsSilenced(alert2))
}

func TestAlertSilencer_IsSilenced_Expired(t *testing.T) {
	silencer := NewAlertSilencer()
	
	// Silence for very short time
	silencer.Silence("rule_001:critical", 1*time.Millisecond, "test")
	
	// Wait for expiration
	time.Sleep(10 * time.Millisecond)
	
	alert := types.Alert{
		RuleID:   "rule_001",
		Severity: types.SeverityCritical,
	}
	
	// Should not be silenced after expiration
	assert.False(t, silencer.IsSilenced(alert))
}

func TestAlertSilencer_RemoveSilence(t *testing.T) {
	silencer := NewAlertSilencer()
	
	silencer.Silence("rule_001:critical", 1*time.Hour, "test")
	
	alert := types.Alert{
		RuleID:   "rule_001",
		Severity: types.SeverityCritical,
	}
	
	assert.True(t, silencer.IsSilenced(alert))
	
	// Remove silence
	silencer.RemoveSilence("rule_001:critical")
	
	assert.False(t, silencer.IsSilenced(alert))
}

func TestAlertSilencer_Cleanup(t *testing.T) {
	silencer := NewAlertSilencer()
	
	// Add expired silence
	silencer.Silence("rule_001:critical", 1*time.Millisecond, "test")
	// Add active silence
	silencer.Silence("rule_002:warning", 1*time.Hour, "test")
	
	time.Sleep(10 * time.Millisecond)
	
	removed := silencer.Cleanup()
	assert.Equal(t, 1, removed)
	
	// Verify only active silence remains
	alert1 := types.Alert{RuleID: "rule_001", Severity: types.SeverityCritical}
	alert2 := types.Alert{RuleID: "rule_002", Severity: types.SeverityWarning}
	
	assert.False(t, silencer.IsSilenced(alert1))
	assert.True(t, silencer.IsSilenced(alert2))
}

func TestAlertSilencer_makeKey(t *testing.T) {
	silencer := NewAlertSilencer()

	alert := types.Alert{
		RuleID:   "rule_001",
		Severity: types.SeverityCritical,
	}

	key := silencer.makeKey(alert)
	assert.Equal(t, "rule_001:critical", key)
}

// №414 (wave 6.3.L, item 2): a silence created against the base rule that
// actually fired must still gate the alert once Rego has renamed it, since
// the base rule_id is the only identity the analyst can name for a rule that
// does not exist under its Rego-visible name in rules/*.yaml.
func TestAlertSilencer_SilenceOnBaseRuleGatesRenamedAlert(t *testing.T) {
	silencer := NewAlertSilencer()

	silencer.Silence("dns_dga_ngram:critical", 1*time.Hour, "known false positive")

	renamed := types.Alert{
		RuleID:   "dga_domain",
		Severity: types.SeverityCritical,
		Details:  map[string]any{types.BaseRuleIDDetailsKey: "dns_dga_ngram"},
	}
	assert.True(t, silencer.IsSilenced(renamed))
}

// The symmetric failure mode: a silence keyed on the Rego-visible name must
// NOT silently expand to gate every base rule that happens to share it — two
// base rules renaming to the same name are independent detects.
func TestAlertSilencer_SilenceOnRenamedNameDoesNotExpandToSiblingBaseRules(t *testing.T) {
	silencer := NewAlertSilencer()

	silencer.Silence("dga_domain:critical", 1*time.Hour, "attempt to silence by dashboard name")

	fromOtherBase := types.Alert{
		RuleID:   "dga_domain",
		Severity: types.SeverityCritical,
		Details:  map[string]any{types.BaseRuleIDDetailsKey: "dns_dga_high_entropy"},
	}
	assert.False(t, silencer.IsSilenced(fromOtherBase))
}
