//go:build rego

package correlator

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/internal/policy"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Wave 6.3-rid, item 2 (№400/№401 — decision б): Rego enrichment still
// renames RuleID, but the pre-rename id must be recoverable via
// types.Alert.BaseRuleID so the suppression axis (drift baseline/dedup/rate
// limiter, all keyed on the base name upstream of Rego) can be joined back
// onto a reporting-side alert (store/metrics/notifications, keyed on the
// possibly-renamed RuleID).
//
// Invariant under test: for any alert that passed through Rego enrichment,
// the base name is recoverable; for an alert Rego evaluated but did not
// rename, the convention is explicit — no base_rule_id key, BaseRuleID()
// returns RuleID unchanged.

func newRegoEngineWithRule(t *testing.T, ruleBody string) *policy.RegoEngine {
	t.Helper()
	tmpDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "test.rego"), []byte(ruleBody), 0644))
	engine, err := policy.NewRegoEngine(policy.RegoEngineConfig{Enabled: true, RulesDir: tmpDir})
	require.NoError(t, err)
	return engine
}

func flushEventually(t *testing.T, ce *CorrelationEngine) []types.Alert {
	t.Helper()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if flushed := ce.Flush(); len(flushed) > 0 {
			return flushed
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no alert flushed within deadline")
	return nil
}

func TestBaseRuleID_RegoRenameIsRecoverable(t *testing.T) {
	regoEng := newRegoEngineWithRule(t, `
package ebpf_guard
default allow := true
decisions[{"rule_id": "dga_domain", "severity": "critical", "message": "renamed", "action": "alert", "matched": true}] {
	count(input.event.dns.qname) > 50
}
`)

	rule := Rule{
		ID:        "long_dns_query",
		EventType: types.EventDNS,
		Condition: RuleCondition{Field: "qname_length", Op: OpGreaterThan, Values: []string{"50"}},
		Severity:  types.SeverityWarning,
		Action:    ActionAlert,
	}

	cfg := DefaultCorrelationEngineConfig()
	cfg.Rules = []Rule{rule}
	cfg.EnableRateLimit = false
	cfg.EnableAnomaly = false
	cfg.EnableRegoEval = true
	cfg.RegoEngine = regoEng
	cfg.RegoWorkerCount = 2

	ce := NewCorrelationEngineWithConfig(cfg)
	defer ce.Close()

	longName := "a-very-long-subdomain-label-used-to-tunnel-data.example.com"
	require.Greater(t, len(longName), 50)

	ev := types.Event{
		Type: types.EventDNS,
		PID:  77,
		DNS:  &types.DNSEvent{QName: longName},
	}
	returned := ce.Ingest(context.Background(), ev)
	require.Len(t, returned, 1, "Ingest returns the pre-Rego alert synchronously")
	assert.Equal(t, "long_dns_query", returned[0].RuleID, "pre-Rego alert must still carry the base id")

	flushed := flushEventually(t, ce)
	require.Len(t, flushed, 1)

	alert := flushed[0]
	assert.Equal(t, "dga_domain", alert.RuleID, "Rego decision renames RuleID for reporting layers")
	assert.Equal(t, "long_dns_query", alert.Details[types.BaseRuleIDDetailsKey],
		"base_rule_id must carry the pre-rename id")
	assert.Equal(t, "long_dns_query", alert.BaseRuleID(),
		"BaseRuleID() must recover the suppression-axis identity after renaming")
}

func TestBaseRuleID_NoRegoDecisionLeavesNoKey(t *testing.T) {
	regoEng := newRegoEngineWithRule(t, `
package ebpf_guard
default allow := true
decisions[{"rule_id": "never_matches", "severity": "critical", "message": "m", "action": "alert", "matched": true}] {
	input.comm == "definitely-not-this-comm"
}
`)

	rule := Rule{
		ID:        "dns_rule",
		EventType: types.EventDNS,
		Condition: RuleCondition{Field: "qname", Op: OpEquals, Values: []string{"benign-but-long-enough-to-clear-the-prefilter-1234567890.example.com"}},
		Severity:  types.SeverityWarning,
		Action:    ActionAlert,
	}

	cfg := DefaultCorrelationEngineConfig()
	cfg.Rules = []Rule{rule}
	cfg.EnableRateLimit = false
	cfg.EnableAnomaly = false
	cfg.EnableRegoEval = true
	cfg.RegoEngine = regoEng
	cfg.RegoWorkerCount = 2

	ce := NewCorrelationEngineWithConfig(cfg)
	defer ce.Close()

	qname := "benign-but-long-enough-to-clear-the-prefilter-1234567890.example.com"
	require.Greater(t, len(qname), 50)

	ev := types.Event{
		Type: types.EventDNS,
		PID:  78,
		DNS:  &types.DNSEvent{QName: qname},
	}
	ce.Ingest(context.Background(), ev)

	flushed := flushEventually(t, ce)
	require.Len(t, flushed, 1)

	alert := flushed[0]
	assert.Equal(t, "dns_rule", alert.RuleID, "Rego evaluated but never matched: RuleID is unchanged")
	_, hasKey := alert.Details[types.BaseRuleIDDetailsKey]
	assert.False(t, hasKey, "convention: no base_rule_id key when Rego never renamed the alert")
	assert.Equal(t, "dns_rule", alert.BaseRuleID(), "BaseRuleID() falls back to RuleID when no key is present")
}
