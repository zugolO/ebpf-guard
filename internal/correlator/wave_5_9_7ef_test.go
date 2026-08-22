package correlator_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// TestWave597e_SSHLoginDoesNotAlert is the regression test for находка №81/№82
// (plan.md 5.9.7e): a routine sshd pubkey-auth login opens (never writes)
// authorized_keys, and the rules must not mistake that for a backdoor key
// drop or credential-directory recon.
func TestWave597e_SSHLoginDoesNotAlert(t *testing.T) {
	catalog, err := correlator.LoadRulesFromDir("../../rules")
	require.NoError(t, err)
	engine := correlator.NewRuleEngine(catalog)

	const opOpen = 0 // fileOpNames[0] == "open"

	sshdOpen := p117FileEvent(4242, "sshd", "/root/.ssh/authorized_keys", opOpen)
	alerts := engine.Evaluate(sshdOpen)
	for _, a := range alerts {
		assert.NotEqual(t, "rootkit_ssh_authorized_keys_modified", a.RuleID,
			"sshd opening (not writing) authorized_keys must not trip the backdoor-key rule")
		assert.NotEqual(t, "sigma_sensitive_dir_listing", a.RuleID,
			"sshd's own login access under /root/.ssh/ must not trip the credential-recon rule")
	}
}

// TestWave597e_ForeignWriteAlerts verifies the rules did not go blind while
// fixing the ssh-login false positive: a write by anyone other than sshd
// still fires rootkit_ssh_authorized_keys_modified, and a directory listing
// by anyone other than sshd (or outside /root/.ssh/) still fires
// sigma_sensitive_dir_listing.
func TestWave597e_ForeignWriteAlerts(t *testing.T) {
	const opOpen = 0
	const opWrite = 2

	t.Run("write by non-sshd process still fires the backdoor-key rule", func(t *testing.T) {
		rules, err := correlator.LoadRulesFromFile("../../rules/rootkit-detection.yaml")
		require.NoError(t, err)
		var target *correlator.Rule
		for i := range rules {
			if rules[i].ID == "rootkit_ssh_authorized_keys_modified" {
				target = &rules[i]
			}
		}
		require.NotNil(t, target, "rootkit_ssh_authorized_keys_modified not found")
		engine := correlator.NewRuleEngine([]correlator.Rule{*target})

		write := p117FileEvent(4242, "attacker", "/root/.ssh/authorized_keys", opWrite)
		assert.NotEmpty(t, engine.Evaluate(write),
			"a write to authorized_keys by a non-sshd process must still alert")

		// A bare open (no write) from a non-sshd process must not fire either —
		// the rule now requires op=write regardless of comm.
		open := p117FileEvent(4242, "cat", "/root/.ssh/authorized_keys", opOpen)
		assert.Empty(t, engine.Evaluate(open),
			"op=write is required; a bare open from any comm must not fire the rule now")
	})

	t.Run("sshd outside /root/.ssh/ still fires the dir-listing rule", func(t *testing.T) {
		rules, err := correlator.LoadRulesFromFile("../../rules/sigma-linux.yaml")
		require.NoError(t, err)
		var target *correlator.Rule
		for i := range rules {
			if rules[i].ID == "sigma_sensitive_dir_listing" {
				target = &rules[i]
			}
		}
		require.NotNil(t, target, "sigma_sensitive_dir_listing not found")
		engine := correlator.NewRuleEngine([]correlator.Rule{*target})

		assert.NotEmpty(t, engine.Evaluate(p117FileEvent(4242, "sshd", "/root/.aws/credentials", opOpen)),
			"the sshd exception is scoped to /root/.ssh/ only; other credential dirs must still alert")
		assert.NotEmpty(t, engine.Evaluate(p117FileEvent(4242, "nc", "/root/.ssh/id_rsa", opOpen)),
			"a non-sshd process reading /root/.ssh/ must still alert")
	})
}

// TestWave597f_DNSAlertCarriesQName is the regression test for находка №83
// (plan.md 5.9.7f): a DNS alert's Details must carry the query name and the
// longest single label, so a long-label alert can be judged from the alert
// record alone rather than a since-rotated collector log.
func TestWave597f_DNSAlertCarriesQName(t *testing.T) {
	rule := correlator.Rule{
		ID:        "test_dns_long_label",
		Name:      "test",
		EventType: types.EventDNS,
		Condition: correlator.RuleCondition{
			Field:  "qname_length",
			Op:     correlator.OpGreaterThan,
			Values: []string{"50"},
		},
		Severity: types.SeverityCritical,
		Action:   correlator.ActionAlert,
	}
	engine := correlator.NewRuleEngine([]correlator.Rule{rule})

	qname := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com"
	event := types.Event{
		Type: types.EventDNS,
		DNS:  &types.DNSEvent{QName: qname},
	}

	alerts := engine.Evaluate(event)
	require.Len(t, alerts, 1)
	require.NotNil(t, alerts[0].Details)
	assert.Equal(t, qname, alerts[0].Details["dns.qname"])
	assert.Equal(t, 60, alerts[0].Details["dns.max_label_len"],
		"the leftmost label (60 a's) is the longest of the two labels")
}
