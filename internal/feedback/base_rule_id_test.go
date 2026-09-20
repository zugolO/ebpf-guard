package feedback

import (
	"testing"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Wave 6.3-rid, №401: FilterAlerts runs downstream of evaluateRegoPolicies, so
// a renamed alert arrives carrying the Rego decision's rule_id. A suppression
// an analyst recorded against the YAML rule that actually fired must still
// apply — otherwise the named exception can never match anything once Rego is
// live, which is exactly what the finding measured.
func TestFilterAlerts_MatchesSuppressionOnBaseRuleID(t *testing.T) {
	renamed := types.Alert{
		RuleID: "long_dns_query",
		Comm:   "curl",
		Details: map[string]interface{}{
			types.BaseRuleIDDetailsKey: "dns_tunneling_long_domain",
		},
	}

	t.Run("suppression on the base name applies to the renamed alert", func(t *testing.T) {
		m := NewManager("", nil)
		base := types.Alert{RuleID: "dns_tunneling_long_domain", Comm: "curl"}
		if _, err := m.Submit(base, VerdictFalsePositive, "analyst"); err != nil {
			t.Fatalf("Submit: %v", err)
		}
		if got := m.FilterAlerts([]types.Alert{renamed}); len(got) != 0 {
			t.Fatalf("renamed alert survived a suppression on its base rule_id: %+v", got)
		}
	})

	t.Run("suppression on the renamed name still applies", func(t *testing.T) {
		m := NewManager("", nil)
		if _, err := m.Submit(renamed, VerdictFalsePositive, "analyst"); err != nil {
			t.Fatalf("Submit: %v", err)
		}
		if got := m.FilterAlerts([]types.Alert{renamed}); len(got) != 0 {
			t.Fatalf("renamed alert survived a suppression on its own rule_id: %+v", got)
		}
	})

	t.Run("a different comm is not suppressed by either name", func(t *testing.T) {
		m := NewManager("", nil)
		base := types.Alert{RuleID: "dns_tunneling_long_domain", Comm: "curl"}
		if _, err := m.Submit(base, VerdictFalsePositive, "analyst"); err != nil {
			t.Fatalf("Submit: %v", err)
		}
		other := renamed
		other.Comm = "dig"
		if got := m.FilterAlerts([]types.Alert{other}); len(got) != 1 {
			t.Fatalf("suppression leaked across comm: %+v", got)
		}
	})

	t.Run("an alert Rego never renamed is unaffected", func(t *testing.T) {
		m := NewManager("", nil)
		plain := types.Alert{RuleID: "dns_tunneling_long_domain", Comm: "curl"}
		if got := m.FilterAlerts([]types.Alert{plain}); len(got) != 1 {
			t.Fatalf("un-renamed alert dropped without any suppression: %+v", got)
		}
	})
}
