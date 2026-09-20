package exporter

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// Wave 6.3-rid, метка 6.3r.2: the metric half of "the base name travels".
// The store keeps details.base_rule_id (pkg/types), and this series is what
// makes the same pair readable in /metrics, so the limiter cut (keyed on the
// pre-Rego name) can be joined to the volume of the alert (keyed on the
// renamed one).
func TestRecordAlertRuleIDRename(t *testing.T) {
	AlertRuleIDRenamed.Reset()

	RecordAlertRuleIDRename("dns_tunneling_long_domain", "long_dns_query")
	RecordAlertRuleIDRename("dns_tunneling_long_domain", "long_dns_query")
	RecordAlertRuleIDRename("dns_dga_ngram", "dga_domain")

	if got := testutil.ToFloat64(AlertRuleIDRenamed.WithLabelValues("dns_tunneling_long_domain", "long_dns_query")); got != 2 {
		t.Fatalf("renamed pair counted %v, want 2", got)
	}
	if got := testutil.ToFloat64(AlertRuleIDRenamed.WithLabelValues("dns_dga_ngram", "dga_domain")); got != 1 {
		t.Fatalf("second renamed pair counted %v, want 1", got)
	}

	// The emitter in run-6.3-pipeline.sh greps /metrics for the literal
	// `base_rule_id=` — the label name is part of the contract, not an
	// implementation detail (память metric-anchor-must-carry-full-series-name).
	out, err := testutil.CollectAndLint(AlertRuleIDRenamed)
	if err != nil {
		t.Fatalf("lint: %v", err)
	}
	for _, p := range out {
		t.Logf("lint: %s: %s", p.Metric, p.Text)
	}
	dump := metricDump(t)
	if !strings.Contains(dump, `ebpf_guard_alert_rule_id_renamed_total{base_rule_id="dns_dga_ngram",rule_id="dga_domain"}`) {
		t.Fatalf("series not exposed with both labels; got:\n%s", dump)
	}
}

func metricDump(t *testing.T) string {
	t.Helper()
	var sb strings.Builder
	if err := testutil.CollectAndCompare(AlertRuleIDRenamed, strings.NewReader("")); err != nil {
		// CollectAndCompare against an empty expectation always fails; its
		// error text carries the rendered exposition, which is what we want
		// to assert the label spelling on.
		sb.WriteString(err.Error())
	}
	return sb.String()
}
