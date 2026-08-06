// Package exporter provides Prometheus metrics and Alertmanager alerting.
package exporter

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// TestFilterAlertsForIntake_InfoHeldBackFromCounterAndStore is the wave-5.1a
// regression test.
//
// Wave 5.1 downgraded the seven-rule daemon cluster to info expecting the idle
// alert rate to fall. It did not move (4986/hour against a <1000 target,
// plan.md "Замер 5.1 на стенде") because alerts_total counts every alert
// regardless of severity — a severity change relabels volume, it does not
// reduce it. This pins the fix: below-threshold alerts leave the intake stream
// entirely, and the volume they represent stays visible on a separate counter
// rather than vanishing.
func TestFilterAlertsForIntake_InfoHeldBackFromCounterAndStore(t *testing.T) {
	AlertsFiltered.Reset()

	alerts := []types.Alert{
		{RuleID: "sigma_passwd_shadow_read_daemon", Severity: types.SeverityInfo},
		{RuleID: "sigma_log_deletion_daemon", Severity: types.SeverityInfo},
		{RuleID: "webshell_script_write_via_web_process", Severity: types.SeverityWarning},
		{RuleID: "container_escape_init_proc", Severity: types.SeverityCritical},
	}

	admitted := FilterAlertsForIntake(alerts, types.SeverityWarning)

	// Only the two info alerts are held back; warning and critical still reach
	// alerts_total and the store. Asserting the admitted set by rule_id rather
	// than by count: a filter that dropped everything would satisfy a bare
	// "fewer alerts" check while destroying detection.
	require.Len(t, admitted, 2)
	admittedIDs := []string{admitted[0].RuleID, admitted[1].RuleID}
	assert.ElementsMatch(t,
		[]string{"webshell_script_write_via_web_process", "container_escape_init_proc"},
		admittedIDs)

	// The suppressed volume is attributable, not merely absent. This is what
	// keeps the filter distinguishable from detection silently stopping — the
	// rules are still loaded and still firing (порядок работы, п. 8).
	assert.Equal(t, 1.0, testutil.ToFloat64(
		AlertsFiltered.WithLabelValues("sigma_passwd_shadow_read_daemon", "info")))
	assert.Equal(t, 1.0, testutil.ToFloat64(
		AlertsFiltered.WithLabelValues("sigma_log_deletion_daemon", "info")))
}

// TestFilterAlertsForIntake_DefaultAdmitsEverything pins the other side: the
// default configuration must behave exactly as it did before wave 5.1a, so
// upgrading an agent cannot start dropping a severity tier by surprise.
func TestFilterAlertsForIntake_DefaultAdmitsEverything(t *testing.T) {
	AlertsFiltered.Reset()

	alerts := []types.Alert{
		{RuleID: "sigma_log_deletion_daemon", Severity: types.SeverityInfo},
		{RuleID: "container_escape_init_proc", Severity: types.SeverityCritical},
	}

	admitted := FilterAlertsForIntake(alerts, types.SeverityInfo)

	require.Len(t, admitted, 2)
	assert.Equal(t, 0.0, testutil.ToFloat64(
		AlertsFiltered.WithLabelValues("sigma_log_deletion_daemon", "info")),
		"nothing may be counted as filtered when the threshold admits everything")
}

// TestFilterAlertsForIntake_CriticalThresholdKeepsCritical guards the strictest
// setting: at min_severity=critical the warning tier goes too, but critical
// must survive. Without this, a rank comparison written with the wrong operator
// would pass the info test above and still discard every real detection.
func TestFilterAlertsForIntake_CriticalThresholdKeepsCritical(t *testing.T) {
	AlertsFiltered.Reset()

	alerts := []types.Alert{
		{RuleID: "sigma_log_deletion_daemon", Severity: types.SeverityInfo},
		{RuleID: "webshell_script_write_via_web_process", Severity: types.SeverityWarning},
		{RuleID: "container_escape_init_proc", Severity: types.SeverityCritical},
	}

	admitted := FilterAlertsForIntake(alerts, types.SeverityCritical)

	require.Len(t, admitted, 1)
	assert.Equal(t, "container_escape_init_proc", admitted[0].RuleID)
	assert.Equal(t, 1.0, testutil.ToFloat64(
		AlertsFiltered.WithLabelValues("webshell_script_write_via_web_process", "warning")))
}

// TestFilterAlertsForIntake_UnknownSeverityTreatedAsInfo documents the
// deliberate consequence of types.SeverityRank ranking unknown values as info:
// a typo in a rule's severity is filtered rather than admitted. That is the
// safe direction for THIS filter's neighbour (an unknown severity never pages
// as if it were critical, wave 5.1), but it means a misspelled severity makes a
// rule's alerts vanish from the store — recorded here so the behaviour is a
// decision on record rather than a surprise during an incident.
func TestFilterAlertsForIntake_UnknownSeverityTreatedAsInfo(t *testing.T) {
	AlertsFiltered.Reset()

	alerts := []types.Alert{{RuleID: "rule_with_typo", Severity: types.Severity("crticial")}}

	admitted := FilterAlertsForIntake(alerts, types.SeverityWarning)

	assert.Empty(t, admitted)
	assert.Equal(t, 1.0, testutil.ToFloat64(
		AlertsFiltered.WithLabelValues("rule_with_typo", "crticial")),
		"a misspelled severity must at least be visible on the filtered counter")
}
