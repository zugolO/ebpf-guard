package correlator

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// TestIncidentTracker_InfoAlertsAlone_DoesNotPromote is the 5.5a regression
// test for находка №8 (замер №2.1): FilterAlertsForIntake sits in
// dispatchAlerts, downstream of IncidentTracker, so an info-only burst from a
// trusted daemon (cron reading its spool through seven downgraded *_daemon
// rules) still reached the scorer with its full RuleIDs/SourceEvents set and
// crossed minUniqueRulesForScore on info alerts alone — 5 of 6 daemon
// incidents in that measurement had no non-info alert behind them at all.
func TestIncidentTracker_InfoAlertsAlone_DoesNotPromote(t *testing.T) {
	tr := newIncidentTracker(60*time.Second, nil, scoringRules())

	now := time.Now()
	for i, id := range []string{"r1", "r2", "r3", "r4", "r5"} {
		a := makeAlertWithComm(id, 4242, "prod", types.SeverityInfo,
			now.Add(time.Duration(i)*time.Second), "cron")
		tr.Add(a)
	}

	incidents := tr.GetAll("", "", 0)
	require.Len(t, incidents, 1)
	inc := incidents[0]

	// Visibility (п. 8) is untouched: all five rules and alerts are still on
	// the incident even though none of them could score it.
	assert.Len(t, inc.RuleIDs, 5, "info alerts must stay visible in RuleIDs")
	assert.Equal(t, 5, inc.AlertCount, "info alerts must stay visible in AlertCount")
	assert.NotEqual(t, types.VerdictAttack, inc.Verdict,
		"a cron burst made entirely of info alerts must not score high enough to promote")
	assert.Zero(t, inc.Score, "info alerts must contribute nothing to score")

	// 5.7e (находка №17): an all-info incident must report an explicit verdict
	// and severity, not the empty string a fresh Incident zero-values to — an
	// empty JSON field is indistinguishable from "scoring never ran".
	assert.Equal(t, types.VerdictNone, inc.Verdict,
		"an all-info incident must report verdict=none, not an empty string")
	assert.Equal(t, types.SeverityInfo, inc.Severity,
		"the first info alert must not lose its severity to the incident's zero value on a rank tie")
}

// TestIncidentTracker_InfoAlerts_DoNotBlockRealCluster is the other side of
// 5.5a: a genuine non-info cluster (sensitive_file_read fired at warning by
// the same cron burst, e.g.) must still be able to promote the incident even
// while info alerts from the same process continue to arrive alongside it —
// the fix must filter info out of scoring, not disable scoring for any
// incident that happens to contain an info alert.
func TestIncidentTracker_InfoAlerts_DoNotBlockRealCluster(t *testing.T) {
	tr := newIncidentTracker(60*time.Second, nil, scoringRules())

	now := time.Now()
	// Five info alerts riding on the same process — noise, per 5.5a must not
	// score, but must stay grouped with what follows since it is the same comm.
	for i, id := range []string{"r1", "r2", "r3", "r4", "r5"} {
		a := makeAlertWithComm(id, 4242, "prod", types.SeverityInfo,
			now.Add(time.Duration(i)*time.Second), "xmrig")
		tr.Add(a)
	}
	// A genuine untrusted signal from the same process: five distinct
	// non-info rules across distinct source events.
	for i, id := range []string{"r1", "r2", "r3", "r4", "r5"} {
		a := makeAlertWithComm(id, 4242, "prod", types.SeverityCritical,
			now.Add(time.Duration(10+i)*time.Second), "xmrig")
		tr.Add(a)
	}

	incidents := tr.GetAll("", "", 0)
	require.Len(t, incidents, 1)
	inc := incidents[0]

	assert.Len(t, inc.RuleIDs, 5, "rule IDs are deduped across info+non-info hits, still visible")
	assert.Equal(t, 10, inc.AlertCount, "all ten alerts, info and non-info, stay visible")
	assert.Equal(t, types.VerdictAttack, inc.Verdict,
		"a real non-info cluster must still promote even with info alerts mixed into the same incident")
}
