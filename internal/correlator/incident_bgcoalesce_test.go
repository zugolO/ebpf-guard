package correlator

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// TestIncidentTracker_CronTick_CoalescesIntoOneIncident is the 5.5d regression
// test for находка №9 (замер №2.1). The tracker window is 60s and a cron minute
// tick lands exactly 60s after the previous one, so `ts.Sub(LastSeen) > window`
// fired on every tick: the same long-lived daemon (root_pid 160579 for the whole
// measurement) minted a fresh incident once a minute, each lasting <1s. With a
// 5-minute retention that is a standing population of exactly five cron
// incidents in every snapshot of /api/v1/incidents — which is what criterion 9
// of run-gate.sh counts, making the daemon share a structural constant no
// scoring change could move.
func TestIncidentTracker_CronTick_CoalescesIntoOneIncident(t *testing.T) {
	tr := newIncidentTracker(60*time.Second, nil, scoringRules())

	now := time.Now()
	// Five minute-ticks — the замер №2.1 pattern (20:40:01.111, 20:41:01.125,
	// … 20:44:01.159). The tick period is a whisker OVER 60s there, and that
	// detail is the whole bug: the reopen check is `> window`, so a gap of
	// exactly 60s would still group. Each tick is a burst of two alerts a
	// millisecond apart, so the gap between the LAST alert of one tick and the
	// first of the next is what must exceed the window — hence the explicit
	// per-tick base rather than a round multiple.
	const tickPeriod = 60*time.Second + 14*time.Millisecond
	for tick := 0; tick < 5; tick++ {
		at := now.Add(time.Duration(tick) * tickPeriod)
		for i, id := range []string{"r1", "r2"} {
			a := makeAlertWithComm(id, 4242, "prod", types.SeverityWarning,
				at.Add(time.Duration(i)*time.Millisecond), "cron")
			tr.Add(a)
		}
	}

	incidents := tr.GetAll("", "", 0)
	assert.Len(t, incidents, 1,
		"five cron minute-ticks must coalesce into one background incident, not five siblings")

	inc := incidents[0]
	// Nothing is hidden (пункт 8): every alert still accrued to the incident.
	assert.Equal(t, 10, inc.AlertCount, "all ten alerts stay visible on the single incident")
	assert.NotEqual(t, types.VerdictAttack, inc.Verdict,
		"pure cron background must not promote to attack")
}

// TestIncidentTracker_CronTick_StatusStaysOpenBetweenTicks guards the API-facing
// half of 5.5d: the reported status must follow the window that actually governs
// grouping, otherwise a coalescing incident reads "closed" while still accepting
// alerts into the same entry.
func TestIncidentTracker_CronTick_StatusStaysOpenBetweenTicks(t *testing.T) {
	tr := newIncidentTracker(60*time.Second, nil, scoringRules())

	now := time.Now().Add(-90 * time.Second)
	tr.Add(makeAlertWithComm("r1", 4242, "prod", types.SeverityWarning, now, "cron"))

	// 90s after the last alert: past the plain 60s window, inside the extended
	// background window.
	incidents := tr.GetAll("", "", 0)
	require.Len(t, incidents, 1)
	assert.Equal(t, "open", incidents[0].Status,
		"periodic background stays open for the window that governs its grouping")
}

// TestIncidentTracker_AttackInDaemon_DoesNotCoalesce is the other side of 5.5d,
// and the one that matters for detection: the extended window must apply only
// while the incident is *background on every dimension*. As soon as an untrusted
// comm appears in a cron-rooted incident, it stops qualifying and the normal 60s
// window governs again — an attacker running out of cron must not be swallowed
// into a 5-minute background bucket.
func TestIncidentTracker_AttackInDaemon_DoesNotCoalesce(t *testing.T) {
	tr := newIncidentTracker(60*time.Second, nil, scoringRules())

	now := time.Now()
	// A cron-rooted tree with an untrusted child. The explicit ProcessTree
	// pins the incident key to the cron root (rootIdentity keys on the tree's
	// root, so the leaf comm can differ between alerts without splitting the
	// incident) — this is the shape 5.5d must stop treating as background the
	// moment xmrig appears in it.
	cronRoot := func(leafComm string) []types.ProcessNode {
		return []types.ProcessNode{
			{PID: 1000, PPID: 1, Comm: "cron"},
			{PID: 4242, PPID: 1000, Comm: leafComm},
		}
	}
	a1 := makeAlertWithComm("r1", 4242, "prod", types.SeverityWarning, now, "cron")
	a1.ProcessTree = cronRoot("cron")
	tr.Add(a1)

	a2 := makeAlertWithComm("r2", 4242, "prod", types.SeverityCritical,
		now.Add(time.Second), "xmrig")
	a2.ProcessTree = cronRoot("xmrig")
	tr.Add(a2)

	first := tr.GetAll("", "", 0)
	require.Len(t, first, 1, "both alerts share a PID and must be one incident")
	require.Equal(t, "cron", first[0].RootComm, "incident is rooted at the trusted daemon")
	require.True(t, first[0].HasUntrustedSignal, "xmrig must mark the incident untrusted")

	// A later alert past the plain 60s window must open a NEW incident: the
	// untrusted signal disqualified the extended background window.
	a3 := makeAlertWithComm("r3", 4242, "prod", types.SeverityCritical,
		now.Add(90*time.Second), "xmrig")
	a3.ProcessTree = cronRoot("xmrig")
	tr.Add(a3)

	incidents := tr.GetAll("", "", 0)
	assert.Len(t, incidents, 2,
		"once an untrusted comm appears, the normal window applies again — an attack in a daemon must not coalesce")
}

// TestIncidentTracker_DaemonWithRealCluster_DoesNotCoalesce covers the third
// disqualifier: a daemon that genuinely trips minUniqueRulesForScore distinct
// non-info rules is a real cluster, not background, even with no untrusted comm
// and no network signal.
func TestIncidentTracker_DaemonWithRealCluster_DoesNotCoalesce(t *testing.T) {
	tr := newIncidentTracker(60*time.Second, nil, scoringRules())

	now := time.Now()
	for i, id := range []string{"r1", "r2", "r3", "r4", "r5"} {
		tr.Add(makeAlertWithComm(id, 4242, "prod", types.SeverityWarning,
			now.Add(time.Duration(i)*time.Second), "cron"))
	}

	tr.Add(makeAlertWithComm("r1", 4242, "prod", types.SeverityWarning,
		now.Add(90*time.Second), "cron"))

	incidents := tr.GetAll("", "", 0)
	assert.Len(t, incidents, 2,
		"a daemon incident that reached the scoring threshold is not background and uses the normal window")
}
