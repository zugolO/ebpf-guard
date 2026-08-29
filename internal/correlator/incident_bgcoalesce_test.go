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

	// Every alert carries the same process tree — cron (root) running the
	// job through its own shell — so root identity (rootIdentity) resolves
	// consistently across the whole test regardless of which comm fired the
	// rule. This is the shape a real lineageTracker-backed event carries; it
	// is what let the 5.9.9.F.5d comm=sh alert below land in the identical
	// incidentKey as the plain "cron" ticks instead of forking a new one.
	cronRoot := func(leafComm string) []types.ProcessNode {
		return []types.ProcessNode{
			{PID: 1000, PPID: 1, Comm: "cron"},
			{PID: 4242, PPID: 1000, Comm: leafComm},
		}
	}

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
			a.ProcessTree = cronRoot("cron")
			tr.Add(a)
		}
	}

	// 5.9.9.F.5d (находка №158): today's actual composition additionally
	// includes drift_new_exec_critical firing on cron's own job shell
	// (comm=sh, severity critical) on the last tick — 4f gave this rule
	// critical severity on every exec, and sh is not in defaultTrustedComms.
	// Before the fix this alone flipped HasUntrustedSignal and forced the
	// plain 60s window on every following tick; it must still coalesce here.
	shAt := now.Add(4*tickPeriod).Add(2 * time.Millisecond)
	shAlert := makeAlertWithComm("r3", 4242, "prod", types.SeverityCritical, shAt, "sh")
	shAlert.ProcessTree = cronRoot("sh")
	tr.Add(shAlert)

	incidents := tr.GetAll("", "", 0)
	assert.Len(t, incidents, 1,
		"five cron minute-ticks plus the daemon's own sh exec must coalesce into one background incident")

	inc := incidents[0]
	// Nothing is hidden (пункт 8): every alert still accrued to the incident.
	assert.Equal(t, 11, inc.AlertCount, "all eleven alerts stay visible on the single incident")
	assert.False(t, inc.HasUntrustedSignal,
		"cron's own job shell (comm=sh) must not be treated as a foreign process — 5.9.9.F.5d variant 1")
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

// TestIncidentTracker_ContainerizedDaemon_CoalescesThroughShim is the 5.9.9.F.5j
// regression test for находка №160 (замер №2.9.9.F.4): five grafana incidents
// per snapshot, verdict "none", score 0, one alert each, on the same minute
// periodicity the cron case of 5.5d already coalesces. grafana IS in
// defaultTrustedComms, but the recorded tree is truncated at the container
// boundary, so RootComm is "containerd-shim" and the trusted-root condition of
// isPeriodicBackground rejected an incident every alert of which came from a
// trusted comm. Each tick minted a row, and those rows land in the denominator
// of the daemon-share criterion.
func TestIncidentTracker_ContainerizedDaemon_CoalescesThroughShim(t *testing.T) {
	tr := newIncidentTracker(60*time.Second, nil, scoringRules())

	shimRoot := func(leafComm string) []types.ProcessNode {
		return []types.ProcessNode{
			{PID: 900, PPID: 1, Comm: "containerd-shim"},
			{PID: 4242, PPID: 900, Comm: leafComm},
		}
	}

	const tickPeriod = 60*time.Second + 14*time.Millisecond
	now := time.Now()
	for tick := 0; tick < 5; tick++ {
		a := makeAlertWithComm("r1", 4242, "prod", types.SeverityWarning,
			now.Add(time.Duration(tick)*tickPeriod), "grafana")
		a.ProcessTree = shimRoot("grafana")
		tr.Add(a)
	}

	incidents := tr.GetAll("", "", 0)
	assert.Len(t, incidents, 1,
		"five minute-ticks of a trusted daemon behind a container shim must coalesce into one incident")
	assert.Equal(t, "containerd-shim", incidents[0].RootComm,
		"the reported root is unchanged — only the trusted-root test looks through the shim")
	assert.Equal(t, 5, incidents[0].AlertCount, "no alert is hidden by the coalescing")
}

// TestIncidentTracker_AttackBehindShim_DoesNotCoalesce is the other side of
// 5.9.9.F.5j: the shim pass-through must not become a blanket trust of anything
// rooted at containerd-shim. An untrusted process behind the shim is exactly the
// containerised-attack case, and it must keep the plain 60s window.
func TestIncidentTracker_AttackBehindShim_DoesNotCoalesce(t *testing.T) {
	tr := newIncidentTracker(60*time.Second, nil, scoringRules())

	shimRoot := []types.ProcessNode{
		{PID: 900, PPID: 1, Comm: "containerd-shim"},
		{PID: 4242, PPID: 900, Comm: "xmrig"},
	}

	now := time.Now()
	a1 := makeAlertWithComm("r1", 4242, "prod", types.SeverityWarning, now, "xmrig")
	a1.ProcessTree = shimRoot
	tr.Add(a1)

	require.True(t, tr.GetAll("", "", 0)[0].HasUntrustedSignal,
		"an untrusted comm behind the shim must mark the incident untrusted")

	a2 := makeAlertWithComm("r2", 4242, "prod", types.SeverityCritical,
		now.Add(90*time.Second), "xmrig")
	a2.ProcessTree = shimRoot
	tr.Add(a2)

	assert.Len(t, tr.GetAll("", "", 0), 2,
		"containerised attack keeps the normal window — the shim never trusts what sits behind it")
}

// TestIncidentTracker_ShimWithoutChain_StaysUntrustedRooted pins the guard that
// keeps the pass-through from firing on a tree that was never recorded: RootComm
// can fall back to the alert's own comm, in which case ProcessChain says nothing
// about what runs behind the shim and the incident must not be read as trusted.
func TestIncidentTracker_ShimWithoutChain_StaysUntrustedRooted(t *testing.T) {
	tr := newIncidentTracker(60*time.Second, nil, scoringRules())

	now := time.Now()
	// No ProcessTree at all: RootComm degrades to the alert comm.
	tr.Add(makeAlertWithComm("r1", 4242, "prod", types.SeverityWarning, now, "containerd-shim"))
	tr.Add(makeAlertWithComm("r2", 4242, "prod", types.SeverityWarning,
		now.Add(90*time.Second), "containerd-shim"))

	assert.Len(t, tr.GetAll("", "", 0), 2,
		"a chain-less shim-rooted incident is not background: nothing proves a trusted process is behind it")
}
