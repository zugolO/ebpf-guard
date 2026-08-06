package correlator

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// TestIncidentTracker_TrustGate_SshdSingleEventStaysNonAttack is the P1-13
// regression test for the production shape that produced 102 of 114 false
// "confirmed attacks": sshd reading /etc/passwd at login trips five
// filename-keyed rules (appexploit_lfi_passwd_access, appexploit_xxe_file_read,
// owasp_web_sensitive_file_read, sigma_passwd_shadow_read,
// sigma_sensitive_file_chmod) from a single kernel event, one PID, one
// nanosecond-precision timestamp.
//
// Before this fix: 5 distinct rule IDs >= minUniqueRulesForScore alone crossed
// the attack threshold. After: the unique-rules signal is capped at the number
// of distinct source events (1, not 5), and even if score still qualified,
// sshd is a trusted comm with no network signal, so promotion is refused.
func TestIncidentTracker_TrustGate_SshdSingleEventStaysNonAttack(t *testing.T) {
	tr := newIncidentTracker(60*time.Second, nil, scoringRules())

	ts := time.Now()
	for _, id := range []string{"r1", "r2", "r3", "r4", "r5"} {
		a := makeAlertWithComm(id, 4242, "prod", types.SeverityCritical, ts, "sshd")
		tr.Add(a)
	}

	incidents := tr.GetAll("", "", 0)
	require.Len(t, incidents, 1)
	inc := incidents[0]
	assert.NotEqual(t, types.VerdictAttack, inc.Verdict,
		"single sshd event fanned out across 5 rules must not confirm an attack")
}

// TestIncidentTracker_TrustGate_UntrustedCommStillPromotes ensures the trust
// gate is a targeted fix, not a global scoring nerf: the same rule/tactic/
// severity shape from an untrusted process across genuinely distinct source
// events still reaches "attack".
func TestIncidentTracker_TrustGate_UntrustedCommStillPromotes(t *testing.T) {
	tr := newIncidentTracker(60*time.Second, nil, scoringRules())

	now := time.Now()
	for i, id := range []string{"r1", "r2", "r3", "r4", "r5"} {
		a := makeAlertWithComm(id, 9999, "prod", types.SeverityCritical,
			now.Add(time.Duration(i)*time.Second), "xmrig")
		tr.Add(a)
	}

	incidents := tr.GetAll("", "", 0)
	require.Len(t, incidents, 1)
	assert.Equal(t, types.VerdictAttack, incidents[0].Verdict,
		"distinct source events from an untrusted process must still confirm an attack")
}

// TestIncidentTracker_TrustGate_TrustedCommWithNetworkSignalPromotes verifies
// the escape hatch: even a trusted comm (sshd) can confirm an attack if a
// network-observable event corroborates it — e.g. sshd making an unexpected
// outbound connection is not "reading /etc/passwd at login" anymore.
func TestIncidentTracker_TrustGate_TrustedCommWithNetworkSignalPromotes(t *testing.T) {
	tr := newIncidentTracker(60*time.Second, nil, scoringRules())

	now := time.Now()
	for i, id := range []string{"r1", "r2", "r3", "r4"} {
		a := makeAlertWithComm(id, 4242, "prod", types.SeverityCritical,
			now.Add(time.Duration(i)*time.Second), "sshd")
		tr.Add(a)
	}
	netAlert := makeAlertWithComm("r5", 4242, "prod", types.SeverityCritical,
		now.Add(4*time.Second), "sshd")
	netAlert.Event.Type = types.EventTCPConnect
	tr.Add(netAlert)

	incidents := tr.GetAll("", "", 0)
	require.Len(t, incidents, 1)
	assert.Equal(t, types.VerdictAttack, incidents[0].Verdict,
		"a network signal must let a trusted-comm incident still confirm as attack")
}

// TestEngine_IncidentTrustedComms_ConfigOverride pins the wave-3 wiring of
// correlator.trusted_comms. Before it, SetTrustedComms had no caller at all and
// the {sshd, cron} set was effectively hardcoded — which daemons are background
// noise is deployment-specific, so tuning the trust gate required a rebuild.
//
// Both directions are asserted: a configured comm gains the gate's protection,
// and a default-trusted comm that is NOT in the override loses it. The second
// half is what makes this an override rather than an addition.
func TestEngine_IncidentTrustedComms_ConfigOverride(t *testing.T) {
	cfg := DefaultCorrelationEngineConfig()
	cfg.Rules = scoringRules()
	cfg.IncidentTrustedComms = []string{"my-daemon"}

	ce := NewCorrelationEngineWithConfig(cfg)
	defer ce.Close()

	tr := ce.incidentTracker
	ts := time.Now()

	// The configured comm is trusted: one event fanned across 5 rules must
	// not confirm, exactly as sshd does under the default set.
	for _, id := range []string{"r1", "r2", "r3", "r4", "r5"} {
		tr.Add(makeAlertWithComm(id, 4242, "prod", types.SeverityCritical, ts, "my-daemon"))
	}

	// sshd is trusted by default but absent from the override, so it must now
	// behave like any other untrusted process across distinct source events.
	for i, id := range []string{"r1", "r2", "r3", "r4", "r5"} {
		tr.Add(makeAlertWithComm(id, 9999, "prod", types.SeverityCritical,
			ts.Add(time.Duration(i)*time.Second), "sshd"))
	}

	byPID := make(map[uint32]types.Incident)
	for _, inc := range tr.GetAll("", "", 0) {
		byPID[inc.RootPID] = inc
	}

	configured, ok := byPID[4242]
	require.True(t, ok, "incident for the configured trusted comm not found")
	assert.NotEqual(t, types.VerdictAttack, configured.Verdict,
		"comm listed in correlator.trusted_comms must get the trust gate")

	replaced, ok := byPID[9999]
	require.True(t, ok, "incident for sshd not found")
	assert.Equal(t, types.VerdictAttack, replaced.Verdict,
		"the config replaces the default set; sshd is not in it and must no longer be gated")
}
