package correlator_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zugolO/ebpf-guard/internal/canary"
	"github.com/zugolO/ebpf-guard/internal/correlator"
)

// catalogWithCanaryRules mirrors main.go's startup sequence: the static
// rules/ catalog plus the canary manager's dynamically generated per-path
// rules (canary_001, canary_002, ...), which never live in a YAML file.
func catalogWithCanaryRules(t *testing.T) []correlator.Rule {
	t.Helper()
	rules := loadStage1Rules(t)
	mgr := canary.New(canary.Config{
		Enabled:       true,
		AlertSeverity: "critical",
		Files:         canary.DefaultFiles,
	})
	return append(rules, mgr.Rules()...)
}

// TestP1_17_SelfTraffic_NoAlertOnRealPaths is the "reverse-direction" test
// called for in the P1-17 remainder (see plan.md, section "P1-17 (остаток)").
//
// TestP1_17_SelfExclusion (p1_17_self_exclusion_test.go) checks the paths that
// were *written into* each ebpf-guard-self exception — by construction it can
// never catch a path the agent touches but nobody enumerated. That is exactly
// what happened on the stand: cred_proc_maps_mass_read and
// mitre_sandbox_detect_proc_read already carry ebpf-guard-self exceptions
// (docs/p1-17-self-exclusion.md) and still fired 79+68 times over a 2h idle
// run, because the agent reads /proc paths that were never listed.
//
// This test flips the direction: start from the real paths the agent's own
// code opens (config, rules, state persistence, SQLite, canary files, audit
// logs — enumerated below from internal/config defaults and the packages that
// write them) and assert that none of them, under comm=ebpf-guard and the
// agent's own PID, trip *any* rule in the full catalog. Extending an
// exception list only fixes the specific path added to it; this test is meant
// to fail the moment a new self-touched path collides with a new or existing
// rule, without anyone having to notice it in production alert volume first.
func TestP1_17_SelfTraffic_NoAlertOnRealPaths(t *testing.T) {
	rules := catalogWithCanaryRules(t)
	engine := correlator.NewRuleEngine(rules)
	selfPID := uint32(os.Getpid()) /* #nosec G115 -- test PID fits uint32 */

	// Real paths the agent's own process opens during normal operation.
	// Source: internal/config/config.go defaults, internal/canary.DefaultFiles,
	// internal/audit (rule-audit + enforcement audit logs), internal/store
	// (SQLite + WAL/journal siblings), internal/profiler (state persistence).
	selfPaths := []string{
		// store.sqlite.path and its WAL/journal siblings (config.go:2070)
		"/var/lib/ebpf-guard/events.db",
		"/var/lib/ebpf-guard/events.db-wal",
		"/var/lib/ebpf-guard/events.db-shm",
		"/var/lib/ebpf-guard/events.db-journal",
		// profiler.state_persistence.path (config.go:2000)
		"/var/lib/ebpf-guard/profiler-state.json",
		// event_log.path (config.go:2205)
		"/var/lib/ebpf-guard/events.jsonl",
		// audit.path — rule-load/hot-reload audit (config.go:2240)
		"/var/log/ebpf-guard/audit.jsonl",
		// rules dir + local tuning overlay (config.yaml, config.go:1958)
		"/opt/ebpf-guard/rules/local-tuning.yaml",
		"/opt/ebpf-guard/rules/checksums.sha256",
		// bearer token file (main.go writeTokenFile)
		"/run/ebpf-guard/token",
		// canary lure files the verification loop reads every VerifyInterval
		"/etc/shadow.canary",
		"/tmp/.secret_key",
		"/var/run/.admin_socket",
		"/root/.ssh/id_rsa.canary",
		"/etc/passwd.canary",
		// self-identification reads (cgroup/uptime, already exempted — kept
		// here so a regression on the exception itself is caught too)
		"/proc/self/cgroup",
		"/proc/uptime",
		"/proc/cpuinfo",
		"/proc/meminfo",
		"/proc/version",
	}

	for _, path := range selfPaths {
		for _, op := range []uint8{0, 1, 2} { // FILE_OP_OPEN, FILE_OP_READ, FILE_OP_WRITE
			e := p117FileEvent(selfPID, "ebpf-guard", path, op)
			alerts := engine.Evaluate(e)
			assert.Empty(t, alerts,
				"agent's own access to %s (op=%d) must not alert — got %d alert(s); "+
					"add a comm+path-scoped ebpf-guard-self exception to the firing rule(s)",
				path, op, len(alerts))
		}
	}
}

// TestP1_17_SelfTraffic_ForeignProcessStillAlerts is the paired negative
// control for the test above: it guards against a fix that suppresses a rule
// outright (e.g. an exception keyed on path alone, or on PID 0) instead of
// scoping it to the agent's own comm+PID. Every path in the self-traffic list
// that any *production* rule cares about should still alert when touched by
// an unrelated process.
func TestP1_17_SelfTraffic_ForeignProcessStillAlerts(t *testing.T) {
	rules := catalogWithCanaryRules(t)
	engine := correlator.NewRuleEngine(rules)

	// Subset of selfPaths that real detection rules are known to key on
	// (the rest — SQLite/state/audit files — are not attacker primitives and
	// aren't expected to be covered by any rule).
	watchedPaths := []struct {
		path string
		op   uint8
	}{
		{"/etc/shadow.canary", 0},
		{"/tmp/.secret_key", 0},
		{"/var/run/.admin_socket", 0},
		{"/root/.ssh/id_rsa.canary", 0},
		{"/etc/passwd.canary", 0},
	}

	for _, wp := range watchedPaths {
		e := p117FileEvent(4242, "nc", wp.path, wp.op)
		assert.NotEmpty(t, engine.Evaluate(e),
			"canary path %s must still alert when touched by a foreign process — "+
				"a self-exception must narrow the rule, not disable it for everyone", wp.path)
	}
}
