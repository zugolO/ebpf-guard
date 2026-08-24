package correlator_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// loadRuleF1 returns one rule by id from a rules file, failing the test if the
// rule has been renamed or removed. Both wave 5.9.9.F.1 rule fixes are edits to
// a regex list, and the failure mode they guard against is exactly the one that
// let findings #107, #111 and #114 survive: a predicate wider than the rule's
// own name, never fed the widening input by any test.
func loadRuleF1(t *testing.T, path, id string) correlator.Rule {
	t.Helper()
	rules, err := correlator.LoadRulesFromFile(path)
	require.NoError(t, err)
	for i := range rules {
		if rules[i].ID == id {
			return rules[i]
		}
	}
	t.Fatalf("rule %q not found in %s", id, path)
	return correlator.Rule{}
}

func f1FileAlerts(rule correlator.Rule, comm, path string) []types.Alert {
	engine := correlator.NewRuleEngine([]correlator.Rule{rule})
	return engine.Evaluate(p117FileEvent(970001, comm, path, 0))
}

// 5.9.9.F.1b (finding #111): sigma_memory_proc_dump is named "Process memory
// read via /proc/*/mem" and tagged credential-access/T1003, but its regex list
// also carried /proc/[0-9]+/cmdline — reading another process's command line,
// which is not a credential-scraping primitive. Wave 5.7a had tried to fix this
// with a comm-scoped exception for pgrep; замер №2.9.9.F showed the exception
// did not generalise (landscape-sysinfo and dbus-daemon do the same reads:
// 18 of the rule's 19 alerts for the run, with exactly one true positive).
//
// The predicate is the fix, and the exception is gone with it. This test feeds
// the rule both outcomes so that re-adding cmdline — or dropping mem/maps while
// "cleaning up" — fails offline rather than as a number on the stand.
func TestF1b_SigmaMemoryProcDump_CmdlineIsNotAMemoryDump(t *testing.T) {
	rule := loadRuleF1(t, "../../rules/sigma-linux.yaml", "sigma_memory_proc_dump")

	t.Run("another process's cmdline never alerts", func(t *testing.T) {
		for _, comm := range []string{"landscape-sysin", "dbus-daemon", "pgrep", "credscrape"} {
			assert.Empty(t, f1FileAlerts(rule, comm, "/proc/1234/cmdline"),
				"comm=%s: /proc/<pid>/cmdline is not a memory dump (finding #111)", comm)
		}
		assert.Empty(t, f1FileAlerts(rule, "landscape-sysin", "/proc/1/cmdline"),
			"/proc/1/cmdline was 9 of this rule's 19 alerts on замер №2.9.9.F")
	})

	// The other half: the rule must not have been blinded. These three are the
	// primitives the rule exists for, and /proc/<pid>/maps under comm=credscrape
	// is the exact shape of the live positive control that keeps the rule at 1
	// alert per run instead of 0 (run_cred_proc_maps_positive_control, 5.9.9.Fa).
	// A rule that goes silent here reads as a detect regression on крит. 6 and
	// is indistinguishable from the fix working — finding #57.
	t.Run("real memory primitives still alert", func(t *testing.T) {
		for _, path := range []string{"/proc/1234/mem", "/proc/1234/maps", "/proc/1234/environ"} {
			assert.NotEmpty(t, f1FileAlerts(rule, "attacker", path),
				"%s must keep alerting — narrowing must not blind the rule", path)
		}
		assert.NotEmpty(t, f1FileAlerts(rule, "credscrape", "/proc/4242/maps"),
			"the live positive control (comm=credscrape) must keep raising sigma_memory_proc_dump")
	})

	t.Run("the dead pgrep-cmdline-scan exception is gone", func(t *testing.T) {
		for _, exc := range rule.Exceptions {
			assert.NotEqual(t, "pgrep-cmdline-scan", exc.Name,
				"the exception existed only to cancel the cmdline predicate; both go together (5.9.9.F.1b)")
		}
	})

	t.Run("systemd-journal and ebpf-guard exceptions are kept", func(t *testing.T) {
		names := map[string]bool{}
		for _, exc := range rule.Exceptions {
			names[exc.Name] = true
		}
		assert.True(t, names["systemd-journal"], "systemd-journal reads /proc/<pid>/{maps,environ} for log attribution")
		assert.True(t, names["ebpf-guard-self"], "the agent reads its own equivalents for self-monitoring")
	})
}

// 5.9.9.F.1c (finding #114): web_sql_injection_files is a critical rule whose
// regex list is matched against a FILENAME, and it carried the bare patterns
// "--", "#" and ";". One character in a path raised a critical "SQL injection".
// On замер №2.9.9.F it produced 10 criticals, zero of them true: nine on
// systemd-logind's session temp files (/run/systemd/sessions/.#…) and one on a
// git man page (git-mergetool--lib.1.gz).
func TestF1c_WebSQLInjectionFiles_OneCharacterIsNotAnInjection(t *testing.T) {
	rule := loadRuleF1(t, "../../rules/web-attacks-enhanced.yaml", "web_sql_injection_files")

	t.Run("the exact false positives of замер №2.9.9.F no longer alert", func(t *testing.T) {
		assert.Empty(t, f1FileAlerts(rule, "systemd-logind", "/run/systemd/sessions/.#114376ChHzY"),
			"a systemd session temp file is not SQL injection (finding #114)")
		assert.Empty(t, f1FileAlerts(rule, "tar", "git-mergetool--lib.1.gz"),
			"a git man page is not SQL injection (finding #114)")
	})

	t.Run("ordinary paths carrying the removed markers no longer alert", func(t *testing.T) {
		for _, path := range []string{
			"/var/cache/apt/archives/libfoo--dev_1.2.3.deb",
			"/etc/systemd/system/multi-user.target.wants/foo#1.service",
			"/tmp/report;final.csv",
			"/usr/share/man/man1/git-diff--tool.1.gz",
		} {
			assert.Empty(t, f1FileAlerts(rule, "bash", path),
				"%s: bare comment markers carry no injection signal in a filename", path)
		}
	})

	// The other half: the remaining patterns require context (a keyword, a
	// paren, percent-encoding) and were deliberately left alone — none of them
	// fired at all on замер №2.9.9.F, so an edit would have had no measured
	// basis. They must still match, or 5.9.9.F.1c has blinded the rule rather
	// than narrowed it, and its return to silent-rules.txt category (b) would
	// be an accident instead of the intended outcome.
	t.Run("context-carrying patterns still alert", func(t *testing.T) {
		for _, path := range []string{
			"/var/www/uploads/union select passwd",
			"/tmp/x' UNION SELECT 1,2--.php",
			"/var/www/DROP TABLE users.log",
			"/tmp/id=1%27' or 1=1",
			"/tmp/sleep (5).php",
		} {
			assert.NotEmpty(t, f1FileAlerts(rule, "nginx", path),
				"%s carries an actual SQLi pattern and must keep alerting", path)
		}
	})
}
