package correlator_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/internal/correlator"
)

// TestWave599b_WebshellCrontab is the regression test for находка №98
// (plan.md 5.9.9b): webshell_crontab_modification's message promises "Web
// server worker wrote to /etc/cron*", but before this wave the condition
// checked only the path — any comm, including the system's own hourly cron
// runner, tripped it. Idle-hour data showed comm=run-parts (the standard
// /etc/cron.hourly dispatcher) firing a critical once per hour with no
// attack present — the same FP class 5.9.8g (находка №96) fixed on
// webshell_script_write_via_web_process, disposed of then as a one-off
// instead of a class. The rule now requires comm to be one of the
// web-worker names it claims to scope to; a positive control (a write by an
// actual web worker) must still fire, per риск №3 (запрет №6 постановки):
// narrowing without a live positive control is находка №57 repeated.
func TestWave599b_WebshellCrontab(t *testing.T) {
	rules, err := correlator.LoadRulesFromFile("../../rules/webshell-detection.yaml")
	require.NoError(t, err)
	var target *correlator.Rule
	for i := range rules {
		if rules[i].ID == "webshell_crontab_modification" {
			target = &rules[i]
		}
	}
	require.NotNil(t, target, "webshell_crontab_modification not found")
	engine := correlator.NewRuleEngine([]correlator.Rule{*target})

	const opWrite = 2

	t.Run("comm=run-parts writing /etc/cron.hourly must not fire (находка №98, idle-hour FP)", func(t *testing.T) {
		event := p117FileEvent(4242, "run-parts", "/etc/cron.hourly/logrotate", opWrite)
		assert.Empty(t, engine.Evaluate(event),
			"the system's own hourly cron dispatcher must not trip this rule — its message claims web-worker scope")
	})

	for _, comm := range []string{"apache2", "nginx", "httpd"} {
		t.Run("positive control: comm="+comm+" writing /etc/cron.d still fires", func(t *testing.T) {
			event := p117FileEvent(4242, comm, "/etc/cron.d/persist", opWrite)
			assert.NotEmpty(t, engine.Evaluate(event),
				"narrowing to web-worker comm must not have blinded the rule to the case it was written for (риск №3)")
		})
	}

	t.Run("comm=apache2 writing a path outside cron scope does not fire", func(t *testing.T) {
		event := p117FileEvent(4242, "apache2", "/var/www/html/shell.php", opWrite)
		assert.Empty(t, engine.Evaluate(event),
			"path condition is unchanged — only /etc/cron* and /var/spool/cron are in scope")
	})
}
