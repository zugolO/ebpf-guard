package correlator_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/internal/correlator"
)

// TestWave598g_WebshellScriptWrite is the regression test for находка №96
// (plan.md 5.9.8g): webshell_script_write_via_web_process's message promises
// "apache2, nginx, or httpd worker wrote a script file", but before this
// wave the condition checked only the filename extension — any comm,
// including a bare shell, tripped it. №2.9.7 observed exactly that: a
// critical alert with comm=bash. The rule now requires comm to be one of
// the web-worker names it claims to scope to; a positive control (write by
// an actual web worker) must still fire, per риск №3 (запрет №6
// постановки): narrowing without a live positive control is находка №57
// repeated.
func TestWave598g_WebshellScriptWrite(t *testing.T) {
	rules, err := correlator.LoadRulesFromFile("../../rules/webshell-detection.yaml")
	require.NoError(t, err)
	var target *correlator.Rule
	for i := range rules {
		if rules[i].ID == "webshell_script_write_via_web_process" {
			target = &rules[i]
		}
	}
	require.NotNil(t, target, "webshell_script_write_via_web_process not found")
	engine := correlator.NewRuleEngine([]correlator.Rule{*target})

	const opOpen = 0
	const opWrite = 2

	t.Run("comm=bash writing a .sh file must not fire (находка №96, №2.9.7)", func(t *testing.T) {
		event := p117FileEvent(4242, "bash", "/tmp/x.sh", opWrite)
		assert.Empty(t, engine.Evaluate(event),
			"a non-web-worker comm writing a script file must not trip this rule — its message claims web-worker scope")
	})

	for _, comm := range []string{"apache2", "nginx", "httpd"} {
		t.Run("positive control: comm="+comm+" writing .php still fires", func(t *testing.T) {
			event := p117FileEvent(4242, comm, "/var/www/html/shell.php", opWrite)
			assert.NotEmpty(t, engine.Evaluate(event),
				"narrowing to web-worker comm must not have blinded the rule to the case it was written for (риск №3)")
		})
	}

	t.Run("comm=apache2 writing a non-script file does not fire", func(t *testing.T) {
		event := p117FileEvent(4242, "apache2", "/var/www/html/index.html", opOpen)
		assert.Empty(t, engine.Evaluate(event),
			"filename condition is unchanged — only script extensions are in scope")
	})
}
