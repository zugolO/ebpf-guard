package correlator

import (
	"bytes"
	"runtime/pprof"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// labelsNow — метки горутин, как их печатает профиль goroutine (debug=1).
func labelsNow() string {
	var b bytes.Buffer
	_ = pprof.Lookup("goroutine").WriteTo(&b, 1)
	return b.String()
}

// G0(а): метки event_type и rule_file/rule_id стоят на время прохода по
// правилам и снимаются после; выключенные — не ставятся.
func TestProfileLabels_EvaluateInto(t *testing.T) {
	rules, err := LoadRulesFromFile("../../rules/sigma-linux.yaml")
	require.NoError(t, err)
	require.NotEmpty(t, rules[0].sourceFile)
	t.Cleanup(func() { SetProfileLabels(false, false) })

	ev := w81FileEvent(4242, "cat", "/etc/os-release", 0)
	run := func() (inside string, fired int) {
		engine := NewRuleEngine(rules)
		engine.EvaluateInto(ev, func(types.Alert) { fired++; inside = labelsNow() })
		return inside, fired
	}

	SetProfileLabels(false, false)
	inside, fired := run()
	require.Positive(t, fired, "событие должно поднять хотя бы одно правило")
	assert.NotContains(t, inside, `"event_type"`, "метки выключены")

	SetProfileLabels(true, false)
	inside, _ = run()
	assert.Contains(t, inside, `"event_type":"file"`)
	assert.NotContains(t, inside, `"rule_file"`)
	assert.NotContains(t, labelsNow(), `"event_type"`, "после прохода метки сняты")

	SetProfileLabels(true, true)
	inside, _ = run()
	assert.Contains(t, inside, `"event_type":"file"`)
	assert.Contains(t, inside, `"rule_file":"sigma-linux.yaml"`)
	assert.Contains(t, inside, `"rule_id":"sigma_kernel_version_read"`)
	assert.NotContains(t, labelsNow(), `"rule_id"`, "после прохода метки сняты")
}
