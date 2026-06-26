package exporter

import (
	"testing"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestSlackNotifier_BuildPayloadWithContext(t *testing.T) {
	n := NewSlackNotifier(SlackConfig{Enabled: true, WebhookURL: "http://localhost", Channel: "#sec"}, notifierLogger(), false)

	// Critical severity exercises the red-color branch.
	crit := n.buildPayloadWithContext(criticalAlert())
	assert.NotNil(t, crit)

	// Warning severity exercises the default-color branch.
	warn := n.buildPayloadWithContext(types.Alert{
		RuleID: "r2", RuleName: "Warn", Severity: types.SeverityWarning, PID: 7, Comm: "x", Message: "m",
	})
	assert.NotNil(t, warn)
}
