package hidden

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDiffTasks_NoHidden(t *testing.T) {
	kernel := []processInfo{
		{TGID: 1, PID: 1, Comm: "systemd"},
		{TGID: 100, PID: 100, Comm: "nginx"},
		{TGID: 200, PID: 200, Comm: "bash"},
	}
	proc := []processInfo{
		{TGID: 1, PID: 1, Comm: "systemd"},
		{TGID: 100, PID: 100, Comm: "nginx"},
		{TGID: 200, PID: 200, Comm: "bash"},
	}
	hidden := diffTasks(kernel, proc)
	assert.Empty(t, hidden)
}

func TestDiffTasks_HiddenFound(t *testing.T) {
	kernel := []processInfo{
		{TGID: 1, PID: 1, Comm: "systemd"},
		{TGID: 100, PID: 100, Comm: "nginx"},
		{TGID: 200, PID: 200, Comm: "bash"},
		{TGID: 666, PID: 666, Comm: "evil"},
	}
	proc := []processInfo{
		{TGID: 1, PID: 1, Comm: "systemd"},
		{TGID: 100, PID: 100, Comm: "nginx"},
		{TGID: 200, PID: 200, Comm: "bash"},
	}
	hidden := diffTasks(kernel, proc)
	assert.Len(t, hidden, 1)
	assert.Equal(t, uint32(666), hidden[0].TGID)
	assert.Equal(t, "evil", hidden[0].Comm)
}

func TestDiffTasks_MultipleHidden(t *testing.T) {
	kernel := []processInfo{
		{TGID: 1, PID: 1, Comm: "systemd"},
		{TGID: 100, PID: 100, Comm: "nginx"},
		{TGID: 666, PID: 666, Comm: "evil1"},
		{TGID: 777, PID: 777, Comm: "evil2"},
	}
	proc := []processInfo{
		{TGID: 1, PID: 1, Comm: "systemd"},
		{TGID: 100, PID: 100, Comm: "nginx"},
	}
	hidden := diffTasks(kernel, proc)
	assert.Len(t, hidden, 2)
	// Results should be sorted by TGID
	assert.Equal(t, uint32(666), hidden[0].TGID)
	assert.Equal(t, uint32(777), hidden[1].TGID)
}

func TestDiffTasks_EmptyKernel(t *testing.T) {
	hidden := diffTasks(nil, []processInfo{{TGID: 1, PID: 1, Comm: "systemd"}})
	assert.Empty(t, hidden)
}

func TestDiffTasks_EmptyProc(t *testing.T) {
	kernel := []processInfo{
		{TGID: 1, PID: 1, Comm: "systemd"},
		{TGID: 666, PID: 666, Comm: "evil"},
	}
	hidden := diffTasks(kernel, nil)
	assert.Len(t, hidden, 2)
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	assert.False(t, cfg.Enabled)
	assert.Equal(t, "critical", cfg.AlertSeverity)
}

func TestNew_DefaultsApplied(t *testing.T) {
	d := New(nil, Config{Enabled: true})
	assert.True(t, d.cfg.Enabled)
	assert.Equal(t, "critical", d.cfg.AlertSeverity)
}

func TestNew_OverrideAlertSeverity(t *testing.T) {
	d := New(nil, Config{
		Enabled:        true,
		AlertSeverity:  "warning",
		CheckInterval:  0,
	})
	assert.Equal(t, "warning", d.cfg.AlertSeverity)
}
