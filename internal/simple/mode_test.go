package simple

import (
	"context"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockExecutor struct {
	executed atomic.Int32
	dryRun   bool
}

func (m *mockExecutor) ExecuteAction(_ context.Context, action string, _ types.Alert) error {
	m.executed.Add(1)
	return nil
}

func (m *mockExecutor) IsDryRun() bool {
	return m.dryRun
}

func TestShouldEscalate_Cryptominer(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	m := New(cfg, slog.Default())

	alert := types.Alert{
		RuleID:   "cryptominer_pool_ports",
		Severity: types.SeverityCritical,
	}
	assert.True(t, m.shouldEscalate(alert))
}

func TestShouldEscalate_Webshell(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	m := New(cfg, slog.Default())

	alert := types.Alert{
		RuleID:   "webshell_php_in_webroot",
		Severity: types.SeverityCritical,
	}
	assert.True(t, m.shouldEscalate(alert))
}

func TestShouldEscalate_ReverseShell(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	m := New(cfg, slog.Default())

	tests := []string{
		"c2_reverse_shell_standard_ports",
		"c2_raw_socket_shell",
		"c2_connect_to_tor_port",
		"c2_remote_access_tool",
		"web_shell_spawn",
		"shell_network_tool",
		"database_shell_spawn",
		"container_escape_attempt",
	}

	for _, ruleID := range tests {
		t.Run(ruleID, func(t *testing.T) {
			alert := types.Alert{
				RuleID:   ruleID,
				Severity: types.SeverityCritical,
			}
			assert.True(t, m.shouldEscalate(alert))
		})
	}
}

func TestShouldEscalate_WarningNotEscalated(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	m := New(cfg, slog.Default())

	alert := types.Alert{
		RuleID:   "cryptominer_pool_ports",
		Severity: types.SeverityWarning,
	}
	assert.False(t, m.shouldEscalate(alert))
}

func TestShouldEscalate_NonMatchingRule(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	m := New(cfg, slog.Default())

	alert := types.Alert{
		RuleID:   "random_rule_xyz",
		Severity: types.SeverityCritical,
	}
	assert.False(t, m.shouldEscalate(alert))
}

func TestPassesSafetyRails_PID1(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AllowlistPIDs = []uint32{1}
	m := New(cfg, slog.Default())

	alert := types.Alert{
		PID:  1,
		Comm: "systemd",
	}
	assert.False(t, m.passesSafetyRails(alert))
}

func TestPassesSafetyRails_AllowlistComm(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AllowlistComms = []string{"kubelet", "containerd"}
	m := New(cfg, slog.Default())

	assert.False(t, m.passesSafetyRails(types.Alert{PID: 100, Comm: "kubelet"}))
	assert.False(t, m.passesSafetyRails(types.Alert{PID: 200, Comm: "containerd"}))
	assert.True(t, m.passesSafetyRails(types.Alert{PID: 300, Comm: "nginx"}))
}

func TestPassesSafetyRails_NormalProcess(t *testing.T) {
	cfg := DefaultConfig()
	m := New(cfg, slog.Default())

	alert := types.Alert{
		PID:  1234,
		Comm: "bad-process",
	}
	assert.True(t, m.passesSafetyRails(alert))
}

func TestIsDryRun_ByFlag(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DryRun = true
	cfg.DryRunDuration = 0
	m := New(cfg, slog.Default())

	assert.True(t, m.IsDryRun())
}

func TestIsDryRun_ByDuration(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DryRun = false
	cfg.DryRunDuration = 24 * time.Hour
	m := New(cfg, slog.Default())

	assert.True(t, m.IsDryRun())
}

func TestIsDryRun_None(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DryRun = false
	cfg.DryRunDuration = 0
	m := New(cfg, slog.Default())

	assert.False(t, m.IsDryRun())
}

func TestProcessAlerts_KillsOnMatch(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.DryRun = false
	cfg.DryRunDuration = 0
	cfg.MaxKillsPerMinute = 100
	m := New(cfg, slog.Default())
	exec := &mockExecutor{}

	alerts := []types.Alert{
		{
			RuleID:   "cryptominer_pool_ports",
			RuleName: "Cryptominer Pool Connection",
			Severity: types.SeverityCritical,
			PID:      5678,
			Comm:     "xmrig",
		},
	}

	result := m.ProcessAlerts(alerts, exec)
	require.Len(t, result, 1)
	assert.Equal(t, int32(1), exec.executed.Load())
	assert.True(t, result[0].Enforced)
	assert.Equal(t, "kill", result[0].Action)
	assert.Contains(t, result[0].Message, "cryptominer")
}

func TestProcessAlerts_DryRunDoesNotExecute(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.DryRun = true
	cfg.DryRunDuration = 0
	cfg.MaxKillsPerMinute = 100
	m := New(cfg, slog.Default())
	exec := &mockExecutor{dryRun: true}

	alerts := []types.Alert{
		{
			RuleID:   "webshell_php_in_webroot",
			RuleName: "PHP in Web Root",
			Severity: types.SeverityCritical,
			PID:      5678,
			Comm:     "php-fpm",
		},
	}

	result := m.ProcessAlerts(alerts, exec)
	require.Len(t, result, 1)
	assert.Equal(t, int32(0), exec.executed.Load()) // Not executed in dry-run
	assert.False(t, result[0].Enforced)
	assert.Contains(t, result[0].Message, "DRY RUN")
}

func TestProcessAlerts_SkipsNonMatching(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.DryRunDuration = 0
	cfg.MaxKillsPerMinute = 100
	m := New(cfg, slog.Default())
	exec := &mockExecutor{}

	alerts := []types.Alert{
		{
			RuleID:   "some_harmless_rule",
			Severity: types.SeverityCritical,
			PID:      1234,
			Comm:     "normal",
		},
	}

	result := m.ProcessAlerts(alerts, exec)
	assert.Len(t, result, 0)
	assert.Equal(t, int32(0), exec.executed.Load())
}

func TestProcessAlerts_SkipsAllowlistedPID(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.DryRunDuration = 0
	cfg.MaxKillsPerMinute = 100
	cfg.AllowlistPIDs = []uint32{1, 9999}
	m := New(cfg, slog.Default())
	exec := &mockExecutor{}

	alerts := []types.Alert{
		{
			RuleID:   "cryptominer_binary_name",
			Severity: types.SeverityCritical,
			PID:      9999,
			Comm:     "xmrig",
		},
	}

	result := m.ProcessAlerts(alerts, exec)
	assert.Len(t, result, 0)
	assert.Equal(t, int32(0), exec.executed.Load())
}

func TestProcessAlerts_RateLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.DryRunDuration = 0
	cfg.MaxKillsPerMinute = 1
	m := New(cfg, slog.Default())
	exec := &mockExecutor{}

	// Create 10 cryptominer alerts — only first should pass rate limit
	alerts := make([]types.Alert, 10)
	for i := range alerts {
		alerts[i] = types.Alert{
			RuleID:   "cryptominer_pool_ports",
			Severity: types.SeverityCritical,
			PID:      uint32(5000 + i),
			Comm:     "xmrig",
		}
	}

	result := m.ProcessAlerts(alerts, exec)
	assert.Len(t, result, 1) // Only first passes rate limit
}

func TestProcessAlerts_EmptyAlerts(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	m := New(cfg, slog.Default())
	exec := &mockExecutor{}

	result := m.ProcessAlerts(nil, exec)
	assert.Len(t, result, 0)

	result = m.ProcessAlerts([]types.Alert{}, exec)
	assert.Len(t, result, 0)
}

func TestBuildPlainNotification_Cryptominer(t *testing.T) {
	cfg := DefaultConfig()
	m := New(cfg, slog.Default())

	alert := types.Alert{
		RuleID:   "cryptominer_binary_name",
		RuleName: "Known Cryptominer Binary",
		PID:      5678,
		Comm:     "xmrig",
	}

	msg := m.buildPlainNotification(alert, false)
	assert.Contains(t, msg, "cryptominer")
	assert.Contains(t, msg, "xmrig")
	assert.Contains(t, msg, "PID 5678")
	assert.NotContains(t, msg, "DRY RUN")
}

func TestBuildPlainNotification_Webshell(t *testing.T) {
	cfg := DefaultConfig()
	m := New(cfg, slog.Default())

	alert := types.Alert{
		RuleID:   "web_shell_spawn",
		RuleName: "Web Server Shell Spawn",
		PID:      1234,
		Comm:     "bash",
	}

	msg := m.buildPlainNotification(alert, false)
	assert.Contains(t, msg, "web server")
	assert.Contains(t, msg, "bash")
}

func TestBuildPlainNotification_DryRun(t *testing.T) {
	cfg := DefaultConfig()
	m := New(cfg, slog.Default())

	alert := types.Alert{
		RuleID:   "cryptominer_pool_ports",
		RuleName: "Pool Connection",
		PID:      5678,
		Comm:     "minerd",
	}

	msg := m.buildPlainNotification(alert, true)
	assert.Contains(t, msg, "DRY RUN")
	assert.Contains(t, msg, "Would have killed")
	assert.Contains(t, msg, "24-hour dry-run period")
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	assert.False(t, cfg.Enabled)
	assert.False(t, cfg.DryRun)
	assert.Equal(t, 24*time.Hour, cfg.DryRunDuration)
	assert.Equal(t, 1, cfg.MaxKillsPerMinute)
	assert.Contains(t, cfg.AllowlistPIDs, uint32(1))
	assert.Contains(t, cfg.AllowlistComms, "systemd")
	assert.Contains(t, cfg.AllowlistComms, "kubelet")
}

func TestNew_AppliesDefaults(t *testing.T) {
	cfg := Config{Enabled: true}
	m := New(cfg, slog.Default())

	assert.True(t, m.cfg.Enabled)
	assert.Equal(t, 1, m.cfg.MaxKillsPerMinute)
	assert.Contains(t, m.cfg.AllowlistPIDs, uint32(1))
	assert.Contains(t, m.cfg.AllowlistComms, "systemd")
}
