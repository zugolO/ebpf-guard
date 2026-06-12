// Package simple implements simple mode — auto-enforcement for unambiguous
// threats out of the box, designed for indie developers and small teams who
// will never write a YAML config.
//
// Simple mode auto-kills processes matching high-confidence detections
// (cryptominers, webshells, reverse shells) with multiple safety rails:
//   - Requires BOTH a rule match AND lineage confirmation.
//   - Never kills PID 1 or allowlisted system processes.
//   - Global enforcement rate cap prevents runaway kills.
//   - First 24 hours are dry-run (logs "would have killed") by default.
//   - Every action produces a plain-language notification.
package simple

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"golang.org/x/time/rate"
)

// Config holds simple-mode configuration.
type Config struct {
	// Enabled activates simple mode auto-enforcement.
	Enabled bool `mapstructure:"enabled"`

	// DryRun toggles dry-run mode. When true, enforcement actions are logged
	// but not executed. Overridden by DryRunDuration during the initial window.
	DryRun bool `mapstructure:"dry_run"`

	// DryRunDuration is the initial dry-run period after startup.
	// Default: 24h. Zero disables the dry-run window.
	DryRunDuration time.Duration `mapstructure:"dry_run_duration"`

	// MaxKillsPerMinute caps the global kill rate. Default: 1.
	MaxKillsPerMinute int `mapstructure:"max_kills_per_minute"`

	// AllowlistPIDs lists PIDs that must never be killed (e.g. PID 1).
	// Default: [1].
	AllowlistPIDs []uint32 `mapstructure:"allowlist_pids"`

	// AllowlistComms lists process names that must never be killed.
	// Default: ["systemd", "init", "kubelet", "containerd"].
	AllowlistComms []string `mapstructure:"allowlist_comms"`
}

// DefaultConfig returns the default simple-mode configuration.
func DefaultConfig() Config {
	return Config{
		Enabled:           false,
		DryRun:            false,
		DryRunDuration:    24 * time.Hour,
		MaxKillsPerMinute: 1,
		AllowlistPIDs:     []uint32{1},
		AllowlistComms:    []string{"systemd", "init", "kubelet", "containerd"},
	}
}

// ActionExecutor is the minimal enforcement interface required by simple mode.
type ActionExecutor interface {
	ExecuteAction(ctx context.Context, action string, alert types.Alert) error
	IsDryRun() bool
}

// Mode is the simple-mode engine. It evaluates alerts from the correlation
// engine and escalates high-confidence cryptominer, webshell, and reverse-shell
// detections to kill actions, subject to safety rails.
type Mode struct {
	cfg       Config
	startTime time.Time
	limiter   *rate.Limiter
	logger    *slog.Logger
	mu        sync.Mutex
}

// New creates a new simple-mode engine.
func New(cfg Config, logger *slog.Logger) *Mode {
	if logger == nil {
		logger = slog.Default()
	}

	if cfg.MaxKillsPerMinute <= 0 {
		cfg.MaxKillsPerMinute = 1
	}
	if len(cfg.AllowlistPIDs) == 0 {
		cfg.AllowlistPIDs = []uint32{1}
	}
	if len(cfg.AllowlistComms) == 0 {
		cfg.AllowlistComms = []string{"systemd", "init", "kubelet", "containerd"}
	}

	r := rate.Limit(float64(cfg.MaxKillsPerMinute) / 60.0)
	return &Mode{
		cfg:       cfg,
		startTime: time.Now(),
		limiter:   rate.NewLimiter(r, cfg.MaxKillsPerMinute),
		logger:    logger,
	}
}

// IsDryRun returns true if simple mode is in dry-run state.
func (m *Mode) IsDryRun() bool {
	if m.cfg.DryRun {
		return true
	}
	if m.cfg.DryRunDuration > 0 {
		if time.Since(m.startTime) < m.cfg.DryRunDuration {
			return true
		}
	}
	return false
}

// autoEnforceRulePrefixes lists rule ID prefixes that simple mode auto-enforces.
var autoEnforceRulePrefixes = []string{
	// Cryptominer rules from rules/cryptominer.yaml
	"cryptominer_",
	// Webshell detection from rules/webshell-detection.yaml
	"webshell_",
	// Reverse shell from rules/command-and-control.yaml
	"c2_reverse_shell_",
	"c2_raw_socket_shell",
	// Lineage-based webshell/reverse shell from rules/lineage-patterns.yaml
	"web_shell_spawn",
	"shell_network_tool",
	"database_shell_spawn",
	"container_escape_attempt",
	// Additional reverse shell patterns
	"c2_connect_to_tor_",
	"c2_remote_access_",
}

// ProcessAlerts evaluates each alert and escalates high-confidence detections
// to kill actions. Returns alerts that should be enforced (with Action="kill").
// The caller should dispatch these to the enforcer.
func (m *Mode) ProcessAlerts(alerts []types.Alert, executor ActionExecutor) []types.Alert {
	var enforced []types.Alert

	for _, alert := range alerts {
		if !m.shouldEscalate(alert) {
			continue
		}

		if !m.passesSafetyRails(alert) {
			continue
		}

		if !m.limiter.Allow() {
			m.logger.Warn("simple: kill rate limit reached, skipping",
				slog.String("rule_id", alert.RuleID),
				slog.Uint64("pid", uint64(alert.PID)))
			continue
		}

		dry := m.IsDryRun()
		message := m.buildPlainNotification(alert, dry)

		if dry {
			m.logger.Warn("simple: would have killed (dry-run)",
				slog.String("rule_id", alert.RuleID),
				slog.Uint64("pid", uint64(alert.PID)),
				slog.String("comm", alert.Comm),
				slog.String("summary", message))
			alert.Enforced = false
			alert.Message = message
			enforced = append(enforced, alert)
			continue
		}

		m.logger.Warn("simple: executing kill",
			slog.String("rule_id", alert.RuleID),
			slog.Uint64("pid", uint64(alert.PID)),
			slog.String("comm", alert.Comm))

		alert.Action = "kill"
		alert.Message = message

		if executor != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := executor.ExecuteAction(ctx, "kill", alert); err != nil {
				m.logger.Error("simple: kill failed",
					slog.String("rule_id", alert.RuleID),
					slog.Uint64("pid", uint64(alert.PID)),
					slog.Any("error", err))
			}
			cancel()
		}

		alert.Enforced = true
		enforced = append(enforced, alert)
	}

	return enforced
}

// lineageRequiredPrefixes lists rule ID prefixes for which simple mode requires
// a non-empty ProcessTree (lineage confirmation) before auto-killing. Cryptominer
// binary detections are self-evidencing and are excluded from this requirement.
var lineageRequiredPrefixes = []string{
	"webshell_",
	"c2_reverse_shell_",
	"c2_raw_socket_shell",
	"web_shell_spawn",
	"shell_network_tool",
	"database_shell_spawn",
	"container_escape_attempt",
	"c2_connect_to_tor_",
	"c2_remote_access_",
}

// shouldEscalate returns true if the alert is from a rule set that simple mode
// auto-enforces (cryptominer, webshell, reverse shell).
// For webshell and reverse-shell rules, a non-empty ProcessTree is required as
// lineage confirmation — the lineage tracker must have recorded a parent-child
// chain before the kill is authorised.
func (m *Mode) shouldEscalate(alert types.Alert) bool {
	if alert.Severity != types.SeverityCritical {
		return false
	}

	matched := false
	for _, prefix := range autoEnforceRulePrefixes {
		if strings.HasPrefix(alert.RuleID, prefix) {
			matched = true
			break
		}
	}
	if !matched {
		return false
	}

	// Webshell/C2 rules require lineage confirmation: the correlation engine must
	// have built a process tree for this PID (via LineageTracker.GetProcessTree).
	// Cryptominer rules are self-evidencing and do not require this check.
	for _, prefix := range lineageRequiredPrefixes {
		if strings.HasPrefix(alert.RuleID, prefix) || alert.RuleID == prefix {
			if len(alert.ProcessTree) == 0 {
				m.logger.Info("simple: skipping — no lineage confirmation",
					slog.String("rule_id", alert.RuleID),
					slog.Uint64("pid", uint64(alert.PID)))
				return false
			}
			break
		}
	}

	return true
}

// passesSafetyRails returns false if an allowlist rule prevents this kill.
func (m *Mode) passesSafetyRails(alert types.Alert) bool {
	for _, pid := range m.cfg.AllowlistPIDs {
		if alert.PID == pid {
			m.logger.Info("simple: skipping allowlisted PID",
				slog.Uint64("pid", uint64(alert.PID)))
			return false
		}
	}
	for _, comm := range m.cfg.AllowlistComms {
		if alert.Comm == comm {
			m.logger.Info("simple: skipping allowlisted comm",
				slog.String("comm", alert.Comm))
			return false
		}
	}
	return true
}

// buildPlainNotification creates a human-readable explanation of what was
// killed and why, suitable for reading on a phone.
func (m *Mode) buildPlainNotification(alert types.Alert, dryRun bool) string {
	prefix := ""
	if dryRun {
		prefix = "[DRY RUN] Would have killed — "
	}

	category := "suspicious activity"
	switch {
	case strings.HasPrefix(alert.RuleID, "cryptominer_"):
		category = "running a cryptominer"
	case strings.HasPrefix(alert.RuleID, "webshell_"):
		category = "webshell activity (likely exploited web server)"
	case strings.HasPrefix(alert.RuleID, "c2_reverse_shell_") || strings.HasPrefix(alert.RuleID, "c2_raw_socket_shell"):
		category = "reverse shell connection"
	case alert.RuleID == "web_shell_spawn":
		category = "a web server unexpectedly spawned a shell"
	case alert.RuleID == "shell_network_tool":
		category = "a shell spawned a network tool (likely reverse shell)"
	case alert.RuleID == "database_shell_spawn":
		category = "a database spawned a shell (possible SQL injection)"
	case alert.RuleID == "container_escape_attempt":
		category = "attempting container escape"
	}

	var b strings.Builder
	b.WriteString(prefix)
	b.WriteString(fmt.Sprintf("Process %s (PID %d) was detected %s",
		alert.Comm, alert.PID, category))

	if alert.RuleName != "" {
		b.WriteString(fmt.Sprintf(" by rule \"%s\"", alert.RuleName))
	}
	b.WriteString(". ")

	switch {
	case strings.HasPrefix(alert.RuleID, "cryptominer_"):
		b.WriteString("This process was using CPU for cryptocurrency mining without authorization. " +
			"Recommended: check how the binary was deployed — it was likely dropped through an exploit or CI/CD pipeline compromise.")
	case strings.HasPrefix(alert.RuleID, "webshell_") || alert.RuleID == "web_shell_spawn" || alert.RuleID == "shell_network_tool":
		b.WriteString("This usually means a web application was exploited and an attacker gained shell access. " +
			"Recommended: restart the container, check web server logs, and look for unpatched dependencies.")
	case alert.RuleID == "database_shell_spawn":
		b.WriteString("This usually means a SQL injection attack succeeded and an attacker spawned a shell from the database process. " +
			"Recommended: restart the container, audit SQL queries, and sanitize inputs.")
	case alert.RuleID == "container_escape_attempt":
		b.WriteString("An attacker is attempting to escape the container. " +
			"Recommended: restart the container immediately, check for privilege escalation paths, and audit container security context.")
	default:
		b.WriteString("This is a high-confidence security threat. " +
			"Recommended: restart the affected container and check for signs of compromise.")
	}

	if dryRun {
		b.WriteString(" The process was not killed because simple mode is in a 24-hour dry-run period. " +
			"Set simple_mode.dry_run: false to enable real enforcement.")
	}

	b.WriteString(fmt.Sprintf(" If this was a false positive, add \"%s\" to the allowlist.",
		alert.Comm))

	return b.String()
}
