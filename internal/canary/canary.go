// Package canary implements canary trap / honeypot file detection.
// Canary files are synthetic lures planted at paths attackers commonly probe
// during reconnaissance (e.g. /etc/shadow.canary). Any file-access event
// touching one of these paths generates a high-confidence critical alert.
package canary

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// DefaultFiles is the set of canary paths created when none are configured.
var DefaultFiles = []string{
	"/etc/shadow.canary",
	"/tmp/.secret_key",
	"/var/run/.admin_socket",
	"/root/.ssh/id_rsa.canary",
	"/etc/passwd.canary",
}

// Config holds canary manager settings.
type Config struct {
	// Enabled activates canary trap detection.
	Enabled bool
	// AutoCreate creates missing canary files at startup.
	AutoCreate bool
	// Files is the list of canary paths to monitor.
	Files []string
	// AlertSeverity is the severity applied to canary access alerts.
	AlertSeverity string
}

// Manager manages canary trap files and generates the corresponding detection rules.
type Manager struct {
	cfg Config
}

// New returns a Manager. If cfg.Files is empty, DefaultFiles is used.
func New(cfg Config) *Manager {
	if len(cfg.Files) == 0 {
		cfg.Files = DefaultFiles
	}
	if cfg.AlertSeverity == "" {
		cfg.AlertSeverity = "critical"
	}
	return &Manager{cfg: cfg}
}

// Setup creates canary files on disk when AutoCreate is enabled.
// Non-fatal: failures are logged as warnings so the agent still starts.
func (m *Manager) Setup() {
	if !m.cfg.AutoCreate {
		return
	}
	for _, path := range m.cfg.Files {
		if err := createCanaryFile(path); err != nil {
			slog.Warn("canary: failed to create trap file",
				slog.String("path", path), slog.Any("error", err))
		} else {
			slog.Info("canary: trap installed", slog.String("path", path))
		}
	}
}

func createCanaryFile(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil // already exists
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0400)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	_, _ = f.WriteString("# ebpf-guard canary trap — DO NOT ACCESS\n")
	return f.Close()
}

// Rules returns one detection rule per configured canary path.
// These rules are merged into the main rule engine at startup.
func (m *Manager) Rules() []correlator.Rule {
	sev := types.AlertSeverity(m.cfg.AlertSeverity)
	rules := make([]correlator.Rule, 0, len(m.cfg.Files))
	for i, path := range m.cfg.Files {
		rules = append(rules, correlator.Rule{
			ID:   fmt.Sprintf("canary_%03d", i+1),
			Name: fmt.Sprintf("Canary Trap: access to %s", path),
			Description: fmt.Sprintf(
				"A process accessed the canary trap file %s. "+
					"This is a high-confidence indicator of attacker reconnaissance — "+
					"no legitimate process should read this file.",
				path,
			),
			EventType: types.EventFileAccess,
			Condition: correlator.RuleCondition{
				Field:  "filename",
				Op:     correlator.OpEquals,
				Values: []string{path},
			},
			Severity: sev,
			Action:   correlator.ActionAlert,
			Tags:     []string{"canary", "honeypot", "reconnaissance", "high-confidence"},
		})
	}
	return rules
}

// Paths returns the configured canary file paths.
func (m *Manager) Paths() []string {
	return m.cfg.Files
}
