// Package canary implements canary trap / honeypot file detection.
// Canary files are synthetic lures planted at paths attackers commonly probe
// during reconnaissance (e.g. /etc/shadow.canary). Any file-access event
// touching one of these paths generates a high-confidence critical alert.
// A periodic verification loop additionally detects post-creation tampering
// (deletion or content modification) and emits alerts via an alertFn callback.
package canary

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
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

// canaryIntactGauge tracks whether each canary file is present and unmodified.
// Registered once at package init time so multiple Manager instances in tests
// don't cause duplicate-registration panics.
var canaryIntactGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Name: "ebpf_guard_canary_files_intact",
	Help: "1 if canary file is present and unmodified, 0 if missing or tampered.",
}, []string{"path"})

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
	// VerifyInterval is how often the periodic verification loop runs.
	// Zero or negative disables periodic verification.
	VerifyInterval time.Duration
	// AlertOnTamper controls whether an alert is emitted when tampering is detected.
	AlertOnTamper bool
}

// fileRecord stores the baseline state captured at Setup time.
type fileRecord struct {
	path   string
	sha256 [32]byte
	mode   os.FileMode
}

// Manager manages canary trap files and generates the corresponding detection rules.
type Manager struct {
	cfg     Config
	records []fileRecord
}

// New returns a Manager. If cfg.Files is empty, DefaultFiles is used.
func New(cfg Config) *Manager {
	if len(cfg.Files) == 0 {
		cfg.Files = DefaultFiles
	}
	if cfg.AlertSeverity == "" {
		cfg.AlertSeverity = "critical"
	}
	if cfg.VerifyInterval == 0 {
		cfg.VerifyInterval = 60 * time.Second
	}
	return &Manager{cfg: cfg}
}

// Setup creates canary files on disk when AutoCreate is enabled and records
// their baseline SHA-256 hash and permissions for later verification.
// Non-fatal: failures are logged as warnings so the agent still starts.
func (m *Manager) Setup() {
	for _, path := range m.cfg.Files {
		if m.cfg.AutoCreate {
			if err := createCanaryFile(path); err != nil {
				slog.Warn("canary: failed to create trap file",
					slog.String("path", path), slog.Any("error", err))
				canaryIntactGauge.WithLabelValues(path).Set(0)
				continue
			}
			slog.Info("canary: trap installed", slog.String("path", path))
		}
		hash, mode, err := hashFile(path)
		if err != nil {
			slog.Warn("canary: cannot hash file for baseline",
				slog.String("path", path), slog.Any("error", err))
			canaryIntactGauge.WithLabelValues(path).Set(0)
			continue
		}
		m.records = append(m.records, fileRecord{path: path, sha256: hash, mode: mode})
		canaryIntactGauge.WithLabelValues(path).Set(1)
	}
}

// Start launches the periodic verification loop. alertFn is called for each
// tampered file; pass nil to disable alerts while still updating the gauge.
// The loop runs until ctx is cancelled.
func (m *Manager) Start(ctx context.Context, alertFn func(types.Alert)) error {
	if m.cfg.VerifyInterval <= 0 || len(m.records) == 0 {
		return nil
	}
	go func() {
		ticker := time.NewTicker(m.cfg.VerifyInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				m.verify(alertFn)
			case <-ctx.Done():
				return
			}
		}
	}()
	return nil
}

func (m *Manager) verify(alertFn func(types.Alert)) {
	for _, rec := range m.records {
		if m.checkFileIntact(rec) {
			canaryIntactGauge.WithLabelValues(rec.path).Set(1)
			continue
		}
		canaryIntactGauge.WithLabelValues(rec.path).Set(0)
		slog.Error("canary: file tampered or deleted", slog.String("path", rec.path))
		if m.cfg.AlertOnTamper && alertFn != nil {
			alertFn(types.Alert{
				ID:        fmt.Sprintf("canary-tamper-%d", time.Now().UnixNano()),
				Timestamp: time.Now(),
				RuleID:    "canary_tampered",
				RuleName:  "Canary File Tampered",
				Severity:  types.Severity(m.cfg.AlertSeverity),
				Message:   fmt.Sprintf("canary file %s missing or modified", rec.path),
				Details:   map[string]interface{}{"path": rec.path},
			})
		}
	}
}

func (m *Manager) checkFileIntact(rec fileRecord) bool {
	hash, mode, err := hashFile(rec.path)
	if err != nil {
		return false
	}
	return hash == rec.sha256 && mode == rec.mode
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

func hashFile(path string) ([32]byte, os.FileMode, error) {
	info, err := os.Stat(path)
	if err != nil {
		return [32]byte{}, 0, err
	}
	f, err := os.Open(path)
	if err != nil {
		return [32]byte{}, 0, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return [32]byte{}, 0, err
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum, info.Mode(), nil
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
