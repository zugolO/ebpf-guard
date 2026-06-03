// Package feedback handles analyst false-positive feedback for alerts.
// When an analyst marks an alert as a false positive, the Manager:
//  1. Adds the (ruleID, comm) pair to an in-memory suppression set so future
//     alerts from the same process triggering the same rule are dropped.
//  2. For anomaly alerts, the comm is added to an anomaly suppression set.
//  3. Persists all feedback records to a YAML file so suppressions survive restarts.
package feedback

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"gopkg.in/yaml.v3"
)

// Verdict classifies an analyst's judgement on an alert.
type Verdict string

const (
	VerdictFalsePositive Verdict = "false_positive"
	VerdictTruePositive  Verdict = "true_positive"
)

// Request is the JSON body accepted by POST /api/v1/alerts/{id}/feedback.
type Request struct {
	Verdict Verdict `json:"verdict"`
	Reason  string  `json:"reason,omitempty"`
}

// Response is returned to the caller after feedback is recorded.
type Response struct {
	AlertID    string  `json:"alert_id"`
	Verdict    Verdict `json:"verdict"`
	Suppressed bool    `json:"suppressed"` // true when a new suppression was added
}

// Record is a single feedback entry, persisted to YAML.
type Record struct {
	AlertID   string    `json:"alert_id"             yaml:"alert_id"`
	Verdict   Verdict   `json:"verdict"              yaml:"verdict"`
	RuleID    string    `json:"rule_id"              yaml:"rule_id"`
	Comm      string    `json:"comm"                 yaml:"comm"`
	Timestamp time.Time `json:"timestamp"            yaml:"timestamp"`
	Reason    string    `json:"reason,omitempty"     yaml:"reason,omitempty"`
}

// suppressKey identifies a (ruleID, comm) suppression entry.
type suppressKey struct {
	ruleID string
	comm   string
}

// anomalyRuleID is the rule ID used by the correlation engine for anomaly alerts.
const anomalyRuleID = "anomaly_detection"

// Manager records analyst feedback and enforces suppressions at alert generation time.
type Manager struct {
	mu                  sync.RWMutex
	records             []Record
	suppressions        map[suppressKey]struct{} // (ruleID, comm) → suppress
	anomalySuppressions map[string]struct{}      // comm → suppress anomaly alerts
	exportPath          string
	logger              *slog.Logger
}

// persistFile is the YAML structure written to disk.
type persistFile struct {
	Records []Record `yaml:"records"`
}

// NewManager creates a new Manager. exportPath is the YAML file used for persistence
// (empty string disables file export/load).
func NewManager(exportPath string, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{
		records:             make([]Record, 0),
		suppressions:        make(map[suppressKey]struct{}),
		anomalySuppressions: make(map[string]struct{}),
		exportPath:          exportPath,
		logger:              logger,
	}
}

// Submit records analyst feedback for alert and applies suppression if the verdict
// is false_positive. Returns the response and an error if persistence fails.
func (m *Manager) Submit(alert types.Alert, verdict Verdict, reason string) (Response, error) {
	rec := Record{
		AlertID:   alert.ID,
		Verdict:   verdict,
		RuleID:    alert.RuleID,
		Comm:      alert.Comm,
		Timestamp: time.Now().UTC(),
		Reason:    reason,
	}

	m.mu.Lock()
	m.records = append(m.records, rec)

	suppressed := false
	if verdict == VerdictFalsePositive {
		key := suppressKey{ruleID: alert.RuleID, comm: alert.Comm}
		if _, exists := m.suppressions[key]; !exists {
			m.suppressions[key] = struct{}{}
			suppressed = true
		}
		// Anomaly alerts use a generic rule ID; suppress by comm only.
		if alert.RuleID == anomalyRuleID {
			if _, exists := m.anomalySuppressions[alert.Comm]; !exists {
				m.anomalySuppressions[alert.Comm] = struct{}{}
				suppressed = true
			}
		}
	}
	m.mu.Unlock()

	m.logger.Info("feedback: recorded",
		slog.String("alert_id", alert.ID),
		slog.String("verdict", string(verdict)),
		slog.String("rule_id", alert.RuleID),
		slog.String("comm", alert.Comm),
		slog.Bool("suppressed", suppressed),
	)

	if err := m.ExportToFile(); err != nil {
		m.logger.Warn("feedback: failed to persist to file", slog.Any("err", err))
		// Return the response but propagate the error so callers can log it.
		return Response{AlertID: alert.ID, Verdict: verdict, Suppressed: suppressed}, err
	}

	return Response{AlertID: alert.ID, Verdict: verdict, Suppressed: suppressed}, nil
}

// IsSuppressed returns true when future alerts from (ruleID, comm) should be dropped.
func (m *Manager) IsSuppressed(ruleID, comm string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.suppressions[suppressKey{ruleID: ruleID, comm: comm}]
	if ok {
		return true
	}
	// Check anomaly suppression.
	if ruleID == anomalyRuleID {
		_, ok = m.anomalySuppressions[comm]
	}
	return ok
}

// FilterAlerts removes alerts whose (ruleID, comm) pair is suppressed.
// It returns the subset of alerts that should still be emitted.
func (m *Manager) FilterAlerts(alerts []types.Alert) []types.Alert {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := alerts[:0:len(alerts)] // reuse backing array
	for _, a := range alerts {
		key := suppressKey{ruleID: a.RuleID, comm: a.Comm}
		if _, suppressed := m.suppressions[key]; suppressed {
			m.logger.Debug("feedback: suppressed alert",
				slog.String("rule_id", a.RuleID),
				slog.String("comm", a.Comm),
			)
			continue
		}
		if a.RuleID == anomalyRuleID {
			if _, suppressed := m.anomalySuppressions[a.Comm]; suppressed {
				continue
			}
		}
		out = append(out, a)
	}
	return out
}

// Records returns a copy of all recorded feedback.
func (m *Manager) Records() []Record {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cp := make([]Record, len(m.records))
	copy(cp, m.records)
	return cp
}

// SuppressionCount returns the number of active suppression entries.
func (m *Manager) SuppressionCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.suppressions) + len(m.anomalySuppressions)
}

// ExportToFile writes all feedback records to the configured YAML export path.
// A no-op when exportPath is empty.
func (m *Manager) ExportToFile() error {
	if m.exportPath == "" {
		return nil
	}

	m.mu.RLock()
	recs := make([]Record, len(m.records))
	copy(recs, m.records)
	m.mu.RUnlock()

	data, err := yaml.Marshal(persistFile{Records: recs})
	if err != nil {
		return fmt.Errorf("feedback: marshal: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(m.exportPath), 0o750); err != nil {
		return fmt.Errorf("feedback: mkdir: %w", err)
	}
	if err := os.WriteFile(m.exportPath, data, 0o640); err != nil {
		return fmt.Errorf("feedback: write: %w", err)
	}
	return nil
}

// LoadFromFile reads previously persisted feedback records and rebuilds the
// suppression sets. Safe to call at startup before any events are processed.
func (m *Manager) LoadFromFile() error {
	if m.exportPath == "" {
		return nil
	}

	data, err := os.ReadFile(m.exportPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // nothing persisted yet
		}
		return fmt.Errorf("feedback: read: %w", err)
	}

	var pf persistFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return fmt.Errorf("feedback: unmarshal: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, rec := range pf.Records {
		m.records = append(m.records, rec)
		if rec.Verdict == VerdictFalsePositive {
			m.suppressions[suppressKey{ruleID: rec.RuleID, comm: rec.Comm}] = struct{}{}
			if rec.RuleID == anomalyRuleID {
				m.anomalySuppressions[rec.Comm] = struct{}{}
			}
		}
	}

	m.logger.Info("feedback: loaded from file",
		slog.Int("records", len(pf.Records)),
		slog.Int("suppressions", len(m.suppressions)),
		slog.String("path", m.exportPath),
	)
	return nil
}
