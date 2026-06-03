package feedback

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeAlert(id, ruleID, comm string) types.Alert {
	return types.Alert{
		ID:        id,
		RuleID:    ruleID,
		Comm:      comm,
		Severity:  types.SeverityWarning,
		Timestamp: time.Now(),
	}
}

func TestManager_Submit_FalsePositive(t *testing.T) {
	m := NewManager("", nil)
	alert := makeAlert("alert-1", "rule_001", "nginx")

	resp, err := m.Submit(alert, VerdictFalsePositive, "noisy rule")
	require.NoError(t, err)
	assert.Equal(t, "alert-1", resp.AlertID)
	assert.Equal(t, VerdictFalsePositive, resp.Verdict)
	assert.True(t, resp.Suppressed)
	assert.True(t, m.IsSuppressed("rule_001", "nginx"))
}

func TestManager_Submit_TruePositive_NoSuppression(t *testing.T) {
	m := NewManager("", nil)
	alert := makeAlert("alert-2", "rule_002", "curl")

	resp, err := m.Submit(alert, VerdictTruePositive, "")
	require.NoError(t, err)
	assert.False(t, resp.Suppressed)
	assert.False(t, m.IsSuppressed("rule_002", "curl"))
}

func TestManager_Submit_Idempotent(t *testing.T) {
	m := NewManager("", nil)
	alert := makeAlert("alert-3", "rule_001", "bash")

	_, _ = m.Submit(alert, VerdictFalsePositive, "")
	resp, err := m.Submit(alert, VerdictFalsePositive, "duplicate")
	require.NoError(t, err)
	// Second submission should record the feedback but not report suppressed=true again.
	assert.False(t, resp.Suppressed)
	assert.Equal(t, 2, len(m.Records()))
}

func TestManager_FilterAlerts(t *testing.T) {
	m := NewManager("", nil)
	_, _ = m.Submit(makeAlert("a1", "rule_001", "nginx"), VerdictFalsePositive, "")

	alerts := []types.Alert{
		makeAlert("b1", "rule_001", "nginx"),   // suppressed
		makeAlert("b2", "rule_001", "apache2"),  // different comm — NOT suppressed
		makeAlert("b3", "rule_002", "nginx"),    // different rule — NOT suppressed
	}

	filtered := m.FilterAlerts(alerts)
	require.Len(t, filtered, 2)
	assert.Equal(t, "b2", filtered[0].ID)
	assert.Equal(t, "b3", filtered[1].ID)
}

func TestManager_AnomalySuppression(t *testing.T) {
	m := NewManager("", nil)
	alert := makeAlert("a1", anomalyRuleID, "malware")

	_, _ = m.Submit(alert, VerdictFalsePositive, "")
	assert.True(t, m.IsSuppressed(anomalyRuleID, "malware"))

	alerts := []types.Alert{
		{ID: "x1", RuleID: anomalyRuleID, Comm: "malware"},
		{ID: "x2", RuleID: anomalyRuleID, Comm: "other"},
	}
	filtered := m.FilterAlerts(alerts)
	require.Len(t, filtered, 1)
	assert.Equal(t, "x2", filtered[0].ID)
}

func TestManager_IsSuppressed_UnknownKey(t *testing.T) {
	m := NewManager("", nil)
	assert.False(t, m.IsSuppressed("unknown_rule", "unknown_comm"))
}

func TestManager_Records(t *testing.T) {
	m := NewManager("", nil)
	_, _ = m.Submit(makeAlert("a1", "r1", "bash"), VerdictFalsePositive, "")
	_, _ = m.Submit(makeAlert("a2", "r2", "curl"), VerdictTruePositive, "")

	recs := m.Records()
	require.Len(t, recs, 2)
	assert.Equal(t, "a1", recs[0].AlertID)
	assert.Equal(t, "a2", recs[1].AlertID)
}

func TestManager_ExportAndLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "feedback.yaml")

	m1 := NewManager(path, nil)
	_, err := m1.Submit(makeAlert("a1", "rule_001", "nginx"), VerdictFalsePositive, "too noisy")
	require.NoError(t, err)
	_, err = m1.Submit(makeAlert("a2", "rule_002", "bash"), VerdictTruePositive, "")
	require.NoError(t, err)

	// File should exist.
	_, err = os.Stat(path)
	require.NoError(t, err)

	// Load into fresh manager and check state is restored.
	m2 := NewManager(path, nil)
	require.NoError(t, m2.LoadFromFile())

	recs := m2.Records()
	require.Len(t, recs, 2)
	assert.True(t, m2.IsSuppressed("rule_001", "nginx"), "suppression should be restored")
	assert.False(t, m2.IsSuppressed("rule_002", "bash"), "true positive should not be suppressed")
}

func TestManager_LoadFromFile_MissingFile(t *testing.T) {
	m := NewManager("/nonexistent/path/feedback.yaml", nil)
	assert.NoError(t, m.LoadFromFile(), "missing file should be a no-op")
}

func TestManager_SuppressionCount(t *testing.T) {
	m := NewManager("", nil)
	assert.Equal(t, 0, m.SuppressionCount())
	_, _ = m.Submit(makeAlert("a1", "rule_001", "nginx"), VerdictFalsePositive, "")
	assert.Equal(t, 1, m.SuppressionCount())
}
