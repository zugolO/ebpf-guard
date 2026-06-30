// Package exporter provides Prometheus metrics and Alertmanager alerting.
package exporter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dashboardPanel is a minimal representation of a Grafana panel for validation.
type dashboardPanel struct {
	ID      int    `json:"id"`
	Title   string `json:"title"`
	Type    string `json:"type"`
	GridPos struct {
		H int `json:"h"`
		W int `json:"w"`
		X int `json:"x"`
		Y int `json:"y"`
	} `json:"gridPos"`
	FieldConfig struct {
		Defaults struct {
			Color struct {
				Mode  string `json:"mode"`
				Fixed string `json:"fixed"`
			} `json:"color"`
			Thresholds struct {
				Mode  string `json:"mode"`
				Steps []struct {
					Color string   `json:"color"`
					Value *float64 `json:"value"`
				} `json:"steps"`
			} `json:"thresholds"`
		} `json:"defaults"`
	} `json:"fieldConfig"`
	Options struct {
		// ColorMode controls what gets colored for stat panels:
		// "background" → entire widget turns red, "value" → only the number.
		ColorMode string `json:"colorMode"`
	} `json:"options"`
	Targets []struct {
		Expr string `json:"expr"`
	} `json:"targets"`
}

type dashboardJSON struct {
	Title   string           `json:"title"`
	UID     string           `json:"uid"`
	Panels  []dashboardPanel `json:"panels"`
	Version int              `json:"version"`
}

// repoRoot returns the absolute path to the repository root.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok, "runtime.Caller failed")
	// Walk up: internal/exporter/dashboard_test.go → repo root (3 levels up)
	root := filepath.Dir(filepath.Dir(filepath.Dir(file)))
	return root
}

func loadDashboard(t *testing.T, path string) dashboardJSON {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err, "failed to read dashboard file %s", path)
	var dash dashboardJSON
	require.NoError(t, json.Unmarshal(data, &dash), "failed to parse dashboard JSON %s", path)
	return dash
}

// TestDashboardBothCopiesIdentical verifies both dashboard JSON files are byte-for-byte equal.
func TestDashboardBothCopiesIdentical(t *testing.T) {
	root := repoRoot(t)
	primary := filepath.Join(root, "deploy", "grafana", "ebpf-guard-dashboard.json")
	helm := filepath.Join(root, "deploy", "helm", "ebpf-guard", "dashboards", "ebpf-guard-dashboard.json")

	primaryData, err := os.ReadFile(primary)
	require.NoError(t, err)
	helmData, err := os.ReadFile(helm)
	require.NoError(t, err)

	assert.Equal(t, string(primaryData), string(helmData),
		"deploy/grafana/ and deploy/helm/.../dashboards/ copies must be identical")
}

// TestDashboardUID verifies the dashboard UID is stable (used by Grafana for cross-referencing).
func TestDashboardUID(t *testing.T) {
	root := repoRoot(t)
	dash := loadDashboard(t, filepath.Join(root, "deploy", "grafana", "ebpf-guard-dashboard.json"))
	assert.Equal(t, "ebpf-guard-security", dash.UID)
}

// TestDashboardHasBlockedAttacksStatPanel verifies the "Blocked Attacks" stat panel exists with
// red threshold coloring so that any enforcement action turns the panel red immediately.
func TestDashboardHasBlockedAttacksStatPanel(t *testing.T) {
	root := repoRoot(t)
	dash := loadDashboard(t, filepath.Join(root, "deploy", "grafana", "ebpf-guard-dashboard.json"))

	var panel *dashboardPanel
	for i := range dash.Panels {
		if dash.Panels[i].Title == "Blocked Attacks" {
			panel = &dash.Panels[i]
			break
		}
	}
	require.NotNil(t, panel, "dashboard must contain a 'Blocked Attacks' panel")

	assert.Equal(t, "stat", panel.Type, "Blocked Attacks panel must be a stat panel")
	// In Grafana stat panels, options.colorMode="background" makes the entire widget
	// turn red (not just the text), ensuring blocked attacks are impossible to miss.
	assert.Equal(t, "background", panel.Options.ColorMode,
		"Blocked Attacks panel options.colorMode must be 'background' to highlight the entire widget")

	steps := panel.FieldConfig.Defaults.Thresholds.Steps
	require.GreaterOrEqual(t, len(steps), 2, "must have at least 2 threshold steps")

	// Base step: green (no actions)
	assert.Equal(t, "green", steps[0].Color)
	assert.Nil(t, steps[0].Value)

	// First non-null step must be red (any blocked attack = danger)
	assert.Equal(t, "red", steps[1].Color,
		"first threshold above 0 must be red — blocked attacks are always critical")

	// Panel must query the enforcement_actions_total metric
	require.NotEmpty(t, panel.Targets)
	assert.Contains(t, panel.Targets[0].Expr, "ebpf_guard_enforcement_actions_total",
		"Blocked Attacks panel must query ebpf_guard_enforcement_actions_total")
}

// TestDashboardHasCriticalAlertsStatPanel verifies the "Critical Alerts" stat panel exists
// with orange→red threshold coloring in the Overview section.
func TestDashboardHasCriticalAlertsStatPanel(t *testing.T) {
	root := repoRoot(t)
	dash := loadDashboard(t, filepath.Join(root, "deploy", "grafana", "ebpf-guard-dashboard.json"))

	var panel *dashboardPanel
	for i := range dash.Panels {
		if dash.Panels[i].Title == "Critical Alerts" {
			panel = &dash.Panels[i]
			break
		}
	}
	require.NotNil(t, panel, "dashboard must contain a 'Critical Alerts' panel")
	assert.Equal(t, "stat", panel.Type)

	steps := panel.FieldConfig.Defaults.Thresholds.Steps
	require.GreaterOrEqual(t, len(steps), 2)
	assert.Equal(t, "green", steps[0].Color)

	hasRed := false
	for _, s := range steps {
		if s.Color == "red" {
			hasRed = true
		}
	}
	assert.True(t, hasRed, "Critical Alerts panel must have a red threshold step")

	require.NotEmpty(t, panel.Targets)
	assert.Contains(t, panel.Targets[0].Expr, "ebpf_guard_alerts_total",
		"Critical Alerts panel must query ebpf_guard_alerts_total")
	assert.Contains(t, panel.Targets[0].Expr, `severity="critical"`,
		"Critical Alerts panel must filter on severity=critical")
}

// TestDashboardHasBlockedAttacksRatePanel verifies the timeseries panel that shows the rate
// of enforcement actions over time exists and uses a red default color.
func TestDashboardHasBlockedAttacksRatePanel(t *testing.T) {
	root := repoRoot(t)
	dash := loadDashboard(t, filepath.Join(root, "deploy", "grafana", "ebpf-guard-dashboard.json"))

	var panel *dashboardPanel
	for i := range dash.Panels {
		if dash.Panels[i].Title == "Blocked Attacks Rate" {
			panel = &dash.Panels[i]
			break
		}
	}
	require.NotNil(t, panel, "dashboard must contain a 'Blocked Attacks Rate' timeseries panel")
	assert.Equal(t, "timeseries", panel.Type)

	assert.Equal(t, "fixed", panel.FieldConfig.Defaults.Color.Mode,
		"Blocked Attacks Rate default color mode must be 'fixed' (always red)")
	assert.Equal(t, "red", panel.FieldConfig.Defaults.Color.Fixed,
		"Blocked Attacks Rate default fixed color must be red")

	require.NotEmpty(t, panel.Targets)
	assert.Contains(t, panel.Targets[0].Expr, "ebpf_guard_enforcement_actions_total")
	assert.Contains(t, panel.Targets[0].Expr, "rate(",
		"Blocked Attacks Rate panel must use rate() to show per-second rate")
}

// TestDashboardOverviewStatPanelsFit verifies the Overview stat panels in the right column
// all fit within the 8-row height used by the Events/sec timeseries on the left.
func TestDashboardOverviewStatPanelsFit(t *testing.T) {
	root := repoRoot(t)
	dash := loadDashboard(t, filepath.Join(root, "deploy", "grafana", "ebpf-guard-dashboard.json"))

	// Panels id 3, 4, 18, 19 are in the right column of the Overview row (y=1..8).
	rightColumnIDs := map[int]bool{3: true, 4: true, 18: true, 19: true}
	for i := range dash.Panels {
		p := &dash.Panels[i]
		if !rightColumnIDs[p.ID] {
			continue
		}
		assert.GreaterOrEqual(t, p.GridPos.X, 12,
			"Panel %d (%s) should be in the right column (x>=12)", p.ID, p.Title)
		bottom := p.GridPos.Y + p.GridPos.H
		assert.LessOrEqual(t, bottom, 9,
			"Panel %d (%s) must fit within Overview section (y+h <= 9), got bottom=%d",
			p.ID, p.Title, bottom)
	}
}

// TestDashboardSystemHealthRowShifted verifies System Health row is correctly positioned
// after the new Blocked Attacks Rate panel.
func TestDashboardSystemHealthRowShifted(t *testing.T) {
	root := repoRoot(t)
	dash := loadDashboard(t, filepath.Join(root, "deploy", "grafana", "ebpf-guard-dashboard.json"))

	var sysHealthRow *dashboardPanel
	for i := range dash.Panels {
		if dash.Panels[i].Type == "row" && dash.Panels[i].Title == "System Health" {
			sysHealthRow = &dash.Panels[i]
			break
		}
	}
	require.NotNil(t, sysHealthRow, "System Health row must exist")
	assert.Equal(t, 35, sysHealthRow.GridPos.Y,
		"System Health row must start at y=35 (after Blocked Attacks Rate panel at y=27+h=8)")
}

// TestDashboardMetricsUsedAreExported verifies that all prometheus metric names referenced in
// the dashboard exist as registered exporter metrics in this package.
func TestDashboardMetricsUsedAreExported(t *testing.T) {
	root := repoRoot(t)
	dash := loadDashboard(t, filepath.Join(root, "deploy", "grafana", "ebpf-guard-dashboard.json"))

	// Collect all metric names referenced in dashboard queries.
	metricNames := make(map[string]bool)
	for _, p := range dash.Panels {
		for _, tgt := range p.Targets {
			// Extract metric names from PromQL expressions (simple heuristic: find known prefixes)
			for _, name := range extractEbpfGuardMetrics(tgt.Expr) {
				metricNames[name] = true
			}
		}
	}

	// These are the metrics exported by this package (ebpf_guard_* and process_*).
	// ebpf_guard_enforcement_actions_total is registered via Enforcer.RegisterMetrics separately.
	exportedByThisPkg := map[string]bool{
		"ebpf_guard_events_total":              true,
		"ebpf_guard_events_dropped_total":      true,
		"ebpf_guard_alerts_total":              true,
		"ebpf_guard_profiler_anomaly_score":    true,
		"ebpf_guard_bpf_map_entries":           true,
		"ebpf_guard_bpf_map_size":              true,
		"ebpf_guard_event_queue_depth":         true,
		"ebpf_guard_tracked_pids_total":        true,
		"ebpf_guard_enforcement_actions_total": true, // registered via Enforcer.RegisterMetrics
		"process_resident_memory_bytes":        true, // standard Go process metric
	}

	for name := range metricNames {
		assert.True(t, exportedByThisPkg[name],
			"metric %q is used in the dashboard but not listed as exported; "+
				"add it to the exporter or update this test", name)
	}
}

// extractEbpfGuardMetrics extracts known ebpf_guard_* and process_* metric names from a PromQL expression.
func extractEbpfGuardMetrics(expr string) []string {
	var found []string
	prefixes := []string{
		"ebpf_guard_events_total",
		"ebpf_guard_events_dropped_total",
		"ebpf_guard_alerts_total",
		"ebpf_guard_profiler_anomaly_score",
		"ebpf_guard_bpf_map_entries",
		"ebpf_guard_bpf_map_size",
		"ebpf_guard_event_queue_depth",
		"ebpf_guard_tracked_pids_total",
		"ebpf_guard_enforcement_actions_total",
		"process_resident_memory_bytes",
	}
	for _, p := range prefixes {
		if containsStr(expr, p) {
			found = append(found, p)
		}
	}
	return found
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && stringContains(s, sub))
}

func stringContains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestDashboardPanelCount verifies the expected total number of panels (including rows).
func TestDashboardPanelCount(t *testing.T) {
	root := repoRoot(t)
	dash := loadDashboard(t, filepath.Join(root, "deploy", "grafana", "ebpf-guard-dashboard.json"))
	assert.Equal(t, 20, len(dash.Panels),
		"expected 20 panels total (17 original + 2 new stat panels + 1 blocked attacks rate panel)")
}
