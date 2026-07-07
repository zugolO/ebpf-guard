package main

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/internal/store"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// writeMinimalConfig writes a config YAML pointing rules.path and store
// settings at the given directories/backends, relying on setDefaults for
// everything else, and returns its path.
func writeMinimalConfig(t *testing.T, rulesPath, storeBackend, sqlitePath string) string {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	content := fmt.Sprintf(`
rules:
  path: %q
store:
  backend: %q
  sqlite:
    path: %q
`, rulesPath, storeBackend, sqlitePath)
	writeFile(t, cfgPath, content)
	return cfgPath
}

func TestNewVersionCmd(t *testing.T) {
	cmd := newVersionCmd()
	out := captureStdout(t, func() {
		cmd.Run(cmd, nil)
	})
	if !strings.Contains(out, "ebpf-guard") || !strings.Contains(out, Version) {
		t.Errorf("version output = %q, want it to contain %q and %q", out, "ebpf-guard", Version)
	}
	if !strings.Contains(out, Commit) {
		t.Errorf("version output = %q, want it to contain commit %q", out, Commit)
	}
}

func TestNewVersionCmd_WithBuildTime(t *testing.T) {
	orig := BuildTime
	BuildTime = "2026-01-01T00:00:00Z"
	defer func() { BuildTime = orig }()

	cmd := newVersionCmd()
	out := captureStdout(t, func() {
		cmd.Run(cmd, nil)
	})
	if !strings.Contains(out, "built 2026-01-01T00:00:00Z") {
		t.Errorf("version output = %q, want it to mention build time", out)
	}
}

func TestNewStatusCmd(t *testing.T) {
	cmd := newStatusCmd()
	out := captureStdout(t, func() {
		cmd.Run(cmd, nil)
	})
	if !strings.Contains(out, "/health") {
		t.Errorf("status output = %q, want it to mention /health", out)
	}
}

func TestNewRootCmd_Wiring(t *testing.T) {
	root := newRootCmd()
	if root.Use != "ebpf-guard" {
		t.Errorf("root.Use = %q, want ebpf-guard", root.Use)
	}
	wantSubcommands := []string{"alerts", "status", "rules", "version", "learn", "dashboard", "config", "attack-sim", "plugins"}
	got := make(map[string]bool)
	for _, c := range root.Commands() {
		got[c.Name()] = true
	}
	for _, want := range wantSubcommands {
		if !got[want] {
			t.Errorf("newRootCmd() missing subcommand %q; got %v", want, got)
		}
	}
}

func TestNewRootCmd_VersionFlag(t *testing.T) {
	root := newRootCmd()
	root.SetArgs([]string{"version"})
	out := captureStdout(t, func() {
		if err := root.Execute(); err != nil {
			t.Errorf("root.Execute() error = %v", err)
		}
	})
	if !strings.Contains(out, "ebpf-guard") {
		t.Errorf("root version subcommand output = %q", out)
	}
}

func TestNewRulesCmd_ListsLoadedRules(t *testing.T) {
	rulesDir := t.TempDir()
	writeFile(t, filepath.Join(rulesDir, "r.yaml"), minimalRuleYAML("rulescmd_rule_one"))
	cfgPath := writeMinimalConfig(t, rulesDir, "memory", "")

	cmd := newRulesCmd(&cfgPath)
	out := captureStdout(t, func() {
		if err := cmd.RunE(cmd, nil); err != nil {
			t.Errorf("rules cmd RunE error = %v", err)
		}
	})
	if !strings.Contains(out, "loaded 1 rules") {
		t.Errorf("rules cmd output = %q, want it to report 1 loaded rule", out)
	}
	if !strings.Contains(out, "rulescmd_rule_one") {
		t.Errorf("rules cmd output = %q, want it to list the rule ID", out)
	}
}

func TestNewRulesCmd_InvalidRulesPath(t *testing.T) {
	cfgPath := writeMinimalConfig(t, filepath.Join(t.TempDir(), "missing"), "memory", "")

	cmd := newRulesCmd(&cfgPath)
	err := cmd.RunE(cmd, nil)
	if err == nil {
		t.Fatal("rules cmd RunE error = nil, want error for missing rules path")
	}
}

func TestNewRulesCmd_InvalidConfigPath(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.yaml")
	cmd := newRulesCmd(&missing)
	err := cmd.RunE(cmd, nil)
	if err == nil {
		t.Fatal("rules cmd RunE error = nil, want error for missing config")
	}
}

// seedSQLiteAlerts opens a sqlite alert store at path, writes the given
// alerts, and closes it — simulating alerts a running agent would have
// already persisted before `ebpf-guard alerts` is invoked against the same
// database file.
func seedSQLiteAlerts(t *testing.T, path string, alerts []types.Alert) {
	t.Helper()
	st, err := store.New(store.Config{
		Backend: "sqlite",
		SQLite:  store.SQLiteConfig{Path: path, MaxOpenConns: 1},
	})
	if err != nil {
		t.Fatalf("open sqlite store: %v", err)
	}
	defer st.Close()
	if err := st.StoreBatch(context.Background(), alerts); err != nil {
		t.Fatalf("seed alerts: %v", err)
	}
}

func TestNewAlertsCmd_PrintsStoredAlerts(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "alerts.db")
	seedSQLiteAlerts(t, dbPath, []types.Alert{
		{
			ID:        "a1",
			Timestamp: time.Now(),
			RuleID:    "cryptominer_pool_ports",
			Severity:  types.SeverityCritical,
			PID:       1234,
			Comm:      "xmrig",
			Message:   "connected to a mining pool",
		},
	})
	cfgPath := writeMinimalConfig(t, t.TempDir(), "sqlite", dbPath)

	cmd := newAlertsCmd(&cfgPath)
	out := captureStdout(t, func() {
		if err := cmd.RunE(cmd, nil); err != nil {
			t.Errorf("alerts cmd RunE error = %v", err)
		}
	})
	if !strings.Contains(out, "cryptominer_pool_ports") || !strings.Contains(out, "xmrig") {
		t.Errorf("alerts cmd output = %q, want it to contain the seeded alert", out)
	}
	if !strings.Contains(out, "connected to a mining pool") {
		t.Errorf("alerts cmd output = %q, want it to contain the alert message", out)
	}
}

func TestNewAlertsCmd_NoAlertsFound(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "empty.db")
	cfgPath := writeMinimalConfig(t, t.TempDir(), "sqlite", dbPath)

	cmd := newAlertsCmd(&cfgPath)
	out := captureStdout(t, func() {
		if err := cmd.RunE(cmd, nil); err != nil {
			t.Errorf("alerts cmd RunE error = %v", err)
		}
	})
	if !strings.Contains(out, "no alerts found") {
		t.Errorf("alerts cmd output = %q, want %q", out, "no alerts found")
	}
}

func TestNewAlertsCmd_SeverityFilter(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "alerts.db")
	seedSQLiteAlerts(t, dbPath, []types.Alert{
		{ID: "a1", Timestamp: time.Now(), RuleID: "r1", Severity: types.SeverityCritical, Comm: "critcomm"},
		{ID: "a2", Timestamp: time.Now(), RuleID: "r2", Severity: types.SeverityWarning, Comm: "warncomm"},
	})
	cfgPath := writeMinimalConfig(t, t.TempDir(), "sqlite", dbPath)

	cmd := newAlertsCmd(&cfgPath)
	if err := cmd.Flags().Set("severity", "critical"); err != nil {
		t.Fatalf("set --severity: %v", err)
	}
	out := captureStdout(t, func() {
		if err := cmd.RunE(cmd, nil); err != nil {
			t.Errorf("alerts cmd RunE error = %v", err)
		}
	})
	if !strings.Contains(out, "critcomm") {
		t.Errorf("alerts cmd output = %q, want critical alert present", out)
	}
	if strings.Contains(out, "warncomm") {
		t.Errorf("alerts cmd output = %q, want warning alert filtered out", out)
	}
}

func TestNewAlertsCmd_InvalidSinceDuration(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "alerts.db")
	cfgPath := writeMinimalConfig(t, t.TempDir(), "sqlite", dbPath)

	cmd := newAlertsCmd(&cfgPath)
	if err := cmd.Flags().Set("since", "not-a-duration"); err != nil {
		t.Fatalf("set --since: %v", err)
	}
	if err := cmd.RunE(cmd, nil); err == nil {
		t.Fatal("alerts cmd RunE error = nil, want error for invalid --since")
	}
}

func TestNewAlertsCmd_InvalidConfigPath(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.yaml")
	cmd := newAlertsCmd(&missing)
	if err := cmd.RunE(cmd, nil); err == nil {
		t.Fatal("alerts cmd RunE error = nil, want error for missing config")
	}
}
