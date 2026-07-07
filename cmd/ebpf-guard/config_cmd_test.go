package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunConfigValidate_NoIssues(t *testing.T) {
	cfgPath := writeMinimalConfig(t, t.TempDir(), "memory", "")
	out := captureStdout(t, func() {
		if err := runConfigValidate(cfgPath); err != nil {
			t.Errorf("runConfigValidate error = %v", err)
		}
	})
	if !strings.Contains(out, "0 issues found") {
		t.Errorf("runConfigValidate output = %q, want '0 issues found'", out)
	}
	if !strings.Contains(out, "✓ store: OK") {
		t.Errorf("runConfigValidate output = %q, want section OK markers", out)
	}
}

func TestRunConfigValidate_DeprecatedAndRemovedFields(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	writeFile(t, cfgPath, `
config_version: "v0.1"
profiler:
  ewma_weight: 0.3
alerting:
  webhook_url: "http://old-alertmanager/webhook"
`)

	var runErr error
	out := captureStdout(t, func() {
		runErr = runConfigValidate(cfgPath)
	})
	if runErr == nil {
		t.Fatal("runConfigValidate error = nil, want error for deprecated/removed fields")
	}
	if !strings.Contains(out, "profiler.ewma_weight") {
		t.Errorf("runConfigValidate output = %q, want it to flag profiler.ewma_weight", out)
	}
	if !strings.Contains(out, "alerting.webhook_url") {
		t.Errorf("runConfigValidate output = %q, want it to flag alerting.webhook_url", out)
	}
	if !strings.Contains(out, "issue(s) found") {
		t.Errorf("runConfigValidate output = %q, want an issue count summary", out)
	}
}

func TestRunConfigValidate_MissingFile(t *testing.T) {
	err := runConfigValidate(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err == nil {
		t.Fatal("runConfigValidate(missing file) error = nil, want error")
	}
}

func TestRunConfigMigrate_WritesMigratedFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	writeFile(t, cfgPath, `
config_version: "v0.1"
profiler:
  ewma_weight: 0.42
alerting:
  webhook_url: "http://old-alertmanager/webhook"
`)
	outPath := filepath.Join(dir, "out.yaml")

	out := captureStdout(t, func() {
		if err := runConfigMigrate(cfgPath, "v0.2.0", outPath); err != nil {
			t.Errorf("runConfigMigrate error = %v", err)
		}
	})
	if !strings.Contains(out, "Migration complete") {
		t.Errorf("runConfigMigrate output = %q, want a completion message", out)
	}

	migrated, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read migrated file: %v", err)
	}
	if !strings.Contains(string(migrated), "ewma") {
		t.Errorf("migrated config = %q, want renamed ewma field present", migrated)
	}
	if strings.Contains(string(migrated), "webhook_url") {
		t.Errorf("migrated config = %q, want removed webhook_url field gone", migrated)
	}
}

func TestRunConfigMigrate_DefaultOutPath(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	writeFile(t, cfgPath, `config_version: "v0.1"`)

	captureStdout(t, func() {
		if err := runConfigMigrate(cfgPath, "v0.2.0", ""); err != nil {
			t.Errorf("runConfigMigrate error = %v", err)
		}
	})
	wantPath := filepath.Join(dir, "config.migrated.yaml")
	if _, err := os.Stat(wantPath); err != nil {
		t.Errorf("expected default migrated output at %s: %v", wantPath, err)
	}
}

func TestRunConfigMigrate_MissingFile(t *testing.T) {
	err := runConfigMigrate(filepath.Join(t.TempDir(), "does-not-exist.yaml"), "v0.2.0", "")
	if err == nil {
		t.Fatal("runConfigMigrate(missing file) error = nil, want error")
	}
}

func TestNewConfigCmd_HasValidateAndMigrateSubcommands(t *testing.T) {
	cmd := newConfigCmd()
	names := make(map[string]bool)
	for _, c := range cmd.Commands() {
		names[c.Name()] = true
	}
	if !names["validate"] || !names["migrate"] {
		t.Errorf("config cmd subcommands = %v, want validate and migrate", names)
	}
}
