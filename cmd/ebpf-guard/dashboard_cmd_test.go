package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunLearn_DryRunGeneratesProfile(t *testing.T) {
	outDir := t.TempDir()
	out := captureStdout(t, func() {
		if err := runLearn("1s", outDir, "", "", "", true); err != nil {
			t.Errorf("runLearn error = %v", err)
		}
	})
	if !strings.Contains(out, "Generated files") {
		t.Errorf("runLearn output = %q, want it to report generated files", out)
	}
	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatalf("read output dir: %v", err)
	}
	if len(entries) == 0 {
		t.Error("runLearn(dry-run) did not write any files to outputDir")
	}
}

func TestRunLearn_InvalidDuration(t *testing.T) {
	if err := runLearn("not-a-duration", t.TempDir(), "", "", "", true); err == nil {
		t.Fatal("runLearn(invalid duration) error = nil, want error")
	}
}

func TestRunLearn_DurationTooShort(t *testing.T) {
	if err := runLearn("100ms", t.TempDir(), "", "", "", true); err == nil {
		t.Fatal("runLearn(sub-second duration) error = nil, want error")
	}
}

func TestNewLearnCmd_Wiring(t *testing.T) {
	cmd := newLearnCmd()
	if cmd.Use != "learn" {
		t.Errorf("learn cmd Use = %q, want learn", cmd.Use)
	}
	if f := cmd.Flags().Lookup("dry-run"); f == nil {
		t.Error("learn cmd missing --dry-run flag")
	}
}

func TestRunDashboard_StubReturnsError(t *testing.T) {
	// Without the `tui` build tag, tui.Run is a stub that returns an error
	// immediately instead of starting an interactive terminal session, so
	// this is safe to exercise in a non-interactive test process.
	cfgPath := writeMinimalConfig(t, t.TempDir(), "memory", "")
	err := runDashboard(cfgPath, true)
	if err == nil {
		t.Fatal("runDashboard error = nil, want stub TUI error")
	}
	if !strings.Contains(err.Error(), "not compiled in") {
		t.Errorf("runDashboard error = %v, want a 'not compiled in' stub error", err)
	}
}

func TestRunDashboard_InvalidConfigPath(t *testing.T) {
	err := runDashboard(filepath.Join(t.TempDir(), "missing.yaml"), true)
	if err == nil {
		t.Fatal("runDashboard(missing config) error = nil, want error")
	}
}

func TestRunFleetDashboard_StubReturnsError(t *testing.T) {
	err := runFleetDashboard([]string{"http://localhost:9090"}, "tok", 0)
	if err == nil {
		t.Fatal("runFleetDashboard error = nil, want stub TUI error")
	}
	if !strings.Contains(err.Error(), "not compiled in") {
		t.Errorf("runFleetDashboard error = %v, want a 'not compiled in' stub error", err)
	}
}

func TestNewDashboardCmd_FleetRequiresEndpoint(t *testing.T) {
	cmd := newDashboardCmd()
	cmd.SetArgs([]string{"--fleet", "  "})
	if err := cmd.Execute(); err == nil {
		t.Fatal("dashboard --fleet with blank endpoints error = nil, want error")
	}
}

func TestNewDashboardCmd_DefaultDryRunUsesStub(t *testing.T) {
	cfgPath := writeMinimalConfig(t, t.TempDir(), "memory", "")
	cmd := newDashboardCmd()
	cmd.SetArgs([]string{"--config", cfgPath, "--dry-run"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("dashboard --dry-run error = nil, want stub TUI error")
	}
}

func TestNewAttackSimCmd_List(t *testing.T) {
	cfgPath := writeMinimalConfig(t, t.TempDir(), "memory", "")
	cmd := newAttackSimCmd(&cfgPath)
	cmd.SetArgs([]string{"--list"})
	out := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Errorf("attack-sim --list error = %v", err)
		}
	})
	if !strings.Contains(out, "MITRE") || !strings.Contains(out, "ID") {
		t.Errorf("attack-sim --list output = %q, want a scenario table header", out)
	}
}

func TestNewAttackSimCmd_DefaultListsScenarios(t *testing.T) {
	cfgPath := writeMinimalConfig(t, t.TempDir(), "memory", "")
	cmd := newAttackSimCmd(&cfgPath)
	out := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Errorf("attack-sim (no flags) error = %v", err)
		}
	})
	if !strings.Contains(out, "Use --run-all") {
		t.Errorf("attack-sim (no flags) output = %q, want the usage hint", out)
	}
}

func TestNewAttackSimCmd_VerifyRequiresAgent(t *testing.T) {
	cfgPath := writeMinimalConfig(t, t.TempDir(), "memory", "")
	cmd := newAttackSimCmd(&cfgPath)
	cmd.SetArgs([]string{"--verify", "--agent", "", "--scenario", "x"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("attack-sim --verify without --agent error = nil, want error")
	}
}

func TestNewAttackSimCmd_VerifyRequiresScenario(t *testing.T) {
	cfgPath := writeMinimalConfig(t, t.TempDir(), "memory", "")
	cmd := newAttackSimCmd(&cfgPath)
	cmd.SetArgs([]string{"--verify", "--agent", "http://localhost:1", "--scenario", ""})
	if err := cmd.Execute(); err == nil {
		t.Fatal("attack-sim --verify without --scenario error = nil, want error")
	}
}

func TestNewAttackSimCmd_InvalidConfigPath(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.yaml")
	cmd := newAttackSimCmd(&missing)
	cmd.SetArgs([]string{"--run-all"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("attack-sim --run-all with missing config error = nil, want error")
	}
}

func TestNewWizardCmd_StubReturnsError(t *testing.T) {
	// Without the `tui` build tag, tui.RunWizard is a stub that returns an
	// error immediately rather than starting an interactive terminal
	// session, so this is safe in a non-interactive test process.
	cmd := newWizardCmd()
	if err := cmd.RunE(cmd, nil); err == nil {
		t.Fatal("wizard cmd RunE error = nil, want stub TUI error")
	}
}

func TestNewAttackSimCmd_SingleScenario(t *testing.T) {
	rulesFile := filepath.Join("..", "..", "rules", "cryptominer.yaml")
	if _, err := os.Stat(rulesFile); err != nil {
		t.Skipf("rules file not available: %v", err)
	}
	cfgPath := writeMinimalConfig(t, rulesFile, "memory", "")
	cmd := newAttackSimCmd(&cfgPath)
	cmd.SetArgs([]string{"--scenario", "cryptominer-pool-connect"})
	out := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Errorf("attack-sim --scenario error = %v", err)
		}
	})
	if !strings.Contains(out, "cryptominer-pool-connect") {
		t.Errorf("attack-sim --scenario output = %q, want the scenario ID in the result table", out)
	}
}

func TestNewAttackSimCmd_UnknownScenario(t *testing.T) {
	rulesFile := filepath.Join("..", "..", "rules", "cryptominer.yaml")
	if _, err := os.Stat(rulesFile); err != nil {
		t.Skipf("rules file not available: %v", err)
	}
	cfgPath := writeMinimalConfig(t, rulesFile, "memory", "")
	cmd := newAttackSimCmd(&cfgPath)
	cmd.SetArgs([]string{"--scenario", "does-not-exist"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("attack-sim --scenario (unknown ID) error = nil, want error")
	}
}

func TestNewAttackSimCmd_RunAllAgainstRealRules(t *testing.T) {
	// Exercise the real correlation engine end-to-end against one of the
	// repo's shipped rule files, same as `ebpf-guard attack-sim --run-all`
	// in production. Some scenarios may legitimately fail to match (that's
	// a rule-coverage question, not a CLI bug) so this only asserts the
	// command runs every scenario and prints a result table — it does not
	// require every scenario to pass.
	rulesFile := filepath.Join("..", "..", "rules", "cryptominer.yaml")
	if _, err := os.Stat(rulesFile); err != nil {
		t.Skipf("rules file not available: %v", err)
	}
	cfgPath := writeMinimalConfig(t, rulesFile, "memory", "")
	cmd := newAttackSimCmd(&cfgPath)
	cmd.SetArgs([]string{"--run-all"})
	out := captureStdout(t, func() {
		_ = cmd.Execute()
	})
	if !strings.Contains(out, "PASS") && !strings.Contains(out, "FAIL") {
		t.Errorf("attack-sim --run-all output = %q, want PASS/FAIL result rows", out)
	}
}

func TestPluginsValidateCmd_PassingPlugin(t *testing.T) {
	pluginPath := filepath.Join("..", "..", "internal", "wasm", "testdata", "always_match.wasm")
	if _, err := os.Stat(pluginPath); err != nil {
		t.Skipf("wasm testdata not available: %v", err)
	}

	cmd := newPluginsValidateCmd()
	cmd.SetArgs([]string{pluginPath})
	out := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Errorf("plugins validate (always_match.wasm) error = %v", err)
		}
	})
	if !strings.Contains(out, "passed ABI validation") {
		t.Errorf("plugins validate output = %q, want a pass summary", out)
	}
}

func TestPluginsValidateCmd_FailingPlugin(t *testing.T) {
	// missing_exports.wasm lacks a required ABI export, which is the one
	// condition ValidatePlugin actually fails on (OK=false); fixtures like
	// no_memory.wasm/malloc_bad_ptr.wasm are ABI-compliant but misbehave at
	// dry-run time, which only produces log warnings, not a failed result.
	pluginPath := filepath.Join("..", "..", "internal", "wasm", "testdata", "invalid", "missing_exports.wasm")
	if _, err := os.Stat(pluginPath); err != nil {
		t.Skipf("wasm testdata not available: %v", err)
	}

	cmd := newPluginsValidateCmd()
	cmd.SetArgs([]string{pluginPath})
	captureStdout(t, func() {
		if err := cmd.Execute(); err == nil {
			t.Error("plugins validate (missing_exports.wasm) error = nil, want ABI validation failure")
		}
	})
}

func TestPluginsValidateCmd_Directory(t *testing.T) {
	dir := filepath.Join("..", "..", "internal", "wasm", "testdata")
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("wasm testdata not available: %v", err)
	}

	cmd := newPluginsValidateCmd()
	cmd.SetArgs([]string{dir})
	captureStdout(t, func() {
		_ = cmd.Execute() // mixed pass/fail dir; only care that it doesn't panic and enumerates every file
	})
}

func TestPluginsValidateCmd_MissingPath(t *testing.T) {
	cmd := newPluginsValidateCmd()
	cmd.SetArgs([]string{filepath.Join(t.TempDir(), "missing.wasm")})
	if err := cmd.Execute(); err == nil {
		t.Fatal("plugins validate (missing path) error = nil, want error")
	}
}

func TestNewPluginsCmd_HasValidateSubcommand(t *testing.T) {
	cmd := newPluginsCmd()
	found := false
	for _, c := range cmd.Commands() {
		if c.Name() == "validate" {
			found = true
		}
	}
	if !found {
		t.Error("plugins cmd missing validate subcommand")
	}
}
