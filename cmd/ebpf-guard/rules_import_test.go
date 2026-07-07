package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

const sigmaFixture = `
title: Suspicious Shell
id: aaaabbbb-1234-5678-9abc-def012345678
status: stable
logsource:
  category: process_creation
detection:
  selection:
    Image: bash
  condition: selection
level: high
`

const ecsFixture = `
name: Suspicious Shell Execution
type: query
language: lucene
query: process.name:bash
severity: high
`

func newRulesImportRootCmd(t *testing.T) *cobra.Command {
	t.Helper()
	return newRulesImportCmd()
}

func TestRulesImportCmd_Sigma(t *testing.T) {
	dir := t.TempDir()
	inPath := filepath.Join(dir, "sigma.yaml")
	writeFile(t, inPath, sigmaFixture)
	outDir := filepath.Join(dir, "out")

	cmd := newRulesImportRootCmd(t)
	cmd.SetArgs([]string{"--format", "sigma", inPath, "--out", outDir})
	out := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Errorf("rules import sigma error = %v", err)
		}
	})
	if !strings.Contains(out, "Sigma import summary") || !strings.Contains(out, "Converted:   1") {
		t.Errorf("sigma import output = %q, want a summary with 1 converted rule", out)
	}
	if _, err := os.Stat(filepath.Join(outDir, "sigma-imported.yaml")); err != nil {
		t.Errorf("sigma import did not write output file: %v", err)
	}
}

func TestRulesImportCmd_Sigma_DryRun(t *testing.T) {
	dir := t.TempDir()
	inPath := filepath.Join(dir, "sigma.yaml")
	writeFile(t, inPath, sigmaFixture)
	outDir := filepath.Join(dir, "out")

	cmd := newRulesImportRootCmd(t)
	cmd.SetArgs([]string{"--source", "sigma", inPath, "--out", outDir, "--dry-run"})
	out := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Errorf("rules import sigma --dry-run error = %v", err)
		}
	})
	if !strings.Contains(out, "dry-run: not writing files") {
		t.Errorf("sigma dry-run output = %q, want dry-run banner", out)
	}
	if _, err := os.Stat(filepath.Join(outDir, "sigma-imported.yaml")); !os.IsNotExist(err) {
		t.Errorf("sigma import --dry-run should not write output file, stat err = %v", err)
	}
}

func TestRulesImportCmd_ECS(t *testing.T) {
	dir := t.TempDir()
	inPath := filepath.Join(dir, "ecs.yaml")
	writeFile(t, inPath, ecsFixture)
	outDir := filepath.Join(dir, "out")

	cmd := newRulesImportRootCmd(t)
	cmd.SetArgs([]string{"--format", "ecs", inPath, "--out", outDir})
	out := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Errorf("rules import ecs error = %v", err)
		}
	})
	if !strings.Contains(out, "ECS import summary") || !strings.Contains(out, "Converted:   1") {
		t.Errorf("ecs import output = %q, want a summary with 1 converted rule", out)
	}
	if _, err := os.Stat(filepath.Join(outDir, "ecs-imported.yaml")); err != nil {
		t.Errorf("ecs import did not write output file: %v", err)
	}
}

func TestRulesImportCmd_ECS_DryRun(t *testing.T) {
	dir := t.TempDir()
	inPath := filepath.Join(dir, "ecs.yaml")
	writeFile(t, inPath, ecsFixture)
	outDir := filepath.Join(dir, "out")

	cmd := newRulesImportRootCmd(t)
	cmd.SetArgs([]string{"--format", "ecs", inPath, "--out", outDir, "--dry-run"})
	out := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Errorf("rules import ecs --dry-run error = %v", err)
		}
	})
	if !strings.Contains(out, "dry-run: not writing files") {
		t.Errorf("ecs dry-run output = %q, want dry-run banner", out)
	}
	if _, err := os.Stat(filepath.Join(outDir, "ecs-imported.yaml")); !os.IsNotExist(err) {
		t.Errorf("ecs import --dry-run should not write output file, stat err = %v", err)
	}
}

func TestRulesImportCmd_ECS_NoRulesConverted(t *testing.T) {
	dir := t.TempDir()
	inPath := filepath.Join(dir, "ecs.yaml")
	writeFile(t, inPath, `
name: Unmappable
type: query
language: lucene
query: some.unmapped.field:value
severity: low
`)
	outDir := filepath.Join(dir, "out")

	cmd := newRulesImportRootCmd(t)
	cmd.SetArgs([]string{"--format", "ecs", inPath, "--out", outDir})
	out := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Errorf("rules import ecs (unmappable) error = %v", err)
		}
	})
	if !strings.Contains(out, "No rules were converted") {
		t.Errorf("output = %q, want 'No rules were converted'", out)
	}
}

func TestRulesImportCmd_Falco_DryRun(t *testing.T) {
	dir := t.TempDir()
	inPath := filepath.Join(dir, "falco.yaml")
	writeFile(t, inPath, `
- rule: Terminal shell in container
  desc: A shell was spawned
  condition: evt.type = execve
  output: "Shell spawned (user=%user.name)"
  priority: NOTICE
  tags: [container, shell]
`)
	outDir := filepath.Join(dir, "out")

	cmd := newRulesImportRootCmd(t)
	cmd.SetArgs([]string{"--format", "falco", inPath, "--out", outDir, "--dry-run"})
	out := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Errorf("rules import falco --dry-run error = %v", err)
		}
	})
	if !strings.Contains(out, "dry-run: not writing files") {
		t.Errorf("falco dry-run output = %q, want dry-run banner", out)
	}
	if _, err := os.Stat(filepath.Join(outDir, "falco-imported.yaml")); !os.IsNotExist(err) {
		t.Errorf("falco import --dry-run should not write output file, stat err = %v", err)
	}
}

func TestRulesImportCmd_Falco_NoRulesConverted(t *testing.T) {
	dir := t.TempDir()
	inPath := filepath.Join(dir, "falco.yaml")
	writeFile(t, inPath, `
- rule: Unmappable pod rule
  desc: process ran in an unexpected pod
  condition: k8s.pod.name != ""
  output: "Unexpected pod (pod=%k8s.pod.name)"
  priority: WARNING
  tags: [k8s]
`)
	outDir := filepath.Join(dir, "out")

	cmd := newRulesImportRootCmd(t)
	cmd.SetArgs([]string{"--format", "falco", inPath, "--out", outDir})
	out := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Errorf("rules import falco (unmappable) error = %v", err)
		}
	})
	if !strings.Contains(out, "No rules were converted") {
		t.Errorf("output = %q, want 'No rules were converted'", out)
	}
}

func TestRulesImportCmd_Falco(t *testing.T) {
	// Reuse the repo's realistic Falco fixture used by internal/migration's
	// own tests, so this exercises the same boolean/macro/list logic end to
	// end through the CLI instead of a trivial single-clause rule.
	fixture, err := os.ReadFile(filepath.Join("..", "..", "internal", "migration", "testdata", "falco_sample.yaml"))
	if err != nil {
		t.Fatalf("read falco fixture: %v", err)
	}
	dir := t.TempDir()
	inPath := filepath.Join(dir, "falco.yaml")
	writeFile(t, inPath, string(fixture))
	outDir := filepath.Join(dir, "out")

	cmd := newRulesImportRootCmd(t)
	cmd.SetArgs([]string{"--format", "falco", inPath, "--out", outDir})
	out := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Errorf("rules import falco error = %v", err)
		}
	})
	if !strings.Contains(out, "Falco import summary") {
		t.Errorf("falco import output = %q, want a summary", out)
	}
	if !strings.Contains(out, "[OK]") {
		t.Errorf("falco import output = %q, want at least one converted rule", out)
	}
	if _, err := os.Stat(filepath.Join(outDir, "falco-imported.yaml")); err != nil {
		t.Errorf("falco import did not write output file: %v", err)
	}
}

func TestRulesImportCmd_MissingFormat(t *testing.T) {
	dir := t.TempDir()
	inPath := filepath.Join(dir, "sigma.yaml")
	writeFile(t, inPath, sigmaFixture)

	cmd := newRulesImportRootCmd(t)
	cmd.SetArgs([]string{inPath})
	if err := cmd.Execute(); err == nil {
		t.Fatal("rules import without --format error = nil, want error")
	}
}

func TestRulesImportCmd_UnsupportedFormat(t *testing.T) {
	dir := t.TempDir()
	inPath := filepath.Join(dir, "sigma.yaml")
	writeFile(t, inPath, sigmaFixture)

	cmd := newRulesImportRootCmd(t)
	cmd.SetArgs([]string{"--format", "bogus", inPath})
	if err := cmd.Execute(); err == nil {
		t.Fatal("rules import with unsupported --format error = nil, want error")
	}
}

func TestRulesImportCmd_MissingInputPath(t *testing.T) {
	cmd := newRulesImportRootCmd(t)
	cmd.SetArgs([]string{"--format", "sigma"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("rules import without input path error = nil, want error")
	}
}

func TestRulesImportCmd_NoRulesConverted(t *testing.T) {
	dir := t.TempDir()
	inPath := filepath.Join(dir, "sigma.yaml")
	// A detection block with a condition referencing an unmapped field
	// converts zero rules, exercising the "No rules were converted" path.
	writeFile(t, inPath, `
title: Unmappable
logsource:
  category: process_creation
detection:
  selection:
    UnmappableFieldXYZ: something
  condition: selection
level: low
`)
	outDir := filepath.Join(dir, "out")

	cmd := newRulesImportRootCmd(t)
	cmd.SetArgs([]string{"--format", "sigma", inPath, "--out", outDir})
	out := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Errorf("rules import (unmappable) error = %v", err)
		}
	})
	if !strings.Contains(out, "No rules were converted") {
		t.Errorf("output = %q, want 'No rules were converted'", out)
	}
}
