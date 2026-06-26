package ruletest

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const rulesYAML = `rules:
  - id: rule_evil
    name: Evil process
    event_type: syscall
    condition:
      field: "comm"
      op: eq
      values: ["evil"]
    severity: critical
    action: alert
`

func suiteYAML(rulesPath string) string {
	return `suite: demo
rules_path: ` + rulesPath + `
tests:
  - name: evil fires
    event:
      type: syscall
      comm: evil
      syscall:
        nr: 1
    expect: alert
  - name: benign is quiet
    event:
      type: syscall
      comm: bash
      syscall:
        nr: 1
    expect: no_alert
`
}

func TestRunner_RunPath(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	require.NoError(t, os.WriteFile(rulesPath, []byte(rulesYAML), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "demo_test.yaml"), []byte(suiteYAML(rulesPath)), 0o644))

	r := &Runner{}
	tap := NewTAPWriter(io.Discard)
	sum, err := r.RunPath(dir, tap)
	require.NoError(t, err)
	assert.Equal(t, 2, sum.Total)
	assert.Equal(t, 2, sum.Passed)
	assert.Equal(t, 0, sum.Failed)
}

func TestRunner_BuildEngine(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	require.NoError(t, os.WriteFile(rulesPath, []byte(rulesYAML), 0o644))

	r := &Runner{}

	// File-based rules path.
	eng, err := r.BuildEngine(rulesPath)
	require.NoError(t, err)
	require.NotNil(t, eng)

	// Directory-based rules path.
	engDir, err := r.BuildEngine(dir)
	require.NoError(t, err)
	require.NotNil(t, engDir)

	// Missing path → error.
	_, err = r.BuildEngine(filepath.Join(dir, "missing.yaml"))
	require.Error(t, err)

	// No rules anywhere → error.
	_, err = r.BuildEngine("")
	require.Error(t, err)
}

func TestRunner_RunPath_NoFiles(t *testing.T) {
	r := &Runner{}
	_, err := r.RunPath(t.TempDir(), NewTAPWriter(io.Discard))
	require.Error(t, err)
}
