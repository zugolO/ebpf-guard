package explainer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_FromDirectory(t *testing.T) {
	dir := t.TempDir()
	tmpl := `templates:
  - id: rule_001
    name: Test Rule
    category: test
    summary: "A {{ .RuleID }} fired"
    detail: "Process {{ .Comm }} did something"
    severity: critical
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.yaml"), []byte(tmpl), 0o644))
	// A non-yaml file is ignored.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("ignored"), 0o644))

	e, err := New(dir)
	require.NoError(t, err)
	require.NotNil(t, e)
	assert.Contains(t, e.templates, "rule_001")
}

func TestNew_MissingDirectoryFallsBackToDefaults(t *testing.T) {
	// A non-existent directory falls back to the embedded default templates.
	e, err := New(filepath.Join(t.TempDir(), "does-not-exist"))
	require.NoError(t, err)
	require.NotNil(t, e)
	assert.NotEmpty(t, e.templates)
}

func TestNew_InvalidTemplateFile(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte("templates: [::::"), 0o644))
	_, err := New(dir)
	require.Error(t, err)
}
