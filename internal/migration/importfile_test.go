package migration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeTemp(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(p, []byte(body), 0o644))
	return p
}

func TestFalcoImporter_ImportFile(t *testing.T) {
	body := "- rule: Test\n  desc: d\n  condition: proc.name = bash\n  output: o\n  priority: WARNING\n"
	imp := NewFalcoImporter()

	res, err := imp.ImportFile(writeTemp(t, "falco.yaml", body))
	require.NoError(t, err)
	assert.NotNil(t, res)

	_, err = imp.ImportFile("/nonexistent/falco.yaml")
	require.Error(t, err)
}

func TestSigmaImporter_ImportFile(t *testing.T) {
	body := `title: Suspicious Shell
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
	imp := NewSigmaImporter()

	res, err := imp.ImportFile(writeTemp(t, "sigma.yaml", body))
	require.NoError(t, err)
	assert.NotNil(t, res)

	_, err = imp.ImportFile("/nonexistent/sigma.yaml")
	require.Error(t, err)
}

func TestECSImporter_ImportFile(t *testing.T) {
	body := `name: Suspicious Shell Execution
type: query
language: lucene
query: process.name:bash
severity: high
`
	imp := NewECSImporter()

	res, err := imp.ImportFile(writeTemp(t, "ecs.yaml", body))
	require.NoError(t, err)
	assert.NotNil(t, res)

	_, err = imp.ImportFile("/nonexistent/ecs.yaml")
	require.Error(t, err)
}
