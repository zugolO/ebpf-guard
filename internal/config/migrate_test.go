package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestCheckConfigBytes_NoIssues(t *testing.T) {
	raw := []byte(`
config_version: "v0.1"
server:
  bind_address: ":9090"
profiler:
  ewma_weight_other: 0.3
`)
	issues, err := checkConfigBytes(raw)
	require.NoError(t, err)
	assert.Empty(t, issues)
}

func TestCheckConfigBytes_DeprecatedRename(t *testing.T) {
	raw := []byte(`
profiler:
  ewma_weight: 0.3
`)
	issues, err := checkConfigBytes(raw)
	require.NoError(t, err)
	require.Len(t, issues, 1)
	assert.Equal(t, IssueSeverityDeprecated, issues[0].Severity)
	assert.Equal(t, "profiler.ewma_weight", issues[0].Field)
	assert.Contains(t, issues[0].Message, "profiler.ewma.weight")
	assert.Contains(t, issues[0].Message, "v0.2.0")
}

func TestCheckConfigBytes_RemovedField(t *testing.T) {
	raw := []byte(`
alerting:
  enabled: true
  webhook_url: "https://alertmanager.example.com"
`)
	issues, err := checkConfigBytes(raw)
	require.NoError(t, err)
	require.Len(t, issues, 1)
	assert.Equal(t, IssueSeverityRemoved, issues[0].Severity)
	assert.Equal(t, "alerting.webhook_url", issues[0].Field)
	assert.Contains(t, issues[0].Message, "v0.2.0")
	assert.Contains(t, issues[0].Message, "alerting.alertmanager.url")
}

func TestCheckConfigBytes_MultipleIssues(t *testing.T) {
	raw := []byte(`
profiler:
  ewma_weight: 0.3
alerting:
  webhook_url: "https://example.com"
`)
	issues, err := checkConfigBytes(raw)
	require.NoError(t, err)
	assert.Len(t, issues, 2)
}

func TestCheckConfigFile_ReadsFromDisk(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.yaml")
	err := os.WriteFile(path, []byte(`
profiler:
  ewma_weight: 0.3
`), 0o600)
	require.NoError(t, err)

	issues, err := CheckConfigFile(path)
	require.NoError(t, err)
	require.Len(t, issues, 1)
}

func TestCheckConfigFile_NotFound(t *testing.T) {
	_, err := CheckConfigFile("/nonexistent/path/config.yaml")
	assert.Error(t, err)
}

func TestMigrateConfigBytes_Rename(t *testing.T) {
	raw := []byte(`
profiler:
  ewma_weight: 0.5
  learning_period: 3600
`)
	out, err := migrateConfigBytes(raw, "v0.2.0")
	require.NoError(t, err)

	var result map[string]interface{}
	require.NoError(t, yaml.Unmarshal(out, &result))

	profiler, ok := result["profiler"].(map[string]interface{})
	require.True(t, ok)

	// Old field should be gone
	_, hasOld := profiler["ewma_weight"]
	assert.False(t, hasOld, "ewma_weight should have been removed")

	// New nested field should exist
	ewma, ok := profiler["ewma"].(map[string]interface{})
	require.True(t, ok, "profiler.ewma should exist")
	assert.Equal(t, 0.5, ewma["weight"])

	// Unrelated field should remain
	assert.Equal(t, 3600, profiler["learning_period"])
}

func TestMigrateConfigBytes_Remove(t *testing.T) {
	raw := []byte(`
alerting:
  enabled: true
  webhook_url: "https://alertmanager.example.com"
  batch_size: 100
`)
	out, err := migrateConfigBytes(raw, "v0.2.0")
	require.NoError(t, err)

	var result map[string]interface{}
	require.NoError(t, yaml.Unmarshal(out, &result))

	alerting, ok := result["alerting"].(map[string]interface{})
	require.True(t, ok)

	_, hasRemoved := alerting["webhook_url"]
	assert.False(t, hasRemoved, "webhook_url should have been removed")
	assert.Equal(t, true, alerting["enabled"])
	assert.Equal(t, 100, alerting["batch_size"])
}

func TestMigrateConfigBytes_SetsConfigVersion(t *testing.T) {
	raw := []byte(`
config_version: "v0.1"
server:
  bind_address: ":9090"
`)
	out, err := migrateConfigBytes(raw, "v0.2.0")
	require.NoError(t, err)

	var result map[string]interface{}
	require.NoError(t, yaml.Unmarshal(out, &result))

	assert.Equal(t, "v0.2.0", result["config_version"])
}

func TestMigrateConfigBytes_VersionBelowAllMigrations(t *testing.T) {
	// v0.1.0 is lower than the earliest migration target (v0.2.0), so nothing applies.
	raw := []byte(`server: {}`)
	_, err := migrateConfigBytes(raw, "v0.1.0")
	assert.Error(t, err)
}

func TestMigrateConfigFile_WritesFile(t *testing.T) {
	tmp := t.TempDir()
	inPath := filepath.Join(tmp, "config.yaml")
	outPath := filepath.Join(tmp, "config.migrated.yaml")

	err := os.WriteFile(inPath, []byte(`
profiler:
  ewma_weight: 0.3
`), 0o600)
	require.NoError(t, err)

	err = MigrateConfigFile(inPath, "v0.2.0", outPath)
	require.NoError(t, err)

	_, err = os.Stat(outPath)
	require.NoError(t, err, "output file should exist")

	// Verify the source is untouched
	src, err := os.ReadFile(inPath)
	require.NoError(t, err)
	assert.Contains(t, string(src), "ewma_weight")
}

func TestYamlHelpers(t *testing.T) {
	doc := map[string]interface{}{
		"a": map[string]interface{}{
			"b": map[string]interface{}{
				"c": "value",
			},
		},
	}

	t.Run("get existing path", func(t *testing.T) {
		v, ok := yamlGetPath(doc, "a.b.c")
		assert.True(t, ok)
		assert.Equal(t, "value", v)
	})

	t.Run("get missing path", func(t *testing.T) {
		_, ok := yamlGetPath(doc, "a.x.y")
		assert.False(t, ok)
	})

	t.Run("path exists", func(t *testing.T) {
		assert.True(t, yamlPathExists(doc, "a.b.c"))
		assert.False(t, yamlPathExists(doc, "a.z"))
	})

	t.Run("delete path", func(t *testing.T) {
		d := map[string]interface{}{
			"x": map[string]interface{}{"y": 42},
		}
		yamlDeletePath(d, "x.y")
		inner := d["x"].(map[string]interface{})
		_, exists := inner["y"]
		assert.False(t, exists)
	})

	t.Run("set creates intermediates", func(t *testing.T) {
		d := make(map[string]interface{})
		yamlSetPath(d, "p.q.r", "hello")
		p := d["p"].(map[string]interface{})
		q := p["q"].(map[string]interface{})
		assert.Equal(t, "hello", q["r"])
	})
}
