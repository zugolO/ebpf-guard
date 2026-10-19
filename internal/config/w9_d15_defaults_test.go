package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loadW9(t *testing.T, yaml string, profile string) *Config {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(p, []byte(yaml), 0o644))
	var (
		mgr *Manager
		err error
	)
	if profile == "" {
		mgr, err = NewManagerSkipPermCheck(p)
	} else {
		mgr, err = NewManagerSkipPermCheckWithProfile(p, profile)
	}
	require.NoError(t, err)
	t.Cleanup(mgr.Stop)
	return mgr.Get()
}

// 9.1 / Д4b: SequenceProfiler (и Марков) выключены по умолчанию в любом профиле;
// включаются явным ключом файла.
func TestW9_D4b_SequenceProfilerOffByDefault(t *testing.T) {
	for _, profile := range []string{"", ProfileLite, ProfileBalanced, ProfileProduction} {
		cfg := loadW9(t, "", profile)
		assert.Falsef(t, cfg.Profiler.Sequence.Enabled, "profile=%q: sequence profiler должен быть выключен по умолчанию", profile)
	}
	cfg := loadW9(t, "profiler:\n  sequence:\n    enabled: true\n", ProfileProduction)
	assert.True(t, cfg.Profiler.Sequence.Enabled, "явный profiler.sequence.enabled: true — опция работает")
}

// 9.1 / Д15: Rego — не умолчание продукта. Включается ключом policy.rego.enabled
// (и сборкой full, тег rego).
func TestW9_D15_RegoOffByDefault(t *testing.T) {
	cfg := loadW9(t, "", "")
	assert.False(t, cfg.Policy.Rego.Enabled, "policy.rego.enabled по умолчанию false (core)")
	cfg = loadW9(t, "policy:\n  rego:\n    enabled: true\n", "")
	assert.True(t, cfg.Policy.Rego.Enabled)
}
