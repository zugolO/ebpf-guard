// Package config provides configuration management with hot-reload support.
package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeConfigAtomic(t *testing.T, path string, data []byte) {
	t.Helper()
	tmp := path + ".tmp"
	require.NoError(t, os.WriteFile(tmp, data, 0644))
	require.NoError(t, os.Rename(tmp, path))
}

func TestNewManager_Defaults(t *testing.T) {
	// Create temp config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Write minimal config
	err := os.WriteFile(configPath, []byte(""), 0644)
	require.NoError(t, err)

	mgr, err := NewManager(configPath)
	require.NoError(t, err)
	defer mgr.Stop()

	cfg := mgr.Get()

	// Check server defaults
	assert.Equal(t, ":9090", cfg.Server.BindAddress)
	assert.Equal(t, "/metrics", cfg.Server.MetricsPath)
	assert.Equal(t, "/health", cfg.Server.HealthPath)

	// Check BPF defaults
	assert.Equal(t, 65536, cfg.BPF.MapSizes.Events)
	assert.Equal(t, 16384, cfg.BPF.MapSizes.Processes)
	assert.Equal(t, 32768, cfg.BPF.MapSizes.Connections)

	// Check rules defaults
	assert.Equal(t, "rules/", cfg.Rules.Path)
	assert.True(t, cfg.Rules.HotReload)
	assert.True(t, cfg.Rules.RateLimitAlerts)
	assert.Equal(t, 60, cfg.Rules.RateLimitWindow)
	assert.Equal(t, 10, cfg.Rules.MaxAlertsPerWindow)

	// Check profiler defaults
	assert.True(t, cfg.Profiler.Enabled)
	assert.Equal(t, 3600, cfg.Profiler.LearningPeriod)
	assert.Equal(t, uint64(100), cfg.Profiler.MinLearningSamples)
	assert.Equal(t, 0.8, cfg.Profiler.AnomalyThreshold)
	assert.Equal(t, 0.3, cfg.Profiler.EWMAWeight)
	assert.Equal(t, 86400, cfg.Profiler.ProfileTTL)

	// Check alerting defaults
	assert.False(t, cfg.Alerting.Enabled)
	assert.Equal(t, "", cfg.Alerting.WebhookURL)
	assert.Equal(t, "http://ebpf-guard:9090", cfg.Alerting.GeneratorURL)
	assert.Equal(t, 100, cfg.Alerting.BatchSize)
	assert.Equal(t, 5, cfg.Alerting.BatchTimeout)
	assert.Equal(t, 5, cfg.Alerting.CircuitBreakerThreshold)

	// Check Kubernetes defaults
	assert.True(t, cfg.Kubernetes.Enabled)
	assert.Equal(t, "", cfg.Kubernetes.KubeconfigPath)
	assert.Equal(t, 300, cfg.Kubernetes.ResyncPeriod)
}

func TestNewManager_CustomValues(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
server:
  bind_address: ":8080"
  metrics_path: "/prometheus"

bpf:
  map_sizes:
    events: 131072

rules:
  hot_reload: false
  rate_limit_window: 120

profiler:
  enabled: false
  anomaly_threshold: 0.9
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	mgr, err := NewManager(configPath)
	require.NoError(t, err)
	defer mgr.Stop()

	cfg := mgr.Get()

	assert.Equal(t, ":8080", cfg.Server.BindAddress)
	assert.Equal(t, "/prometheus", cfg.Server.MetricsPath)
	assert.Equal(t, 131072, cfg.BPF.MapSizes.Events)
	assert.False(t, cfg.Rules.HotReload)
	assert.Equal(t, 120, cfg.Rules.RateLimitWindow)
	assert.False(t, cfg.Profiler.Enabled)
	assert.Equal(t, 0.9, cfg.Profiler.AnomalyThreshold)
}

func TestManager_Watch(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Write initial config
	err := os.WriteFile(configPath, []byte(`
server:
  bind_address: ":9090"
`), 0644)
	require.NoError(t, err)

	mgr, err := NewManager(configPath)
	require.NoError(t, err)
	defer mgr.Stop()

	// Verify initial value
	assert.Equal(t, ":9090", mgr.Get().Server.BindAddress)

	// Set up change callback
	changeCh := make(chan *Config, 1)
	mgr.OnChange(func(cfg *Config) {
		changeCh <- cfg
	})

	// Start watching
	err = mgr.Watch()
	require.NoError(t, err)

	writeConfigAtomic(t, configPath, []byte(`
server:
  bind_address: ":8080"
`))

	select {
	case cfg := <-changeCh:
		assert.Equal(t, ":8080", cfg.Server.BindAddress)
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for config change")
	}
}

func TestNewManager_FileNotFound(t *testing.T) {
	_, err := NewManager("/nonexistent/config.yaml")
	assert.Error(t, err)
}

func TestManager_Watch_MultipleChanges(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Write initial config
	err := os.WriteFile(configPath, []byte(`
server:
  bind_address: ":9090"
  metrics_path: "/metrics"
`), 0644)
	require.NoError(t, err)

	mgr, err := NewManager(configPath)
	require.NoError(t, err)
	defer mgr.Stop()

	// Verify initial values
	assert.Equal(t, ":9090", mgr.Get().Server.BindAddress)
	assert.Equal(t, "/metrics", mgr.Get().Server.MetricsPath)

	// Set up change callback with buffer for multiple changes
	changeCh := make(chan *Config, 3)
	mgr.OnChange(func(cfg *Config) {
		changeCh <- cfg
	})

	// Start watching
	err = mgr.Watch()
	require.NoError(t, err)

	writeConfigAtomic(t, configPath, []byte(`
server:
  bind_address: ":8080"
  metrics_path: "/metrics"
`))

	// Wait for first callback
	select {
	case cfg := <-changeCh:
		assert.Equal(t, ":8080", cfg.Server.BindAddress)
		assert.Equal(t, "/metrics", cfg.Server.MetricsPath)
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for first config change")
	}

	// Verify manager state updated
	assert.Equal(t, ":8080", mgr.Get().Server.BindAddress)

	writeConfigAtomic(t, configPath, []byte(`
server:
  bind_address: ":8080"
  metrics_path: "/prometheus"
`))

	// Wait for second callback
	select {
	case cfg := <-changeCh:
		assert.Equal(t, ":8080", cfg.Server.BindAddress)
		assert.Equal(t, "/prometheus", cfg.Server.MetricsPath)
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for second config change")
	}

	// Verify final state
	assert.Equal(t, ":8080", mgr.Get().Server.BindAddress)
	assert.Equal(t, "/prometheus", mgr.Get().Server.MetricsPath)
}

func TestManager_Watch_InvalidConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Write initial valid config
	err := os.WriteFile(configPath, []byte(`
server:
  bind_address: ":9090"
`), 0644)
	require.NoError(t, err)

	mgr, err := NewManager(configPath)
	require.NoError(t, err)
	defer mgr.Stop()

	// Set up change callback
	changeCh := make(chan *Config, 1)
	mgr.OnChange(func(cfg *Config) {
		changeCh <- cfg
	})

	// Start watching
	err = mgr.Watch()
	require.NoError(t, err)

	writeConfigAtomic(t, configPath, []byte(`
server:
  bind_address: ":8080"
profiler:
  enabled: "not_a_boolean"
`))

	// Viper may or may not call callback depending on how it handles the error
	// The important thing is that the manager doesn't panic
	select {
	case cfg := <-changeCh:
		// If callback is called, verify we got some config
		assert.NotNil(t, cfg)
		// bind_address should be updated if unmarshal succeeded
		assert.Equal(t, ":8080", cfg.Server.BindAddress)
	case <-time.After(500 * time.Millisecond):
		// If no callback, that's also acceptable (viper may have rejected the config)
	}

	// Manager should still be in a valid state
	assert.NotNil(t, mgr.Get())
}
