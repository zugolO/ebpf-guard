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

// TestShippedConfigLoadsAndValidates loads the repository's example
// config/config.yaml and asserts it parses and passes ValidateConfig. This
// locks the ai_sandbox example (exec pins, dns_refresh_interval, and the
// writable-exec rule) against regressions in the shipped sample.
func TestShippedConfigLoadsAndValidates(t *testing.T) {
	path := filepath.Join("..", "..", "config", "config.yaml")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("shipped config not found at %s: %v", path, err)
	}
	m, err := NewManagerSkipPermCheck(path)
	require.NoError(t, err)
	require.NoError(t, ValidateConfig(m.Get()))

	c := m.Get()
	if c.AISandbox.DNSRefreshInterval != 60*time.Second {
		t.Errorf("dns_refresh_interval = %s, want 60s", c.AISandbox.DNSRefreshInterval)
	}
	require.NotEmpty(t, c.AISandbox.Profiles)
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

	// Check AI sandbox defaults (issue #255) — disabled, audit-first.
	assert.False(t, cfg.AISandbox.Enabled)
	assert.Equal(t, "audit", cfg.AISandbox.Mode)
	assert.Equal(t, "rules/ai-agent/ai-agent.yaml", cfg.AISandbox.RulesPath)
	assert.Equal(t, "ebpf-guard.io/sandbox-profile", cfg.AISandbox.Selector.KubeLabel)
	assert.Empty(t, cfg.AISandbox.Profiles)
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

// TestNewZeroConfigManager_Defaults verifies the zero-config overrides:
// K8s off, auth on, and — critically — that the core collectors are declared
// as the readiness-required set. Without this, /health/ready gates on every
// registered collector, so an optional / kernel-gated collector that fails to
// attach flips readiness to 503 (the e2e TestReadyEndpoint flake this fixes).
func TestNewZeroConfigManager_Defaults(t *testing.T) {
	mgr := NewZeroConfigManager()
	cfg := mgr.Get()
	require.NotNil(t, cfg)

	assert.False(t, cfg.Kubernetes.Enabled, "k8s must be off in zero-config")
	assert.True(t, cfg.Auth.Enabled, "auth must be on in zero-config")
	assert.Equal(t, []string{"syscall", "network", "fileaccess"}, cfg.Collectors.Required,
		"zero-config must gate readiness on the core collectors only")
	// fail-open keeps optional collector failures from aborting startup.
	assert.NotEqual(t, "fail-closed", cfg.Collectors.StartupPolicy)
}

// TestNewZeroConfigManager_AuthTokenFromEnv verifies the admin token override.
func TestNewZeroConfigManager_AuthTokenFromEnv(t *testing.T) {
	t.Setenv("EBPF_GUARD_AUTH_TOKEN", "fixed-test-token")
	cfg := NewZeroConfigManager().Get()
	assert.Equal(t, "fixed-test-token", cfg.Auth.AdminToken)
}

// TestNetworkBlocklistConfig_Defaults verifies that the network blocklist
// starts empty when no config is provided.
func TestNetworkBlocklistConfig_Defaults(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(""), 0644))

	mgr, err := NewManager(configPath)
	require.NoError(t, err)
	defer mgr.Stop()

	cfg := mgr.Get()
	assert.Empty(t, cfg.Enforcement.NetworkBlocklist.Subnets,
		"network_blocklist.subnets should default to empty")
	assert.Empty(t, cfg.Enforcement.NetworkBlocklist.Ports,
		"network_blocklist.ports should default to empty")
}

// TestNetworkBlocklistConfig_FromYAML verifies that subnets and ports are
// loaded correctly from a YAML config file.
func TestNetworkBlocklistConfig_FromYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	yaml := []byte(`
enforcement:
  network_blocklist:
    subnets:
      - "10.0.0.0/8"
      - "192.168.0.0/16"
      - "2001:db8::/32"
    ports:
      - 4444
      - 6666
`)
	require.NoError(t, os.WriteFile(configPath, yaml, 0644))

	mgr, err := NewManager(configPath)
	require.NoError(t, err)
	defer mgr.Stop()

	cfg := mgr.Get()
	bl := cfg.Enforcement.NetworkBlocklist

	require.Len(t, bl.Subnets, 3)
	assert.Equal(t, "10.0.0.0/8", bl.Subnets[0])
	assert.Equal(t, "192.168.0.0/16", bl.Subnets[1])
	assert.Equal(t, "2001:db8::/32", bl.Subnets[2])

	require.Len(t, bl.Ports, 2)
	assert.Equal(t, uint16(4444), bl.Ports[0])
	assert.Equal(t, uint16(6666), bl.Ports[1])
}

// TestNetworkBlocklistConfig_EmptySubnets ensures partial config (only ports)
// works correctly.
func TestNetworkBlocklistConfig_EmptySubnets(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	yaml := []byte(`
enforcement:
  network_blocklist:
    ports:
      - 1337
`)
	require.NoError(t, os.WriteFile(configPath, yaml, 0644))

	mgr, err := NewManager(configPath)
	require.NoError(t, err)
	defer mgr.Stop()

	cfg := mgr.Get()
	bl := cfg.Enforcement.NetworkBlocklist
	assert.Empty(t, bl.Subnets)
	require.Len(t, bl.Ports, 1)
	assert.Equal(t, uint16(1337), bl.Ports[0])
}

// TestNetworkBlocklistConfig_EmptyPorts ensures partial config (only subnets)
// works correctly.
func TestNetworkBlocklistConfig_EmptyPorts(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	yaml := []byte(`
enforcement:
  network_blocklist:
    subnets:
      - "172.16.0.0/12"
`)
	require.NoError(t, os.WriteFile(configPath, yaml, 0644))

	mgr, err := NewManager(configPath)
	require.NoError(t, err)
	defer mgr.Stop()

	cfg := mgr.Get()
	bl := cfg.Enforcement.NetworkBlocklist
	require.Len(t, bl.Subnets, 1)
	assert.Equal(t, "172.16.0.0/12", bl.Subnets[0])
	assert.Empty(t, bl.Ports)
}

func TestKernelFilterConfig_DefaultDaemonDenylist(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	require.NoError(t, os.WriteFile(configPath, []byte(""), 0644))

	mgr, err := NewManager(configPath)
	require.NoError(t, err)
	defer mgr.Stop()

	cfg := mgr.Get()
	// Default: daemon denylist is active (not disabled).
	assert.False(t, cfg.BPF.KernelFilter.DisableDefaultDaemonDenylist)
	// Default: noisy_daemon_denylist override is empty (use built-in).
	assert.Empty(t, cfg.BPF.KernelFilter.NoisyDaemonDenylist)
}

func TestKernelFilterConfig_DisableDefaultDaemonDenylist(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	yaml := []byte(`
bpf:
  kernel_filter:
    disable_default_daemon_denylist: true
`)
	require.NoError(t, os.WriteFile(configPath, yaml, 0644))

	mgr, err := NewManager(configPath)
	require.NoError(t, err)
	defer mgr.Stop()

	cfg := mgr.Get()
	assert.True(t, cfg.BPF.KernelFilter.DisableDefaultDaemonDenylist)
	assert.Empty(t, cfg.BPF.KernelFilter.NoisyDaemonDenylist)
}

func TestKernelFilterConfig_NoisyDaemonDenylistOverride(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	yaml := []byte(`
bpf:
  kernel_filter:
    noisy_daemon_denylist:
      - mylogd
      - myagent
`)
	require.NoError(t, os.WriteFile(configPath, yaml, 0644))

	mgr, err := NewManager(configPath)
	require.NoError(t, err)
	defer mgr.Stop()

	cfg := mgr.Get()
	assert.False(t, cfg.BPF.KernelFilter.DisableDefaultDaemonDenylist)
	require.Len(t, cfg.BPF.KernelFilter.NoisyDaemonDenylist, 2)
	assert.Equal(t, "mylogd", cfg.BPF.KernelFilter.NoisyDaemonDenylist[0])
	assert.Equal(t, "myagent", cfg.BPF.KernelFilter.NoisyDaemonDenylist[1])
}
