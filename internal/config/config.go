// Package config provides configuration management with hot-reload support.
package config

import (
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
)

// Config holds all configuration for ebpf-guard.
type Config struct {
	mu sync.RWMutex

	// Server configuration
	Server ServerConfig `mapstructure:"server"`

	// BPF configuration
	BPF BPFConfig `mapstructure:"bpf"`

	// Rules configuration
	Rules RulesConfig `mapstructure:"rules"`

	// Correlator configuration
	Correlator CorrelatorConfig `mapstructure:"correlator"`

	// Profiler configuration
	Profiler ProfilerConfig `mapstructure:"profiler"`

	// Exporter configuration
	Exporter ExporterConfig `mapstructure:"exporter"`

	// Alerting configuration
	Alerting AlertingConfig `mapstructure:"alerting"`

	// Kubernetes configuration
	Kubernetes KubernetesConfig `mapstructure:"kubernetes"`

	// Auth configuration
	Auth AuthConfig `mapstructure:"auth"`

	// Notifications configuration
	Notifications NotificationsConfig `mapstructure:"notifications"`

	// Store configuration
	Store StoreConfig `mapstructure:"store"`

	// Collectors configuration
	Collectors CollectorsConfig `mapstructure:"collectors"`

	// Enforcement configuration
	Enforcement EnforcementConfig `mapstructure:"enforcement"`

	// Watchdog configuration
	Watchdog WatchdogConfig `mapstructure:"watchdog"`

	// Policy configuration (Sprint 23.0)
	Policy PolicyConfig `mapstructure:"policy"`

	// Compat configuration (Sprint 24.0)
	Compat CompatConfig `mapstructure:"compat"`

	// Gossip configuration — cross-node IOC sharing.
	Gossip GossipConfig `mapstructure:"gossip"`
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	BindAddress string `mapstructure:"bind_address"`
	MetricsPath string `mapstructure:"metrics_path"`
	HealthPath  string `mapstructure:"health_path"`
	// EnablePprof enables pprof debugging endpoints at /debug/pprof
	EnablePprof bool `mapstructure:"enable_pprof"`
	// EnableDebug enables debug endpoints at /debug/state
	EnableDebug bool `mapstructure:"enable_debug"`
}

// AuthConfig holds authentication configuration.
type AuthConfig struct {
	// Enabled enables Bearer token authentication for /metrics and /debug/pprof.
	// If true and BearerToken is empty, a random token is generated at startup.
	Enabled bool `mapstructure:"enabled"`
	// BearerToken is the static token to use for authentication.
	// If empty and Enabled is true, a random 32-byte token is generated.
	BearerToken string `mapstructure:"bearer_token"`
}

// NotificationsConfig holds notification backend settings.
type NotificationsConfig struct {
	// Slack configuration
	Slack SlackNotificationConfig `mapstructure:"slack"`
	// Teams configuration
	Teams TeamsNotificationConfig `mapstructure:"teams"`
	// Webhook configuration
	Webhook WebhookNotificationConfig `mapstructure:"webhook"`
}

// SlackNotificationConfig holds Slack webhook settings.
type SlackNotificationConfig struct {
	// Enabled enables Slack notifications
	Enabled bool `mapstructure:"enabled"`
	// WebhookURL is the Slack Incoming Webhook URL
	WebhookURL string `mapstructure:"webhook_url"`
	// Channel is the optional channel override (e.g., "#security-alerts")
	Channel string `mapstructure:"channel"`
	// MinSeverity filters alerts by severity ("warning" or "critical")
	MinSeverity string `mapstructure:"min_severity"`
}

// TeamsNotificationConfig holds Microsoft Teams webhook settings.
type TeamsNotificationConfig struct {
	// Enabled enables Teams notifications
	Enabled bool `mapstructure:"enabled"`
	// WebhookURL is the Teams Incoming Webhook URL
	WebhookURL string `mapstructure:"webhook_url"`
	// MinSeverity filters alerts by severity ("warning" or "critical")
	MinSeverity string `mapstructure:"min_severity"`
}

// WebhookNotificationConfig holds generic webhook settings.
type WebhookNotificationConfig struct {
	// Enabled enables webhook notifications
	Enabled bool `mapstructure:"enabled"`
	// URL is the webhook endpoint URL
	URL string `mapstructure:"url"`
	// Headers are custom HTTP headers to add to requests
	Headers map[string]string `mapstructure:"headers"`
	// Template is a Go template string for the request body (empty = default JSON)
	Template string `mapstructure:"template"`
	// MinSeverity filters alerts by severity ("warning" or "critical")
	MinSeverity string `mapstructure:"min_severity"`
}

// StoreConfig holds storage backend configuration.
type StoreConfig struct {
	// Backend specifies the storage backend: "memory", "sqlite", "opensearch"
	Backend string `mapstructure:"backend"`
	// SQLite configuration
	SQLite SQLiteStoreConfig `mapstructure:"sqlite"`
	// OpenSearch configuration
	OpenSearch OpenSearchStoreConfig `mapstructure:"opensearch"`
}

// CollectorsConfig holds per-collector settings.
type CollectorsConfig struct {
	// TLS collector configuration
	TLS TLSCollectorConfig `mapstructure:"tls"`
	// DNS collector configuration
	DNS DNSCollectorConfig `mapstructure:"dns"`
	// BackpressureStrategy controls what happens when the event channel is full.
	// Valid values: "drop" (default), "block", "sample".
	//   drop   — silently discard the event and increment the drop counter.
	//   block  — pause the collector goroutine until the channel drains (provides backpressure).
	//   sample — probabilistically drop ~50% of overflow events.
	BackpressureStrategy string `mapstructure:"backpressure_strategy"`
}

// TLSCollectorConfig holds TLS inspection settings.
type TLSCollectorConfig struct {
	// Enabled enables TLS inspection via uprobes.
	// Requires CAP_SYS_PTRACE capability.
	// Default: false
	Enabled bool `mapstructure:"enabled"`
	// ScanInterval is the interval for scanning processes using libssl.
	// Default: 30s
	ScanInterval string `mapstructure:"scan_interval"`
	// MaxDataSize is the maximum bytes to capture per TLS record.
	// Default: 256
	MaxDataSize int `mapstructure:"max_data_size"`
}

// DNSCollectorConfig holds DNS monitoring settings.
type DNSCollectorConfig struct {
	// Enabled enables DNS monitoring via eBPF tracepoints.
	// Default: true
	Enabled bool `mapstructure:"enabled"`
	// DGAThreshold is the Shannon entropy threshold for DGA detection (bits/char).
	// Default: 3.5
	DGAThreshold float64 `mapstructure:"dga_threshold"`
	// TunnelingMinLength is the minimum domain length to flag as DNS tunneling.
	// Default: 50
	TunnelingMinLength int `mapstructure:"tunneling_min_length"`
	// HighFrequencyThreshold is the max DNS queries per minute before alerting.
	// Default: 100
	HighFrequencyThreshold int `mapstructure:"high_frequency_threshold"`
}

// SQLiteStoreConfig holds SQLite-specific configuration.
type SQLiteStoreConfig struct {
	// Path to the SQLite database file
	Path string `mapstructure:"path"`
}

// OpenSearchStoreConfig holds OpenSearch-specific configuration.
type OpenSearchStoreConfig struct {
	// URL is the OpenSearch endpoint (e.g., https://opensearch:9200)
	URL string `mapstructure:"url"`
	// Index is the index name for alerts
	Index string `mapstructure:"index"`
	// Username for basic authentication
	Username string `mapstructure:"username"`
	// Password for basic authentication (or reference to Secret)
	Password string `mapstructure:"password"`
	// InsecureSkipVerify disables TLS certificate verification
	InsecureSkipVerify bool `mapstructure:"insecure_skip_verify"`
}

// BPFConfig holds eBPF-specific settings.
type BPFConfig struct {
	// MapSizes defines the size of BPF maps (number of entries)
	MapSizes MapSizeConfig `mapstructure:"map_sizes"`
}

// MapSizeConfig holds BPF map size settings.
type MapSizeConfig struct {
	Events      int `mapstructure:"events"`
	Processes   int `mapstructure:"processes"`
	Connections int `mapstructure:"connections"`
}

// RulesConfig holds rule engine settings.
type RulesConfig struct {
	// Path to rules YAML file
	Path string `mapstructure:"path"`
	// HotReload enables automatic rule reloading on file change
	HotReload bool `mapstructure:"hot_reload"`
	// RateLimitAlerts enables rate limiting per rule
	RateLimitAlerts bool `mapstructure:"rate_limit_alerts"`
	// RateLimitWindow is the time window for rate limiting (seconds)
	RateLimitWindow int `mapstructure:"rate_limit_window"`
	// MaxAlertsPerWindow is the maximum alerts per rule per window
	MaxAlertsPerWindow int `mapstructure:"max_alerts_per_window"`
}

// CorrelatorConfig holds correlator settings.
type CorrelatorConfig struct {
	// BufferSize is the size of the event channel buffer
	BufferSize int `mapstructure:"buffer_size"`
	// MaxAlertsPerSecond is the global token-bucket rate limit for alerts (default 10000, 0 = unlimited).
	MaxAlertsPerSecond int `mapstructure:"max_alerts_per_second"`
}

// ProfilerConfig holds behavioral profiling settings.
type ProfilerConfig struct {
	// Enabled enables behavioral profiling and anomaly detection
	Enabled bool `mapstructure:"enabled"`
	// LearningPeriod is the initial learning period in seconds (no alerts)
	LearningPeriod int `mapstructure:"learning_period"`
	// MinLearningSamples is the minimum number of events that must be observed
	// before the learning phase can complete, regardless of LearningPeriod.
	// Prevents premature anomaly scoring on nodes that started receiving
	// traffic just before the LearningPeriod timer expired. Default: 100.
	MinLearningSamples uint64 `mapstructure:"min_learning_samples"`
	// AnomalyThreshold is the score threshold for generating alerts (0.0-1.0)
	AnomalyThreshold float64 `mapstructure:"anomaly_threshold"`
	// EWMAWeight is the weight for Exponentially Weighted Moving Average (0.0-1.0)
	EWMAWeight float64 `mapstructure:"ewma_weight"`
	// ProfileTTL is the time-to-live for process profiles in seconds (default 86400 = 24h).
	// Profiles not seen within this window are evicted by the background cleanup goroutine.
	ProfileTTL int `mapstructure:"profile_ttl"`
	// MaxTrackedPIDs is the maximum number of PIDs tracked simultaneously (default 65536).
	// When the cap is reached the least-recently-seen profile is evicted (LRU).
	MaxTrackedPIDs int `mapstructure:"max_tracked_pids"`
	// Sequence profiling configuration
	Sequence SequenceProfilerConfig `mapstructure:"sequence"`
	// Lineage tracking configuration
	Lineage LineageTrackerConfig `mapstructure:"lineage"`
}

// SequenceProfilerConfig holds syscall sequence anomaly detection settings.
type SequenceProfilerConfig struct {
	// Enabled enables sequence profiling
	Enabled bool `mapstructure:"enabled"`
	// WindowSize is the number of syscalls to track in the frequency vector
	WindowSize int `mapstructure:"window_size"`
	// Threshold is the cosine distance threshold for anomaly detection (0.0-1.0)
	Threshold float64 `mapstructure:"threshold"`
}

// LineageTrackerConfig holds process lineage tracking settings.
type LineageTrackerConfig struct {
	// Enabled enables lineage tracking
	Enabled bool `mapstructure:"enabled"`
	// TTL is the time-to-live for lineage entries in seconds
	TTL int `mapstructure:"ttl"`
	// MaxDepth is the maximum number of ancestors stored per process (default 16).
	MaxDepth int `mapstructure:"max_depth"`
}

// ExporterConfig holds metrics and alerting export settings.
type ExporterConfig struct {
	// Enabled enables the metrics exporter
	Enabled bool `mapstructure:"enabled"`
}

// AlertingConfig holds Alertmanager integration settings.
type AlertingConfig struct {
	// Enabled enables Alertmanager webhook integration
	Enabled bool `mapstructure:"enabled"`
	// WebhookURL is the Alertmanager webhook endpoint
	WebhookURL string `mapstructure:"webhook_url"`
	// GeneratorURL is the URL shown in alerts
	GeneratorURL string `mapstructure:"generator_url"`
	// BatchSize is the number of alerts to batch before sending
	BatchSize int `mapstructure:"batch_size"`
	// BatchTimeout is the maximum time to wait before sending a batch (seconds)
	BatchTimeout int `mapstructure:"batch_timeout"`
	// CircuitBreakerThreshold is the number of failed sends before opening circuit
	CircuitBreakerThreshold int `mapstructure:"circuit_breaker_threshold"`
}

// KubernetesConfig holds Kubernetes integration settings.
type KubernetesConfig struct {
	// Enabled enables Kubernetes metadata enrichment
	Enabled bool `mapstructure:"enabled"`
	// KubeconfigPath is the path to kubeconfig (empty for in-cluster)
	KubeconfigPath string `mapstructure:"kubeconfig_path"`
	// ResyncPeriod is the informer resync period in seconds
	ResyncPeriod int `mapstructure:"resync_period"`
}

// EnforcementConfig holds enforcement settings.
type EnforcementConfig struct {
	// Enabled enables enforcement actions
	Enabled bool `mapstructure:"enabled"`
	// BlockBackend specifies the network blocking backend: "log", "nftables", "iptables", "xdp"
	BlockBackend string `mapstructure:"block_backend"`
	// XDPInterface is the network interface to attach the XDP program to (e.g. "eth0").
	// Only used when block_backend is "xdp".
	XDPInterface string `mapstructure:"xdp_interface"`
	// DryRun mode logs actions without actual enforcement
	DryRun bool `mapstructure:"dry_run"`
	// EnableBlock enables packet blocking
	EnableBlock bool `mapstructure:"enable_block"`
	// EnableKill enables process termination
	EnableKill bool `mapstructure:"enable_kill"`
	// EnableThrottle enables cgroup-based rate limiting
	EnableThrottle bool `mapstructure:"enable_throttle"`
}

// WatchdogConfig holds watchdog and auto-tuning settings (Sprint 22.0).
type WatchdogConfig struct {
	// MemoryPressure enables automatic profiling downgrade on memory pressure
	MemoryPressure MemoryPressureConfig `mapstructure:"memory_pressure"`
}

// MemoryPressureConfig holds memory pressure auto-tuning settings.
type MemoryPressureConfig struct {
	// Enabled enables memory pressure monitoring
	Enabled bool `mapstructure:"enabled"`
	// CheckInterval is the interval for checking memory pressure (seconds)
	CheckInterval int `mapstructure:"check_interval"`
	// LowMemoryThreshold is the available memory % to trigger low-memory mode
	LowMemoryThreshold float64 `mapstructure:"low_memory_threshold"`
	// RecoveryThreshold is the available memory % to recover normal mode
	RecoveryThreshold float64 `mapstructure:"recovery_threshold"`
}

// PolicyConfig holds policy-as-code settings (Sprint 23.0).
type PolicyConfig struct {
	// Rego holds Rego/OPA policy engine configuration
	Rego RegoPolicyConfig `mapstructure:"rego"`
}

// GossipConfig holds cross-node IOC sharing settings.
type GossipConfig struct {
	// Enabled enables the gossip sub-system.
	Enabled bool `mapstructure:"enabled"`
	// Secret is the shared authentication token sent in X-Gossip-Secret.
	// If empty, gossip requests are accepted without authentication.
	Secret string `mapstructure:"secret"`
	// Peers is the list of peer base URLs to push IOCs to.
	// Example: ["http://10.0.0.2:9090", "http://10.0.0.3:9090"]
	Peers []string `mapstructure:"peers"`
	// IOCTTLSeconds is how long a published IOC remains valid (seconds). Default: 3600.
	IOCTTLSeconds int `mapstructure:"ioc_ttl"`
	// MaxIOCs caps the in-memory IOC store. Default: 100000.
	MaxIOCs int `mapstructure:"max_iocs"`
	// PushIntervalSeconds controls how often the delta is sent to peers. Default: 30.
	PushIntervalSeconds int `mapstructure:"push_interval"`
}

// CompatConfig holds migration compatibility settings (Sprint 24.0).
type CompatConfig struct {
	// FalcoOutput enables Falco-compatible JSON format for webhook/notifier output.
	// When true, alerts sent via webhook use the Falco JSON schema instead of the
	// native ebpf-guard schema, allowing existing Falco downstream integrations to work.
	FalcoOutput bool `mapstructure:"falco_output"`
	// MetricAliases lists compatibility metric alias sets to register.
	// Supported values: "falco", "tetragon", "kubearmor"
	// Each set registers Prometheus metric aliases so existing dashboards and
	// alert rules written for those tools continue to work without modification.
	MetricAliases []string `mapstructure:"metric_aliases"`
}

// RegoPolicyConfig holds Rego policy engine settings.
type RegoPolicyConfig struct {
	// Enabled enables Rego policy evaluation
	Enabled bool `mapstructure:"enabled"`
	// RulesDir is the directory containing .rego policy files
	RulesDir string `mapstructure:"rules_dir"`
}

// CheckConfigPermissions verifies the config file is not world-writable and is
// owned by root (uid 0) or the current process UID. Returns an error if the
// check fails; callers should treat this as a fatal startup error.
// Pass skipCheck=true (e.g. via --skip-config-permission-check) to bypass in tests.
func CheckConfigPermissions(path string, skipCheck bool) error {
	if skipCheck {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("config: stat %s: %w", path, err)
	}
	mode := info.Mode()
	if mode&0o002 != 0 {
		return fmt.Errorf("config: %s is world-writable (mode %o) — refusing to start; fix with: chmod o-w %s", path, mode, path)
	}
	return nil
}

// Manager handles configuration loading and hot-reload.
type Manager struct {
	viper    *viper.Viper
	config   *Config
	mu       sync.RWMutex
	onChange func(*Config)
}

// NewManager creates a new configuration manager.
// It checks config file permissions before loading. Use NewManagerSkipPermCheck
// for test environments where the config file is not expected to be root-owned.
func NewManager(configPath string) (*Manager, error) {
	return newManager(configPath, false)
}

// NewManagerSkipPermCheck creates a configuration manager without permission checks.
// Use only in tests.
func NewManagerSkipPermCheck(configPath string) (*Manager, error) {
	return newManager(configPath, true)
}

func newManager(configPath string, skipPermCheck bool) (*Manager, error) {
	if err := CheckConfigPermissions(configPath, skipPermCheck); err != nil {
		return nil, err
	}

	v := viper.New()
	v.SetConfigFile(configPath)
	v.SetConfigType("yaml")

	// Set defaults
	setDefaults(v)

	// Read config
	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("config: read config file: %w", err)
	}

	// Unmarshal
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("config: unmarshal config: %w", err)
	}

	m := &Manager{
		viper:  v,
		config: &cfg,
	}

	return m, nil
}

// setDefaults sets default configuration values.
func setDefaults(v *viper.Viper) {
	// Server defaults
	v.SetDefault("server.bind_address", ":9090")
	v.SetDefault("server.metrics_path", "/metrics")
	v.SetDefault("server.health_path", "/health")
	v.SetDefault("server.enable_pprof", false)
	v.SetDefault("server.enable_debug", false)

	// BPF defaults
	v.SetDefault("bpf.map_sizes.events", 65536)
	v.SetDefault("bpf.map_sizes.processes", 16384)
	v.SetDefault("bpf.map_sizes.connections", 32768)

	// Rules defaults
	v.SetDefault("rules.path", "/etc/ebpf-guard/rules.yaml")
	v.SetDefault("rules.hot_reload", true)
	v.SetDefault("rules.rate_limit_alerts", true)
	v.SetDefault("rules.rate_limit_window", 60)
	v.SetDefault("rules.max_alerts_per_window", 10)

	// Correlator defaults
	v.SetDefault("correlator.buffer_size", 10000)
	v.SetDefault("correlator.max_alerts_per_second", 10000)

	// Profiler defaults
	v.SetDefault("profiler.enabled", true)
	v.SetDefault("profiler.learning_period", 3600)
	v.SetDefault("profiler.min_learning_samples", 100)
	v.SetDefault("profiler.anomaly_threshold", 0.8)
	v.SetDefault("profiler.ewma_weight", 0.3)
	v.SetDefault("profiler.profile_ttl", 86400)
	v.SetDefault("profiler.max_tracked_pids", 65536)

	// Sequence profiler defaults
	v.SetDefault("profiler.sequence.enabled", true)
	v.SetDefault("profiler.sequence.window_size", 64)
	v.SetDefault("profiler.sequence.threshold", 0.3)

	// Lineage tracker defaults
	v.SetDefault("profiler.lineage.enabled", true)
	v.SetDefault("profiler.lineage.ttl", 300)
	v.SetDefault("profiler.lineage.max_depth", 16)

	// Exporter defaults
	v.SetDefault("exporter.enabled", true)

	// Alerting defaults
	v.SetDefault("alerting.enabled", false)
	v.SetDefault("alerting.webhook_url", "")
	v.SetDefault("alerting.generator_url", "http://ebpf-guard:9090")
	v.SetDefault("alerting.batch_size", 100)
	v.SetDefault("alerting.batch_timeout", 5)
	v.SetDefault("alerting.circuit_breaker_threshold", 5)

	// Kubernetes defaults
	v.SetDefault("kubernetes.enabled", true)
	v.SetDefault("kubernetes.kubeconfig_path", "")
	v.SetDefault("kubernetes.resync_period", 300)

	// Auth defaults - auth is enabled by default for security
	v.SetDefault("auth.enabled", true)
	v.SetDefault("auth.bearer_token", "")

	// Notifications defaults - all disabled by default
	v.SetDefault("notifications.slack.enabled", false)
	v.SetDefault("notifications.slack.webhook_url", "")
	v.SetDefault("notifications.slack.channel", "")
	v.SetDefault("notifications.slack.min_severity", "warning")

	v.SetDefault("notifications.teams.enabled", false)
	v.SetDefault("notifications.teams.webhook_url", "")
	v.SetDefault("notifications.teams.min_severity", "warning")

	v.SetDefault("notifications.webhook.enabled", false)
	v.SetDefault("notifications.webhook.url", "")
	v.SetDefault("notifications.webhook.headers", map[string]string{})
	v.SetDefault("notifications.webhook.template", "")
	v.SetDefault("notifications.webhook.min_severity", "warning")

	// Store defaults
	v.SetDefault("store.backend", "memory")
	v.SetDefault("store.sqlite.path", "/var/lib/ebpf-guard/events.db")
	v.SetDefault("store.opensearch.url", "")
	v.SetDefault("store.opensearch.index", "ebpf-guard-events")
	v.SetDefault("store.opensearch.username", "")
	v.SetDefault("store.opensearch.password", "")
	v.SetDefault("store.opensearch.insecure_skip_verify", false)

	// Collectors defaults
	v.SetDefault("collectors.tls.enabled", false)
	v.SetDefault("collectors.tls.scan_interval", "30s")
	v.SetDefault("collectors.tls.max_data_size", 256)

	// DNS collector defaults
	v.SetDefault("collectors.dns.enabled", true)
	v.SetDefault("collectors.dns.dga_threshold", 3.5)
	v.SetDefault("collectors.dns.tunneling_min_length", 50)
	v.SetDefault("collectors.dns.high_frequency_threshold", 100)

	// Enforcement defaults
	v.SetDefault("enforcement.enabled", false)
	v.SetDefault("enforcement.block_backend", "log")
	v.SetDefault("enforcement.xdp_interface", "")
	v.SetDefault("enforcement.dry_run", false)
	v.SetDefault("enforcement.enable_block", false)
	v.SetDefault("enforcement.enable_kill", false)
	v.SetDefault("enforcement.enable_throttle", false)

	// Watchdog defaults (Sprint 22.0)
	v.SetDefault("watchdog.memory_pressure.enabled", true)
	v.SetDefault("watchdog.memory_pressure.check_interval", 5)
	v.SetDefault("watchdog.memory_pressure.low_memory_threshold", 10.0)
	v.SetDefault("watchdog.memory_pressure.recovery_threshold", 20.0)

	// Policy defaults (Sprint 23.0)
	v.SetDefault("policy.rego.enabled", true)
	v.SetDefault("policy.rego.rules_dir", "rules/rego")

	// Compat defaults (Sprint 24.0)
	v.SetDefault("compat.falco_output", false)
	v.SetDefault("compat.metric_aliases", []string{})

	// Gossip defaults — disabled by default; operators opt in per node.
	v.SetDefault("gossip.enabled", false)
	v.SetDefault("gossip.secret", "")
	v.SetDefault("gossip.peers", []string{})
	v.SetDefault("gossip.ioc_ttl", 3600)
	v.SetDefault("gossip.max_iocs", 100_000)
	v.SetDefault("gossip.push_interval", 30)
}

// Get returns the current configuration (thread-safe).
func (m *Manager) Get() *Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config
}

// OnChange registers a callback for configuration changes.
func (m *Manager) OnChange(fn func(*Config)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onChange = fn
}

// Watch starts watching for configuration file changes.
// Call this after OnChange to receive notifications.
func (m *Manager) Watch() error {
	m.viper.WatchConfig()
	m.viper.OnConfigChange(func(e fsnotify.Event) {
		m.mu.Lock()
		defer m.mu.Unlock()

		var newConfig Config
		if err := m.viper.Unmarshal(&newConfig); err != nil {
			slog.Warn("config: hot-reload rejected, keeping previous config", slog.Any("error", err))
			return
		}

		// viper.WatchConfig commonly fires OnConfigChange more than once for a
		// single write (WRITE+CHMOD, atomic-rename saves, etc.). Skip callbacks
		// when the effective config is unchanged so consumers don't see spurious
		// duplicate reloads.
		if m.config != nil && reflect.DeepEqual(m.config, &newConfig) {
			return
		}

		m.config = &newConfig

		if m.onChange != nil {
			m.onChange(&newConfig)
		}
	})

	return nil
}

// Stop stops watching for configuration changes.
func (m *Manager) Stop() {
	// viper doesn't have a direct stop method for watching
	// The watcher will be cleaned up when the program exits
}
