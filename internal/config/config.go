// Package config provides configuration management with hot-reload support.
package config

import (
	"fmt"
	"log/slog"
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
	Events     int `mapstructure:"events"`
	Processes  int `mapstructure:"processes"`
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
}

// ProfilerConfig holds behavioral profiling settings.
type ProfilerConfig struct {
	// Enabled enables behavioral profiling and anomaly detection
	Enabled bool `mapstructure:"enabled"`
	// LearningPeriod is the initial learning period in seconds (no alerts)
	LearningPeriod int `mapstructure:"learning_period"`
	// AnomalyThreshold is the score threshold for generating alerts (0.0-1.0)
	AnomalyThreshold float64 `mapstructure:"anomaly_threshold"`
	// EWMAWeight is the weight for Exponentially Weighted Moving Average (0.0-1.0)
	EWMAWeight float64 `mapstructure:"ewma_weight"`
	// ProfileTTL is the time-to-live for process profiles in seconds
	ProfileTTL int `mapstructure:"profile_ttl"`
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

// Manager handles configuration loading and hot-reload.
type Manager struct {
	viper  *viper.Viper
	config *Config
	mu     sync.RWMutex
	onChange func(*Config)
}

// NewManager creates a new configuration manager.
func NewManager(configPath string) (*Manager, error) {
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

	// Profiler defaults
	v.SetDefault("profiler.enabled", true)
	v.SetDefault("profiler.learning_period", 3600)
	v.SetDefault("profiler.anomaly_threshold", 0.8)
	v.SetDefault("profiler.ewma_weight", 0.3)
	v.SetDefault("profiler.profile_ttl", 86400)

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
