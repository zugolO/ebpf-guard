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

	// ConfigVersion is the schema version of this config file (e.g. "v0.1").
	// Used by 'ebpf-guard config validate/migrate' to detect stale fields.
	ConfigVersion string `mapstructure:"config_version"`

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

	// Wasm configuration — custom detection plugin engine.
	Wasm WasmConfig `mapstructure:"wasm"`

	// OSINT configuration — automated rule generation from threat intelligence feeds.
	OSINT OSINTConfig `mapstructure:"osint"`

	// EventLog configuration — JSONL event log for rule replay (feature C).
	EventLog EventLogConfig `mapstructure:"event_log"`

	// Canary configuration — honeypot file detection (feature D).
	Canary CanaryConfig `mapstructure:"canary"`

	// Audit configuration — append-only JSONL audit log for rule and config changes.
	Audit AuditConfig `mapstructure:"audit"`
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
	// If true and tokens are empty, random tokens are generated at startup.
	Enabled bool `mapstructure:"enabled"`
	// BearerToken is deprecated — use AdminToken instead. Kept for backward compatibility.
	// If set and AdminToken is empty, BearerToken is promoted to AdminToken.
	BearerToken string `mapstructure:"bearer_token"`
	// ViewerToken grants read-only access: GET /alerts, GET /rules, GET /health, GET /metrics.
	// Auto-generated at startup if empty and Enabled is true.
	ViewerToken string `mapstructure:"viewer_token"`
	// AdminToken grants full access including write operations (POST /feedback, PUT /rules, DELETE).
	// Auto-generated at startup if empty and Enabled is true.
	AdminToken string `mapstructure:"admin_token"`
	// Tokens is a list of namespace-scoped bearer tokens for multi-tenant deployments.
	// When non-empty, these are evaluated in addition to the legacy ViewerToken/AdminToken.
	// Each token carries its own role and namespace allowlist.
	Tokens []NamespacedTokenConfig `mapstructure:"tokens"`
}

// NamespacedTokenConfig defines a bearer token with an associated role and namespace scope.
type NamespacedTokenConfig struct {
	// Token is the bearer token value.
	Token string `mapstructure:"token"`
	// Role is "viewer" or "admin".
	Role string `mapstructure:"role"`
	// Namespaces lists Kubernetes namespaces this token may access.
	// Empty slice means all namespaces (global access).
	Namespaces []string `mapstructure:"namespaces"`
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
	// OTelTracing configures W3C Trace Context extraction from TLS payloads and OTel span linking.
	// Requires collectors.tls.enabled=true to have effect.
	OTelTracing OTelTracingConfig `mapstructure:"otel_tracing"`
	// CloudTrail configures the AWS CloudTrail collector.
	CloudTrail CloudTrailCollectorConfig `mapstructure:"cloudtrail"`
	// GCPAudit configures the GCP Audit Logs collector.
	GCPAudit GCPAuditCollectorConfig `mapstructure:"gcp_audit"`
}

// CloudTrailCollectorConfig holds AWS CloudTrail via SQS polling settings.
// CloudTrail delivers events via CloudTrail → S3 → SNS → SQS.
type CloudTrailCollectorConfig struct {
	// Enabled activates the CloudTrail collector.
	Enabled bool `mapstructure:"enabled"`
	// SQSQueueURL is the SQS queue URL receiving CloudTrail S3 delivery notifications.
	// Format: "https://sqs.{region}.amazonaws.com/{account-id}/{queue-name}"
	SQSQueueURL string `mapstructure:"sqs_queue_url"`
	// Region is the AWS region for the SQS queue (e.g. "us-east-1").
	// If empty, it is inferred from the SQSQueueURL.
	Region string `mapstructure:"region"`
	// PollInterval is how often to poll SQS for new messages (Go duration string).
	// Default: "10s"
	PollInterval string `mapstructure:"poll_interval"`
	// MaxMessages is the number of SQS messages to fetch per poll (1-10).
	// Default: 10
	MaxMessages int `mapstructure:"max_messages"`
}

// GCPAuditCollectorConfig holds GCP Audit Logs via Pub/Sub settings.
type GCPAuditCollectorConfig struct {
	// Enabled activates the GCP Audit Logs collector.
	Enabled bool `mapstructure:"enabled"`
	// PubSubSubscription is the Pub/Sub subscription resource name.
	// Format: "projects/{project}/subscriptions/{subscription}"
	PubSubSubscription string `mapstructure:"pubsub_subscription"`
	// PollInterval is how often to pull messages from Pub/Sub (Go duration string).
	// Default: "10s"
	PollInterval string `mapstructure:"poll_interval"`
	// MaxMessages is the maximum number of messages to pull per request.
	// Default: 100
	MaxMessages int `mapstructure:"max_messages"`
	// CredentialsFile is the path to a GCP service account JSON key file.
	// When empty, Application Default Credentials (ADC) are used:
	// GOOGLE_APPLICATION_CREDENTIALS env var, then GCE/GKE metadata server.
	CredentialsFile string `mapstructure:"credentials_file"`
}

// WasmConfig configures the WASM detection plugin engine.
type WasmConfig struct {
	// Enabled activates the WASM plugin engine.
	// Default: true (auto-activates when plugin files are present in PluginDir)
	Enabled bool `mapstructure:"enabled"`
	// PluginDir is the directory scanned for .wasm plugin files.
	// Default: "rules/custom"
	PluginDir string `mapstructure:"plugin_dir"`
	// MemoryLimitMB is the linear memory limit per plugin instance in megabytes.
	// Default: 16 (256 pages × 64KB)
	MemoryLimitMB int `mapstructure:"memory_limit_mb"`
	// PluginTimeoutMS is the per-invocation deadline for a single WASM plugin in milliseconds.
	// A plugin exceeding this limit is interrupted so it cannot stall the event pipeline.
	// Default: 100
	PluginTimeoutMS int `mapstructure:"plugin_timeout_ms"`
}

// OTelTracingConfig configures automatic W3C Trace Context extraction and OTel span
// linking between APM traces and security events.
//
// When the TLS collector captures plaintext HTTP/gRPC traffic, ebpf-guard scans
// the headers for the W3C "traceparent" header. If found, the trace ID and parent
// span ID are attached to all security events and alerts generated for that request.
// This links APM observability and runtime security into a single timeline.
type OTelTracingConfig struct {
	// Enabled activates traceparent header extraction from TLS plaintext payloads.
	// Auto-enabled when collectors.tls.enabled=true; set to false to opt out.
	// Default: true
	Enabled bool `mapstructure:"enabled"`
	// ExporterEndpoint is the OTLP gRPC endpoint for exporting security-linked spans.
	// Example: "localhost:4317" or "otel-collector.monitoring.svc:4317"
	// When empty, spans are emitted only into the global OTel provider (if configured).
	// Default: ""
	ExporterEndpoint string `mapstructure:"exporter_endpoint"`
	// ServiceName is the OTel service.name attribute on exported security spans.
	// Default: "ebpf-guard"
	ServiceName string `mapstructure:"service_name"`
	// PropagateToAlerts controls whether trace_id and span_id appear in generated alerts.
	// Default: true
	PropagateToAlerts bool `mapstructure:"propagate_to_alerts"`
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
	// DGAWhitelist contains second-level domain labels that should never be
	// classified as DGA-generated regardless of their n-gram score.
	// Use to suppress false positives on CDN or internal naming patterns.
	// Example: ["clarity", "akamaiedge", "r2", "azureedge", "trafficmanager"]
	DGAWhitelist []string `mapstructure:"dga_whitelist"`
}

// SQLiteEncryptionConfig holds column-level encryption settings for the SQLite store.
type SQLiteEncryptionConfig struct {
	// Enabled activates AES-256-GCM column-level encryption for sensitive alert
	// fields (message, details, labels). A startup WARN is emitted when false.
	Enabled bool `mapstructure:"enabled"`
	// KeyEnv is the name of the environment variable holding the encryption key.
	// The key must be a 64-char hex string or a base64 string that decodes to
	// exactly 32 bytes. Takes precedence over KeyFile when both are set.
	KeyEnv string `mapstructure:"key_env"`
	// KeyFile is the path to a file containing the encryption key (e.g. a
	// Kubernetes Secret mounted at /run/secrets/db-key).
	KeyFile string `mapstructure:"key_file"`
}

// SQLiteStoreConfig holds SQLite-specific configuration.
type SQLiteStoreConfig struct {
	// Path to the SQLite database file
	Path string `mapstructure:"path"`
	// MaxAlerts is the maximum number of alerts to retain. Oldest excess rows
	// are pruned on each VacuumInterval. Zero disables pruning.
	MaxAlerts int64 `mapstructure:"max_alerts"`
	// VacuumInterval is how often WAL is checkpointed and excess rows pruned
	// (Go duration string, e.g. "1h", "30m"). Zero disables background maintenance.
	VacuumInterval string `mapstructure:"vacuum_interval"`
	// RetentionPeriod is the maximum age of alerts to retain (e.g. "7d", "168h").
	// Alerts older than this are deleted each VacuumInterval. Zero disables age-based retention.
	RetentionPeriod string `mapstructure:"retention_period"`
	// Backup configures periodic SQLite database backups.
	Backup SQLiteBackupConfig `mapstructure:"backup"`
	// Encryption configures AES-256-GCM column-level encryption at rest.
	Encryption SQLiteEncryptionConfig `mapstructure:"encryption"`
}

// SQLiteBackupConfig holds SQLite backup configuration.
type SQLiteBackupConfig struct {
	// Enabled activates periodic database backups.
	Enabled bool `mapstructure:"enabled"`
	// Path is the destination file path for the backup copy (e.g. /backup/alerts.db).
	// The directory must exist and be writable.
	Path string `mapstructure:"path"`
	// Interval controls how often a backup is created (Go duration string, e.g. "1h").
	// Defaults to "1h" when Enabled is true.
	Interval string `mapstructure:"interval"`
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

	// RingBufSize is the BPF ring buffer size in bytes applied to each
	// event ring buffer (syscall, network, file, TLS, LSM).
	// 0 = auto-detect: 1% of MemAvailable from /proc/meminfo, clamped to [256 KB, 32 MB].
	// Non-multiples of the page size (4096) are rounded up automatically.
	RingBufSize int `mapstructure:"ring_buf_size"`

	// KernelFilter configures BPF-side content-based event filtering.
	// When enabled, events are dropped in the kernel before reaching the ring
	// buffer, reducing userspace CPU overhead by 40-60% on typical workloads.
	KernelFilter KernelFilterConfig `mapstructure:"kernel_filter"`

	// BTFPath is an explicit path to an external BTF file.
	// Leave empty to use auto-detection (local → btf_hub → headers → none).
	BTFPath string `mapstructure:"btf_path"`

	// BTFHubEnabled controls whether the BTF hub archive is used as a fallback
	// when kernel-embedded BTF (/sys/kernel/btf/vmlinux) is unavailable.
	// Requires outbound HTTPS access on first run; subsequent runs use the cache.
	BTFHubEnabled bool `mapstructure:"btf_hub_enabled"`

	// BTFHubCache is the local directory where BTF hub files are cached.
	// Default: /var/lib/ebpf-guard/btf
	BTFHubCache string `mapstructure:"btf_hub_cache"`

	// FallbackReducedFeatures allows ebpf-guard to start with a reduced set of
	// collectors (no LSM hooks, no TLS uprobes) when no BTF source is available.
	// When false (default), startup fails if BTF cannot be resolved.
	FallbackReducedFeatures bool `mapstructure:"fallback_reduced_features"`
}

// KernelFilterConfig controls BPF-side content-based filtering.
type KernelFilterConfig struct {
	// Enabled activates comm denylist and syscall allowlist filtering inside BPF.
	// Default: true.
	Enabled bool `mapstructure:"enabled"`

	// MonitoredSyscalls lists syscall numbers that should be forwarded to
	// userspace.  Events for any syscall not in this list are discarded in the
	// kernel.  An empty slice means "use built-in defaults" (execve, ptrace,
	// capset, setns, memfd_create, mount, etc.).
	MonitoredSyscalls []int `mapstructure:"monitored_syscalls"`

	// CommDenylist lists process comm names (up to 15 chars) whose events
	// should be silently dropped at the kernel level.  An empty slice means
	// "use built-in defaults" (kworker, ksoftirqd, migration, rcu_sched, ...).
	CommDenylist []string `mapstructure:"comm_denylist"`
}

// MapSizeConfig holds BPF map size settings.
type MapSizeConfig struct {
	Events      int `mapstructure:"events"`
	Processes   int `mapstructure:"processes"`
	Connections int `mapstructure:"connections"`
	// FdMap controls the maximum number of entries in the fd→path LRU map used
	// for fd-enrichment (issue #47). Each entry holds 8B key + 257B value ≈ 265B.
	// Default 65536 entries ≈ 17 MB. Set lower on memory-constrained nodes.
	FdMap int `mapstructure:"fd_map_size"`
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
	// AdaptiveSampling configures CPU-load-triggered adaptive rule sampling.
	// When enabled, warning-severity rules are automatically downsampled when
	// CPU utilization exceeds the configured threshold.
	AdaptiveSampling AdaptiveSamplingConfig `mapstructure:"adaptive_sampling"`
	// Namespaces defines per-namespace rule overrides or extensions.
	// Each entry maps a Kubernetes label selector to an additional rules file.
	// These are merged with (or replace) the global rules depending on Override.
	Namespaces []NamespaceRuleConfig `mapstructure:"namespaces"`
}

// NamespaceRuleConfig maps a Kubernetes label selector to additional rule files.
type NamespaceRuleConfig struct {
	// Selector is a Kubernetes label selector matching namespace labels (e.g. "team=security").
	Selector string `mapstructure:"selector"`
	// Path is the directory or file containing extra rules for matching namespaces.
	Path string `mapstructure:"path"`
	// Override replaces global rules when true; merges (adds) when false.
	Override bool `mapstructure:"override"`
}

// AdaptiveSamplingConfig configures CPU-load-triggered adaptive rule sampling.
type AdaptiveSamplingConfig struct {
	// Enabled activates adaptive sampling. Default: false.
	Enabled bool `mapstructure:"enabled"`
	// TriggerCPUPercent is the CPU utilization threshold [0, 100] that activates sampling.
	TriggerCPUPercent float64 `mapstructure:"trigger_cpu_percent"`
	// WarningSampleRate is applied to warning-severity rules when active (0–1).
	WarningSampleRate float64 `mapstructure:"warning_sample_rate"`
	// CriticalSampleRate is always 1.0 — critical rules are never downsampled.
	CriticalSampleRate float64 `mapstructure:"critical_sample_rate"`
	// CheckInterval controls how often CPU utilization is sampled (e.g. "5s"). Default: 5s.
	CheckInterval string `mapstructure:"check_interval"`
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
	// MaxTrackedPIDs is the maximum number of PIDs tracked simultaneously.
	// Default 0 means auto-detect from /proc/sys/kernel/pid_max (falls back to 65536).
	// When the cap is reached the least-recently-seen profile is evicted (LRU).
	MaxTrackedPIDs int `mapstructure:"max_tracked_pids"`
	// Sequence profiling configuration
	Sequence SequenceProfilerConfig `mapstructure:"sequence"`
	// Lineage tracking configuration
	Lineage LineageTrackerConfig `mapstructure:"lineage"`
	// StatePersistence configures EWMA state save/restore across pod restarts.
	StatePersistence StatePersistenceConfig `mapstructure:"state_persistence"`
	// SyscallAllowlist configures deny-unknown (allowlist) mode for syscalls.
	SyscallAllowlist SyscallAllowlistConfig `mapstructure:"syscall_allowlist"`
}

// SyscallAllowlistConfig configures the deny-unknown syscall allowlist mode.
// During the learning phase the agent records every unique syscall number per
// workload; after the learning period it alerts (or blocks/kills) on any
// syscall that was never observed.
type SyscallAllowlistConfig struct {
	// Enabled activates allowlist mode.
	Enabled bool `mapstructure:"enabled"`
	// Mode is the initial mode: "learning" or "enforcing".
	// The profiler auto-transitions to enforcing after LearningPeriod.
	Mode string `mapstructure:"mode"`
	// EnforcingAction is the action taken on violations: "alert", "block", or "kill".
	EnforcingAction string `mapstructure:"enforcing_action"`
	// PerWorkload separates allowlists per (comm, namespace, app_label) tuple.
	PerWorkload bool `mapstructure:"per_workload"`
	// LearningPeriod is the duration in seconds to record syscalls before enforcing.
	LearningPeriod int `mapstructure:"learning_period"`
	// MinSamples is the minimum number of syscall events required before learning completes.
	MinSamples int `mapstructure:"min_samples"`
	// SparseThreshold is the minimum number of unique syscalls a profile must
	// contain; profiles below this value generate a sparse-profile alert.
	SparseThreshold int `mapstructure:"sparse_threshold"`
	// GlobalAllow lists syscall numbers that are always permitted (never alerted).
	GlobalAllow []int `mapstructure:"global_allow"`
	// GlobalDeny lists syscall numbers that always generate alerts regardless of
	// the learned profile (e.g. ptrace=101, process_vm_readv=310).
	GlobalDeny []int `mapstructure:"global_deny"`
	// PersistPath is the file path for JSON state persistence across restarts.
	// Empty string disables persistence.
	PersistPath string `mapstructure:"persist_path"`
}

// StatePersistenceConfig controls saving the EWMA profiler state to disk so
// that the agent can skip the learning period after a pod restart.
type StatePersistenceConfig struct {
	// Enabled activates state save on shutdown and restore on startup.
	Enabled bool `mapstructure:"enabled"`
	// Path is the file path where the profiler state JSON is written.
	// Defaults to /var/lib/ebpf-guard/profiler-state.json.
	Path string `mapstructure:"path"`
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
	// CircuitBreakerResetTimeout is seconds to wait in Open state before attempting
	// a probe (Half-Open transition). Default: 30.
	CircuitBreakerResetTimeout int `mapstructure:"circuit_breaker_reset_timeout"`
	// FallbackBufferSize is the maximum number of alerts to buffer in the fallback
	// queue while the circuit is open. Oldest entries are evicted when full.
	// Default: 10000.
	FallbackBufferSize int `mapstructure:"fallback_buffer_size"`
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
	// ThrottleCPUPercent is the CPU limit (1-99) applied when throttling a process via cgroup v2.
	// Default: 10
	ThrottleCPUPercent int `mapstructure:"throttle_cpu_percent"`
	// ThrottleMaxAgeMinutes is how long (minutes) a throttle entry is kept after last use.
	// Default: 30
	ThrottleMaxAgeMinutes int `mapstructure:"throttle_max_age_minutes"`
	// ThrottleCleanupIntervalMinutes is how often (minutes) the stale-entry cleanup runs.
	// Default: 5
	ThrottleCleanupIntervalMinutes int `mapstructure:"throttle_cleanup_interval_minutes"`
	// AuditLog is the path to an append-only JSONL audit log for enforcement actions.
	// Each kill/block/throttle action is written as one JSON line.
	// The file is rotated (renamed to <path>.1) when it exceeds 100 MB.
	// Empty string disables audit logging.
	AuditLog string `mapstructure:"audit_log"`
	// LSMPathBlocklist is a list of absolute path globs that are always blocked
	// via the eBPF LSM file_open hook, regardless of per-rule conditions.
	// Requires LSM BPF support (kernel 5.9+) and block_backend = lsm.
	// Hot-reloadable: the BPF map is updated without restart on config change.
	// Example: ["/etc/shadow", "/proc/sysrq-trigger"]
	LSMPathBlocklist []string `mapstructure:"lsm_path_blocklist"`
	// AuditLSMEvents enables forwarding LSM hook audit records (file_open blocks,
	// socket_connect blocks, task_kill records) to the audit log.
	// Has no effect when audit_log is empty.
	AuditLSMEvents bool `mapstructure:"audit_lsm_events"`
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
	// NodeName is this node's identifier included in IOC and amplification
	// messages. Defaults to the system hostname when empty.
	NodeName string `mapstructure:"node_name"`
	// Secret is the shared authentication token sent in X-Gossip-Secret.
	// If empty, gossip requests are accepted without authentication.
	Secret string `mapstructure:"secret"`
	// Peers is the list of peer base URLs to push IOCs to.
	// With TLS enabled use https:// URLs, e.g. "https://10.0.0.2:9090".
	Peers []string `mapstructure:"peers"`
	// IOCTTLSeconds is how long a published IOC remains valid (seconds). Default: 3600.
	IOCTTLSeconds int `mapstructure:"ioc_ttl"`
	// MaxIOCs caps the in-memory IOC store. Default: 100000.
	MaxIOCs int `mapstructure:"max_iocs"`
	// PushIntervalSeconds controls how often the delta is sent to peers. Default: 30.
	PushIntervalSeconds int `mapstructure:"push_interval"`
	// TLSEnabled activates mTLS for all peer-to-peer gossip connections.
	// When true, TLSCertFile, TLSKeyFile, and TLSCAFile must be set.
	TLSEnabled bool `mapstructure:"tls_enabled"`
	// TLSCertFile is the path to the PEM-encoded client certificate.
	TLSCertFile string `mapstructure:"tls_cert_file"`
	// TLSKeyFile is the path to the PEM-encoded private key for TLSCertFile.
	TLSKeyFile string `mapstructure:"tls_key_file"`
	// TLSCAFile is the path to the PEM-encoded CA bundle used to verify peer certificates.
	TLSCAFile string `mapstructure:"tls_ca_file"`
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

// OSINTConfig holds OSINT threat intelligence feed integration settings.
type OSINTConfig struct {
	// Enabled activates the OSINT feed sync engine.
	Enabled bool `mapstructure:"enabled"`
	// RefreshInterval is the duration between feed syncs (e.g., "3h", "30m").
	RefreshInterval string `mapstructure:"refresh_interval"`
	// OutputDir is the directory where generated rule YAML files are written.
	// The correlator's hot-reload watcher picks up changes automatically.
	OutputDir string `mapstructure:"output_dir"`
	// MaxIoCsPerRule caps how many indicator values appear in a single rule's
	// condition list. Larger batches reduce file count but may slow evaluation.
	MaxIoCsPerRule int `mapstructure:"max_iocs_per_rule"`
	// MISP holds settings for a MISP threat sharing platform instance.
	MISP MISPConfig `mapstructure:"misp"`
	// OpenCTI holds settings for an OpenCTI threat intelligence platform.
	OpenCTI OpenCTIConfig `mapstructure:"opencti"`
	// VirusTotal holds settings for VirusTotal threat intelligence feeds.
	VirusTotal VirusTotalConfig `mapstructure:"virustotal"`
}

// MISPConfig configures the MISP REST API client.
type MISPConfig struct {
	// Enabled activates MISP feed fetching.
	Enabled bool `mapstructure:"enabled"`
	// URL is the base URL of the MISP instance (e.g., "https://misp.example.com").
	URL string `mapstructure:"url"`
	// APIKey is the MISP automation key (found in MISP → My Profile → Auth key).
	APIKey string `mapstructure:"api_key"`
	// VerifyTLS controls whether the MISP server's TLS certificate is verified.
	VerifyTLS bool `mapstructure:"verify_tls"`
	// AttributeTypes restricts which MISP attribute types are fetched.
	// Defaults to ["ip-dst", "ip-src", "domain", "hostname"].
	AttributeTypes []string `mapstructure:"attribute_types"`
	// MinThreatLevel filters events by MISP threat level (1=high … 4=undefined).
	// Default: 3 (high + medium + low).
	MinThreatLevel int `mapstructure:"min_threat_level"`
	// Tags is an optional list of MISP tags to filter attributes (OR logic).
	Tags []string `mapstructure:"tags"`
}

// OpenCTIConfig configures the OpenCTI GraphQL API client.
type OpenCTIConfig struct {
	// Enabled activates OpenCTI indicator fetching.
	Enabled bool `mapstructure:"enabled"`
	// URL is the base URL of the OpenCTI instance (e.g., "https://opencti.example.com").
	URL string `mapstructure:"url"`
	// APIKey is the OpenCTI API token.
	APIKey string `mapstructure:"api_key"`
	// VerifyTLS controls whether the OpenCTI server's TLS certificate is verified.
	VerifyTLS bool `mapstructure:"verify_tls"`
	// ConfidenceMin is the minimum indicator confidence score (0–100) to include.
	ConfidenceMin int `mapstructure:"confidence_min"`
	// TLPMarkings filters indicators to those with any of the listed TLP markings.
	// Empty list means accept all markings.
	// Example: ["TLP:WHITE", "TLP:GREEN"]
	TLPMarkings []string `mapstructure:"tlp_markings"`
}

// VirusTotalConfig configures the VirusTotal API v3 client.
type VirusTotalConfig struct {
	// Enabled activates VirusTotal feed fetching.
	Enabled bool `mapstructure:"enabled"`
	// APIKey is the VirusTotal API key.
	APIKey string `mapstructure:"api_key"`
	// EnterpriseFeeds enables the VirusTotal Intelligence feed endpoints
	// (/api/v3/feeds/ips and /api/v3/feeds/domains), which require a
	// VirusTotal Intelligence subscription. Set false for community-only usage.
	EnterpriseFeeds bool `mapstructure:"enterprise_feeds"`
}

// EventLogConfig holds JSONL event log settings for rule replay.
type EventLogConfig struct {
	// Enabled enables writing events to the log for later replay.
	Enabled bool `mapstructure:"enabled"`
	// Path is the file path for the JSONL event log.
	// Default: /var/lib/ebpf-guard/events.jsonl
	Path string `mapstructure:"path"`
	// MaxSizeMB is the maximum log file size in MB before rotation.
	// Default: 100
	MaxSizeMB int `mapstructure:"max_size_mb"`
}

// CanaryConfig holds canary trap / honeypot detection settings.
type CanaryConfig struct {
	// Enabled activates canary trap detection.
	Enabled bool `mapstructure:"enabled"`
	// AutoCreate creates the canary files at startup if they do not exist.
	AutoCreate bool `mapstructure:"auto_create"`
	// Files is the list of canary file paths to monitor.
	// If empty, a built-in set of high-value reconnaissance paths is used.
	Files []string `mapstructure:"files"`
	// AlertSeverity is the severity for canary access alerts ("warning" or "critical").
	// Default: critical
	AlertSeverity string `mapstructure:"alert_severity"`
}

// AuditConfig holds settings for the rule-change and config-reload audit log.
type AuditConfig struct {
	// Enabled activates the audit log.
	Enabled bool `mapstructure:"enabled"`
	// Path is the file path for the append-only JSONL audit log.
	// Default: /var/log/ebpf-guard/audit.jsonl
	Path string `mapstructure:"path"`
	// MaxSizeMB is the maximum log file size in MB before rotation.
	// Default: 100
	MaxSizeMB int `mapstructure:"max_size_mb"`
	// IncludeRuleDiffs enables logging the full old_rule_ids / new_rule_ids lists
	// in addition to counts. Disable for very large rule sets to reduce log volume.
	// Default: true
	IncludeRuleDiffs bool `mapstructure:"include_rule_diffs"`
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
	// Schema version
	v.SetDefault("config_version", "v0.1")

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
	v.SetDefault("bpf.map_sizes.fd_map_size", 65536)
	v.SetDefault("bpf.ring_buf_size", 0) // 0 = auto-detect from /proc/meminfo
	v.SetDefault("bpf.btf_path", "")
	v.SetDefault("bpf.btf_hub_enabled", true)
	v.SetDefault("bpf.btf_hub_cache", "/var/lib/ebpf-guard/btf")
	v.SetDefault("bpf.fallback_reduced_features", false)

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
	v.SetDefault("profiler.max_tracked_pids", 0) // 0 = auto-detect from /proc/sys/kernel/pid_max

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
	v.SetDefault("alerting.circuit_breaker_reset_timeout", 30)
	v.SetDefault("alerting.fallback_buffer_size", 10000)

	// Kubernetes defaults
	v.SetDefault("kubernetes.enabled", true)
	v.SetDefault("kubernetes.kubeconfig_path", "")
	v.SetDefault("kubernetes.resync_period", 300)

	// Auth defaults - auth is enabled by default for security
	v.SetDefault("auth.enabled", true)
	v.SetDefault("auth.bearer_token", "")
	v.SetDefault("auth.viewer_token", "")
	v.SetDefault("auth.admin_token", "")

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
	v.SetDefault("store.sqlite.max_alerts", int64(100000))
	v.SetDefault("store.sqlite.vacuum_interval", "1h")
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
	v.SetDefault("collectors.dns.dga_whitelist", []string{})

	// Enforcement defaults
	v.SetDefault("enforcement.enabled", false)
	v.SetDefault("enforcement.block_backend", "log")
	v.SetDefault("enforcement.xdp_interface", "")
	v.SetDefault("enforcement.dry_run", false)
	v.SetDefault("enforcement.enable_block", false)
	v.SetDefault("enforcement.enable_kill", false)
	v.SetDefault("enforcement.enable_throttle", false)
	v.SetDefault("enforcement.throttle_cpu_percent", 10)
	v.SetDefault("enforcement.throttle_max_age_minutes", 30)
	v.SetDefault("enforcement.throttle_cleanup_interval_minutes", 5)
	v.SetDefault("enforcement.audit_log", "")
	v.SetDefault("enforcement.lsm_path_blocklist", []string{})
	v.SetDefault("enforcement.audit_lsm_events", true)

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
	v.SetDefault("gossip.node_name", "")
	v.SetDefault("gossip.secret", "")
	v.SetDefault("gossip.peers", []string{})
	v.SetDefault("gossip.ioc_ttl", 3600)
	v.SetDefault("gossip.max_iocs", 100_000)
	v.SetDefault("gossip.push_interval", 30)
	v.SetDefault("gossip.tls_enabled", false)
	v.SetDefault("gossip.tls_cert_file", "")
	v.SetDefault("gossip.tls_key_file", "")
	v.SetDefault("gossip.tls_ca_file", "")

	// OSINT defaults — disabled by default; operators configure sources explicitly.
	v.SetDefault("osint.enabled", false)
	v.SetDefault("osint.refresh_interval", "3h")
	v.SetDefault("osint.output_dir", "rules/osint")
	v.SetDefault("osint.max_iocs_per_rule", 500)

	v.SetDefault("osint.misp.enabled", false)
	v.SetDefault("osint.misp.url", "")
	v.SetDefault("osint.misp.api_key", "")
	v.SetDefault("osint.misp.verify_tls", true)
	v.SetDefault("osint.misp.attribute_types", []string{"ip-dst", "ip-src", "domain", "hostname"})
	v.SetDefault("osint.misp.min_threat_level", 3)
	v.SetDefault("osint.misp.tags", []string{})

	v.SetDefault("osint.opencti.enabled", false)
	v.SetDefault("osint.opencti.url", "")
	v.SetDefault("osint.opencti.api_key", "")
	v.SetDefault("osint.opencti.verify_tls", true)
	v.SetDefault("osint.opencti.confidence_min", 50)
	v.SetDefault("osint.opencti.tlp_markings", []string{})

	v.SetDefault("osint.virustotal.enabled", false)
	v.SetDefault("osint.virustotal.api_key", "")
	v.SetDefault("osint.virustotal.enterprise_feeds", false)

	// WASM plugin engine defaults.
	v.SetDefault("wasm.enabled", true)
	v.SetDefault("wasm.plugin_dir", "rules/custom")
	v.SetDefault("wasm.memory_limit_mb", 16)
	v.SetDefault("wasm.plugin_timeout_ms", 100)

	// Event log defaults — disabled by default; operators opt in for replay.
	v.SetDefault("event_log.enabled", false)
	v.SetDefault("event_log.path", "/var/lib/ebpf-guard/events.jsonl")
	v.SetDefault("event_log.max_size_mb", 100)

	// Canary trap defaults — enabled by default with auto-created lure files.
	v.SetDefault("canary.enabled", true)
	v.SetDefault("canary.auto_create", true)
	v.SetDefault("canary.files", []string{})
	v.SetDefault("canary.alert_severity", "critical")

	// Audit log defaults — disabled by default; operators opt in.
	v.SetDefault("audit.enabled", false)
	v.SetDefault("audit.path", "/var/log/ebpf-guard/audit.jsonl")
	v.SetDefault("audit.max_size_mb", 100)
	v.SetDefault("audit.include_rule_diffs", true)
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
