// Package config provides configuration management with hot-reload support.
package config

import (
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"sync"
	"time"

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
	// HiddenProcess configures hidden process detection via BPF task iterator.
	HiddenProcess HiddenProcessConfig `mapstructure:"hidden_process"`

	// Audit configuration — append-only JSONL audit log for rule and config changes.
	Audit AuditConfig `mapstructure:"audit"`

	// AdmissionWebhook configures the Kubernetes ValidatingAdmissionWebhook server.
	AdmissionWebhook AdmissionWebhookConfig `mapstructure:"admission_webhook"`

	// Runtime configures container runtime enrichment (CRI/Docker) for non-Kubernetes hosts.
	Runtime RuntimeConfig `mapstructure:"runtime"`

	// Drift configures container drift detection against image manifest baselines.
	Drift DriftConfig `mapstructure:"drift"`

	// SimpleMode configures simple-mode auto-enforcement for indie developers.
	SimpleMode SimpleModeConfig `mapstructure:"simple_mode"`

	// StrictConfig enables strict config file security checks at startup.
	// When true, the agent refuses to start if the config file is readable by
	// group or world (mode 0644, 0640, etc.). When false (default), a warning
	// is logged but startup proceeds.
	StrictConfig bool `mapstructure:"strict_config"`

	// SelfProtection configures BPF anti-tampering detection (issue #220).
	// Detects and optionally blocks attempts by external processes to detach
	// or modify our BPF programs/maps. Graceful no-op on kernel < 5.7.
	SelfProtection SelfProtectionConfig `mapstructure:"self_protection"`

	// Profile selects a built-in hardware-aware preset — "lite", "balanced",
	// or "production" — that sets BPF map sizes, tracked-PID limits, and
	// sequence/lineage profiler enablement for the host (issue #287). Left
	// empty in the file, it's resolved by autodetecting nproc/meminfo; any
	// value explicitly set elsewhere in this file still overrides the
	// preset for that field. Prefer the --profile flag or Manager's
	// resolved-profile accessors over reading this field directly, since it
	// reflects the raw config value, not the final autodetect/flag decision.
	Profile string `mapstructure:"profile"`
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
	// ShutdownTimeout is the total time budget for graceful shutdown. Valid range: [5s, 300s]. Default: 30s.
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
	// ShutdownDrainEnforcement caps the time spent draining the enforcement queue during shutdown. Default: 5s.
	ShutdownDrainEnforcement time.Duration `mapstructure:"shutdown_drain_enforcement"`
	// ShutdownDrainRego caps the time spent draining async Rego evaluation workers during shutdown. Default: 5s.
	ShutdownDrainRego time.Duration `mapstructure:"shutdown_drain_rego"`
	// CORSAllowedOrigins lists the origins allowed to access the OpenAPI spec via CORS.
	// Include "*" to allow any origin (backward-compatible default).
	// An empty list means same-origin only (no CORS header).
	// Example: ["https://docs.mydomain.com", "https://dev.mydomain.com"]
	CORSAllowedOrigins []string `mapstructure:"cors_allowed_origins"`
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
	// OTLP log exporter configuration
	OTLP OTLPNotificationConfig `mapstructure:"otlp"`
	// Kafka producer configuration
	Kafka KafkaNotificationConfig `mapstructure:"kafka"`
	// Syslog/CEF configuration
	SyslogCEF SyslogCEFNotificationConfig `mapstructure:"syslog_cef"`
	// Discord webhook configuration
	Discord DiscordNotificationConfig `mapstructure:"discord"`
	// Telegram Bot API configuration
	Telegram TelegramNotificationConfig `mapstructure:"telegram"`
	// UnixSocket streams alerts as JSON lines to a Unix domain socket.
	UnixSocket UnixSocketNotificationConfig `mapstructure:"unix_socket"`
	// StrictSSRF enables strict SSRF prevention for all HTTP-based notifiers
	// by blocking RFC-1918 private IP ranges (10/8, 172.16/12, 192.168/16).
	// Disable when targets are cluster-internal services.
	// Default: false — safe for Kubernetes; set true for external targets.
	StrictSSRF bool `mapstructure:"strict_ssrf"`
}

// UnixSocketNotificationConfig configures the Unix domain socket alert stream.
type UnixSocketNotificationConfig struct {
	// Enabled activates the Unix socket notifier.
	Enabled bool `mapstructure:"enabled"`
	// Path is the filesystem path for the Unix domain socket.
	Path string `mapstructure:"path"`
}

// OTLPNotificationConfig holds OTLP log exporter settings.
type OTLPNotificationConfig struct {
	// Enabled enables OTLP log exports
	Enabled bool `mapstructure:"enabled"`
	// Endpoint is the OTLP HTTP endpoint (e.g. "https://otel-collector:4318")
	Endpoint string `mapstructure:"endpoint"`
	// TLSEnabled upgrades to HTTPS and validates the server certificate
	TLSEnabled bool `mapstructure:"tls_enabled"`
	// CACert is the path to a PEM CA bundle for server verification
	CACert string `mapstructure:"ca_cert"`
	// ClientCert and ClientKey enable mTLS
	ClientCert string `mapstructure:"client_cert"`
	ClientKey  string `mapstructure:"client_key"`
	// Headers are additional HTTP headers sent with each request (e.g. API keys)
	Headers map[string]string `mapstructure:"headers"`
	// MinSeverity filters alerts by severity ("warning" or "critical")
	MinSeverity string `mapstructure:"min_severity"`
}

// KafkaNotificationConfig holds Kafka producer settings.
type KafkaNotificationConfig struct {
	// Enabled enables Kafka alert publishing
	Enabled bool `mapstructure:"enabled"`
	// Brokers is the list of Kafka broker addresses (e.g. ["kafka:9092"])
	Brokers []string `mapstructure:"brokers"`
	// Topic is the destination Kafka topic
	Topic string `mapstructure:"topic"`
	// Payload selects the message format: "json" (default) or "falco"
	Payload string `mapstructure:"payload"`
	// SASLEnabled enables SASL/PLAIN authentication
	SASLEnabled  bool   `mapstructure:"sasl_enabled"`
	SASLUsername string `mapstructure:"sasl_username"`
	SASLPassword string `mapstructure:"sasl_password"`
	// TLSEnabled enables TLS transport security
	TLSEnabled bool   `mapstructure:"tls_enabled"`
	CACert     string `mapstructure:"ca_cert"`
	ClientCert string `mapstructure:"client_cert"`
	ClientKey  string `mapstructure:"client_key"`
	// MinSeverity filters alerts by severity ("warning" or "critical")
	MinSeverity string `mapstructure:"min_severity"`
}

// SyslogCEFNotificationConfig holds syslog RFC 5424 / CEF settings.
type SyslogCEFNotificationConfig struct {
	// Enabled enables syslog/CEF alert delivery
	Enabled bool `mapstructure:"enabled"`
	// Network is the transport protocol: "tcp" (default), "tcp+tls", or "udp"
	Network string `mapstructure:"network"`
	// Address is the syslog server address (e.g. "siem.corp:514")
	Address string `mapstructure:"address"`
	// Format selects the wire format: "rfc5424" (default) or "cef"
	Format string `mapstructure:"format"`
	// AppName is the syslog APP-NAME field (default "ebpf-guard")
	AppName string `mapstructure:"app_name"`
	// Facility is the syslog facility number (1=user, 16=local0 … 23=local7)
	Facility int `mapstructure:"facility"`
	// TLS certificate paths (used when Network == "tcp+tls")
	CACert     string `mapstructure:"ca_cert"`
	ClientCert string `mapstructure:"client_cert"`
	ClientKey  string `mapstructure:"client_key"`
	// MinSeverity filters alerts by severity ("warning" or "critical")
	MinSeverity string `mapstructure:"min_severity"`
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

// DiscordNotificationConfig holds Discord webhook notification settings.
type DiscordNotificationConfig struct {
	// Enabled enables Discord notifications
	Enabled bool `mapstructure:"enabled"`
	// WebhookURL is the Discord webhook URL
	WebhookURL string `mapstructure:"webhook_url"`
	// MinSeverity filters alerts by severity ("warning" or "critical")
	MinSeverity string `mapstructure:"min_severity"`
}

// TelegramNotificationConfig holds Telegram Bot API notification settings.
type TelegramNotificationConfig struct {
	// Enabled enables Telegram notifications
	Enabled bool `mapstructure:"enabled"`
	// BotToken is the Telegram Bot API token (from @BotFather)
	BotToken string `mapstructure:"bot_token"`
	// ChatID is the target chat ID (user, group, or channel)
	ChatID string `mapstructure:"chat_id"`
	// MinSeverity filters alerts by severity ("warning" or "critical")
	MinSeverity string `mapstructure:"min_severity"`
}

// MemoryStoreConfig holds in-memory store configuration.
type MemoryStoreConfig struct {
	// MaxAlerts is the maximum number of alerts to retain in memory.
	// When the cap is reached the oldest alerts are evicted to bound RSS.
	// Zero disables the cap (unbounded growth — not recommended for long-running VPS deployments).
	MaxAlerts int64 `mapstructure:"max_alerts"`
	// RetentionPeriod is the maximum age of alerts to retain (Go duration string, e.g. "24h", "6h").
	// A background goroutine evicts alerts older than this every RetentionPeriod/4.
	// Zero disables age-based eviction.
	RetentionPeriod string `mapstructure:"retention_period"`
}

// StoreBatchingConfig holds async-batching configuration for alert writes.
type StoreBatchingConfig struct {
	// BatchSize is the number of alerts that trigger an immediate flush.
	// Zero disables batching (writes are synchronous). Default: 0 (disabled).
	BatchSize int `mapstructure:"batch_size"`
	// FlushInterval is the maximum time an alert waits before being flushed,
	// regardless of batch size. Parsed as a duration string (e.g. "500ms").
	FlushInterval string `mapstructure:"flush_interval"`
	// MaxBuffer is the upper bound on queued alerts before alerts are dropped.
	// Default: 10 × batch_size.
	MaxBuffer int `mapstructure:"max_buffer"`
}

// StoreConfig holds storage backend configuration.
type StoreConfig struct {
	// Backend specifies the storage backend: "memory", "sqlite", "opensearch"
	Backend string `mapstructure:"backend"`
	// Memory configuration
	Memory MemoryStoreConfig `mapstructure:"memory"`
	// SQLite configuration
	SQLite SQLiteStoreConfig `mapstructure:"sqlite"`
	// OpenSearch configuration
	OpenSearch OpenSearchStoreConfig `mapstructure:"opensearch"`
	// Batching configures async write batching. When batch_size > 0 alerts are
	// buffered and written in groups, reducing per-write overhead under burst load.
	Batching StoreBatchingConfig `mapstructure:"batching"`
}

// FileOpsConfig controls which file-access operations are collected.
// Disabling read/write tracking dramatically reduces event volume on busy hosts
// while preserving open(2) visibility for sensitive-path detection.
type FileOpsConfig struct {
	// TrackOpen enables sys_enter_openat hooks. Default: true.
	TrackOpen bool `mapstructure:"track_open"`
	// TrackRead enables sys_enter_read hooks. Default: false (very high volume).
	TrackRead bool `mapstructure:"track_read"`
	// TrackWrite enables sys_enter_write hooks. Default: false (very high volume).
	TrackWrite bool `mapstructure:"track_write"`
}

// CollectorsConfig holds per-collector settings.
type CollectorsConfig struct {
	// TLS collector configuration
	TLS TLSCollectorConfig `mapstructure:"tls"`
	// HTTPPlaintext collector configuration (issue #281 network-based detection gap)
	HTTPPlaintext HTTPPlaintextCollectorConfig `mapstructure:"http_plaintext"`
	// DNS collector configuration
	DNS DNSCollectorConfig `mapstructure:"dns"`
	// FileOps controls which file operation types are collected.
	// Disabling read/write hooks reduces event volume by 10-50x on typical hosts.
	FileOps FileOpsConfig `mapstructure:"file_ops"`
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
	// AzureMonitor configures the Azure Activity Log collector.
	AzureMonitor AzureMonitorCollectorConfig `mapstructure:"azure_monitor"`
	// IOUring configures the io_uring activity monitoring collector.
	IOUring IOUringCollectorConfig `mapstructure:"iouring"`
	// BPFMonitor configures the bpf() syscall monitoring collector.
	BPFMonitor BPFMonitorCollectorConfig `mapstructure:"bpf_monitor"`
	// TLSFingerprint configures the TLS ClientHello JA3/JA4 fingerprinting collector.
	TLSFingerprint TLSFingerprintCollectorConfig `mapstructure:"tls_fingerprint"`
	// StartupPolicy controls agent behaviour when a collector fails to start.
	// "fail-open"  (default) — log the error and continue with reduced coverage.
	// "fail-closed"          — exit with a non-zero code if any Required collector fails.
	StartupPolicy string `mapstructure:"startup_policy"`
	// Required lists collector names that MUST start successfully when StartupPolicy
	// is "fail-closed". The agent exits if any of these fail.
	Required []string `mapstructure:"required"`
	// Optional lists collector names for which startup failures are always tolerated
	// regardless of StartupPolicy.
	Optional []string `mapstructure:"optional"`
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

// AzureMonitorCollectorConfig holds Azure Activity Log via Azure Monitor REST API settings.
// The collector polls the Azure Management API with OAuth2 client-credentials authentication.
type AzureMonitorCollectorConfig struct {
	// Enabled activates the Azure Activity Log collector.
	Enabled bool `mapstructure:"enabled"`
	// SubscriptionID is the Azure subscription ID to collect activity logs from.
	// Format: UUID (e.g. "00000000-1111-2222-3333-444444444444")
	SubscriptionID string `mapstructure:"subscription_id"`
	// TenantID is the Azure AD tenant ID for OAuth2 authentication.
	TenantID string `mapstructure:"tenant_id"`
	// ClientID is the Azure AD application (service principal) client ID.
	ClientID string `mapstructure:"client_id"`
	// ClientSecret is the Azure AD application client secret.
	ClientSecret string `mapstructure:"client_secret"`
	// PollInterval is how often to poll the Activity Log API (Go duration string).
	// Default: "60s"
	PollInterval string `mapstructure:"poll_interval"`
	// MaxEvents is the maximum number of events to fetch per poll.
	// Default: 100
	MaxEvents int `mapstructure:"max_events"`
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

// HTTPPlaintextCollectorConfig holds plaintext (non-TLS) HTTP inspection settings.
// This is the network-based detection collector added for issue #281: TLSCollector
// only sees data that goes through OpenSSL/libssl, so plaintext HTTP traffic
// (unencrypted, or terminated by a non-OpenSSL TLS stack in front of the app)
// was previously invisible to network-based SQLi/XSS rules.
type HTTPPlaintextCollectorConfig struct {
	// Enabled enables plaintext HTTP inspection via uprobes on libc read/recv.
	// Requires CAP_SYS_PTRACE capability.
	// Default: false
	Enabled bool `mapstructure:"enabled"`
	// ScanInterval is the interval for scanning for known web-server processes.
	// Default: 30s
	ScanInterval string `mapstructure:"scan_interval"`
	// MaxDataSize is the maximum bytes to capture per read()/recv() call.
	// Default: 256
	MaxDataSize int `mapstructure:"max_data_size"`
	// ServerComms is the list of process names (comm) to attach uprobes to.
	// Default: nginx, apache2, httpd, node, python, python3, php-fpm, java, ruby,
	// gunicorn, uwsgi, caddy, traefik, lighttpd (see defaultHTTPServerComms in
	// internal/collector/http_uprobe.go).
	ServerComms []string `mapstructure:"server_comms"`
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

// IOUringCollectorConfig holds io_uring monitoring settings.
type IOUringCollectorConfig struct {
	// Enabled enables io_uring activity monitoring via kprobes.
	// When enabled, kprobes are attached to io_uring_setup and io_uring_enter
	// to detect processes using the io_uring interface. Default: false.
	Enabled bool `mapstructure:"enabled"`
}

// BPFMonitorCollectorConfig holds bpf() syscall monitoring settings.
type BPFMonitorCollectorConfig struct {
	// Enabled enables bpf() syscall monitoring via kprobe/kretprobe on
	// __x64_sys_bpf. Captures BPF_PROG_LOAD and BPF_MAP_CREATE calls to
	// detect malicious eBPF program loading by rootkits. Default: false.
	Enabled bool `mapstructure:"enabled"`
}

// TLSFingerprintCollectorConfig holds TLS ClientHello fingerprinting settings.
type TLSFingerprintCollectorConfig struct {
	// Enabled enables TLS ClientHello capture via kprobe on __x64_sys_sendto.
	// Computes JA3/JA4 fingerprints for C2 framework detection. Default: false.
	Enabled bool `mapstructure:"enabled"`
}

// HiddenProcessConfig holds hidden process detection settings.
type HiddenProcessConfig struct {
	// Enabled activates periodic hidden process detection via BPF iter/task
	// diffed against /proc. Default: false.
	Enabled bool `mapstructure:"enabled"`
	// CheckInterval is the interval between kernel-vs-proc comparisons.
	// Default: "60s"
	CheckInterval time.Duration `mapstructure:"check_interval"`
	// AlertSeverity is the severity applied to hidden process alerts.
	// Valid: "critical", "warning". Default: "critical".
	AlertSeverity string `mapstructure:"alert_severity"`
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
	// InsecureSkipVerify disables TLS certificate verification.
	// A warning is emitted at startup when this is true.
	InsecureSkipVerify bool `mapstructure:"insecure_skip_verify"`
	// CACert is the path to a PEM-encoded CA certificate file used to verify
	// the OpenSearch server certificate. Leave empty to use the system CA pool.
	CACert string `mapstructure:"ca_cert"`
	// TLSServerName overrides the SNI hostname sent during the TLS handshake.
	// Useful when connecting via IP to a cluster with a DNS-based certificate
	// (e.g. "opensearch.monitoring.svc.cluster.local").
	TLSServerName string `mapstructure:"server_name"`
}

// BPFConfig holds eBPF-specific settings.
type BPFConfig struct {
	// MapSizes defines the size of BPF maps (number of entries)
	MapSizes MapSizeConfig `mapstructure:"map_sizes"`

	// RingBufSize is the BPF ring buffer size in bytes applied to each
	// event ring buffer (syscall, network, file, TLS, LSM).
	// 0 = auto-detect: 1% of MemAvailable from /proc/meminfo, clamped to [4 MB, 32 MB].
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

	// MaxConcurrentEvents is the maximum number of events that may be processed
	// concurrently by the correlation engine worker pool. Zero disables the pool
	// cap (legacy behaviour). Recommended: 4096.
	MaxConcurrentEvents int `mapstructure:"max_concurrent_events"`

	// EventQueueDepth is the size of the in-process event channel between
	// collectors and the correlation engine. When the channel is full, the
	// OverflowPolicy is applied. Defaults to the correlator.buffer_size when
	// unset. Recommended: 65536.
	EventQueueDepth int `mapstructure:"event_queue_depth"`

	// OverflowPolicy controls what happens to events when the queue is full.
	// Valid values: "drop" (default), "block", "sample".
	OverflowPolicy string `mapstructure:"overflow_policy"`

	// LiveUpdate configures in-place eBPF program replacement without agent restart.
	LiveUpdate LiveUpdateBPFConfig `mapstructure:"live_update"`

	// AdaptiveLoad configures ring-buffer-load-based adaptive sampling.
	// When enabled, the agent automatically reduces BPF sample rates for
	// high-volume event types (syscall, file) when the event-processing
	// channel is filling up, preventing silent kernel-side ring buffer drops
	// while keeping security-critical types (network, LSM, privesc) intact.
	AdaptiveLoad AdaptiveLoadConfig `mapstructure:"adaptive_load"`

	// Sampling configures the static (non-adaptive) BPF-side base sample
	// rate, applied unconditionally regardless of channel load. Every
	// sys_enter_read/sys_enter_write syscall on the host emits an event by
	// default — at typical workloads this is orders of magnitude higher
	// volume than the syscall allowlist filter, so file events need a base
	// rate well below 1.0 even under normal load.
	Sampling SamplingConfig `mapstructure:"sampling"`
}

// SamplingConfig configures the BPF-side static sampling rates (1 in N events).
type SamplingConfig struct {
	// Enabled activates BPF-side sampling. Default: true.
	Enabled bool `mapstructure:"enabled"`
	// SyscallRate samples 1 in N syscall events. 1 = all events. Default: 1.
	SyscallRate uint32 `mapstructure:"syscall_rate"`
	// NetworkRate samples 1 in N network events. 1 = all events. Default: 1.
	NetworkRate uint32 `mapstructure:"network_rate"`
	// FileRate samples 1 in N file-access events (open/read/write). Reads and
	// writes fire on every syscall system-wide, so the default is well below
	// 1 to avoid flooding the event channel. Default: 50.
	FileRate uint32 `mapstructure:"file_rate"`
}

// AdaptiveLoadConfig configures ring-buffer-load-based adaptive BPF sampling.
type AdaptiveLoadConfig struct {
	// Enabled activates the ring-buffer load controller. Default: false.
	Enabled bool `mapstructure:"enabled"`
	// CheckInterval is how often the event channel depth is sampled. Default: 2s.
	CheckInterval string `mapstructure:"check_interval"`
	// DegradedThreshold is the channel fill ratio [0.0–1.0] that triggers the
	// Degraded state (syscall+file rates reduced). Default: 0.50.
	DegradedThreshold float64 `mapstructure:"degraded_threshold"`
	// CriticalThreshold triggers the Critical state (all rates reduced). Default: 0.80.
	CriticalThreshold float64 `mapstructure:"critical_threshold"`
	// RecoveryThreshold is the fill ratio below which Normal state is restored.
	// Must be lower than DegradedThreshold for hysteresis. Default: 0.30.
	RecoveryThreshold float64 `mapstructure:"recovery_threshold"`
	// SyscallDegradedRate is the syscall sampling rate in Degraded state. Default: 0.25.
	SyscallDegradedRate float64 `mapstructure:"syscall_degraded_rate"`
	// SyscallCriticalRate is the syscall sampling rate in Critical state. Default: 0.10.
	SyscallCriticalRate float64 `mapstructure:"syscall_critical_rate"`
	// FileDegradedRate is the file-event sampling rate in Degraded state. Default: 0.50.
	FileDegradedRate float64 `mapstructure:"file_degraded_rate"`
	// FileCriticalRate is the file-event sampling rate in Critical state. Default: 0.25.
	FileCriticalRate float64 `mapstructure:"file_critical_rate"`
	// NetworkCriticalRate is the network-event sampling rate in Critical state. Default: 0.50.
	// Network events are reduced last (lower volume, higher security value).
	NetworkCriticalRate float64 `mapstructure:"network_critical_rate"`
	// MinSyscallRate is the absolute floor for syscall sampling. Default: 0.05.
	MinSyscallRate float64 `mapstructure:"min_syscall_rate"`
	// MinFileRate is the absolute floor for file sampling. Default: 0.10.
	MinFileRate float64 `mapstructure:"min_file_rate"`
	// MinNetworkRate is the absolute floor for network sampling. Default: 0.25.
	MinNetworkRate float64 `mapstructure:"min_network_rate"`
}

// LiveUpdateBPFConfig configures the eBPF live program update feature.
type LiveUpdateBPFConfig struct {
	// Enabled activates live eBPF program updates. Off by default; opt-in.
	Enabled bool `mapstructure:"enabled"`
	// WatchPath is a directory of .o BPF object files to watch for changes.
	// When a file changes, the live updater reloads it automatically (fsnotify).
	// Empty disables file watching; reload is still available via the API.
	WatchPath string `mapstructure:"watch_path"`
	// PendingPinDir is the bpffs directory used to stage new programs before
	// atomic replacement. Defaults to /sys/fs/bpf/ebpf-guard/pending.
	PendingPinDir string `mapstructure:"pending_pin_dir"`
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

	// DisableDefaultDaemonDenylist disables the built-in list of noisy
	// user-space monitoring daemons (journald, rsyslog, node_exporter, etc.)
	// that are silently dropped at the kernel level by default.
	// Set to true if you need full visibility into those daemons' activity,
	// or if you are running under a threat model where comm-name spoofing is a
	// concern and you prefer not to have any process invisibly filtered.
	// Default: false (daemon denylist is active).
	DisableDefaultDaemonDenylist bool `mapstructure:"disable_default_daemon_denylist"`

	// NoisyDaemonDenylist overrides the built-in user-space daemon denylist.
	// When non-empty, this list replaces DefaultNoisyDaemonDenylist().
	// Has no effect when DisableDefaultDaemonDenylist is true.
	// Each entry must be at most 15 characters (kernel TASK_COMM_LEN - 1).
	// SECURITY NOTE: comm names can be spoofed via prctl(PR_SET_NAME).
	NoisyDaemonDenylist []string `mapstructure:"noisy_daemon_denylist"`
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
	// VerifyChecksums enables SHA-256 integrity verification of rule files at
	// startup and on hot-reload. When enabled, each rule file is verified against
	// the checksum file before loading. Startup aborts if a mismatch is detected.
	VerifyChecksums bool `mapstructure:"verify_checksums"`
	// ChecksumFile is the path to the SHA-256 checksum file (sha256sum format).
	// Defaults to <rules_dir>/checksums.sha256.
	ChecksumFile string `mapstructure:"checksum_file"`
	// LocalTuningPath points to an optional local-tuning overlay YAML file
	// (see correlator.TuningOverlay) that adds exceptions to existing rules by
	// rule_id without editing the shipped rule files. Missing file is a no-op.
	LocalTuningPath string `mapstructure:"local_tuning_path"`
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
	// AlertAggregation folds repeated alerts sharing the same rule/comm/path-prefix/pod
	// key within a time window into a single alert carrying a count, instead of
	// forwarding one row per occurrence to storage/notifications.
	AlertAggregation AlertAggregationConfig `mapstructure:"alert_aggregation"`
}

// AlertAggregationConfig configures alert aggregation (see correlator.AlertAggregator).
type AlertAggregationConfig struct {
	// Enabled activates aggregation. Default: false.
	Enabled bool `mapstructure:"enabled"`
	// Window is the aggregation period, e.g. "60s". Default: 60s.
	Window string `mapstructure:"window"`
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
	// EWMAWeight is the weight for Exponentially Weighted Moving Average (0.0-1.0).
	// Deprecated: set profiler.ewma.weight instead (see EWMA). Retained for
	// backward compatibility; the nested value takes precedence when set.
	EWMAWeight float64 `mapstructure:"ewma_weight"`
	// EWMA groups Exponentially Weighted Moving Average settings (since v0.2.0).
	EWMA EWMASettings `mapstructure:"ewma"`
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
	// DriftBaseline configures observe-mode baselining for rules tagged
	// `class: drift` (issue #286): matches are learned per-workload during a
	// learning window and only alerted on thereafter when they deviate from
	// that baseline, instead of alerting on every match like a threat rule.
	DriftBaseline DriftBaselineConfig `mapstructure:"drift_baseline"`
}

// DriftBaselineConfig configures observe-mode baselining for class: drift rules.
type DriftBaselineConfig struct {
	// Enabled activates drift-class alert suppression via the learned baseline.
	// When false, class: drift rules alert exactly like class: threat rules.
	Enabled bool `mapstructure:"enabled"`
	// LearningPeriod is the duration in seconds to observe drift-class matches
	// before a workload's baseline is considered complete.
	LearningPeriod int `mapstructure:"learning_period"`
	// MinSamples is the minimum number of drift-class matches required before
	// learning completes, in addition to LearningPeriod elapsing.
	MinSamples int `mapstructure:"min_samples"`
	// PerWorkload separates baselines per (comm, namespace, app_label) tuple.
	PerWorkload bool `mapstructure:"per_workload"`
}

// EWMASettings groups Exponentially Weighted Moving Average tuning under
// profiler.ewma.* (the v0.2.0 schema replacing the flat profiler.ewma_weight).
type EWMASettings struct {
	// Weight is the EWMA weight (0.0-1.0). Takes precedence over the legacy
	// profiler.ewma_weight when set.
	Weight float64 `mapstructure:"weight"`
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
	// EnforcingAction is the action taken on violations: "alert", "block", "kill", or "audit".
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
	// WebhookURL is the Alertmanager webhook endpoint.
	// Deprecated: set alerting.alertmanager.url instead (see Alertmanager).
	// Retained for backward compatibility; the nested value takes precedence.
	WebhookURL string `mapstructure:"webhook_url"`
	// Alertmanager groups Alertmanager endpoint settings (since v0.2.0).
	Alertmanager AlertmanagerSettings `mapstructure:"alertmanager"`
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
	// StrictSSRF enables strict SSRF prevention for the webhook URL by also
	// blocking RFC-1918 private IP ranges (10/8, 172.16/12, 192.168/16).
	// Disable when Alertmanager is deployed inside the cluster and its service
	// IP is in a private range (the default for in-cluster deployments).
	// Default: false — safe for Kubernetes; set true for external webhook targets.
	StrictSSRF bool `mapstructure:"strict_ssrf"`
}

// AlertmanagerSettings groups the Alertmanager endpoint under
// alerting.alertmanager.* (the v0.2.0 schema replacing alerting.webhook_url).
type AlertmanagerSettings struct {
	// URL is the Alertmanager webhook endpoint. Takes precedence over the
	// legacy alerting.webhook_url when set.
	URL string `mapstructure:"url"`
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

// RuntimeConfig holds container runtime enrichment settings (issue #123).
// Enrichment via CRI or Docker sockets works on non-Kubernetes hosts where
// the k8s API is unavailable. On K8s hosts both enrichers can run together.
type RuntimeConfig struct {
	// Enrichment controls the runtime enrichment mode.
	// auto  — try CRI first (/run/containerd/containerd.sock, /run/crio/crio.sock),
	//         fall back to Docker (/var/run/docker.sock).
	// cri   — use CRI socket only.
	// docker — use Docker socket only.
	// off   — disable runtime enrichment (default).
	Enrichment string `mapstructure:"enrichment"`
	// SocketPath overrides the auto-detected runtime socket path.
	SocketPath string `mapstructure:"socket_path"`
	// CacheTTL is the container metadata cache lifetime (Go duration string). Default: "30s".
	CacheTTL string `mapstructure:"cache_ttl"`
}

// DriftConfig holds container drift detection settings.
type DriftConfig struct {
	// Enabled enables container drift detection against baselines.
	// When true, the Detector is created and runs on every event.
	// Default: false (created but no ImageManifest).
	Enabled bool `mapstructure:"enabled"`
	// BaselineWindow is how long to observe a new container before locking
	// the baseline. Default: "5m".
	BaselineWindow string `mapstructure:"baseline_window"`
	// ImageManifest enables pre-seeding the ExecPaths baseline from the
	// container image layers via overlayfs lowerdir walk. Default: false.
	ImageManifest bool `mapstructure:"image_manifest"`
	// EnforceMode sets the enforcement action for drift alerts:
	//   ""       — alert only (default)
	//   "kill"   — SIGKILL the offending process
	//   "block"  — block network access (nftables/iptables/XDP)
	EnforceMode string `mapstructure:"enforce_mode"`
	// AllowlistExec is a list of executable paths or directory prefixes that
	// are exempt from drift detection.
	AllowlistExec []string `mapstructure:"allowlist_exec"`
	// PurgeInterval is how often stale baselines are purged. Default: "10m".
	PurgeInterval string `mapstructure:"purge_interval"`
	// PurgeTTL is the time after which an unseen baseline is stale. Default: "30m".
	PurgeTTL string `mapstructure:"purge_ttl"`
}

// SimpleModeConfig holds simple-mode auto-enforcement settings.
type SimpleModeConfig struct {
	// Enabled enables simple mode — auto-enforce kills for high-confidence
	// cryptominer, webshell, and reverse shell detections.
	Enabled bool `mapstructure:"enabled"`
	// DryRun toggles dry-run mode (log but don't kill). Overridden by DryRunDuration.
	DryRun bool `mapstructure:"dry_run"`
	// DryRunDuration is the initial dry-run period after startup.
	// Default: "24h". The first 24 hours after startup, actions are logged but
	// not executed. Set to "0" to skip the dry-run window.
	DryRunDuration string `mapstructure:"dry_run_duration"`
	// MaxKillsPerMinute caps the global kill rate. Default: 1.
	MaxKillsPerMinute int `mapstructure:"max_kills_per_minute"`
	// AllowlistPIDs lists PIDs that must never be killed (e.g., [1]).
	AllowlistPIDs []uint32 `mapstructure:"allowlist_pids"`
	// AllowlistComms lists process names that must never be killed.
	AllowlistComms []string `mapstructure:"allowlist_comms"`
}

// SelfProtectionConfig holds anti-tampering self-protection settings (issue #220).
// Monitors BPF operations targeting our programs and maps, generating Critical
// alerts when an external process attempts detach or modification.
// Graceful no-op on kernel < 5.7 or when CONFIG_BPF_LSM is absent.
type SelfProtectionConfig struct {
	// Enabled activates BPF anti-tampering detection.
	// Default: false
	Enabled bool `mapstructure:"enabled"`

	// EnforceMode enables blocking of tampering attempts via the LSM bpf hook
	// (-EPERM returned to the caller). Requires kernel 5.7+ with CONFIG_BPF_LSM=y.
	// When false (default), tampering is detected and alerted but not blocked
	// (alert-first mode, analogous to enforcer.dry_run = true).
	EnforceMode bool `mapstructure:"enforce_mode"`

	// ExtraAgentPIDs lists additional PIDs that are part of the agent or its
	// upgrade/restart process. These are added to the allowlist and are never
	// treated as tampering. The current process PID is always included automatically.
	ExtraAgentPIDs []uint32 `mapstructure:"extra_agent_pids"`

	// PinBasePath is the bpffs directory where the agent pins its BPF objects.
	// Used to scope ownership checks to our own programs/maps.
	// Default: /sys/fs/bpf/ebpf-guard
	PinBasePath string `mapstructure:"pin_base_path"`

	// AlertSeverity is the severity level for tampering alerts.
	// Valid values: "critical" (default), "warning".
	AlertSeverity string `mapstructure:"alert_severity"`
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
	// NetworkBlocklist configures in-kernel network connection blocking via BPF
	// LPM trie maps.  Connections to matching subnets or ports are dropped in the
	// kernel without reaching user-space (kprobe path) or are denied with EPERM
	// (LSM socket_connect path, kernel 5.9+).
	// Hot-reloadable: the BPF maps are updated without restart on config change.
	// Example:
	//   subnets: ["10.0.0.0/8", "2001:db8::/32"]
	//   ports:   [4444, 6666]
	NetworkBlocklist NetworkBlocklistConfig `mapstructure:"network_blocklist"`
	// NetworkPolicy configures automatic Kubernetes NetworkPolicy generation and application.
	NetworkPolicy NetworkPolicyEnforcementConfig `mapstructure:"networkpolicy"`
}

// NetworkBlocklistConfig holds the in-kernel network blocklist configuration.
// Subnets and Ports entries are loaded into BPF LPM trie / hash maps at
// startup and on hot-reload.
type NetworkBlocklistConfig struct {
	// Subnets is a list of CIDR notation subnets to block (IPv4 and IPv6).
	// Both host addresses (/32, /128) and subnets (/8, /24, /32 …) are supported.
	// Examples: ["10.0.0.0/8", "192.168.1.0/24", "2001:db8::/32"]
	Subnets []string `mapstructure:"subnets" yaml:"subnets"`
	// Ports is a list of destination TCP ports to block.
	// Examples: [4444, 6666, 1337]
	Ports []uint16 `mapstructure:"ports" yaml:"ports"`
}

// NetworkPolicyEnforcementConfig configures the networkpolicy enforcement action.
type NetworkPolicyEnforcementConfig struct {
	// Enabled activates the networkpolicy action type in the rule engine.
	Enabled bool `mapstructure:"enabled"`
	// Mode is "suggest" (default) or "apply".
	// suggest: generate the policy YAML and send it via the notification channel.
	// apply: apply directly via the Kubernetes API (requires networkpolicies write RBAC).
	Mode string `mapstructure:"mode"`
	// AutoCleanupAfter is how long applied policies are kept before automatic removal.
	// Format: Go duration string, e.g. "1h". Zero disables auto-cleanup.
	AutoCleanupAfter string `mapstructure:"auto_cleanup_after"`
	// DryRun generates and logs policies without sending or applying them.
	DryRun bool `mapstructure:"dry_run"`
}

// WatchdogConfig holds watchdog and auto-tuning settings (Sprint 22.0).
type WatchdogConfig struct {
	// MemoryPressure enables automatic profiling downgrade on memory pressure
	MemoryPressure MemoryPressureConfig `mapstructure:"memory_pressure"`
	// CPUPressure enables adaptive load shedding of noisy collectors on CPU pressure
	CPUPressure CPUPressureConfig `mapstructure:"cpu_pressure"`
}

// MemoryPressureConfig holds memory pressure auto-tuning settings.
type MemoryPressureConfig struct {
	// Enabled enables memory pressure monitoring
	Enabled bool `mapstructure:"enabled"`
	// CheckInterval is the interval for checking memory pressure (seconds)
	CheckInterval int `mapstructure:"check_interval"`
	// LowMemoryThreshold is the available memory % to trigger low-memory mode (deprecated: use DisableSequenceThreshold)
	LowMemoryThreshold float64 `mapstructure:"low_memory_threshold"`
	// RecoveryThreshold is the available memory % to recover normal mode
	RecoveryThreshold float64 `mapstructure:"recovery_threshold"`
	// DisableSequenceThreshold is the available memory % below which sequence profiling is disabled (level 1).
	// Default: 10.0 (10% free RAM). Falls back to LowMemoryThreshold when zero.
	DisableSequenceThreshold float64 `mapstructure:"disable_sequence_threshold"`
	// DisableAllThreshold is the available memory % below which all profiling is disabled (level 2).
	// Must be less than DisableSequenceThreshold. Default: 5.0 (5% free RAM).
	DisableAllThreshold float64 `mapstructure:"disable_all_threshold"`
}

// CPUPressureConfig holds CPU pressure auto-tuning settings.
//
// When the agent's own CPU usage (as a percentage of a SINGLE core — 100 ==
// one full core busy, not normalized by host core count) exceeds the
// thresholds, the watchdog adaptively reduces BPF-side sampling of the
// noisiest collectors — file first (level 1), then syscall/network (level
// 2) — and restores them once usage drops back below the recovery threshold
// AND the current level has been held for at least MinDwell. LSM/canary/exec
// hooks are never shed. Using an absolute per-core budget (instead of a
// percentage of total host CPU) means the defaults behave the same way on a
// 1-core VPS and an 8-core box.
type CPUPressureConfig struct {
	// Enabled enables CPU pressure monitoring.
	Enabled bool `mapstructure:"enabled"`
	// CheckInterval is the interval for sampling CPU usage (seconds).
	CheckInterval int `mapstructure:"check_interval"`
	// CPULimitPercent is the target CPU budget (% of a single core). It seeds
	// the level thresholds when those are left at zero. Default: 40.0.
	CPULimitPercent float64 `mapstructure:"cpu_limit_percent"`
	// FileShedThreshold is the CPU % (of one core) above which file sampling
	// is reduced (level 1). Defaults to CPULimitPercent.
	FileShedThreshold float64 `mapstructure:"file_shed_threshold"`
	// AllShedThreshold is the CPU % (of one core) above which syscall/network
	// are also reduced (level 2). Defaults to 1.75x FileShedThreshold.
	AllShedThreshold float64 `mapstructure:"all_shed_threshold"`
	// RecoveryThreshold is the CPU % (of one core) below which the watcher
	// steps back one level (hysteresis). Defaults to 0.5x FileShedThreshold.
	RecoveryThreshold float64 `mapstructure:"recovery_threshold"`
	// WindowSize is the number of samples averaged into the sliding window. Default: 6.
	WindowSize int `mapstructure:"window_size"`
	// MinDwell is the minimum time (seconds) a shed level is held before the
	// watcher will step back down, even once CPU is back under
	// RecoveryThreshold. Default: 30.
	MinDwell int `mapstructure:"min_dwell"`
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
	// SecretPrevious is the old shared secret accepted during a rolling rotation.
	// Peers still using the old secret are allowed to connect until
	// SecretRotationTTL elapses from startup. Clear once all nodes use the new Secret.
	SecretPrevious string `mapstructure:"secret_previous"`
	// SecretRotationTTL is how long SecretPrevious remains valid after startup.
	// Default: 5m. Zero disables the rotation window even if SecretPrevious is set.
	SecretRotationTTL time.Duration `mapstructure:"secret_rotation_ttl"`
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
	// SyncToKernelMaps enables loading IP/CIDR IoCs directly into kernel BPF
	// blocklist maps (requires kernel blocklist maps from #179). Domain and
	// URL IoCs continue through the YAML/detection-rule path regardless.
	// Gracefully degrades to a no-op if the kernel maps are unavailable.
	SyncToKernelMaps bool `mapstructure:"sync_to_kernel_maps"`
	// MaxKernelEntries caps the total number of IP/CIDR entries loaded into
	// the kernel maps at one time. IoCs are prioritised by ThreatScore.
	// Default: 100 000. 0 means use the default.
	MaxKernelEntries int `mapstructure:"max_kernel_entries"`
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
	// InsecureSkipVerify controls whether the MISP server's TLS certificate is verified.
	// Default false means the certificate is verified.
	InsecureSkipVerify bool `mapstructure:"insecure_skip_verify"`
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
	// InsecureSkipVerify controls whether the OpenCTI server's TLS certificate is verified.
	// Default false means the certificate is verified.
	InsecureSkipVerify bool `mapstructure:"insecure_skip_verify"`
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
	// VerifyInterval is how often canary file integrity is checked after creation.
	// Default: 60s
	VerifyInterval time.Duration `mapstructure:"verify_interval"`
	// AlertOnTamper controls whether an alert is emitted when a canary file is
	// found missing or modified during periodic verification.
	// Default: true
	AlertOnTamper bool `mapstructure:"alert_on_tamper"`
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

// AdmissionWebhookConfig configures the optional Kubernetes ValidatingAdmissionWebhook.
// When enabled, ebpf-guard serves a webhook endpoint that kube-apiserver calls
// before admitting pods, evaluating pod specs against the same Rego policies
// used for runtime enforcement.
type AdmissionWebhookConfig struct {
	// Enabled activates the admission webhook server. Default: false.
	Enabled bool `mapstructure:"enabled"`
	// BindAddress is the listen address for the webhook HTTPS server.
	// Default: ":8443"
	BindAddress string `mapstructure:"bind_address"`
	// Mode controls webhook enforcement. "warn" annotates pods and allows them;
	// "enforce" denies pods that violate policies. Default: "warn".
	Mode string `mapstructure:"mode"`
	// FailurePolicy controls kube-apiserver behaviour when the webhook is
	// unavailable: "Ignore" allows pods through (safe default), "Fail" blocks.
	// Default: "Ignore"
	FailurePolicy string `mapstructure:"failure_policy"`
	// TLSCertFile is the path to the PEM-encoded TLS certificate file.
	// Required when Enabled is true (unless TLSAutoGenerate is set).
	TLSCertFile string `mapstructure:"tls_cert_file"`
	// TLSKeyFile is the path to the PEM-encoded private key file.
	// Required when Enabled is true (unless TLSAutoGenerate is set).
	TLSKeyFile string `mapstructure:"tls_key_file"`
	// TLSAutoGenerate generates a self-signed certificate on startup when
	// TLSCertFile and TLSKeyFile are empty. Suitable for development; use
	// cert-manager in production.
	TLSAutoGenerate bool `mapstructure:"tls_auto_generate"`
	// WebhookPath is the URL path kube-apiserver sends admission requests to.
	// Default: "/admission"
	WebhookPath string `mapstructure:"webhook_path"`
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

// CheckConfigReadPermissions verifies the config file is not readable by group
// or world. Config files often contain secrets (passwords, webhook URLs, API
// tokens) and should be mode 0600 (owner-only).
//
// When strict is true the check is fatal — the agent refuses to start.
// When strict is false a warning is logged and startup continues.
func CheckConfigReadPermissions(path string, strict bool) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("config: stat %s: %w", path, err)
	}
	mode := info.Mode()
	masked := mode & 0o044
	if masked != 0 {
		msg := fmt.Sprintf(
			"config: %s is readable by %s (mode %o) — consider chmod 0600 %s",
			path,
			modeWho(masked),
			mode,
			path,
		)
		if strict {
			return fmt.Errorf("%s", msg)
		}
		slog.Warn(msg, "path", path, "mode", fmt.Sprintf("%o", mode))
	}
	return nil
}

// modeWho returns a human-readable description of which permission bits are set.
func modeWho(masked os.FileMode) string {
	switch masked {
	case 0o004:
		return "world"
	case 0o040:
		return "group"
	case 0o044:
		return "group and world"
	default:
		return fmt.Sprintf("mask 0%o", masked)
	}
}

// Manager handles configuration loading and hot-reload.
type Manager struct {
	viper           *viper.Viper
	config          *Config
	mu              sync.RWMutex
	onChange        func(*Config)
	hardwareProfile HardwareProfileInfo
}

// HardwareProfileInfo describes how the active hardware profile was chosen
// and what it applied, for startup logging and the /debug/state endpoint.
type HardwareProfileInfo struct {
	// Profile is the resolved preset name: "lite", "balanced", or "production".
	Profile string `json:"profile"`
	// Source explains how Profile was decided: "flag", "config", or "autodetect".
	Source string `json:"source"`
	// Reason is a human-readable justification (e.g. detected CPU/RAM for autodetect).
	Reason string `json:"reason"`
	// Hardware is the detected host resources used for autodetection.
	Hardware HardwareInfo `json:"hardware"`
	// Applied is the preset's tuning values (before any per-field config-file override).
	Applied ProfileDefaults `json:"applied"`
}

// HardwareProfile returns how the active hardware profile was resolved.
func (m *Manager) HardwareProfile() HardwareProfileInfo {
	return m.hardwareProfile
}

// NewManager creates a new configuration manager.
// It checks config file permissions before loading. Use NewManagerSkipPermCheck
// for test environments where the config file is not expected to be root-owned.
func NewManager(configPath string) (*Manager, error) {
	return newManager(configPath, false, "")
}

// NewManagerSkipPermCheck creates a configuration manager without permission checks.
// Use only in tests.
func NewManagerSkipPermCheck(configPath string) (*Manager, error) {
	return newManager(configPath, true, "")
}

// NewManagerWithProfile is like NewManager but accepts an explicit hardware
// profile override (e.g. from --profile), taking precedence over any
// "profile:" key in the config file and over autodetection.
func NewManagerWithProfile(configPath, profileOverride string) (*Manager, error) {
	return newManager(configPath, false, profileOverride)
}

// NewManagerSkipPermCheckWithProfile is NewManagerSkipPermCheck plus an
// explicit hardware profile override. Use only in tests.
func NewManagerSkipPermCheckWithProfile(configPath, profileOverride string) (*Manager, error) {
	return newManager(configPath, true, profileOverride)
}

func newManager(configPath string, skipPermCheck bool, profileOverride string) (*Manager, error) {
	if err := CheckConfigPermissions(configPath, skipPermCheck); err != nil {
		return nil, err
	}

	// Peek at the raw file (no defaults registered) so we can tell which
	// keys the file explicitly sets, separate from the base defaults
	// registered on the real viper instance below.
	fileV := viper.New()
	fileV.SetConfigFile(configPath)
	fileV.SetConfigType("yaml")
	_ = fileV.ReadInConfig()

	if profileOverride != "" && !ValidProfileName(profileOverride) {
		return nil, fmt.Errorf("config: invalid --profile %q (valid: %s, %s, %s)",
			profileOverride, ProfileLite, ProfileBalanced, ProfileProduction)
	}
	hwInfo := resolveHardwareProfile(profileOverride, fileV)

	v := viper.New()
	v.SetConfigFile(configPath)
	v.SetConfigType("yaml")

	// Set defaults
	setDefaults(v)

	applied, err := ApplyHardwareProfile(v, fileV.IsSet, hwInfo.Profile)
	if err != nil {
		return nil, fmt.Errorf("config: apply hardware profile: %w", err)
	}
	hwInfo.Applied = applied
	v.SetDefault("profile", hwInfo.Profile)

	// Read config
	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("config: read config file: %w", err)
	}

	// Unmarshal
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("config: unmarshal config: %w", err)
	}

	// Map the v0.2.0 nested keys onto their legacy fields that consumers read.
	normalizeSchemaAliases(&cfg)

	// Apply env-var overrides for secrets so they don't have to be stored
	// in plaintext config files or Kubernetes ConfigMaps.
	applyEnvOverrides(&cfg)

	// Post-load security check: warn or fail if the config file is readable
	// by group or world, depending on the strict_config setting.
	if err := CheckConfigReadPermissions(configPath, cfg.StrictConfig); err != nil {
		return nil, err
	}

	m := &Manager{
		viper:           v,
		config:          &cfg,
		hardwareProfile: hwInfo,
	}

	return m, nil
}

// NewZeroConfigManager creates a Manager with all defaults set and no config
// file required. Used by `ebpf-guard --zero-config` for one-command deployments
// where no config file or rules directory exists on disk.
func NewZeroConfigManager() *Manager {
	return NewZeroConfigManagerWithProfile("")
}

// NewZeroConfigManagerWithProfile is NewZeroConfigManager plus an explicit
// hardware profile override (e.g. from --profile); empty autodetects from
// nproc/meminfo, matching the "curl | sh" one-command install path.
func NewZeroConfigManagerWithProfile(profileOverride string) *Manager {
	v := viper.New()
	v.SetConfigType("yaml")
	setDefaults(v)
	// Override specific defaults for zero-config mode:
	// - Server on port 9090 with auth token auto-generated
	// - Memory store (no disk required)
	// - All collectors disabled by default (no BPF unless --privileged)
	// - Kubernetes disabled (no K8s config available)
	// - Rules loaded from embedded filesystem (handled by main.go)

	hwInfo := resolveHardwareProfile(profileOverride, nil)
	if applied, err := ApplyHardwareProfile(v, nil, hwInfo.Profile); err == nil {
		hwInfo.Applied = applied
	}
	v.SetDefault("profile", hwInfo.Profile)

	var cfg Config
	_ = v.Unmarshal(&cfg)

	// Force K8s off in zero-config mode — there's no kubeconfig.
	cfg.Kubernetes.Enabled = false
	// Gate /health/ready on the core collectors only. Without an explicit
	// required set, handleReady treats *every* registered collector as required,
	// so an optional / kernel-gated collector that cannot attach on a given
	// kernel (e.g. on a CI runner) flips readiness to 503 even though the agent
	// is collecting fine. Declaring the core collectors keeps readiness
	// deterministic: it reflects whether core telemetry is up, while optional
	// collectors may be unavailable without blocking readiness. StartupPolicy
	// stays "fail-open", so this only affects readiness — it never aborts startup.
	cfg.Collectors.Required = []string{"syscall", "network", "fileaccess"}
	// Enable auth with auto-generated tokens.
	cfg.Auth.Enabled = true
	// Allow a fixed admin bearer token to be injected via env so containerized
	// zero-config deployments (and e2e tests) can authenticate with a known
	// value instead of the random token generated at startup. The viewer token
	// is still auto-generated.
	if tok := os.Getenv("EBPF_GUARD_AUTH_TOKEN"); tok != "" {
		cfg.Auth.AdminToken = tok
	}

	return &Manager{
		viper:           v,
		config:          &cfg,
		hardwareProfile: hwInfo,
	}
}

// applyEnvOverrides applies environment-variable overrides for secrets so that
// sensitive credentials never need to be written to config files or ConfigMaps.
//
// Supported env vars (all prefixed with EBPF_GUARD_):
//
//	EBPF_GUARD_OPENSEARCH_USERNAME   — OpenSearch basic-auth username
//	EBPF_GUARD_OPENSEARCH_PASSWORD   — OpenSearch basic-auth password
//	EBPF_GUARD_SLACK_WEBHOOK_URL     — Slack Incoming Webhook URL
//	EBPF_GUARD_TEAMS_WEBHOOK_URL     — Microsoft Teams Incoming Webhook URL
//	EBPF_GUARD_DISCORD_WEBHOOK_URL   — Discord webhook URL
//	EBPF_GUARD_TELEGRAM_BOT_TOKEN    — Telegram Bot API token
//	EBPF_GUARD_TELEGRAM_CHAT_ID      — Telegram target chat ID
//	EBPF_GUARD_ALERTMANAGER_WEBHOOK  — Alertmanager webhook URL
//
// normalizeSchemaAliases maps the v0.2.0 nested config keys onto the legacy
// flat fields that the rest of the codebase reads, so a value set under the new
// schema (profiler.ewma.weight, alerting.alertmanager.url) actually takes
// effect. The nested value wins when set; the legacy keys remain accepted.
func normalizeSchemaAliases(cfg *Config) {
	if cfg.Profiler.EWMA.Weight != 0 {
		cfg.Profiler.EWMAWeight = cfg.Profiler.EWMA.Weight
	}
	if cfg.Alerting.Alertmanager.URL != "" {
		cfg.Alerting.WebhookURL = cfg.Alerting.Alertmanager.URL
	}
}

// An env var always overrides the config-file value when non-empty.
func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("EBPF_GUARD_OPENSEARCH_USERNAME"); v != "" {
		cfg.Store.OpenSearch.Username = v
	}
	if v := os.Getenv("EBPF_GUARD_OPENSEARCH_PASSWORD"); v != "" {
		cfg.Store.OpenSearch.Password = v
	}
	if v := os.Getenv("EBPF_GUARD_SLACK_WEBHOOK_URL"); v != "" {
		cfg.Notifications.Slack.WebhookURL = v
	}
	if v := os.Getenv("EBPF_GUARD_TEAMS_WEBHOOK_URL"); v != "" {
		cfg.Notifications.Teams.WebhookURL = v
	}
	if v := os.Getenv("EBPF_GUARD_DISCORD_WEBHOOK_URL"); v != "" {
		cfg.Notifications.Discord.WebhookURL = v
	}
	if v := os.Getenv("EBPF_GUARD_TELEGRAM_BOT_TOKEN"); v != "" {
		cfg.Notifications.Telegram.BotToken = v
	}
	if v := os.Getenv("EBPF_GUARD_TELEGRAM_CHAT_ID"); v != "" {
		cfg.Notifications.Telegram.ChatID = v
	}
	if v := os.Getenv("EBPF_GUARD_ALERTMANAGER_WEBHOOK"); v != "" {
		cfg.Alerting.WebhookURL = v
	}
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
	v.SetDefault("server.shutdown_timeout", "30s")
	v.SetDefault("server.shutdown_drain_enforcement", "5s")
	v.SetDefault("server.shutdown_drain_rego", "5s")
	v.SetDefault("server.cors_allowed_origins", []string{"*"})

	// BPF defaults
	v.SetDefault("bpf.map_sizes.events", 65536)
	v.SetDefault("bpf.map_sizes.processes", 16384)
	v.SetDefault("bpf.map_sizes.connections", 32768)
	v.SetDefault("bpf.map_sizes.fd_map_size", 65536)
	v.SetDefault("bpf.ring_buf_size", 0) // 0 = auto-detect from /proc/meminfo
	// Event channel depth. Set explicitly so lowering correlator.buffer_size
	// (the per-PID forensic ring buffer) never shrinks the ingest channel, which
	// would increase drops under burst.
	v.SetDefault("bpf.event_queue_depth", 65536)
	v.SetDefault("bpf.kernel_filter.enabled", true)
	v.SetDefault("bpf.kernel_filter.disable_default_daemon_denylist", false)
	v.SetDefault("bpf.kernel_filter.noisy_daemon_denylist", []string{})
	v.SetDefault("bpf.sampling.enabled", true)
	v.SetDefault("bpf.sampling.syscall_rate", 1)
	v.SetDefault("bpf.sampling.network_rate", 1)
	v.SetDefault("bpf.sampling.file_rate", 50)
	v.SetDefault("bpf.btf_path", "")
	v.SetDefault("bpf.btf_hub_enabled", true)
	v.SetDefault("bpf.btf_hub_cache", "/var/lib/ebpf-guard/btf")
	v.SetDefault("bpf.fallback_reduced_features", false)

	// Rules defaults
	v.SetDefault("rules.path", "rules/")
	v.SetDefault("rules.hot_reload", true)
	v.SetDefault("rules.local_tuning_path", "rules/local-tuning.yaml")
	v.SetDefault("rules.rate_limit_alerts", true)
	v.SetDefault("rules.rate_limit_window", 60)
	v.SetDefault("rules.max_alerts_per_window", 10)

	// Correlator defaults
	// Per-PID forensic event ring buffer depth. This buffer is not on the
	// detection hot path (rules evaluate per-event); it only retains recent
	// per-process history. 256 events × ~208 B ≈ 53 KB/PID keeps memory bounded.
	v.SetDefault("correlator.buffer_size", 256)
	v.SetDefault("correlator.max_alerts_per_second", 10000)
	v.SetDefault("correlator.alert_aggregation.enabled", false)
	v.SetDefault("correlator.alert_aggregation.window", "60s")

	// Profiler defaults
	v.SetDefault("profiler.enabled", true)
	v.SetDefault("profiler.learning_period", 3600)
	v.SetDefault("profiler.min_learning_samples", 100)
	v.SetDefault("profiler.anomaly_threshold", 0.8)
	v.SetDefault("profiler.ewma_weight", 0.3)
	v.SetDefault("profiler.profile_ttl", 86400)
	// Max distinct workload classes / PIDs tracked at once. A single node rarely
	// runs more than a few thousand distinct (comm,namespace,app) workloads;
	// 4096 bounds profiler memory while LRU eviction handles the cold tail.
	// Previously 0 = auto-detect from /proc/sys/kernel/pid_max, which on modern
	// kernels is up to 4194304 — effectively unbounded.
	v.SetDefault("profiler.max_tracked_pids", 4096)

	// Sequence profiler defaults
	v.SetDefault("profiler.sequence.enabled", true)
	v.SetDefault("profiler.sequence.window_size", 64)
	v.SetDefault("profiler.sequence.threshold", 0.3)

	// Lineage tracker defaults
	v.SetDefault("profiler.lineage.enabled", true)
	v.SetDefault("profiler.lineage.ttl", 300)
	v.SetDefault("profiler.lineage.max_depth", 16)

	// Drift-baseline observe mode defaults (issue #286). Disabled by default:
	// class: drift rules alert like class: threat rules until an operator
	// opts in. When enabled without further tuning, one hour and 20 samples
	// mirrors the syscall allowlist profiler's learning defaults.
	v.SetDefault("profiler.drift_baseline.enabled", false)
	v.SetDefault("profiler.drift_baseline.learning_period", 3600)
	v.SetDefault("profiler.drift_baseline.min_samples", 20)
	v.SetDefault("profiler.drift_baseline.per_workload", true)

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

	// Container runtime enrichment. "auto" probes CRI then Docker and adds
	// container name/image plus node-local pod identity (namespace/pod/uid from
	// OCI annotations). Gracefully no-ops when no runtime socket is present.
	v.SetDefault("runtime.enrichment", "auto")

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

	v.SetDefault("notifications.discord.enabled", false)
	v.SetDefault("notifications.discord.webhook_url", "")
	v.SetDefault("notifications.discord.min_severity", "warning")

	v.SetDefault("notifications.telegram.enabled", false)
	v.SetDefault("notifications.telegram.bot_token", "")
	v.SetDefault("notifications.telegram.chat_id", "")
	v.SetDefault("notifications.telegram.min_severity", "warning")

	// Store defaults
	v.SetDefault("store.backend", "memory")
	v.SetDefault("store.memory.max_alerts", int64(10000))
	v.SetDefault("store.memory.retention_period", "6h")
	v.SetDefault("store.sqlite.path", "/var/lib/ebpf-guard/events.db")
	v.SetDefault("store.sqlite.max_alerts", int64(100000))
	v.SetDefault("store.sqlite.vacuum_interval", "1h")
	v.SetDefault("store.opensearch.url", "")
	v.SetDefault("store.opensearch.index", "ebpf-guard-events")
	v.SetDefault("store.opensearch.username", "")
	v.SetDefault("store.opensearch.password", "")
	v.SetDefault("store.opensearch.insecure_skip_verify", false)
	v.SetDefault("store.batching.batch_size", 0)
	v.SetDefault("store.batching.flush_interval", "500ms")
	v.SetDefault("store.batching.max_buffer", 0)

	// Collectors defaults
	v.SetDefault("collectors.tls.enabled", false)
	v.SetDefault("collectors.tls.scan_interval", "30s")
	v.SetDefault("collectors.tls.max_data_size", 256)

	// Plaintext HTTP collector defaults (issue #281 network-based detection gap)
	v.SetDefault("collectors.http_plaintext.enabled", false)
	v.SetDefault("collectors.http_plaintext.scan_interval", "30s")
	v.SetDefault("collectors.http_plaintext.max_data_size", 256)
	v.SetDefault("collectors.http_plaintext.server_comms", []string{})

	// DNS collector defaults
	v.SetDefault("collectors.dns.enabled", true)
	v.SetDefault("collectors.dns.dga_threshold", 3.5)
	v.SetDefault("collectors.dns.tunneling_min_length", 50)
	v.SetDefault("collectors.dns.high_frequency_threshold", 100)
	v.SetDefault("collectors.dns.dga_whitelist", []string{})
	v.SetDefault("collectors.iouring.enabled", false)
	v.SetDefault("collectors.bpf_monitor.enabled", false)
	v.SetDefault("collectors.tls_fingerprint.enabled", false)
	v.SetDefault("collectors.file_ops.track_open", true)
	v.SetDefault("collectors.file_ops.track_read", false)
	v.SetDefault("collectors.file_ops.track_write", false)
	v.SetDefault("collectors.cloudtrail.enabled", false)
	v.SetDefault("collectors.gcp_audit.enabled", false)
	v.SetDefault("collectors.azure_monitor.enabled", false)
	v.SetDefault("collectors.startup_policy", "fail-open")
	v.SetDefault("collectors.required", []string{})
	v.SetDefault("collectors.optional", []string{})

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
	v.SetDefault("enforcement.network_blocklist.subnets", []string{})
	v.SetDefault("enforcement.network_blocklist.ports", []uint16{})

	// Watchdog defaults (Sprint 22.0)
	v.SetDefault("watchdog.memory_pressure.enabled", true)
	v.SetDefault("watchdog.memory_pressure.check_interval", 5)
	v.SetDefault("watchdog.memory_pressure.low_memory_threshold", 10.0)
	v.SetDefault("watchdog.memory_pressure.recovery_threshold", 20.0)
	v.SetDefault("watchdog.memory_pressure.disable_sequence_threshold", 10.0)
	v.SetDefault("watchdog.memory_pressure.disable_all_threshold", 5.0)
	v.SetDefault("watchdog.cpu_pressure.enabled", true)
	v.SetDefault("watchdog.cpu_pressure.check_interval", 5)
	v.SetDefault("watchdog.cpu_pressure.cpu_limit_percent", 40.0)
	v.SetDefault("watchdog.cpu_pressure.file_shed_threshold", 40.0)
	v.SetDefault("watchdog.cpu_pressure.all_shed_threshold", 70.0)
	v.SetDefault("watchdog.cpu_pressure.recovery_threshold", 20.0)
	v.SetDefault("watchdog.cpu_pressure.window_size", 6)
	v.SetDefault("watchdog.cpu_pressure.min_dwell", 30)

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
	v.SetDefault("gossip.secret_previous", "")
	v.SetDefault("gossip.secret_rotation_ttl", 5*time.Minute)
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
	v.SetDefault("osint.misp.insecure_skip_verify", false)
	v.SetDefault("osint.misp.attribute_types", []string{"ip-dst", "ip-src", "domain", "hostname"})
	v.SetDefault("osint.misp.min_threat_level", 3)
	v.SetDefault("osint.misp.tags", []string{})

	v.SetDefault("osint.opencti.enabled", false)
	v.SetDefault("osint.opencti.url", "")
	v.SetDefault("osint.opencti.api_key", "")
	v.SetDefault("osint.opencti.insecure_skip_verify", false)
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
	v.SetDefault("canary.verify_interval", 60*time.Second)
	v.SetDefault("canary.alert_on_tamper", true)

	// Hidden process detection defaults — disabled by default; operators opt in.
	v.SetDefault("hidden_process.enabled", false)
	v.SetDefault("hidden_process.check_interval", 60*time.Second)
	v.SetDefault("hidden_process.alert_severity", "critical")

	// Drift detection defaults — disabled by default; enabled for image-manifest mode.
	v.SetDefault("drift.enabled", false)
	v.SetDefault("drift.baseline_window", "5m")
	v.SetDefault("drift.image_manifest", false)
	v.SetDefault("drift.enforce_mode", "")
	v.SetDefault("drift.allowlist_exec", []string{"/usr/lib/jvm/", "/usr/lib/jvm/", "/usr/lib/gcc/", "/usr/lib/llvm-", "/tmp/", "/var/cache/", "/var/tmp/"})
	v.SetDefault("drift.purge_interval", "10m")
	v.SetDefault("drift.purge_ttl", "30m")

	// Simple mode defaults — disabled by default; enabled via --simple flag.
	v.SetDefault("simple_mode.enabled", false)
	v.SetDefault("simple_mode.dry_run", false)
	v.SetDefault("simple_mode.dry_run_duration", "24h")
	v.SetDefault("simple_mode.max_kills_per_minute", 1)
	v.SetDefault("simple_mode.allowlist_pids", []uint32{1})
	v.SetDefault("simple_mode.allowlist_comms", []string{"systemd", "init", "kubelet", "containerd"})

	// Audit log defaults — disabled by default; operators opt in.
	v.SetDefault("audit.enabled", false)
	v.SetDefault("audit.path", "/var/log/ebpf-guard/audit.jsonl")
	v.SetDefault("audit.max_size_mb", 100)
	v.SetDefault("audit.include_rule_diffs", true)

	// Rule checksum verification defaults (issue #119) — opt-in.
	v.SetDefault("rules.verify_checksums", false)
	v.SetDefault("rules.checksum_file", "")

	// Admission webhook defaults (issue #120) — disabled by default; opt-in.
	v.SetDefault("admission_webhook.enabled", false)
	v.SetDefault("admission_webhook.bind_address", ":8443")
	v.SetDefault("admission_webhook.mode", "warn")
	v.SetDefault("admission_webhook.failure_policy", "Ignore")
	v.SetDefault("admission_webhook.tls_cert_file", "")
	v.SetDefault("admission_webhook.tls_key_file", "")
	v.SetDefault("admission_webhook.tls_auto_generate", false)
	v.SetDefault("admission_webhook.webhook_path", "/admission")
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
		normalizeSchemaAliases(&newConfig)

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
