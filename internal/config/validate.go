package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// ValidateConfig checks the loaded configuration for invalid values and
// returns a combined error listing every problem found.
//
// Call this immediately after loading — before any subsystem is initialised —
// so misconfigurations surface as a clean startup error rather than a
// runtime panic deep inside a component.
func ValidateConfig(cfg *Config) error {
	var errs []error
	add := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}

	// ── Store ────────────────────────────────────────────────────────────────
	add(validateOneOf("store.backend", cfg.Store.Backend,
		[]string{"memory", "sqlite", "opensearch"}))

	// ── Server ───────────────────────────────────────────────────────────────
	if cfg.Server.BindAddress != "" {
		add(validateBindAddress("server.bind_address", cfg.Server.BindAddress))
	}
	if t := cfg.Server.ShutdownTimeout; t != 0 && (t < 5*time.Second || t > 300*time.Second) {
		add(fmt.Errorf("server.shutdown_timeout: must be in [5s, 300s], got %s", t))
	}

	// ── Profiler ─────────────────────────────────────────────────────────────
	add(validateFraction("profiler.anomaly_threshold", cfg.Profiler.AnomalyThreshold))
	add(validateFraction("profiler.ewma_weight", cfg.Profiler.EWMAWeight))
	add(validateFraction("profiler.sequence.threshold", cfg.Profiler.Sequence.Threshold))

	if cfg.Profiler.Enabled && cfg.Profiler.LearningPeriod <= 0 {
		add(fmt.Errorf("profiler.learning_period: must be > 0, got %d", cfg.Profiler.LearningPeriod))
	}

	// ── Rules ────────────────────────────────────────────────────────────────
	if cfg.Rules.RateLimitAlerts && cfg.Rules.RateLimitWindow <= 0 {
		add(fmt.Errorf("rules.rate_limit_window: must be > 0 when rate_limit_alerts is true, got %d",
			cfg.Rules.RateLimitWindow))
	}

	// ── Alerting ─────────────────────────────────────────────────────────────
	if cfg.Alerting.Enabled {
		if cfg.Alerting.WebhookURL == "" {
			add(fmt.Errorf("alerting.webhook_url: required when alerting.enabled is true"))
		} else {
			add(validateHTTPURL("alerting.webhook_url", cfg.Alerting.WebhookURL))
		}
		if cfg.Alerting.BatchTimeout <= 0 {
			add(fmt.Errorf("alerting.batch_timeout: must be > 0, got %d", cfg.Alerting.BatchTimeout))
		}
	}

	// ── Enforcement ──────────────────────────────────────────────────────────
	if cfg.Enforcement.Enabled {
		add(validateOneOf("enforcement.block_backend", cfg.Enforcement.BlockBackend,
			[]string{"log", "nftables", "iptables", "lsm", "xdp"}))
		if cfg.Enforcement.ThrottleCPUPercent < 1 || cfg.Enforcement.ThrottleCPUPercent > 99 {
			add(fmt.Errorf("enforcement.throttle_cpu_percent: must be in [1, 99], got %d",
				cfg.Enforcement.ThrottleCPUPercent))
		}
		if cfg.Enforcement.ThrottleMaxAgeMinutes <= 0 {
			add(fmt.Errorf("enforcement.throttle_max_age_minutes: must be > 0, got %d",
				cfg.Enforcement.ThrottleMaxAgeMinutes))
		}
	}

	// ── Watchdog ─────────────────────────────────────────────────────────────
	if cfg.Watchdog.MemoryPressure.Enabled {
		lo := cfg.Watchdog.MemoryPressure.LowMemoryThreshold
		hi := cfg.Watchdog.MemoryPressure.RecoveryThreshold
		if lo < 0 || lo > 100 {
			add(fmt.Errorf("watchdog.memory_pressure.low_memory_threshold: must be in [0, 100], got %.2f", lo))
		}
		if hi < 0 || hi > 100 {
			add(fmt.Errorf("watchdog.memory_pressure.recovery_threshold: must be in [0, 100], got %.2f", hi))
		}
		if lo > 0 && hi > 0 && lo >= hi {
			add(fmt.Errorf("watchdog.memory_pressure.low_memory_threshold (%.2f) must be less than recovery_threshold (%.2f)",
				lo, hi))
		}
	}
	if cfg.Watchdog.CPUPressure.Enabled {
		cp := cfg.Watchdog.CPUPressure
		for name, v := range map[string]float64{
			"cpu_limit_percent":   cp.CPULimitPercent,
			"file_shed_threshold": cp.FileShedThreshold,
			"all_shed_threshold":  cp.AllShedThreshold,
			"recovery_threshold":  cp.RecoveryThreshold,
		} {
			if v < 0 || v > 100 {
				add(fmt.Errorf("watchdog.cpu_pressure.%s: must be in [0, 100], got %.2f", name, v))
			}
		}
		if cp.FileShedThreshold > 0 && cp.AllShedThreshold > 0 && cp.FileShedThreshold > cp.AllShedThreshold {
			add(fmt.Errorf("watchdog.cpu_pressure.file_shed_threshold (%.2f) must be <= all_shed_threshold (%.2f)",
				cp.FileShedThreshold, cp.AllShedThreshold))
		}
		if cp.RecoveryThreshold > 0 && cp.FileShedThreshold > 0 && cp.RecoveryThreshold >= cp.FileShedThreshold {
			add(fmt.Errorf("watchdog.cpu_pressure.recovery_threshold (%.2f) must be less than file_shed_threshold (%.2f)",
				cp.RecoveryThreshold, cp.FileShedThreshold))
		}
		if cp.WindowSize < 0 {
			add(fmt.Errorf("watchdog.cpu_pressure.window_size: must be >= 0, got %d", cp.WindowSize))
		}
	}

	// ── Collectors ───────────────────────────────────────────────────────────
	if s := cfg.Collectors.BackpressureStrategy; s != "" {
		add(validateOneOf("collectors.backpressure_strategy", s,
			[]string{"drop", "block", "sample"}))
	}
	if cfg.Collectors.DNS.DGAThreshold < 0 {
		add(fmt.Errorf("collectors.dns.dga_threshold: must be >= 0, got %.2f", cfg.Collectors.DNS.DGAThreshold))
	}
	if s := cfg.Collectors.StartupPolicy; s != "" {
		add(validateOneOf("collectors.startup_policy", s, []string{"fail-open", "fail-closed"}))
	}

	// ── Notifications ────────────────────────────────────────────────────────
	if cfg.Notifications.Slack.Enabled {
		if cfg.Notifications.Slack.WebhookURL == "" {
			add(fmt.Errorf("notifications.slack.webhook_url: required when slack.enabled is true"))
		} else {
			add(validateHTTPURL("notifications.slack.webhook_url", cfg.Notifications.Slack.WebhookURL))
		}
		add(validateOneOf("notifications.slack.min_severity", cfg.Notifications.Slack.MinSeverity,
			[]string{"warning", "critical"}))
	}
	if cfg.Notifications.Teams.Enabled {
		if cfg.Notifications.Teams.WebhookURL == "" {
			add(fmt.Errorf("notifications.teams.webhook_url: required when teams.enabled is true"))
		} else {
			add(validateHTTPURL("notifications.teams.webhook_url", cfg.Notifications.Teams.WebhookURL))
		}
		add(validateOneOf("notifications.teams.min_severity", cfg.Notifications.Teams.MinSeverity,
			[]string{"warning", "critical"}))
	}
	if cfg.Notifications.Webhook.Enabled {
		if cfg.Notifications.Webhook.URL == "" {
			add(fmt.Errorf("notifications.webhook.url: required when webhook.enabled is true"))
		} else {
			add(validateHTTPURL("notifications.webhook.url", cfg.Notifications.Webhook.URL))
		}
		add(validateOneOf("notifications.webhook.min_severity", cfg.Notifications.Webhook.MinSeverity,
			[]string{"warning", "critical"}))
	}

	// ── Gossip ───────────────────────────────────────────────────────────────
	if cfg.Gossip.Enabled && cfg.Gossip.TLSEnabled {
		if cfg.Gossip.TLSCertFile == "" {
			add(fmt.Errorf("gossip.tls_cert_file: required when gossip.tls_enabled is true"))
		}
		if cfg.Gossip.TLSKeyFile == "" {
			add(fmt.Errorf("gossip.tls_key_file: required when gossip.tls_enabled is true"))
		}
		if cfg.Gossip.TLSCAFile == "" {
			add(fmt.Errorf("gossip.tls_ca_file: required when gossip.tls_enabled is true"))
		}
	}
	if cfg.Gossip.Enabled && cfg.Gossip.SecretPrevious != "" {
		if cfg.Gossip.SecretRotationTTL <= 0 {
			add(fmt.Errorf("gossip.secret_rotation_ttl: must be > 0 when gossip.secret_previous is set"))
		}
	}
	for i, peer := range cfg.Gossip.Peers {
		add(validateHTTPURL(fmt.Sprintf("gossip.peers[%d]", i), peer))
	}

	// ── Canary ───────────────────────────────────────────────────────────────
	if cfg.Canary.Enabled && cfg.Canary.AlertSeverity != "" {
		add(validateOneOf("canary.alert_severity", cfg.Canary.AlertSeverity,
			[]string{"warning", "critical"}))
	}

	return errors.Join(errs...)
}

// validateOneOf returns an error when value is not in the valid set.
func validateOneOf(field, value string, valid []string) error {
	for _, v := range valid {
		if value == v {
			return nil
		}
	}
	return fmt.Errorf("%s: invalid value %q; must be one of [%s]",
		field, value, strings.Join(valid, ", "))
}

// validateFraction returns an error when v is outside [0.0, 1.0].
func validateFraction(field string, v float64) error {
	if v < 0 || v > 1 {
		return fmt.Errorf("%s: must be in [0.0, 1.0], got %.4f", field, v)
	}
	return nil
}

// validateHTTPURL returns an error when rawURL is not a valid http/https URL.
func validateHTTPURL(field, rawURL string) error {
	u, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return fmt.Errorf("%s: invalid URL %q: %w", field, rawURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%s: URL scheme must be http or https, got %q", field, u.Scheme)
	}
	return nil
}

// validateBindAddress checks that addr is a valid "host:port" or ":port" string.
// The host may be an IP address or a hostname; it is not resolved at startup.
func validateBindAddress(field, addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%s: invalid address %q (expected host:port or :port): %w", field, addr, err)
	}
	if port == "" {
		return fmt.Errorf("%s: missing port in address %q", field, addr)
	}
	// If the host looks like an IP literal, make sure it parses.
	if host != "" && strings.IndexByte(host, '.') != -1 || strings.IndexByte(host, ':') != -1 {
		if net.ParseIP(host) == nil {
			return fmt.Errorf("%s: %q is not a valid IP address in %q", field, host, addr)
		}
	}
	return nil
}
