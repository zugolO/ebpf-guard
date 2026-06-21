// Package exporter provides notification fanout to multiple backends.
package exporter

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Notifier is the interface for alert notification backends.
type Notifier interface {
	// Name returns the notifier's identifier (e.g., "slack", "teams", "webhook").
	Name() string

	// Send sends an alert to the notification backend.
	// Implementations should respect the context timeout and return an error if the send fails.
	Send(ctx context.Context, alert types.Alert) error

	// Enabled returns true if the notifier is configured and ready to send.
	Enabled() bool
}

// FanoutNotifier dispatches alerts to multiple configured notifiers in parallel.
type FanoutNotifier struct {
	notifiers []Notifier
	timeout   time.Duration
	logger    *slog.Logger
}

// FanoutConfig holds configuration for all notification backends.
type FanoutConfig struct {
	Slack       SlackConfig      `mapstructure:"slack"`
	Teams       TeamsConfig      `mapstructure:"teams"`
	Webhook     WebhookConfig    `mapstructure:"webhook"`
	OTLP        OTLPConfig       `mapstructure:"otlp"`
	Kafka       KafkaConfig      `mapstructure:"kafka"`
	SyslogCEF   SyslogCEFConfig  `mapstructure:"syslog_cef"`
	Discord     DiscordConfig    `mapstructure:"discord"`
	Telegram    TelegramConfig   `mapstructure:"telegram"`
	UnixSocket  UnixSocketConfig `mapstructure:"unix_socket"`
	FalcoOutput bool             `mapstructure:"falco_output"` // emit Falco-compatible JSON for the webhook notifier
	// StrictSSRF enables strict SSRF prevention for all HTTP-based notifiers
	// by blocking RFC-1918 private IP ranges in addition to the default
	// loopback and link-local address blocking.
	// Set false for in-cluster services; true for external targets.
	StrictSSRF bool `mapstructure:"strict_ssrf"`
}

// NewFanoutNotifier creates a new fanout notifier with the given configuration.
// Returns an error if any notifier has a security-critical misconfiguration (e.g. credentials over plaintext).
func NewFanoutNotifier(cfg FanoutConfig, timeout time.Duration, logger *slog.Logger) (*FanoutNotifier, error) {
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	f := &FanoutNotifier{
		timeout: timeout,
		logger:  logger,
	}

	// Initialize Slack notifier if enabled
	if slackNotifier := NewSlackNotifier(cfg.Slack, logger, cfg.StrictSSRF); slackNotifier.Enabled() {
		f.notifiers = append(f.notifiers, slackNotifier)
		logger.Info("exporter/notifier: Slack notifier enabled",
			slog.String("channel", cfg.Slack.Channel))
	}

	// Initialize Teams notifier if enabled
	if teamsNotifier := NewTeamsNotifier(cfg.Teams, logger, cfg.StrictSSRF); teamsNotifier.Enabled() {
		f.notifiers = append(f.notifiers, teamsNotifier)
		logger.Info("exporter/notifier: Teams notifier enabled")
	}

	// Initialize generic webhook notifier if enabled
	if webhookNotifier := NewGenericWebhookNotifierWithCompat(cfg.Webhook, logger, cfg.FalcoOutput, cfg.StrictSSRF); webhookNotifier.Enabled() {
		f.notifiers = append(f.notifiers, webhookNotifier)
		logger.Info("exporter/notifier: Webhook notifier enabled",
			slog.String("url", cfg.Webhook.URL))
	}

	// Initialize OTLP log notifier if enabled
	otlpNotifier, err := NewOTLPNotifier(cfg.OTLP, logger, cfg.StrictSSRF)
	if err != nil {
		return nil, fmt.Errorf("exporter/notifier: OTLP misconfigured: %w", err)
	}
	if otlpNotifier.Enabled() {
		f.notifiers = append(f.notifiers, otlpNotifier)
		logger.Info("exporter/notifier: OTLP notifier enabled",
			slog.String("endpoint", cfg.OTLP.Endpoint))
	}

	// Initialize Kafka notifier if enabled
	kafkaNotifier, err := NewKafkaNotifier(cfg.Kafka, logger)
	if err != nil {
		return nil, fmt.Errorf("exporter/notifier: Kafka misconfigured: %w", err)
	}
	if kafkaNotifier.Enabled() {
		f.notifiers = append(f.notifiers, kafkaNotifier)
		logger.Info("exporter/notifier: Kafka notifier enabled",
			slog.String("topic", cfg.Kafka.Topic))
	}

	// Initialize syslog/CEF notifier if enabled
	if syslogNotifier := NewSyslogCEFNotifier(cfg.SyslogCEF, logger); syslogNotifier.Enabled() {
		f.notifiers = append(f.notifiers, syslogNotifier)
		logger.Info("exporter/notifier: Syslog/CEF notifier enabled",
			slog.String("address", cfg.SyslogCEF.Address),
			slog.String("format", cfg.SyslogCEF.Format))
	}

	// Initialize Discord notifier if enabled
	if discordNotifier := NewDiscordNotifier(cfg.Discord, logger, cfg.StrictSSRF); discordNotifier.Enabled() {
		f.notifiers = append(f.notifiers, discordNotifier)
		logger.Info("exporter/notifier: Discord notifier enabled")
	}

	// Initialize Telegram notifier if enabled
	if telegramNotifier := NewTelegramNotifier(cfg.Telegram, logger, cfg.StrictSSRF); telegramNotifier.Enabled() {
		f.notifiers = append(f.notifiers, telegramNotifier)
		logger.Info("exporter/notifier: Telegram notifier enabled",
			slog.String("chat_id", cfg.Telegram.ChatID))
	}

	// Initialize Unix socket notifier if enabled
	if socketNotifier := NewUnixSocketNotifier(cfg.UnixSocket, logger); socketNotifier.Enabled() {
		f.notifiers = append(f.notifiers, socketNotifier)
		logger.Info("exporter/notifier: Unix socket notifier enabled",
			slog.String("path", cfg.UnixSocket.Path))
	}

	if len(f.notifiers) == 0 {
		logger.Warn("exporter/notifier: no notification backends configured")
	} else {
		logger.Info("exporter/notifier: fanout notifier initialized",
			slog.Int("backends", len(f.notifiers)))
	}

	return f, nil
}

// Send dispatches an alert to all configured notifiers in parallel.
// Errors from individual notifiers are logged but do not block other sends.
func (f *FanoutNotifier) Send(ctx context.Context, alert types.Alert) {
	if len(f.notifiers) == 0 {
		return
	}

	// Create a timeout context for this send operation
	sendCtx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()

	var wg sync.WaitGroup
	for _, notifier := range f.notifiers {
		if !notifier.Enabled() {
			continue
		}

		wg.Add(1)
		go func(n Notifier) {
			defer wg.Done()

			if err := n.Send(sendCtx, alert); err != nil {
				f.logger.Warn("exporter/notifier: failed to send alert",
					slog.String("notifier", n.Name()),
					slog.String("rule_id", alert.RuleID),
					slog.Any("error", err))
			} else {
				f.logger.Debug("exporter/notifier: alert sent successfully",
					slog.String("notifier", n.Name()),
					slog.String("rule_id", alert.RuleID))
			}
		}(notifier)
	}

	wg.Wait()
}

// SendAlert is an alias for Send to satisfy interfaces expecting SendAlert.
func (f *FanoutNotifier) SendAlert(ctx context.Context, alert types.Alert) {
	f.Send(ctx, alert)
}

// NotifierNames returns the names of all configured notifiers.
func (f *FanoutNotifier) NotifierNames() []string {
	names := make([]string, 0, len(f.notifiers))
	for _, n := range f.notifiers {
		names = append(names, n.Name())
	}
	return names
}

// Close gracefully shuts down all notifiers.
func (f *FanoutNotifier) Close() error {
	var errs []error
	for _, n := range f.notifiers {
		if closer, ok := n.(interface{ Close() error }); ok {
			if err := closer.Close(); err != nil {
				errs = append(errs, fmt.Errorf("close %s: %w", n.Name(), err))
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("fanout close errors: %v", errs)
	}
	return nil
}
