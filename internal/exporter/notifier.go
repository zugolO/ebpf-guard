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
	Slack       SlackConfig   `mapstructure:"slack"`
	Teams       TeamsConfig   `mapstructure:"teams"`
	Webhook     WebhookConfig `mapstructure:"webhook"`
	FalcoOutput bool          `mapstructure:"falco_output"` // emit Falco-compatible JSON for the webhook notifier
}

// NewFanoutNotifier creates a new fanout notifier with the given configuration.
func NewFanoutNotifier(cfg FanoutConfig, timeout time.Duration, logger *slog.Logger) *FanoutNotifier {
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	f := &FanoutNotifier{
		timeout: timeout,
		logger:  logger,
	}

	// Initialize Slack notifier if enabled
	if slackNotifier := NewSlackNotifier(cfg.Slack, logger); slackNotifier.Enabled() {
		f.notifiers = append(f.notifiers, slackNotifier)
		logger.Info("exporter/notifier: Slack notifier enabled",
			slog.String("channel", cfg.Slack.Channel))
	}

	// Initialize Teams notifier if enabled
	if teamsNotifier := NewTeamsNotifier(cfg.Teams, logger); teamsNotifier.Enabled() {
		f.notifiers = append(f.notifiers, teamsNotifier)
		logger.Info("exporter/notifier: Teams notifier enabled")
	}

	// Initialize generic webhook notifier if enabled
	if webhookNotifier := NewGenericWebhookNotifierWithCompat(cfg.Webhook, logger, cfg.FalcoOutput); webhookNotifier.Enabled() {
		f.notifiers = append(f.notifiers, webhookNotifier)
		logger.Info("exporter/notifier: Webhook notifier enabled",
			slog.String("url", cfg.Webhook.URL))
	}

	if len(f.notifiers) == 0 {
		logger.Warn("exporter/notifier: no notification backends configured")
	} else {
		logger.Info("exporter/notifier: fanout notifier initialized",
			slog.Int("backends", len(f.notifiers)))
	}

	return f
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
