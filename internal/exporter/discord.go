package exporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// DiscordConfig holds Discord webhook configuration.
type DiscordConfig struct {
	Enabled     bool   `mapstructure:"enabled"`
	WebhookURL  string `mapstructure:"webhook_url"`
	MinSeverity string `mapstructure:"min_severity"` // "warning" or "critical"
}

// DiscordNotifier sends alerts to Discord via webhooks with rich embeds.
type DiscordNotifier struct {
	config      DiscordConfig
	client      *http.Client
	logger      *slog.Logger
	minSeverity types.Severity
}

// NewDiscordNotifier creates a new Discord notifier.
// strictSSRF enables blocking of RFC-1918 private IP ranges in addition to the
// default loopback and link-local address blocking.
func NewDiscordNotifier(cfg DiscordConfig, logger *slog.Logger, strictSSRF bool) *DiscordNotifier {
	if !cfg.Enabled || cfg.WebhookURL == "" {
		return &DiscordNotifier{config: cfg, logger: logger}
	}

	if logger == nil {
		logger = slog.Default()
	}

	if err := ValidateWebhookURL(cfg.WebhookURL, strictSSRF); err != nil {
		logger.Warn("exporter/discord: unsafe webhook URL",
			slog.String("url", cfg.WebhookURL),
			slog.Any("error", err))
	}

	minSev := types.SeverityWarning
	if cfg.MinSeverity == "critical" {
		minSev = types.SeverityCritical
	}

	return &DiscordNotifier{
		config:      cfg,
		client:      &http.Client{Timeout: 10 * time.Second},
		logger:      logger,
		minSeverity: minSev,
	}
}

// Name returns the notifier identifier.
func (d *DiscordNotifier) Name() string {
	return "discord"
}

// escapeDiscordMarkdown escapes Discord markdown formatting characters
// in user-supplied strings to prevent spoofing (masked links, fake bold,
// and other cosmetic injection) in security alert embeds.
func escapeDiscordMarkdown(s string) string {
	r := strings.NewReplacer(
		`\`, `\\`,
		`*`, `\*`,
		`_`, `\_`,
		`~`, `\~`,
		"`", "\\`",
		`>`, `\>`,
		`[`, `\[`,
		`]`, `\]`,
	)
	return r.Replace(s)
}

// Enabled returns true if the notifier is configured and ready.
func (d *DiscordNotifier) Enabled() bool {
	return d.config.Enabled && d.config.WebhookURL != "" && d.client != nil
}

// Send sends an alert to Discord.
func (d *DiscordNotifier) Send(ctx context.Context, alert types.Alert) error {
	if !d.Enabled() {
		return fmt.Errorf("discord notifier not enabled")
	}

	if alert.Severity != types.SeverityCritical && d.minSeverity == types.SeverityCritical {
		return nil
	}

	payload := d.buildPayload(alert)
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal discord payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.config.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create discord request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("send discord request: %w", redactURLError(err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("discord returned status %d", resp.StatusCode)
	}

	return nil
}

// DiscordWebhookPayload represents a Discord webhook message with embeds.
type DiscordWebhookPayload struct {
	Embeds []DiscordEmbed `json:"embeds"`
}

// DiscordEmbed represents a rich embed in Discord.
type DiscordEmbed struct {
	Title       string              `json:"title"`
	Description string              `json:"description"`
	Color       int                 `json:"color"`
	Timestamp   string              `json:"timestamp"`
	Fields      []DiscordEmbedField `json:"fields,omitempty"`
	Footer      *DiscordEmbedFooter `json:"footer,omitempty"`
}

// DiscordEmbedField represents a field in a Discord embed.
type DiscordEmbedField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

// DiscordEmbedFooter represents the footer of a Discord embed.
type DiscordEmbedFooter struct {
	Text string `json:"text"`
}

func (d *DiscordNotifier) buildPayload(alert types.Alert) DiscordWebhookPayload {
	color := 16753920 // Orange for warning
	if alert.Severity == types.SeverityCritical {
		color = 16711680 // Red for critical
	}

	fields := []DiscordEmbedField{
		{Name: "Rule ID", Value: escapeDiscordMarkdown(alert.RuleID), Inline: true},
		{Name: "Severity", Value: string(alert.Severity), Inline: true},
		{Name: "Process", Value: fmt.Sprintf("%s (PID: %d)", escapeDiscordMarkdown(alert.Comm), alert.PID), Inline: true},
		{Name: "Time", Value: alert.Timestamp.Format(time.RFC3339), Inline: true},
	}

	if alert.Enrichment.PodName != "" {
		fields = append(fields,
			DiscordEmbedField{Name: "Pod", Value: alert.Enrichment.PodName, Inline: true},
			DiscordEmbedField{Name: "Namespace", Value: alert.Enrichment.Namespace, Inline: true},
		)
	}

	if len(alert.ProcessTree) > 0 {
		var parts []string
		for _, node := range alert.ProcessTree {
			parts = append(parts, fmt.Sprintf("%s (PID %d)", escapeDiscordMarkdown(node.Comm), node.PID))
		}
		fields = append(fields, DiscordEmbedField{Name: "Process Tree", Value: strings.Join(parts, " → "), Inline: false})
	}

	var footer *DiscordEmbedFooter
	if alert.Fingerprint != "" {
		footer = &DiscordEmbedFooter{Text: fmt.Sprintf("Fingerprint: %s", alert.Fingerprint)}
	}

	return DiscordWebhookPayload{
		Embeds: []DiscordEmbed{
			{
				Title:       fmt.Sprintf("Security Alert: %s", escapeDiscordMarkdown(alert.RuleName)),
				Description: escapeDiscordMarkdown(alert.Message),
				Color:       color,
				Timestamp:   alert.Timestamp.Format(time.RFC3339),
				Fields:      fields,
				Footer:      footer,
			},
		},
	}
}
