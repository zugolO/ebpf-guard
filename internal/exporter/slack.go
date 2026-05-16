// Package exporter provides Slack notification support.
package exporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/ebpf-guard/ebpf-guard/pkg/types"
)

// SlackConfig holds Slack webhook configuration.
type SlackConfig struct {
	Enabled     bool   `mapstructure:"enabled"`
	WebhookURL  string `mapstructure:"webhook_url"`
	Channel     string `mapstructure:"channel"`      // Optional channel override
	MinSeverity string `mapstructure:"min_severity"` // "warning" or "critical"
}

// SlackNotifier sends alerts to Slack via Incoming Webhooks.
type SlackNotifier struct {
	config     SlackConfig
	client     *http.Client
	logger     *slog.Logger
	minSeverity types.Severity
}

// NewSlackNotifier creates a new Slack notifier.
func NewSlackNotifier(cfg SlackConfig, logger *slog.Logger) *SlackNotifier {
	if !cfg.Enabled || cfg.WebhookURL == "" {
		return &SlackNotifier{config: cfg, logger: logger}
	}

	minSev := types.SeverityWarning
	if cfg.MinSeverity == "critical" {
		minSev = types.SeverityCritical
	}

	return &SlackNotifier{
		config:      cfg,
		client:      &http.Client{Timeout: 10 * time.Second},
		logger:      logger,
		minSeverity: minSev,
	}
}

// Name returns the notifier identifier.
func (s *SlackNotifier) Name() string {
	return "slack"
}

// Enabled returns true if the notifier is configured and ready.
func (s *SlackNotifier) Enabled() bool {
	return s.config.Enabled && s.config.WebhookURL != "" && s.client != nil
}

// Send sends an alert to Slack.
func (s *SlackNotifier) Send(ctx context.Context, alert types.Alert) error {
	if !s.Enabled() {
		return fmt.Errorf("slack notifier not enabled")
	}

	// Filter by severity
	if alert.Severity != types.SeverityCritical && s.minSeverity == types.SeverityCritical {
		return nil // Skip non-critical alerts when min_severity is critical
	}

	payload := s.buildPayload(alert)
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal slack payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.config.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create slack request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("send slack request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack returned status %d", resp.StatusCode)
	}

	return nil
}

// SlackBlockKitPayload represents a Slack Block Kit message.
type SlackBlockKitPayload struct {
	Channel string       `json:"channel,omitempty"`
	Blocks  []SlackBlock `json:"blocks"`
}

// SlackBlock represents a single block in a Slack message.
type SlackBlock struct {
	Type     string      `json:"type"`
	Text     *SlackText  `json:"text,omitempty"`
	Fields   []SlackText `json:"fields,omitempty"`
	Elements []SlackText `json:"elements,omitempty"` // For context blocks
}

// SlackText represents text content in a Slack block.
type SlackText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func (s *SlackNotifier) buildPayload(alert types.Alert) SlackBlockKitPayload {
	// Determine color based on severity
	color := "#FFA500" // Orange for warning
	if alert.Severity == types.SeverityCritical {
		color = "#FF0000" // Red for critical
	}

	_ = color // Reserved for future use with attachments

	// Build the message
	blocks := []SlackBlock{
		{
			Type: "header",
			Text: &SlackText{
				Type: "plain_text",
				Text: fmt.Sprintf("🚨 Security Alert: %s", alert.RuleName),
			},
		},
		{
			Type: "section",
			Fields: []SlackText{
				{Type: "mrkdwn", Text: fmt.Sprintf("*Rule ID:*\n%s", alert.RuleID)},
				{Type: "mrkdwn", Text: fmt.Sprintf("*Severity:*\n%s", alert.Severity)},
			},
		},
		{
			Type: "section",
			Fields: []SlackText{
				{Type: "mrkdwn", Text: fmt.Sprintf("*Process:*\n%s (PID: %d)", alert.Comm, alert.PID)},
				{Type: "mrkdwn", Text: fmt.Sprintf("*Time:*\n%s", alert.Timestamp.Format(time.RFC3339))},
			},
		},
	}

	// Add K8s metadata if available
	if alert.Enrichment.PodName != "" {
		blocks = append(blocks, SlackBlock{
			Type: "section",
			Fields: []SlackText{
				{Type: "mrkdwn", Text: fmt.Sprintf("*Pod:*\n%s", alert.Enrichment.PodName)},
				{Type: "mrkdwn", Text: fmt.Sprintf("*Namespace:*\n%s", alert.Enrichment.Namespace)},
			},
		})
	}

	// Add message and fingerprint
	blocks = append(blocks,
		SlackBlock{
			Type: "section",
			Text: &SlackText{
				Type: "mrkdwn",
				Text: fmt.Sprintf("*Description:*\n%s", alert.Message),
			},
		},
	)

	if alert.Fingerprint != "" {
		blocks = append(blocks, SlackBlock{
			Type: "context",
			Elements: []SlackText{
				{Type: "mrkdwn", Text: fmt.Sprintf("Fingerprint: `%s`", alert.Fingerprint)},
			},
		})
	}

	payload := SlackBlockKitPayload{
		Blocks: blocks,
	}

	if s.config.Channel != "" {
		payload.Channel = s.config.Channel
	}

	return payload
}

// SlackContextBlock is a context block with elements.
type SlackContextBlock struct {
	Type     string      `json:"type"`
	Elements []SlackText `json:"elements"`
}

// SlackBlockWithElements is used for blocks that have elements instead of fields.
type SlackBlockWithElements struct {
	Type     string      `json:"type"`
	Elements []SlackText `json:"elements"`
}

func (s *SlackNotifier) buildPayloadWithContext(alert types.Alert) interface{} {
	// Alternative implementation with context block support
	type contextBlock struct {
		Type     string      `json:"type"`
		Elements []SlackText `json:"elements"`
	}

	type payload struct {
		Channel string      `json:"channel,omitempty"`
		Blocks  interface{} `json:"blocks"`
	}

	color := "#FFA500"
	if alert.Severity == types.SeverityCritical {
		color = "#FF0000"
	}
	_ = color

	blocks := []interface{}{
		map[string]interface{}{
			"type": "header",
			"text": map[string]string{
				"type": "plain_text",
				"text": fmt.Sprintf("🚨 Security Alert: %s", alert.RuleName),
			},
		},
		map[string]interface{}{
			"type":   "section",
			"fields": []SlackText{
				{Type: "mrkdwn", Text: fmt.Sprintf("*Rule ID:*\n%s", alert.RuleID)},
				{Type: "mrkdwn", Text: fmt.Sprintf("*Severity:*\n%s", alert.Severity)},
			},
		},
		map[string]interface{}{
			"type":   "section",
			"fields": []SlackText{
				{Type: "mrkdwn", Text: fmt.Sprintf("*Process:*\n%s (PID: %d)", alert.Comm, alert.PID)},
				{Type: "mrkdwn", Text: fmt.Sprintf("*Time:*\n%s", alert.Timestamp.Format(time.RFC3339))},
			},
		},
	}

	if alert.Enrichment.PodName != "" {
		blocks = append(blocks, map[string]interface{}{
			"type": "section",
			"fields": []SlackText{
				{Type: "mrkdwn", Text: fmt.Sprintf("*Pod:*\n%s", alert.Enrichment.PodName)},
				{Type: "mrkdwn", Text: fmt.Sprintf("*Namespace:*\n%s", alert.Enrichment.Namespace)},
			},
		})
	}

	blocks = append(blocks,
		map[string]interface{}{
			"type": "section",
			"text": map[string]string{
				"type": "mrkdwn",
				"text": fmt.Sprintf("*Description:*\n%s", alert.Message),
			},
		},
	)

	if alert.Fingerprint != "" {
		blocks = append(blocks, contextBlock{
			Type: "context",
			Elements: []SlackText{
				{Type: "mrkdwn", Text: fmt.Sprintf("Fingerprint: `%s`", alert.Fingerprint)},
			},
		})
	}

	p := payload{Blocks: blocks}
	if s.config.Channel != "" {
		p.Channel = s.config.Channel
	}

	return p
}
