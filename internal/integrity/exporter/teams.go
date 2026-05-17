// Package exporter provides Microsoft Teams notification support.
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

// TeamsConfig holds Microsoft Teams webhook configuration.
type TeamsConfig struct {
	Enabled     bool   `mapstructure:"enabled"`
	WebhookURL  string `mapstructure:"webhook_url"`
	MinSeverity string `mapstructure:"min_severity"` // "warning" or "critical"
}

// TeamsNotifier sends alerts to Microsoft Teams via Incoming Webhooks.
type TeamsNotifier struct {
	config      TeamsConfig
	client      *http.Client
	logger      *slog.Logger
	minSeverity types.Severity
}

// NewTeamsNotifier creates a new Teams notifier.
func NewTeamsNotifier(cfg TeamsConfig, logger *slog.Logger) *TeamsNotifier {
	if !cfg.Enabled || cfg.WebhookURL == "" {
		return &TeamsNotifier{config: cfg, logger: logger}
	}

	minSev := types.SeverityWarning
	if cfg.MinSeverity == "critical" {
		minSev = types.SeverityCritical
	}

	return &TeamsNotifier{
		config:      cfg,
		client:      &http.Client{Timeout: 10 * time.Second},
		logger:      logger,
		minSeverity: minSev,
	}
}

// Name returns the notifier identifier.
func (t *TeamsNotifier) Name() string {
	return "teams"
}

// Enabled returns true if the notifier is configured and ready.
func (t *TeamsNotifier) Enabled() bool {
	return t.config.Enabled && t.config.WebhookURL != "" && t.client != nil
}

// Send sends an alert to Teams.
func (t *TeamsNotifier) Send(ctx context.Context, alert types.Alert) error {
	if !t.Enabled() {
		return fmt.Errorf("teams notifier not enabled")
	}

	// Filter by severity
	if alert.Severity != types.SeverityCritical && t.minSeverity == types.SeverityCritical {
		return nil // Skip non-critical alerts when min_severity is critical
	}

	payload := t.buildPayload(alert)
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal teams payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.config.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create teams request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("send teams request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("teams returned status %d", resp.StatusCode)
	}

	return nil
}

// TeamsAdaptiveCard represents a Teams Adaptive Card message.
type TeamsAdaptiveCard struct {
	Type        string              `json:"type"`
	Attachments []TeamsAttachment   `json:"attachments"`
}

// TeamsAttachment represents a card attachment.
type TeamsAttachment struct {
	ContentType string                 `json:"contentType"`
	ContentURL  string                 `json:"contentUrl,omitempty"`
	Content     TeamsAdaptiveCardContent `json:"content"`
}

// TeamsAdaptiveCardContent represents the card content.
type TeamsAdaptiveCardContent struct {
	Schema  string                 `json:"$schema"`
	Type    string                 `json:"type"`
	Version string                 `json:"version"`
	Body    []TeamsCardElement     `json:"body"`
	Actions []TeamsCardAction      `json:"actions,omitempty"`
}

// TeamsCardElement represents a card body element.
type TeamsCardElement struct {
	Type      string            `json:"type"`
	Text      string            `json:"text,omitempty"`
	Size      string            `json:"size,omitempty"`
	Weight    string            `json:"weight,omitempty"`
	Color     string            `json:"color,omitempty"`
	Spacing   string            `json:"spacing,omitempty"`
	Separator bool              `json:"separator,omitempty"`
	Wrap      bool              `json:"wrap,omitempty"`
	Columns   []TeamsColumn     `json:"columns,omitempty"`
	Facts     []TeamsFact       `json:"facts,omitempty"`
}

// TeamsColumn represents a column in a column set.
type TeamsColumn struct {
	Type  string           `json:"type"`
	Width string           `json:"width"`
	Items []TeamsCardElement `json:"items"`
}

// TeamsFact represents a fact in a fact set.
type TeamsFact struct {
	Title string `json:"title"`
	Value string `json:"value"`
}

// TeamsCardAction represents an action button.
type TeamsCardAction struct {
	Type  string `json:"type"`
	Title string `json:"title"`
	URL   string `json:"url"`
}

func (t *TeamsNotifier) buildPayload(alert types.Alert) TeamsAdaptiveCard {
	// Determine color based on severity
	color := "warning" // Yellow for warning
	if alert.Severity == types.SeverityCritical {
		color = "attention" // Red for critical
	}

	// Build facts
	facts := []TeamsFact{
		{Title: "Rule ID:", Value: alert.RuleID},
		{Title: "Severity:", Value: string(alert.Severity)},
		{Title: "Process:", Value: fmt.Sprintf("%s (PID: %d)", alert.Comm, alert.PID)},
		{Title: "Time:", Value: alert.Timestamp.Format(time.RFC3339)},
	}

	if alert.Enrichment.PodName != "" {
		facts = append(facts, TeamsFact{Title: "Pod:", Value: alert.Enrichment.PodName})
		facts = append(facts, TeamsFact{Title: "Namespace:", Value: alert.Enrichment.Namespace})
	}

	if alert.Fingerprint != "" {
		facts = append(facts, TeamsFact{Title: "Fingerprint:", Value: alert.Fingerprint})
	}

	body := []TeamsCardElement{
		{
			Type:   "TextBlock",
			Text:   "🚨 Security Alert: " + alert.RuleName,
			Size:   "Large",
			Weight: "Bolder",
			Color:  color,
		},
		{
			Type:      "TextBlock",
			Text:      alert.Message,
			Wrap:      true,
			Spacing:   "Medium",
			Separator: true,
		},
		{
			Type:    "FactSet",
			Facts:   facts,
			Spacing: "Medium",
		},
	}

	return TeamsAdaptiveCard{
		Type: "message",
		Attachments: []TeamsAttachment{
			{
				ContentType: "application/vnd.microsoft.card.adaptive",
				Content: TeamsAdaptiveCardContent{
					Schema:  "http://adaptivecards.io/schemas/adaptive-card.json",
					Type:    "AdaptiveCard",
					Version: "1.4",
					Body:    body,
				},
			},
		},
	}
}


