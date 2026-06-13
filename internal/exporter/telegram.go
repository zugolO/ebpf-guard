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

// TelegramConfig holds Telegram Bot API configuration.
type TelegramConfig struct {
	Enabled     bool   `mapstructure:"enabled"`
	BotToken    string `mapstructure:"bot_token"`
	ChatID      string `mapstructure:"chat_id"`
	MinSeverity string `mapstructure:"min_severity"` // "warning" or "critical"
}

// TelegramNotifier sends alerts to Telegram via the Bot API.
type TelegramNotifier struct {
	config      TelegramConfig
	client      *http.Client
	logger      *slog.Logger
	minSeverity types.Severity
	apiBase     string
}

// NewTelegramNotifier creates a new Telegram notifier.
// strictSSRF enables blocking of RFC-1918 private IP ranges in addition to the
// default loopback and link-local address blocking.
func NewTelegramNotifier(cfg TelegramConfig, logger *slog.Logger, strictSSRF bool) *TelegramNotifier {
	if !cfg.Enabled || cfg.BotToken == "" || cfg.ChatID == "" {
		return &TelegramNotifier{config: cfg, logger: logger}
	}

	if logger == nil {
		logger = slog.Default()
	}

	apiBase := fmt.Sprintf("https://api.telegram.org/bot%s", cfg.BotToken)
	if err := ValidateWebhookURL(apiBase, strictSSRF); err != nil {
		logger.Warn("exporter/telegram: unsafe API base URL",
			slog.Any("error", err))
	}

	minSev := types.SeverityWarning
	if cfg.MinSeverity == "critical" {
		minSev = types.SeverityCritical
	}

	return &TelegramNotifier{
		config:      cfg,
		client:      &http.Client{Timeout: 10 * time.Second},
		logger:      logger,
		minSeverity: minSev,
		apiBase:     apiBase,
	}
}

// Name returns the notifier identifier.
func (t *TelegramNotifier) Name() string {
	return "telegram"
}

// Enabled returns true if the notifier is configured and ready.
func (t *TelegramNotifier) Enabled() bool {
	return t.config.Enabled && t.config.BotToken != "" && t.config.ChatID != "" && t.client != nil
}

// Send sends an alert to Telegram.
func (t *TelegramNotifier) Send(ctx context.Context, alert types.Alert) error {
	if !t.Enabled() {
		return fmt.Errorf("telegram notifier not enabled")
	}

	if alert.Severity != types.SeverityCritical && t.minSeverity == types.SeverityCritical {
		return nil
	}

	text := t.buildMessage(alert)

	payload := map[string]interface{}{
		"chat_id":    t.config.ChatID,
		"text":       text,
		"parse_mode": "MarkdownV2",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal telegram payload: %w", err)
	}

	url := fmt.Sprintf("%s/sendMessage", t.apiBase)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create telegram request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("send telegram request: %w", redactURLError(err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram returned status %d", resp.StatusCode)
	}

	return nil
}

func (t *TelegramNotifier) buildMessage(alert types.Alert) string {
	var b strings.Builder

	severityEmoji := "⚠️"
	if alert.Severity == types.SeverityCritical {
		severityEmoji = "🚨"
	}

	b.WriteString(fmt.Sprintf("%s *Security Alert: %s*\n", severityEmoji, escapeMarkdownV2(alert.RuleName)))
	b.WriteString(fmt.Sprintf("\n*Rule ID:* `%s`\n", escapeMarkdownV2(alert.RuleID)))
	b.WriteString(fmt.Sprintf("*Severity:* `%s`\n", escapeMarkdownV2(string(alert.Severity))))
	b.WriteString(fmt.Sprintf("*Process:* `%s` \\(PID: %d\\)\n", escapeMarkdownV2(alert.Comm), alert.PID))
	b.WriteString(fmt.Sprintf("*Time:* %s\n", alert.Timestamp.Format(time.RFC3339)))

	if alert.Enrichment.PodName != "" {
		b.WriteString(fmt.Sprintf("*Pod:* `%s`\n", escapeMarkdownV2(alert.Enrichment.PodName)))
		b.WriteString(fmt.Sprintf("*Namespace:* `%s`\n", escapeMarkdownV2(alert.Enrichment.Namespace)))
	}

	if alert.Message != "" {
		b.WriteString(fmt.Sprintf("\n*Description:*\n%s\n", escapeMarkdownV2(alert.Message)))
	}

	if alert.Fingerprint != "" {
		b.WriteString(fmt.Sprintf("\n_`%s`_", escapeMarkdownV2(alert.Fingerprint)))
	}

	return b.String()
}

func escapeMarkdownV2(s string) string {
	replacer := strings.NewReplacer(
		"_", "\\_",
		"*", "\\*",
		"[", "\\[",
		"]", "\\]",
		"(", "\\(",
		")", "\\)",
		"~", "\\~",
		"`", "\\`",
		">", "\\>",
		"#", "\\#",
		"+", "\\+",
		"-", "\\-",
		"=", "\\=",
		"|", "\\|",
		"{", "\\{",
		"}", "\\}",
		".", "\\.",
		"!", "\\!",
	)
	return replacer.Replace(s)
}
