// Package exporter provides generic webhook notification support.
package exporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"text/template"
	"time"

	"github.com/ebpf-guard/ebpf-guard/pkg/types"
)

// WebhookConfig holds generic webhook configuration.
type WebhookConfig struct {
	Enabled     bool              `mapstructure:"enabled"`
	URL         string            `mapstructure:"url"`
	Headers     map[string]string `mapstructure:"headers"`
	Template    string            `mapstructure:"template"`     // Go template string; empty = default JSON
	MinSeverity string            `mapstructure:"min_severity"` // "warning" or "critical"
}

// GenericWebhookNotifier sends alerts to a custom HTTP endpoint.
type GenericWebhookNotifier struct {
	config      WebhookConfig
	client      *http.Client
	logger      *slog.Logger
	minSeverity types.Severity
	tmpl        *template.Template
}

// defaultWebhookTemplate is the default JSON template for webhook payloads.
const defaultWebhookTemplate = `{
  "alert": {
    "id": "{{.ID}}",
    "rule_id": "{{.RuleID}}",
    "rule_name": "{{.RuleName}}",
    "severity": "{{.Severity}}",
    "message": {{.Message | json}},
    "timestamp": "{{.Timestamp}}",
    "pid": {{.PID}},
    "comm": "{{.Comm}}",
    "fingerprint": "{{.Fingerprint}}"
  },
  "source": "ebpf-guard",
  "version": "1.0"
}`

// WebhookTemplateData holds data for the webhook template.
type WebhookTemplateData struct {
	ID          string
	RuleID      string
	RuleName    string
	Severity    string
	Message     string
	Timestamp   string
	PID         uint32
	Comm        string
	Fingerprint string
	Pod         string
	Namespace   string
	ContainerID string
	Details     map[string]interface{}
}

// NewGenericWebhookNotifier creates a new generic webhook notifier.
func NewGenericWebhookNotifier(cfg WebhookConfig, logger *slog.Logger) *GenericWebhookNotifier {
	if !cfg.Enabled || cfg.URL == "" {
		return &GenericWebhookNotifier{config: cfg, logger: logger}
	}

	minSev := types.SeverityWarning
	if cfg.MinSeverity == "critical" {
		minSev = types.SeverityCritical
	}

	// Parse custom template or use default
	tmplStr := defaultWebhookTemplate
	if cfg.Template != "" {
		tmplStr = cfg.Template
	}

	// Add json function for proper JSON escaping
	funcMap := template.FuncMap{
		"json": jsonEncode,
	}

	tmpl, err := template.New("webhook").Funcs(funcMap).Parse(tmplStr)
	if err != nil {
		logger.Warn("exporter/webhook: failed to parse custom template, using default",
			slog.Any("error", err))
		tmpl, err = template.New("webhook").Funcs(funcMap).Parse(defaultWebhookTemplate)
		if err != nil {
			logger.Error("exporter/webhook: failed to parse default template", slog.Any("error", err))
			return &GenericWebhookNotifier{config: cfg, logger: logger}
		}
	}

	return &GenericWebhookNotifier{
		config:      cfg,
		client:      &http.Client{Timeout: 10 * time.Second},
		logger:      logger,
		minSeverity: minSev,
		tmpl:        tmpl,
	}
}

// Name returns the notifier identifier.
func (w *GenericWebhookNotifier) Name() string {
	return "webhook"
}

// Enabled returns true if the notifier is configured and ready.
func (w *GenericWebhookNotifier) Enabled() bool {
	return w.config.Enabled && w.config.URL != "" && w.client != nil
}

// Send sends an alert to the webhook endpoint.
func (w *GenericWebhookNotifier) Send(ctx context.Context, alert types.Alert) error {
	if !w.Enabled() {
		return fmt.Errorf("webhook notifier not enabled")
	}

	// Filter by severity
	if alert.Severity != types.SeverityCritical && w.minSeverity == types.SeverityCritical {
		return nil // Skip non-critical alerts when min_severity is critical
	}

	payload, err := w.buildPayload(alert)
	if err != nil {
		return fmt.Errorf("build webhook payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.config.URL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create webhook request: %w", err)
	}

	// Set default content type
	req.Header.Set("Content-Type", "application/json")

	// Add custom headers
	for key, value := range w.config.Headers {
		req.Header.Set(key, value)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("send webhook request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}

func (w *GenericWebhookNotifier) buildPayload(alert types.Alert) ([]byte, error) {
	data := WebhookTemplateData{
		ID:          alert.ID,
		RuleID:      alert.RuleID,
		RuleName:    alert.RuleName,
		Severity:    string(alert.Severity),
		Message:     alert.Message,
		Timestamp:   alert.Timestamp.Format(time.RFC3339),
		PID:         alert.PID,
		Comm:        alert.Comm,
		Fingerprint: alert.Fingerprint,
		Details:     alert.Details,
	}

	if alert.Enrichment.PodName != "" {
		data.Pod = alert.Enrichment.PodName
		data.Namespace = alert.Enrichment.Namespace
		data.ContainerID = alert.Enrichment.ContainerID
	}

	var buf bytes.Buffer
	if err := w.tmpl.Execute(&buf, data); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// jsonEncode is a template function that JSON-encodes a value.
func jsonEncode(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return `"marshal_error"`
	}
	return string(b)
}

// ValidateWebhookTemplate validates a custom webhook template.
func ValidateWebhookTemplate(tmplStr string) error {
	funcMap := template.FuncMap{
		"json": jsonEncode,
	}

	tmpl, err := template.New("validate").Funcs(funcMap).Parse(tmplStr)
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}

	// Test with sample data
	sampleData := WebhookTemplateData{
		ID:          "test-id",
		RuleID:      "rule_001",
		RuleName:    "Test Rule",
		Severity:    "critical",
		Message:     "Test alert message with \"quotes\" and \n newlines",
		Timestamp:   time.Now().Format(time.RFC3339),
		PID:         1234,
		Comm:        "nginx",
		Fingerprint: "sha256:abc123",
		Pod:         "test-pod",
		Namespace:   "default",
		ContainerID: "container123",
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, sampleData); err != nil {
		return fmt.Errorf("execute template: %w", err)
	}

	// Validate output is valid JSON
	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		// Not JSON - that's okay if user wants to send something else
		// But warn if it looks like they intended JSON
		trimmed := strings.TrimSpace(buf.String())
		if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
			return fmt.Errorf("template produces invalid JSON: %w", err)
		}
	}

	return nil
}
