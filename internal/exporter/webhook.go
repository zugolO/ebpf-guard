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

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// validateHeaders checks that all header names are valid RFC 7230 tokens and
// header values contain no CR or LF characters (header injection prevention).
func validateHeaders(headers map[string]string) error {
	for name, value := range headers {
		if !isValidHeaderName(name) {
			return fmt.Errorf("exporter/webhook: invalid header name %q (must be RFC 7230 token)", name)
		}
		if strings.ContainsAny(value, "\r\n") {
			return fmt.Errorf("exporter/webhook: header %q value contains CR or LF (header injection)", name)
		}
	}
	return nil
}

// isValidHeaderName checks the name against RFC 7230 token definition:
// token = 1*tchar  tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" /
//         "-" / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
func isValidHeaderName(name string) bool {
	if name == "" {
		return false
	}
	const tchar = "!#$%&'*+-.^_`|~"
	for _, c := range name {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			continue
		}
		if strings.ContainsRune(tchar, c) {
			continue
		}
		return false
	}
	return true
}

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
	falcoOutput bool // emit Falco-compatible JSON when true
}

// defaultWebhookTemplate is the default JSON template for webhook payloads.
const defaultWebhookTemplate = `{
  "alert": {
    "id": {{.ID | json}},
    "rule_id": {{.RuleID | json}},
    "rule_name": {{.RuleName | json}},
    "severity": {{.Severity | json}},
    "message": {{.Message | json}},
    "timestamp": {{.Timestamp | json}},
    "pid": {{.PID}},
    "comm": {{.Comm | json}},
    "fingerprint": {{.Fingerprint | json}}
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
// Use NewGenericWebhookNotifierWithCompat to enable Falco-compatible output.
func NewGenericWebhookNotifier(cfg WebhookConfig, logger *slog.Logger, strictSSRF bool) *GenericWebhookNotifier {
	return NewGenericWebhookNotifierWithCompat(cfg, logger, false, strictSSRF)
}

// NewGenericWebhookNotifierWithCompat creates a webhook notifier with optional Falco-compatible output.
// When falcoOutput is true the payload uses the Falco JSON schema regardless of any custom template.
// Returns an error if any custom header name or value is invalid (RFC 7230 / header-injection check).
// strictSSRF enables blocking of RFC-1918 private IP ranges in addition to the default loopback and
// link-local address blocking.
func NewGenericWebhookNotifierWithCompat(cfg WebhookConfig, logger *slog.Logger, falcoOutput bool, strictSSRF bool) *GenericWebhookNotifier {
	// Guard against a nil logger: callers may not wire one, and the
	// invalid-headers path below logs, which would otherwise nil-panic.
	if logger == nil {
		logger = slog.Default()
	}

	if !cfg.Enabled || cfg.URL == "" {
		return &GenericWebhookNotifier{config: cfg, logger: logger}
	}

	if err := ValidateWebhookURL(cfg.URL, strictSSRF); err != nil {
		logger.Warn("exporter/webhook: unsafe webhook URL",
			slog.String("url", cfg.URL),
			slog.Any("error", err))
	}

	if err := validateHeaders(cfg.Headers); err != nil {
		logger.Error("exporter/webhook: invalid headers — notifier disabled", "error", err)
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
		tmpl, _ = template.New("webhook").Funcs(funcMap).Parse(defaultWebhookTemplate)
	}

	return &GenericWebhookNotifier{
		config:      cfg,
		client:      &http.Client{Timeout: 10 * time.Second},
		logger:      logger,
		minSeverity: minSev,
		tmpl:        tmpl,
		falcoOutput: falcoOutput,
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
	if w.falcoOutput {
		return MarshalFalcoAlert(alert)
	}
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
	b, _ := json.Marshal(v)
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
