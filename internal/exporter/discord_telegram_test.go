package exporter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiscordNotifierSend(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	var receivedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := DiscordConfig{
		Enabled:     true,
		WebhookURL:  server.URL,
		MinSeverity: "warning",
	}
	notifier := NewDiscordNotifier(config, logger, false)

	alert := types.Alert{
		ID:       "test-001",
		RuleID:   "rule_001",
		RuleName: "Test Discord Rule",
		Severity: types.SeverityCritical,
		Message:  "Test discord alert",
		PID:      1234,
		Comm:     "testproc",
		Timestamp: time.Now(),
		ProcessTree: types.ProcessTree{
			{PID: 1, PPID: 0, Comm: "systemd"},
			{PID: 1234, PPID: 1, Comm: "testproc"},
		},
		Fingerprint: "sha256:abc123",
	}

	ctx := context.Background()
	err := notifier.Send(ctx, alert)
	require.NoError(t, err)

	var payload DiscordWebhookPayload
	err = json.Unmarshal(receivedBody, &payload)
	require.NoError(t, err)

	require.Len(t, payload.Embeds, 1)
	embed := payload.Embeds[0]
	assert.Contains(t, embed.Title, "Test Discord Rule")
	assert.Equal(t, "Test discord alert", embed.Description)
	assert.Equal(t, 16711680, embed.Color) // Red for critical

	require.Len(t, embed.Fields, 5) // Rule ID, Severity, Process, Time, Process Tree
	assert.Equal(t, "Rule ID", embed.Fields[0].Name)
	assert.Equal(t, "rule\\_001", embed.Fields[0].Value)
	assert.Equal(t, "Severity", embed.Fields[1].Name)
	assert.Equal(t, "critical", embed.Fields[1].Value)

	require.NotNil(t, embed.Footer)
	assert.Contains(t, embed.Footer.Text, "sha256:abc123")
}

func TestDiscordNotifierSeverityFilter(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	var received int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := DiscordConfig{
		Enabled:     true,
		WebhookURL:  server.URL,
		MinSeverity: "critical",
	}
	notifier := NewDiscordNotifier(config, logger, false)

	ctx := context.Background()

	warningAlert := types.Alert{
		ID:       "test-001",
		RuleID:   "rule_001",
		RuleName: "Test",
		Severity: types.SeverityWarning,
		Message:  "Warning",
		Timestamp: time.Now(),
	}
	_ = notifier.Send(ctx, warningAlert)

	criticalAlert := types.Alert{
		ID:       "test-002",
		RuleID:   "rule_002",
		RuleName: "Test",
		Severity: types.SeverityCritical,
		Message:  "Critical",
		Timestamp: time.Now(),
	}
	_ = notifier.Send(ctx, criticalAlert)

	assert.Equal(t, int32(1), received, "Only critical alert should be sent")
}

func TestDiscordNotifierDisabled(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	config := DiscordConfig{Enabled: false}
	notifier := NewDiscordNotifier(config, logger, false)
	assert.False(t, notifier.Enabled())
	assert.Equal(t, "discord", notifier.Name())

	alert := types.Alert{ID: "test"}
	err := notifier.Send(context.Background(), alert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not enabled")
}

func TestDiscordNotifierNoWebhookURL(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	config := DiscordConfig{Enabled: true, WebhookURL: ""}
	notifier := NewDiscordNotifier(config, logger, false)
	assert.False(t, notifier.Enabled())
}

func TestDiscordNotifierServerError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	config := DiscordConfig{
		Enabled:    true,
		WebhookURL: server.URL,
	}
	notifier := NewDiscordNotifier(config, logger, false)

	alert := types.Alert{
		ID:        "test-001",
		RuleID:    "rule_001",
		RuleName:  "Test",
		Severity:  types.SeverityCritical,
		Message:   "Test",
		Timestamp: time.Now(),
	}
	err := notifier.Send(context.Background(), alert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestDiscordNotifierWarningEmbedColor(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	var receivedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := DiscordConfig{
		Enabled:     true,
		WebhookURL:  server.URL,
		MinSeverity: "warning",
	}
	notifier := NewDiscordNotifier(config, logger, false)

	alert := types.Alert{
		ID:        "test-001",
		RuleID:    "rule_001",
		RuleName:  "Test",
		Severity:  types.SeverityWarning,
		Message:   "Warning alert",
		Timestamp: time.Now(),
	}

	err := notifier.Send(context.Background(), alert)
	require.NoError(t, err)

	var payload DiscordWebhookPayload
	err = json.Unmarshal(receivedBody, &payload)
	require.NoError(t, err)

	require.Len(t, payload.Embeds, 1)
	assert.Equal(t, 16753920, payload.Embeds[0].Color) // Orange for warning
}

func TestDiscordNotifierProcessTree(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	var receivedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := DiscordConfig{
		Enabled:    true,
		WebhookURL: server.URL,
	}
	notifier := NewDiscordNotifier(config, logger, false)

	alert := types.Alert{
		ID:          "test-001",
		RuleID:      "rule_001",
		RuleName:    "Test",
		Severity:    types.SeverityCritical,
		Message:     "Test",
		PID:         9999,
		Comm:        "curl",
		Timestamp:   time.Now(),
		Enrichment:  types.EnrichmentInfo{PodName: "nginx-abc", Namespace: "prod"},
		ProcessTree: types.ProcessTree{
			{PID: 1, PPID: 0, Comm: "systemd"},
			{PID: 500, PPID: 1, Comm: "containerd"},
			{PID: 5000, PPID: 500, Comm: "nginx"},
			{PID: 9999, PPID: 5000, Comm: "curl"},
		},
	}

	err := notifier.Send(context.Background(), alert)
	require.NoError(t, err)

	var payload DiscordWebhookPayload
	err = json.Unmarshal(receivedBody, &payload)
	require.NoError(t, err)

	require.Len(t, payload.Embeds, 1)
	embed := payload.Embeds[0]

	foundTree := false
	foundPod := false
	foundNS := false
	for _, field := range embed.Fields {
		if field.Name == "Process Tree" {
			foundTree = true
			assert.Contains(t, field.Value, "systemd")
			assert.Contains(t, field.Value, "containerd")
			assert.Contains(t, field.Value, "nginx")
			assert.Contains(t, field.Value, "curl")
		}
		if field.Name == "Pod" {
			foundPod = true
			assert.Equal(t, "nginx-abc", field.Value)
		}
		if field.Name == "Namespace" {
			foundNS = true
			assert.Equal(t, "prod", field.Value)
		}
	}
	assert.True(t, foundTree)
	assert.True(t, foundPod)
	assert.True(t, foundNS)
}

func TestDiscordNotifier_MarkdownEscaping(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	var receivedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := DiscordConfig{
		Enabled:    true,
		WebhookURL: server.URL,
	}
	notifier := NewDiscordNotifier(config, logger, false)

	alert := types.Alert{
		ID:       "test-001",
		RuleID:   "rule_001",
		RuleName: "[Click here](https://phishing.example)",
		Severity: types.SeverityCritical,
		Message:  "Suspicious process: *important* _warning_ ~ignore~ `cmd`",
		PID:      5678,
		Comm:     "**evil**proc",
		Timestamp: time.Now(),
		ProcessTree: types.ProcessTree{
			{PID: 1, PPID: 0, Comm: "*systemd*"},
			{PID: 5678, PPID: 1, Comm: "**evil**proc"},
		},
	}

	err := notifier.Send(context.Background(), alert)
	require.NoError(t, err)

	var payload DiscordWebhookPayload
	err = json.Unmarshal(receivedBody, &payload)
	require.NoError(t, err)

	require.Len(t, payload.Embeds, 1)
	embed := payload.Embeds[0]

	assert.Contains(t, embed.Title, `\[Click here\](https://phishing.example)`)

	assert.Contains(t, embed.Description, `\*important\*`)
	assert.Contains(t, embed.Description, `\_warning\_`)
	assert.Contains(t, embed.Description, `\~ignore\~`)
	assert.Contains(t, embed.Description, "\\\x60cmd\\\x60")

	foundProc := false
	for _, field := range embed.Fields {
		if field.Name == "Process" {
			foundProc = true
			assert.Contains(t, field.Value, `\*\*evil\*\*proc`)
		}
	}
	assert.True(t, foundProc, "Process field should be present")
}

func TestEscapeDiscordMarkdown(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"normal text", "normal text"},
		{"*bold*", `\*bold\*`},
		{"_italic_", `\_italic\_`},
		{"~strike~", `\~strike\~`},
		{"\x60code\x60", "\\\x60code\\\x60"},
		{"> quote", `\> quote`},
		{"[link](url)", `\[link\](url)`},
		{"back\\slash", `back\\slash`},
		{"mix*_~\x60>[]", "mix\\*\\_\\~\\\x60\\>\\[\\]"},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := escapeDiscordMarkdown(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTelegramNotifierSend(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	var receivedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := TelegramConfig{
		Enabled:     true,
		BotToken:    "test-bot-token",
		ChatID:      "test-chat-id",
		MinSeverity: "warning",
	}
	notifier := NewTelegramNotifier(config, logger, false)
	notifier.apiBase = server.URL

	alert := types.Alert{
		ID:       "test-001",
		RuleID:   "rule_001",
		RuleName: "Test Telegram Rule",
		Severity: types.SeverityCritical,
		Message:  "Test telegram alert message",
		PID:      5678,
		Comm:     "evilproc",
		Timestamp: time.Now(),
		Enrichment: types.EnrichmentInfo{
			PodName:   "web-pod",
			Namespace: "staging",
		},
		Fingerprint: "sha256:def456",
	}

	ctx := context.Background()
	err := notifier.Send(ctx, alert)
	require.NoError(t, err)

	var payload map[string]interface{}
	err = json.Unmarshal(receivedBody, &payload)
	require.NoError(t, err)

	assert.Equal(t, "MarkdownV2", payload["parse_mode"])
	text := payload["text"].(string)
	assert.Contains(t, text, "Test Telegram Rule")
	assert.Contains(t, text, "evilproc")
	assert.Contains(t, text, "staging")
	assert.Contains(t, text, "def456")
}

func TestTelegramNotifierSeverityFilter(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	var received int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := TelegramConfig{
		Enabled:     true,
		BotToken:    "test-token",
		ChatID:      "12345",
		MinSeverity: "critical",
	}
	notifier := NewTelegramNotifier(config, logger, false)
	notifier.apiBase = server.URL

	ctx := context.Background()

	warningAlert := types.Alert{
		ID:       "test-001",
		RuleID:   "rule_001",
		RuleName: "Test",
		Severity: types.SeverityWarning,
		Message:  "Warning",
		Timestamp: time.Now(),
	}
	_ = notifier.Send(ctx, warningAlert)

	criticalAlert := types.Alert{
		ID:       "test-002",
		RuleID:   "rule_002",
		RuleName: "Test",
		Severity: types.SeverityCritical,
		Message:  "Critical",
		Timestamp: time.Now(),
	}
	_ = notifier.Send(ctx, criticalAlert)

	assert.Equal(t, int32(1), received, "Only critical alert should be sent")
}

func TestTelegramNotifierDisabled(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	config := TelegramConfig{Enabled: false}
	notifier := NewTelegramNotifier(config, logger, false)
	assert.False(t, notifier.Enabled())
	assert.Equal(t, "telegram", notifier.Name())

	alert := types.Alert{ID: "test"}
	err := notifier.Send(context.Background(), alert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not enabled")
}

func TestTelegramNotifierMissingToken(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	config := TelegramConfig{Enabled: true, BotToken: "", ChatID: "12345"}
	notifier := NewTelegramNotifier(config, logger, false)
	assert.False(t, notifier.Enabled())
}

func TestTelegramNotifierMissingChatID(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	config := TelegramConfig{Enabled: true, BotToken: "test-token", ChatID: ""}
	notifier := NewTelegramNotifier(config, logger, false)
	assert.False(t, notifier.Enabled())
}

func TestTelegramNotifierServerError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	config := TelegramConfig{
		Enabled:     true,
		BotToken:    "test-token",
		ChatID:      "12345",
		MinSeverity: "warning",
	}
	notifier := NewTelegramNotifier(config, logger, false)
	notifier.apiBase = server.URL

	alert := types.Alert{
		ID:        "test-001",
		RuleID:    "rule_001",
		RuleName:  "Test",
		Severity:  types.SeverityCritical,
		Message:   "Test",
		Timestamp: time.Now(),
	}
	err := notifier.Send(context.Background(), alert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestTelegramMarkdownV2Escape(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"hello_world", "hello\\_world"},
		{"test*star", "test\\*star"},
		{"[link](url)", "\\[link\\]\\(url\\)"},
		{"~strike~", "\\~strike\\~"},
		{"\x60code\x60", "\\\x60code\\\x60"},
		{"a>b", "a\\>b"},
		{"#header", "\\#header"},
		{"a+b=c", "a\\+b\\=c"},
		{"normal text", "normal text"},
		{"dot.in.name", "dot\\.in\\.name"},
		{"bang!", "bang\\!"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := escapeMarkdownV2(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFanoutNotifierDiscordTelegram(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	discordServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer discordServer.Close()

	telegramServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer telegramServer.Close()

	config := FanoutConfig{
		Discord:  DiscordConfig{Enabled: true, WebhookURL: discordServer.URL},
		Telegram: TelegramConfig{Enabled: true, BotToken: "token", ChatID: "chat"},
	}
	notifier, err := NewFanoutNotifier(config, 5*time.Second, logger)
	require.NoError(t, err)
	// Override telegram API base for test
	for _, n := range notifier.notifiers {
		if tn, ok := n.(*TelegramNotifier); ok {
			tn.apiBase = telegramServer.URL
		}
	}

	assert.Len(t, notifier.NotifierNames(), 2)

	alert := types.Alert{
		ID:        "test-001",
		RuleID:    "rule_001",
		RuleName:  "Test",
		Severity:  types.SeverityCritical,
		Message:   "Test",
		Timestamp: time.Now(),
	}
	notifier.Send(context.Background(), alert)
	time.Sleep(100 * time.Millisecond)
}

func TestRedactURLError(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{
			name: "url.Error with secret in URL",
			err: &url.Error{
				Op:  "Post",
				URL: "https://api.telegram.org/bot12345:AAHsecret_token/sendMessage",
				Err: fmt.Errorf("connection refused"),
			},
		},
		{
			name: "url.Error with Discord webhook",
			err: &url.Error{
				Op:  "Post",
				URL: "https://discord.com/api/webhooks/secret/token",
				Err: fmt.Errorf("timeout"),
			},
		},
		{
			name: "url.Error redacted before wrapping",
			err: func() error {
				raw := &url.Error{
					Op:  "Post",
					URL: "https://outlook.office.com/webhook/teams-secret",
					Err: fmt.Errorf("dns error"),
				}
				return fmt.Errorf("request failed: %w", redactURLError(raw))
			}(),
		},
		{
			name: "non-url error passes through",
			err:  fmt.Errorf("context deadline exceeded"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := redactURLError(tt.err)
			assert.NotNil(t, result)

			errStr := result.Error()
			assert.NotContains(t, errStr, "bot12345")
			assert.NotContains(t, errStr, "webhooks/secret")
			assert.NotContains(t, errStr, "teams-secret")

			var urlErr *url.Error
			if errors.As(result, &urlErr) {
				assert.Equal(t, "[redacted]", urlErr.URL)
			}
		})
	}
}

func TestRedactURLError_SideEffect(t *testing.T) {
	original := &url.Error{
		Op:  "Post",
		URL: "https://api.telegram.org/botSECRET/sendMessage",
		Err: fmt.Errorf("timeout"),
	}
	_ = redactURLError(original)
	assert.Equal(t, "[redacted]", original.URL)
}
