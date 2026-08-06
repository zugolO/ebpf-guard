package exporter

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

func TestNewFanoutNotifier(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	tests := []struct {
		name     string
		config   FanoutConfig
		expected int
	}{
		{
			name:     "no notifiers enabled",
			config:   FanoutConfig{},
			expected: 0,
		},
		{
			name: "slack enabled only",
			config: FanoutConfig{
				Slack: SlackConfig{Enabled: true, WebhookURL: "https://hooks.slack.com/test"},
			},
			expected: 1,
		},
		{
			name: "teams enabled only",
			config: FanoutConfig{
				Teams: TeamsConfig{Enabled: true, WebhookURL: "https://outlook.office.com/webhook/test"},
			},
			expected: 1,
		},
		{
			name: "webhook enabled only",
			config: FanoutConfig{
				Webhook: WebhookConfig{Enabled: true, URL: "https://example.com/webhook"},
			},
			expected: 1,
		},
		{
			name: "all enabled",
			config: FanoutConfig{
				Slack:   SlackConfig{Enabled: true, WebhookURL: "https://hooks.slack.com/test"},
				Teams:   TeamsConfig{Enabled: true, WebhookURL: "https://outlook.office.com/webhook/test"},
				Webhook: WebhookConfig{Enabled: true, URL: "https://example.com/webhook"},
			},
			expected: 3,
		},
		{
			name: "slack enabled but no URL",
			config: FanoutConfig{
				Slack: SlackConfig{Enabled: true, WebhookURL: ""},
			},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			notifier, err := NewFanoutNotifier(tt.config, 5*time.Second, logger)
			require.NoError(t, err)
			assert.Len(t, notifier.NotifierNames(), tt.expected)
		})
	}
}

func TestFanoutNotifierSend(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create test servers
	var slackReceived, teamsReceived, webhookReceived atomic.Bool

	slackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload SlackBlockKitPayload
		if err := json.Unmarshal(body, &payload); err == nil && len(payload.Blocks) > 0 {
			slackReceived.Store(true)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer slackServer.Close()

	teamsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload TeamsAdaptiveCard
		if err := json.Unmarshal(body, &payload); err == nil && len(payload.Attachments) > 0 {
			teamsReceived.Store(true)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer teamsServer.Close()

	webhookServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err == nil {
			webhookReceived.Store(true)
		}
		_ = body
		w.WriteHeader(http.StatusOK)
	}))
	defer webhookServer.Close()

	config := FanoutConfig{
		Slack:   SlackConfig{Enabled: true, WebhookURL: slackServer.URL, MinSeverity: "warning"},
		Teams:   TeamsConfig{Enabled: true, WebhookURL: teamsServer.URL, MinSeverity: "warning"},
		Webhook: WebhookConfig{Enabled: true, URL: webhookServer.URL, MinSeverity: "warning"},
	}

	notifier, err := NewFanoutNotifier(config, 5*time.Second, logger)
	require.NoError(t, err)

	alert := types.Alert{
		ID:        "test-001",
		RuleID:    "rule_001",
		RuleName:  "Test Rule",
		Severity:  types.SeverityCritical,
		Message:   "Test alert message",
		PID:       1234,
		Comm:      "test",
		Timestamp: time.Now(),
	}

	ctx := context.Background()
	notifier.Send(ctx, alert)

	// Wait for goroutines to complete
	time.Sleep(100 * time.Millisecond)

	assert.True(t, slackReceived.Load(), "Slack should have received the alert")
	assert.True(t, teamsReceived.Load(), "Teams should have received the alert")
	assert.True(t, webhookReceived.Load(), "Webhook should have received the alert")
}

func TestSlackNotifierSeverityFilter(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	var received atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := SlackConfig{
		Enabled:     true,
		WebhookURL:  server.URL,
		MinSeverity: "critical",
	}
	notifier := NewSlackNotifier(config, logger, false)

	ctx := context.Background()

	// Warning alert should be filtered
	warningAlert := types.Alert{
		ID:        "test-001",
		RuleID:    "rule_001",
		RuleName:  "Test Rule",
		Severity:  types.SeverityWarning,
		Message:   "Warning alert",
		Timestamp: time.Now(),
	}
	notifier.Send(ctx, warningAlert)

	// Critical alert should pass through
	criticalAlert := types.Alert{
		ID:        "test-002",
		RuleID:    "rule_002",
		RuleName:  "Test Rule",
		Severity:  types.SeverityCritical,
		Message:   "Critical alert",
		Timestamp: time.Now(),
	}
	notifier.Send(ctx, criticalAlert)

	time.Sleep(50 * time.Millisecond)

	assert.Equal(t, int32(1), received.Load(), "Only critical alert should be sent")
}

func TestTeamsNotifierSeverityFilter(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	var received atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := TeamsConfig{
		Enabled:     true,
		WebhookURL:  server.URL,
		MinSeverity: "critical",
	}
	notifier := NewTeamsNotifier(config, logger, false)

	ctx := context.Background()

	// Warning alert should be filtered
	warningAlert := types.Alert{
		ID:        "test-001",
		RuleID:    "rule_001",
		RuleName:  "Test Rule",
		Severity:  types.SeverityWarning,
		Message:   "Warning alert",
		Timestamp: time.Now(),
	}
	notifier.Send(ctx, warningAlert)

	// Critical alert should pass through
	criticalAlert := types.Alert{
		ID:        "test-002",
		RuleID:    "rule_002",
		RuleName:  "Test Rule",
		Severity:  types.SeverityCritical,
		Message:   "Critical alert",
		Timestamp: time.Now(),
	}
	notifier.Send(ctx, criticalAlert)

	time.Sleep(50 * time.Millisecond)

	assert.Equal(t, int32(1), received.Load(), "Only critical alert should be sent")
}

func TestWebhookNotifierCustomTemplate(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	var receivedBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	customTemplate := `{"custom_alert":"{{.RuleName}}","severity":"{{.Severity}}","pid":{{.PID}}}`
	config := WebhookConfig{
		Enabled:  true,
		URL:      server.URL,
		Template: customTemplate,
	}
	notifier := NewGenericWebhookNotifier(config, logger, false)

	alert := types.Alert{
		ID:        "test-001",
		RuleID:    "rule_001",
		RuleName:  "CustomTestRule",
		Severity:  types.SeverityCritical,
		Message:   "Test message",
		PID:       5678,
		Timestamp: time.Now(),
	}

	ctx := context.Background()
	err := notifier.Send(ctx, alert)
	require.NoError(t, err)

	assert.Contains(t, receivedBody, "CustomTestRule")
	assert.Contains(t, receivedBody, "critical")
	assert.Contains(t, receivedBody, "5678")
}

func TestWebhookNotifierDefaultTemplate(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	var receivedBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := WebhookConfig{
		Enabled: true,
		URL:     server.URL,
		// Template is empty, should use default
	}
	notifier := NewGenericWebhookNotifier(config, logger, false)

	alert := types.Alert{
		ID:          "test-001",
		RuleID:      "rule_001",
		RuleName:    "TestRule",
		Severity:    types.SeverityWarning,
		Message:     "Test message",
		PID:         1234,
		Fingerprint: "sha256:abc123",
		Timestamp:   time.Now(),
	}

	ctx := context.Background()
	err := notifier.Send(ctx, alert)
	require.NoError(t, err)

	var result map[string]interface{}
	err = json.Unmarshal([]byte(receivedBody), &result)
	require.NoError(t, err)

	alertData := result["alert"].(map[string]interface{})
	assert.Equal(t, "test-001", alertData["id"])
	assert.Equal(t, "rule_001", alertData["rule_id"])
	assert.Equal(t, "TestRule", alertData["rule_name"])
	assert.Equal(t, "warning", alertData["severity"])
	assert.Equal(t, float64(1234), alertData["pid"])
	assert.Equal(t, "sha256:abc123", alertData["fingerprint"])
}

func TestWebhookNotifierCustomHeaders(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	receivedHeaders := make(http.Header)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := WebhookConfig{
		Enabled: true,
		URL:     server.URL,
		Headers: map[string]string{
			"X-Custom-Header": "custom-value",
			"Authorization":   "Bearer test-token",
			"X-Event-Source":  "ebpf-guard",
		},
	}
	notifier := NewGenericWebhookNotifier(config, logger, false)

	alert := types.Alert{
		ID:        "test-001",
		RuleID:    "rule_001",
		RuleName:  "TestRule",
		Severity:  types.SeverityWarning,
		Message:   "Test",
		Timestamp: time.Now(),
	}

	ctx := context.Background()
	err := notifier.Send(ctx, alert)
	require.NoError(t, err)

	assert.Equal(t, "custom-value", receivedHeaders.Get("X-Custom-Header"))
	assert.Equal(t, "Bearer test-token", receivedHeaders.Get("Authorization"))
	assert.Equal(t, "ebpf-guard", receivedHeaders.Get("X-Event-Source"))
}

func TestNotifierServerError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	config := SlackConfig{
		Enabled:    true,
		WebhookURL: server.URL,
	}
	notifier := NewSlackNotifier(config, logger, false)

	alert := types.Alert{
		ID:        "test-001",
		RuleID:    "rule_001",
		RuleName:  "TestRule",
		Severity:  types.SeverityCritical,
		Message:   "Test",
		Timestamp: time.Now(),
	}

	ctx := context.Background()
	err := notifier.Send(ctx, alert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestNotifierTimeout(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Server that never responds
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := SlackConfig{
		Enabled:    true,
		WebhookURL: server.URL,
	}
	notifier := NewSlackNotifier(config, logger, false)

	alert := types.Alert{
		ID:        "test-001",
		RuleID:    "rule_001",
		RuleName:  "TestRule",
		Severity:  types.SeverityCritical,
		Message:   "Test",
		Timestamp: time.Now(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := notifier.Send(ctx, alert)
	assert.Error(t, err)
}

func TestValidateWebhookTemplate(t *testing.T) {
	tests := []struct {
		name    string
		tmpl    string
		wantErr bool
	}{
		{
			name:    "valid template",
			tmpl:    `{"alert": "{{.RuleName}}"}`,
			wantErr: false,
		},
		{
			name:    "invalid template syntax",
			tmpl:    `{"alert": "{{.RuleName"}`,
			wantErr: true,
		},
		{
			name:    "template with json function",
			tmpl:    `{"msg": {{.Message | json}}}`,
			wantErr: false,
		},
		{
			name:    "invalid JSON output",
			tmpl:    `{"broken": {{.RuleName}}}`, // unquoted string value
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateWebhookTemplate(tt.tmpl)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestFanoutNotifierClose(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	config := FanoutConfig{
		Slack: SlackConfig{Enabled: true, WebhookURL: "https://hooks.slack.com/test"},
	}
	notifier, err := NewFanoutNotifier(config, 5*time.Second, logger)
	require.NoError(t, err)

	err = notifier.Close()
	assert.NoError(t, err)
}

func TestFanoutNotifierSendNoBackends(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	notifier, err := NewFanoutNotifier(FanoutConfig{}, 5*time.Second, logger)
	require.NoError(t, err)

	alert := types.Alert{
		ID:        "test-001",
		RuleID:    "rule_001",
		RuleName:  "TestRule",
		Severity:  types.SeverityCritical,
		Message:   "Test",
		Timestamp: time.Now(),
	}

	ctx := context.Background()
	// Should not panic or error when no backends are configured
	notifier.Send(ctx, alert)
}

func TestFanoutNotifierConcurrentSend(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	var received atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := FanoutConfig{
		Slack: SlackConfig{Enabled: true, WebhookURL: server.URL},
	}
	notifier, err := NewFanoutNotifier(config, 5*time.Second, logger)
	require.NoError(t, err)

	alert := types.Alert{
		ID:        "test-001",
		RuleID:    "rule_001",
		RuleName:  "TestRule",
		Severity:  types.SeverityCritical,
		Message:   "Test",
		Timestamp: time.Now(),
	}

	ctx := context.Background()

	// Send alerts concurrently
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			notifier.Send(ctx, alert)
		}()
	}
	wg.Wait()

	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, int32(10), received.Load())
}

// TestNotifierSeverityFilter_InfoBlockedAtDefaultMinSeverity pins the wave 5.1
// severity threshold across every notifier that carries one.
//
// Wave 5.1 downgraded the seven-rule idle-noise cluster to "info" on the premise
// that info-level daemon traffic is routine background. That premise only holds
// if info actually stops somewhere: the filters were written as
// `alert.Severity != critical && minSeverity == critical`, which is a two-value
// test — with the default min_severity of "warning" it let info straight through
// to Slack, Teams, Discord, Telegram and webhook. The cluster produced ~4600
// alerts/hour on an idle host, so the practical effect was paging on exactly the
// volume the wave existed to remove.
//
// Asserted per notifier rather than once, because each one owns its own copy of
// the comparison — that duplication is how the original defect reached eight
// call sites at once.
func TestNotifierSeverityFilter_InfoBlockedAtDefaultMinSeverity(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := context.Background()

	alertOf := func(sev types.Severity) types.Alert {
		return types.Alert{
			ID:        "test-" + string(sev),
			RuleID:    "sigma_passwd_shadow_read_daemon",
			RuleName:  "Credential files read by login/cron daemon",
			Severity:  sev,
			Message:   "daemon touched a sensitive path",
			Timestamp: time.Now(),
		}
	}

	// Each notifier under test, constructed against the same counting server.
	backends := []struct {
		name string
		make func(url string) Notifier
	}{
		{"slack", func(u string) Notifier {
			return NewSlackNotifier(SlackConfig{Enabled: true, WebhookURL: u, MinSeverity: "warning"}, logger, false)
		}},
		{"teams", func(u string) Notifier {
			return NewTeamsNotifier(TeamsConfig{Enabled: true, WebhookURL: u, MinSeverity: "warning"}, logger, false)
		}},
		{"discord", func(u string) Notifier {
			return NewDiscordNotifier(DiscordConfig{Enabled: true, WebhookURL: u, MinSeverity: "warning"}, logger, false)
		}},
		{"webhook", func(u string) Notifier {
			return NewGenericWebhookNotifier(WebhookConfig{Enabled: true, URL: u, MinSeverity: "warning"}, logger, false)
		}},
	}

	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			var received atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				received.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			n := b.make(server.URL)
			require.True(t, n.Enabled(), "notifier should be enabled")

			// info is below the "warning" threshold — must not be delivered.
			_ = n.Send(ctx, alertOf(types.SeverityInfo))
			time.Sleep(50 * time.Millisecond)
			assert.Equal(t, int32(0), received.Load(),
				"info alert must not reach %s at min_severity=warning", b.name)

			// The other side of the same threshold: warning and critical still
			// deliver. Without this the filter could pass by rejecting everything.
			_ = n.Send(ctx, alertOf(types.SeverityWarning))
			_ = n.Send(ctx, alertOf(types.SeverityCritical))
			time.Sleep(50 * time.Millisecond)
			assert.Equal(t, int32(2), received.Load(),
				"warning and critical must still reach %s", b.name)
		})
	}
}

// TestSeverityRank_Ordering pins the ordering the notifier thresholds depend on.
func TestSeverityRank_Ordering(t *testing.T) {
	assert.Less(t, types.SeverityRank(types.SeverityInfo), types.SeverityRank(types.SeverityWarning))
	assert.Less(t, types.SeverityRank(types.SeverityWarning), types.SeverityRank(types.SeverityCritical))

	// An unknown severity must rank with info, never above it — a rule carrying
	// a typo'd severity should not become the most urgent thing in the pipeline.
	assert.Equal(t, types.SeverityRank(types.SeverityInfo), types.SeverityRank(types.Severity("bogus")))

	assert.True(t, types.SeverityAtLeast(types.SeverityCritical, types.SeverityWarning))
	assert.True(t, types.SeverityAtLeast(types.SeverityWarning, types.SeverityWarning))
	assert.False(t, types.SeverityAtLeast(types.SeverityInfo, types.SeverityWarning))
	assert.True(t, types.SeverityAtLeast(types.SeverityInfo, types.SeverityInfo))
}

// TestMain runs all tests
func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
