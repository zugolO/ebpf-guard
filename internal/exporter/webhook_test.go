package exporter

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// TestWebhookBuildPayloadNoEnrichment verifies that buildPayload does not panic
// and produces valid output when alert.Enrichment holds zero values (non-Kubernetes deployments).
func TestWebhookBuildPayloadNoEnrichment(t *testing.T) {
	cfg := WebhookConfig{
		Enabled: true,
		URL:     "http://example.com/hook",
	}
	notifier := NewGenericWebhookNotifier(cfg, nil)

	alert := types.Alert{
		ID:        "test-id",
		RuleID:    "rule_001",
		RuleName:  "Test Rule",
		Severity:  types.SeverityWarning,
		Message:   "test alert",
		Timestamp: time.Now(),
		PID:       1234,
		Comm:      "nginx",
		// Enrichment intentionally zero — simulates non-Kubernetes environment
	}

	payload, err := notifier.buildPayload(alert)
	require.NoError(t, err)
	assert.NotEmpty(t, payload)

	// Pod and Namespace must be absent (empty enrichment)
	body := string(payload)
	assert.NotContains(t, body, "k8s.pod.name")
}

// TestWebhookBuildPayloadWithEnrichmentFalco verifies K8s metadata is included when Falco
// output is enabled, since the default template does not expose pod/namespace fields.
func TestWebhookBuildPayloadWithEnrichmentFalco(t *testing.T) {
	cfg := WebhookConfig{
		Enabled: true,
		URL:     "http://example.com/hook",
	}
	notifier := NewGenericWebhookNotifierWithCompat(cfg, nil, true)

	alert := types.Alert{
		ID:        "test-id",
		RuleID:    "rule_001",
		RuleName:  "Test Rule",
		Severity:  types.SeverityWarning,
		Message:   "test alert",
		Timestamp: time.Now(),
		PID:       1234,
		Comm:      "nginx",
		Enrichment: types.EnrichmentInfo{
			PodName:   "my-pod",
			Namespace: "default",
		},
	}

	payload, err := notifier.buildPayload(alert)
	require.NoError(t, err)
	assert.NotEmpty(t, payload)
	assert.Contains(t, string(payload), "my-pod")
}

// TestFalcoOutputNoEnrichment verifies ToFalcoAlert does not panic with empty enrichment.
func TestFalcoOutputNoEnrichment(t *testing.T) {
	alert := types.Alert{
		ID:        "test-id",
		RuleID:    "rule_001",
		RuleName:  "Test Rule",
		Severity:  types.SeverityCritical,
		Message:   "test",
		Timestamp: time.Now(),
		PID:       42,
		Comm:      "bash",
		// Enrichment zero-value
	}

	assert.NotPanics(t, func() {
		fa := ToFalcoAlert(alert)
		assert.Equal(t, "Test Rule", fa.Rule)
		assert.Equal(t, "Critical", fa.Priority)
		_, hasPod := fa.OutputFields["k8s.pod.name"]
		assert.False(t, hasPod, "k8s.pod.name should be absent without enrichment")
	})
}

func TestValidateHeaders(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		wantErr bool
	}{
		{"valid headers", map[string]string{"X-Custom": "value", "Authorization": "Bearer tok"}, false},
		{"empty headers", map[string]string{}, false},
		{"header with CR injection", map[string]string{"X-Evil": "val\r\nX-Injected: bad"}, true},
		{"header with LF injection", map[string]string{"X-Evil": "val\nX-Injected: bad"}, true},
		{"invalid header name space", map[string]string{"X Custom": "value"}, true},
		{"invalid header name colon", map[string]string{"X:Custom": "value"}, true},
		{"empty header name", map[string]string{"": "value"}, true},
		{"valid tchar name", map[string]string{"X-My_Header.Name": "ok"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateHeaders(tt.headers)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNewGenericWebhookNotifier_InvalidHeaders_Disabled(t *testing.T) {
	cfg := WebhookConfig{
		Enabled: true,
		URL:     "http://example.com/hook",
		Headers: map[string]string{
			"X-Inject": "bad\r\nvalue",
		},
	}
	notifier := NewGenericWebhookNotifier(cfg, nil)
	// Notifier must be disabled when headers are invalid.
	assert.False(t, notifier.Enabled())
}

// TestFalcoOutputWithEnrichment verifies K8s fields appear when enrichment is set.
func TestFalcoOutputWithEnrichment(t *testing.T) {
	alert := types.Alert{
		ID:        "test-id",
		RuleID:    "rule_001",
		RuleName:  "Test Rule",
		Severity:  types.SeverityWarning,
		Message:   "test",
		Timestamp: time.Now(),
		PID:       42,
		Comm:      "nginx",
		Enrichment: types.EnrichmentInfo{
			PodName:   "web-pod",
			Namespace: "production",
		},
	}

	fa := ToFalcoAlert(alert)
	assert.Equal(t, "web-pod", fa.OutputFields["k8s.pod.name"])
	assert.Equal(t, "production", fa.OutputFields["k8s.ns.name"])
}
