package exporter

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestToFalcoAlert_BasicFields(t *testing.T) {
	ts := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	alert := types.Alert{
		ID:          "alert-001",
		Timestamp:   ts,
		RuleID:      "rule_001",
		RuleName:    "Sensitive File Read",
		Severity:    types.SeverityWarning,
		PID:         1234,
		Comm:        "nginx",
		Message:     "Sensitive file read detected",
		Fingerprint: "sha256:abc123",
		Event:       types.Event{Type: types.EventFileAccess},
	}

	fa := ToFalcoAlert(alert)

	assert.Equal(t, "2024-01-15T12:00:00Z", fa.Time)
	assert.Equal(t, "Sensitive File Read", fa.Rule)
	assert.Equal(t, "Warning", fa.Priority)
	assert.Equal(t, "ebpf-guard", fa.Source)
	assert.Contains(t, fa.Output, "Sensitive file read detected")
	assert.Contains(t, fa.Output, "nginx")
	assert.Equal(t, "nginx", fa.OutputFields["proc.name"])
	assert.Equal(t, "1234", fa.OutputFields["proc.pid"])
	assert.Equal(t, "open", fa.OutputFields["evt.type"])
	assert.Equal(t, "sha256:abc123", fa.OutputFields["fingerprint"])
	assert.Equal(t, "rule_001", fa.OutputFields["rule.id"])
}

func TestToFalcoAlert_CriticalPriority(t *testing.T) {
	alert := types.Alert{
		Timestamp: time.Now(),
		Severity:  types.SeverityCritical,
		Event:     types.Event{Type: types.EventSyscall},
	}
	fa := ToFalcoAlert(alert)
	assert.Equal(t, "Critical", fa.Priority)
}

func TestToFalcoAlert_WithK8sEnrichment(t *testing.T) {
	alert := types.Alert{
		Timestamp: time.Now(),
		Severity:  types.SeverityWarning,
		Event:     types.Event{Type: types.EventTCPConnect},
		Enrichment: types.EnrichmentInfo{
			PodName:     "my-pod-abc",
			Namespace:   "production",
			ContainerID: "container123",
		},
	}

	fa := ToFalcoAlert(alert)
	assert.Equal(t, "my-pod-abc", fa.OutputFields["k8s.pod.name"])
	assert.Equal(t, "production", fa.OutputFields["k8s.ns.name"])
	assert.Equal(t, "container123", fa.OutputFields["container.id"])
}

func TestToFalcoAlert_NoK8sEnrichment(t *testing.T) {
	alert := types.Alert{
		Timestamp: time.Now(),
		Severity:  types.SeverityWarning,
		Event:     types.Event{Type: types.EventSyscall},
	}
	fa := ToFalcoAlert(alert)
	_, hasPod := fa.OutputFields["k8s.pod.name"]
	assert.False(t, hasPod, "k8s.pod.name should not be set without enrichment")
}

func TestMarshalFalcoAlert_ValidJSON(t *testing.T) {
	alert := types.Alert{
		ID:        "test-001",
		Timestamp: time.Now(),
		RuleID:    "rule_002",
		RuleName:  "Shell Spawn",
		Severity:  types.SeverityCritical,
		PID:       5678,
		Comm:      "bash",
		Message:   "Shell spawned by web server",
		Event:     types.Event{Type: types.EventSyscall},
	}

	data, err := MarshalFalcoAlert(alert)
	require.NoError(t, err)

	// Must be valid JSON
	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &parsed))

	// Required Falco fields
	assert.Contains(t, parsed, "time")
	assert.Contains(t, parsed, "rule")
	assert.Contains(t, parsed, "priority")
	assert.Contains(t, parsed, "output")
	assert.Contains(t, parsed, "output_fields")
	assert.Contains(t, parsed, "source")
	assert.Equal(t, "ebpf-guard", parsed["source"])
}

func TestToFalcoAlert_EventTypeMapping(t *testing.T) {
	cases := []struct {
		eventType types.EventType
		want      string
	}{
		{types.EventSyscall, "syscall"},
		{types.EventTCPConnect, "connect"},
		{types.EventFileAccess, "open"},
		{types.EventTLS, "tls"},
		{types.EventDNS, "dns"},
	}

	for _, tc := range cases {
		alert := types.Alert{
			Timestamp: time.Now(),
			Severity:  types.SeverityWarning,
			Event:     types.Event{Type: tc.eventType},
		}
		fa := ToFalcoAlert(alert)
		assert.Equal(t, tc.want, fa.OutputFields["evt.type"], "event type %d", tc.eventType)
	}
}
