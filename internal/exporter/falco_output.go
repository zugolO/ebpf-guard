// Package exporter provides Falco-compatible alert output conversion.
package exporter

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// FalcoAlert is the Falco-compatible JSON alert format.
// Downstream integrations (SIEM, PagerDuty connectors, Slack bots) that
// were written for Falco can consume this format without modification.
type FalcoAlert struct {
	Time         string                 `json:"time"`
	Rule         string                 `json:"rule"`
	Priority     string                 `json:"priority"`
	Output       string                 `json:"output"`
	OutputFields map[string]interface{} `json:"output_fields"`
	Source       string                 `json:"source"`
	Tags         []string               `json:"tags,omitempty"`
}

// ToFalcoAlert converts an ebpf-guard Alert to the Falco JSON format.
func ToFalcoAlert(alert types.Alert) FalcoAlert {
	fa := FalcoAlert{
		Time:     alert.Timestamp.UTC().Format(time.RFC3339Nano),
		Rule:     alert.RuleName,
		Priority: toFalcoPriority(alert.Severity),
		Output:   buildFalcoOutput(alert),
		Source:   "ebpf-guard",
		OutputFields: map[string]interface{}{
			"proc.name":   alert.Comm,
			"proc.pid":    fmt.Sprintf("%d", alert.PID),
			"evt.type":    eventTypeName(alert.Event.Type),
			"fingerprint": alert.Fingerprint,
		},
	}

	if alert.Enrichment.PodName != "" {
		fa.OutputFields["k8s.pod.name"] = alert.Enrichment.PodName
		fa.OutputFields["k8s.ns.name"] = alert.Enrichment.Namespace
	}
	if alert.Enrichment.ContainerID != "" {
		fa.OutputFields["container.id"] = alert.Enrichment.ContainerID
	}
	if alert.RuleID != "" {
		fa.OutputFields["rule.id"] = alert.RuleID
	}

	return fa
}

// MarshalFalcoAlert serializes an alert to Falco-compatible JSON.
func MarshalFalcoAlert(alert types.Alert) ([]byte, error) {
	return json.Marshal(ToFalcoAlert(alert))
}

// toFalcoPriority maps ebpf-guard Severity to Falco priority string.
func toFalcoPriority(s types.Severity) string {
	switch s {
	case types.SeverityCritical:
		return "Critical"
	default:
		return "Warning"
	}
}

// buildFalcoOutput constructs the human-readable output string like Falco does.
func buildFalcoOutput(alert types.Alert) string {
	msg := alert.Message
	if msg == "" {
		msg = alert.RuleName
	}
	out := fmt.Sprintf("%s (proc=%s pid=%d", msg, alert.Comm, alert.PID)
	if alert.Enrichment.PodName != "" {
		out += fmt.Sprintf(" pod=%s ns=%s", alert.Enrichment.PodName, alert.Enrichment.Namespace)
	}
	out += ")"
	return out
}

// eventTypeName converts an EventType to the Falco evt.type string.
func eventTypeName(t types.EventType) string {
	switch t {
	case types.EventSyscall:
		return "syscall"
	case types.EventTCPConnect:
		return "connect"
	case types.EventFileAccess:
		return "open"
	case types.EventTLS:
		return "tls"
	case types.EventDNS:
		return "dns"
	default:
		return "unknown"
	}
}
