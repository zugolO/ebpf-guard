//go:build tui

package tui

import (
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// TestFeedTracksSandboxDecisions verifies that PushAlert recognizes
// ai_agent_sandbox_audit/ai_agent_sandbox_deny alerts, tallies them into
// DashboardStats, and records them for the live "Sandbox" panel feed
// (issue #273).
func TestFeedTracksSandboxDecisions(t *testing.T) {
	f := NewFeed()

	f.PushAlert(types.Alert{
		RuleID:    "ai_agent_sandbox_deny",
		Severity:  types.SeverityCritical,
		Timestamp: time.Now(),
		PID:       4242,
		Comm:      "claude",
		Details: map[string]interface{}{
			"hook":       "file_open",
			"decision":   "sandbox_deny",
			"path":       "/etc/shadow",
			"enforced":   true,
			"profile_id": uint32(1),
		},
	})
	f.PushAlert(types.Alert{
		RuleID:    "ai_agent_sandbox_audit",
		Severity:  types.SeverityWarning,
		Timestamp: time.Now(),
		PID:       4242,
		Comm:      "claude",
		Details: map[string]interface{}{
			"hook":       "socket_connect",
			"decision":   "sandbox_audit",
			"path":       "169.254.169.254:80",
			"enforced":   false,
			"profile_id": uint32(1),
		},
	})
	// A non-sandbox alert must not be counted.
	f.PushAlert(types.Alert{RuleID: "some_other_rule", Severity: types.SeverityWarning})

	_, _, stats := f.Snapshot(10, 10)
	if stats.SandboxDenials != 1 {
		t.Fatalf("expected 1 sandbox denial, got %d", stats.SandboxDenials)
	}
	if stats.SandboxAudits != 1 {
		t.Fatalf("expected 1 sandbox audit, got %d", stats.SandboxAudits)
	}
	if stats.SandboxByHook["file_open"] != 1 || stats.SandboxByHook["socket_connect"] != 1 {
		t.Fatalf("unexpected SandboxByHook: %+v", stats.SandboxByHook)
	}
	if stats.TotalAlerts != 3 {
		t.Fatalf("expected 3 total alerts, got %d", stats.TotalAlerts)
	}

	decisions := f.SandboxDecisions(10)
	if len(decisions) != 2 {
		t.Fatalf("expected 2 sandbox decisions, got %d", len(decisions))
	}
	if decisions[0].Decision != "sandbox_deny" || decisions[0].Path != "/etc/shadow" {
		t.Fatalf("unexpected first decision: %+v", decisions[0])
	}
	if decisions[1].Decision != "sandbox_audit" || decisions[1].Hook != "socket_connect" {
		t.Fatalf("unexpected second decision: %+v", decisions[1])
	}
}
