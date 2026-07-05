package correlator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

const aiAgentRulesPath = "../../rules/ai-agent/ai-agent.yaml"

func lsmAuditEvent(decision, hook, path string, pid, uid uint32) types.Event {
	e := types.Event{
		Type: types.EventLSMAudit,
		PID:  pid,
		UID:  uid,
		LSMAudit: &types.LSMAuditEvent{
			Hook:     hook,
			Decision: decision,
			Path:     path,
			Enforced: decision == "sandbox_deny",
		},
	}
	copy(e.Comm[:], "claude")
	return e
}

func alertIDs(alerts []types.Alert) map[string]types.Severity {
	m := make(map[string]types.Severity, len(alerts))
	for _, a := range alerts {
		m[a.RuleID] = a.Severity
	}
	return m
}

// TestAIAgentSandboxLSMAuditRules verifies that the ai_sandbox lsm_audit rules
// (issue #268) match forwarded sandbox decisions and produce alerts — the path
// that surfaces sandbox violations in /api/v1/alerts and Prometheus.
func TestAIAgentSandboxLSMAuditRules(t *testing.T) {
	rules, err := LoadRulesFromFile(aiAgentRulesPath)
	require.NoError(t, err, "ai-agent.yaml must load without error")
	engine := NewRuleEngine(rules)

	t.Run("sandbox_deny fires critical", func(t *testing.T) {
		alerts := engine.Evaluate(lsmAuditEvent("sandbox_deny", "file_open", "/etc/shadow", 4242, 0))
		ids := alertIDs(alerts)
		require.Contains(t, ids, "ai_agent_sandbox_deny", "sandbox_deny must fire ai_agent_sandbox_deny")
		assert.Equal(t, types.SeverityCritical, ids["ai_agent_sandbox_deny"])
		assert.NotContains(t, ids, "ai_agent_sandbox_audit", "a deny must not also fire the audit-only rule")

		for _, a := range alerts {
			if a.RuleID == "ai_agent_sandbox_deny" {
				require.NotNil(t, a.Details, "Details must be populated so the TUI/API can surface hook+path (issue #273)")
				assert.Equal(t, "file_open", a.Details["hook"])
				assert.Equal(t, "sandbox_deny", a.Details["decision"])
				assert.Equal(t, "/etc/shadow", a.Details["path"])
				assert.Equal(t, true, a.Details["enforced"])
			}
		}
	})

	t.Run("sandbox_audit fires warning", func(t *testing.T) {
		alerts := engine.Evaluate(lsmAuditEvent("sandbox_audit", "socket_connect", "169.254.169.254:80", 4242, 0))
		ids := alertIDs(alerts)
		require.Contains(t, ids, "ai_agent_sandbox_audit", "sandbox_audit must fire ai_agent_sandbox_audit")
		assert.Equal(t, types.SeverityWarning, ids["ai_agent_sandbox_audit"])
		assert.NotContains(t, ids, "ai_agent_sandbox_deny")

		for _, a := range alerts {
			if a.RuleID == "ai_agent_sandbox_audit" {
				require.NotNil(t, a.Details)
				assert.Equal(t, "socket_connect", a.Details["hook"])
				assert.Equal(t, "sandbox_audit", a.Details["decision"])
				assert.Equal(t, "169.254.169.254:80", a.Details["path"])
				assert.Equal(t, false, a.Details["enforced"])
			}
		}
	})
}
