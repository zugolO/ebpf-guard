package correlator

import (
	"context"
	"testing"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mkComm16(s string) [16]byte {
	var b [16]byte
	copy(b[:], s)
	return b
}

func TestEngineIngest_MatchingRules(t *testing.T) {
	rules := []Rule{
		{
			ID: "r-net", Name: "Bad port", EventType: types.EventTCPConnect,
			Severity: types.SeverityCritical, Action: "alert",
			Condition: RuleCondition{Field: "dport", Op: "eq", Values: []string{"4444"}},
		},
		{
			ID: "r-dns", Name: "Bad domain", EventType: types.EventDNS,
			Severity: types.SeverityWarning, Action: "alert",
			Condition: RuleCondition{Field: "qname", Op: "eq", Values: []string{"evil.example.com"}},
		},
		{
			ID: "r-file", Name: "Sensitive file", EventType: types.EventFileAccess,
			Severity: types.SeverityCritical, Action: "alert",
			Condition: RuleCondition{Field: "filename", Op: "eq", Values: []string{"/etc/shadow"}},
		},
	}

	cfg := DefaultCorrelationEngineConfig()
	cfg.Rules = rules
	ce := NewCorrelationEngineWithConfig(cfg)
	ctx := context.Background()

	// Matching network event → alert.
	netAlerts := ce.Ingest(ctx, types.Event{
		Type: types.EventTCPConnect, PID: 10, Comm: mkComm16("nc"),
		Network: &types.NetworkEvent{Dport: 4444, Family: types.AFInet},
	})
	require.NotEmpty(t, netAlerts)
	assert.Equal(t, "r-net", netAlerts[0].RuleID)
	assert.NotEmpty(t, netAlerts[0].ID)

	// Matching DNS event → alert.
	dnsAlerts := ce.Ingest(ctx, types.Event{
		Type: types.EventDNS, PID: 11, Comm: mkComm16("curl"),
		DNS: &types.DNSEvent{QName: "evil.example.com", QType: 1},
	})
	require.NotEmpty(t, dnsAlerts)
	assert.Equal(t, "r-dns", dnsAlerts[0].RuleID)

	// Matching file event → alert.
	fileAlerts := ce.Ingest(ctx, types.Event{
		Type: types.EventFileAccess, PID: 12, Comm: mkComm16("cat"),
		File: &types.FileEvent{Filename: func() [256]byte { var b [256]byte; copy(b[:], "/etc/shadow"); return b }()},
	})
	require.NotEmpty(t, fileAlerts)
	assert.Equal(t, "r-file", fileAlerts[0].RuleID)

	// Non-matching event → no alert.
	none := ce.Ingest(ctx, types.Event{
		Type: types.EventTCPConnect, PID: 13, Comm: mkComm16("nc"),
		Network: &types.NetworkEvent{Dport: 80, Family: types.AFInet},
	})
	assert.Empty(t, none)

	// Engine counters advanced.
	stats := ce.GetStats()
	assert.GreaterOrEqual(t, stats.ProcessedEvents, uint64(4))
	assert.GreaterOrEqual(t, stats.AlertsGenerated, uint64(3))
}

func TestEngineIngest_Dedup(t *testing.T) {
	cfg := DefaultCorrelationEngineConfig()
	cfg.Rules = []Rule{{
		ID: "r-dup", Name: "Dup", EventType: types.EventTCPConnect,
		Severity: types.SeverityWarning, Action: "alert",
		Condition: RuleCondition{Field: "dport", Op: "eq", Values: []string{"4444"}},
	}}
	ce := NewCorrelationEngineWithConfig(cfg)
	ctx := context.Background()

	ev := types.Event{Type: types.EventTCPConnect, PID: 99, Comm: mkComm16("nc"),
		Network: &types.NetworkEvent{Dport: 4444, Family: types.AFInet}}

	first := ce.Ingest(ctx, ev)
	require.NotEmpty(t, first)
	// Immediate duplicate within the dedup window should be suppressed.
	second := ce.Ingest(ctx, ev)
	assert.Empty(t, second)
}
