//go:build rego

package correlator

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 6.3.L, №418: с включённым слоем Rego `ingestWithAD` возвращает
// regoQueued=true СРАЗУ после постановки задачи в очередь и пропускает
// собственный цикл `incidentTracker.Add`. Пока проводки Rego не было
// (до волны 6.3-up), каждый алерт шёл сквозным путём и дыра была не видна;
// с живым Rego инцидентный слой перестал получать что-либо вовсе —
// архивы collect-6.3-up2 и collect-6.3-rid не несут серии
// ebpf_guard_incidents_total ни одной строкой, тогда как collect-6.3-run7
// (та же нода, Rego ещё не проводён) даёт suspicious=28/attack=3.
//
// Инвариант: алерт, прошедший ЧЕРЕЗ Rego, обязан дойти до инцидентного слоя.
func TestWave6_3L_RegoPathStillFeedsIncidentTracker(t *testing.T) {
	regoEng := newRegoEngineWithRule(t, `
package ebpf_guard
default allow := true
decisions[{"rule_id": "dga_domain", "severity": "critical", "message": "renamed", "action": "alert", "matched": true}] {
	count(input.event.dns.qname) > 50
}
`)

	cfg := DefaultCorrelationEngineConfig()
	cfg.Rules = []Rule{{
		ID:        "long_dns_query",
		EventType: types.EventDNS,
		Condition: RuleCondition{Field: "qname_length", Op: OpGreaterThan, Values: []string{"50"}},
		Severity:  types.SeverityWarning,
		Action:    ActionAlert,
	}}
	cfg.EnableRateLimit = false
	cfg.EnableAnomaly = false
	cfg.EnableRegoEval = true
	cfg.RegoEngine = regoEng
	cfg.RegoWorkerCount = 2

	ce := NewCorrelationEngineWithConfig(cfg)
	defer ce.Close()

	ev := types.Event{
		Type: types.EventDNS,
		PID:  4242,
		DNS:  &types.DNSEvent{QName: "a-very-long-subdomain-label-used-to-tunnel-data.example.com"},
	}
	require.Len(t, ce.Ingest(context.Background(), ev), 1)

	flushed := flushEventually(t, ce)
	require.Len(t, flushed, 1)
	require.Equal(t, "dga_domain", flushed[0].RuleID, "предусловие: Rego переименовал алерт")

	incidents := ce.IncidentTracker().GetAll("", "", 0)
	require.Len(t, incidents, 1, "алерт, ушедший в очередь Rego, обязан дойти до инцидентного слоя")
	assert.Equal(t, 1, incidents[0].AlertCount)
}
