package correlator

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/internal/policy"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// fakeIOCMatcher is a minimal IOCMatcher stub for testing checkIOCMatch.
type fakeIOCMatcher struct {
	ips     map[string]bool
	domains map[string]bool
}

func (f *fakeIOCMatcher) MatchIP(ip string) bool          { return f.ips[ip] }
func (f *fakeIOCMatcher) MatchDNS(domain string) bool     { return f.domains[domain] }
func (f *fakeIOCMatcher) MatchFingerprint(fp string) bool { return false }

// ─────────────────────────────────────────────────────────────────────────────
// checkIOCMatch — via the full Ingest path (exercises the ce.iocMatcher != nil
// wiring in ingestWithAD as well as checkIOCMatch itself).
// ─────────────────────────────────────────────────────────────────────────────

func TestIngest_IOCMatch_IPHit(t *testing.T) {
	matcher := &fakeIOCMatcher{ips: map[string]bool{"1.2.3.4": true}}
	cfg := DefaultCorrelationEngineConfig()
	cfg.EnableAnomaly = false
	cfg.IOCMatcher = matcher
	ce := NewCorrelationEngineWithConfig(cfg)
	defer ce.Close()

	daddr := [16]byte{1, 2, 3, 4}
	ev := types.Event{
		Type:    types.EventTCPConnect,
		PID:     100,
		Network: &types.NetworkEvent{Daddr: daddr, Family: types.AFInet, Dport: 443},
	}
	alerts := ce.Ingest(context.Background(), ev)
	require.Len(t, alerts, 1)
	assert.Equal(t, "gossip_ioc_match", alerts[0].RuleID)
	assert.Contains(t, alerts[0].Message, "ip:1.2.3.4")
	assert.Equal(t, types.SeverityCritical, alerts[0].Severity)
}

func TestIngest_IOCMatch_DNSHit(t *testing.T) {
	matcher := &fakeIOCMatcher{domains: map[string]bool{"evil.example.com": true}}
	cfg := DefaultCorrelationEngineConfig()
	cfg.EnableAnomaly = false
	cfg.IOCMatcher = matcher
	ce := NewCorrelationEngineWithConfig(cfg)
	defer ce.Close()

	ev := types.Event{
		Type: types.EventDNS,
		PID:  100,
		DNS:  &types.DNSEvent{QName: "evil.example.com"},
	}
	alerts := ce.Ingest(context.Background(), ev)
	require.Len(t, alerts, 1)
	assert.Equal(t, "gossip_ioc_match", alerts[0].RuleID)
	assert.Contains(t, alerts[0].Message, "dns:evil.example.com")
}

func TestIngest_IOCMatch_NoMatch(t *testing.T) {
	matcher := &fakeIOCMatcher{}
	cfg := DefaultCorrelationEngineConfig()
	cfg.EnableAnomaly = false
	cfg.IOCMatcher = matcher
	ce := NewCorrelationEngineWithConfig(cfg)
	defer ce.Close()

	ev := types.Event{
		Type:    types.EventTCPConnect,
		PID:     100,
		Network: &types.NetworkEvent{Daddr: [16]byte{9, 9, 9, 9}, Family: types.AFInet},
	}
	alerts := ce.Ingest(context.Background(), ev)
	assert.Empty(t, alerts)
}

func TestIngest_IOCMatch_WithTraceContextAndEnrichment(t *testing.T) {
	matcher := &fakeIOCMatcher{ips: map[string]bool{"1.2.3.4": true}}
	cfg := DefaultCorrelationEngineConfig()
	cfg.EnableAnomaly = false
	cfg.IOCMatcher = matcher
	ce := NewCorrelationEngineWithConfig(cfg)
	defer ce.Close()

	ev := types.Event{
		Type:         types.EventTCPConnect,
		PID:          100,
		Network:      &types.NetworkEvent{Daddr: [16]byte{1, 2, 3, 4}, Family: types.AFInet},
		TraceContext: &types.TraceContext{TraceID: "trace1", SpanID: "span1"},
		Enrichment:   &types.EnrichmentInfo{ContainerID: "c1"},
	}
	alerts := ce.Ingest(context.Background(), ev)
	require.Len(t, alerts, 1)
	assert.Equal(t, "trace1", alerts[0].TraceID)
	assert.Equal(t, "span1", alerts[0].SpanID)
	assert.Equal(t, "c1", alerts[0].Enrichment.ContainerID)
}

// ─────────────────────────────────────────────────────────────────────────────
// QueueDepth — default / zero-cap edge cases
// ─────────────────────────────────────────────────────────────────────────────

func TestQueueDepth_DefaultsToZeroWhenUnwired(t *testing.T) {
	ce := NewCorrelationEngine(nil)
	defer ce.Close()
	assert.Equal(t, 0.0, ce.QueueDepth())
}

func TestQueueDepth_ZeroCapacityAvoidsDivideByZero(t *testing.T) {
	ce := NewCorrelationEngine(nil)
	defer ce.Close()
	ce.SetQueueDepthFn(func() int { return 5 }, func() int { return 0 })
	assert.Equal(t, 0.0, ce.QueueDepth())
}

// ─────────────────────────────────────────────────────────────────────────────
// evaluateRegoPolicies — DNS pre-filter skip branch
// ─────────────────────────────────────────────────────────────────────────────

func TestEvaluateRegoPolicies_DNSPrefilterSkipsBenignQuery(t *testing.T) {
	regoEng, err := policy.NewRegoEngine(policy.RegoEngineConfig{Enabled: true})
	require.NoError(t, err)

	rule := Rule{
		ID:        "dns_rule",
		EventType: types.EventDNS,
		Condition: RuleCondition{Field: "qname", Op: OpEquals, Values: []string{"benign.example.com"}},
		Severity:  types.SeverityWarning,
		Action:    ActionAlert,
	}

	cfg := DefaultCorrelationEngineConfig()
	cfg.Rules = []Rule{rule}
	cfg.EnableRateLimit = false
	cfg.EnableAnomaly = false
	cfg.EnableRegoEval = true
	cfg.RegoEngine = regoEng
	cfg.RegoWorkerCount = 2

	ce := NewCorrelationEngineWithConfig(cfg)
	defer ce.Close()

	ev := types.Event{
		Type: types.EventDNS,
		PID:  55,
		DNS:  &types.DNSEvent{QName: "benign.example.com"},
	}
	returned := ce.Ingest(context.Background(), ev)
	require.Len(t, returned, 1, "Ingest must return the pre-rego alert synchronously")

	deadline := time.Now().Add(200 * time.Millisecond)
	var flushed []types.Alert
	for time.Now().Before(deadline) {
		flushed = ce.Flush()
		if len(flushed) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	require.Len(t, flushed, 1)
	assert.Equal(t, "dns_rule", flushed[0].RuleID, "DNS prefilter skip must pass the alert through unmodified")
}
