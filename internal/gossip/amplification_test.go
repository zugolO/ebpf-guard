package gossip

import (
	"testing"
	"time"
)

func newSig(ns, source string, mult float64, ttl time.Duration) AmplificationSignal {
	return AmplificationSignal{
		Namespace:           ns,
		RuleID:              "test_rule",
		Severity:            "critical",
		Source:              source,
		ThresholdMultiplier: mult,
		ExpiresAt:           time.Now().Add(ttl),
	}
}

func TestAmplificationStore_AddAndMultiplier(t *testing.T) {
	s := newAmplificationStore()
	s.Add(newSig("production", "node-1", 0.6, time.Hour))

	mult := s.GetThresholdMultiplier("production")
	if mult != 0.6 {
		t.Errorf("expected multiplier 0.6, got %f", mult)
	}
}

func TestAmplificationStore_NoSignal(t *testing.T) {
	s := newAmplificationStore()
	if s.GetThresholdMultiplier("staging") != 1.0 {
		t.Error("expected 1.0 for namespace with no signal")
	}
}

func TestAmplificationStore_EmptyNamespace(t *testing.T) {
	s := newAmplificationStore()
	s.Add(newSig("production", "node-1", 0.5, time.Hour))
	if s.GetThresholdMultiplier("") != 1.0 {
		t.Error("expected 1.0 for empty namespace")
	}
}

func TestAmplificationStore_LowestMultiplier(t *testing.T) {
	s := newAmplificationStore()
	s.Add(newSig("ns1", "node-a", 0.7, time.Hour))
	s.Add(newSig("ns1", "node-b", 0.4, time.Hour))

	mult := s.GetThresholdMultiplier("ns1")
	if mult != 0.4 {
		t.Errorf("expected lowest multiplier 0.4, got %f", mult)
	}
}

func TestAmplificationStore_Expired(t *testing.T) {
	s := newAmplificationStore()
	s.Add(newSig("ns1", "node-1", 0.5, -time.Millisecond)) // already expired

	if s.GetThresholdMultiplier("ns1") != 1.0 {
		t.Error("expired signal should return 1.0")
	}
	if s.IsAmplified("ns1") {
		t.Error("expired signal should not count as amplified")
	}
}

func TestAmplificationStore_IsAmplified(t *testing.T) {
	s := newAmplificationStore()
	if s.IsAmplified("ns") {
		t.Error("empty store: IsAmplified should be false")
	}
	s.Add(newSig("ns", "node-1", 0.6, time.Hour))
	if !s.IsAmplified("ns") {
		t.Error("should be amplified after add")
	}
}

func TestAmplificationStore_CleanExpired(t *testing.T) {
	s := newAmplificationStore()
	s.Add(newSig("ns1", "node-1", 0.5, -time.Millisecond)) // expired
	s.Add(newSig("ns2", "node-2", 0.6, time.Hour))          // active

	removed := s.CleanExpired()
	if removed != 1 {
		t.Errorf("expected 1 removed, got %d", removed)
	}
	if s.ActiveCount() != 1 {
		t.Errorf("expected 1 active after cleanup, got %d", s.ActiveCount())
	}
}

func TestAmplificationStore_UpdateExisting(t *testing.T) {
	s := newAmplificationStore()
	s.Add(newSig("ns", "node-1", 0.7, time.Hour))
	s.Add(newSig("ns", "node-1", 0.5, 2*time.Hour)) // same source+namespace

	// Should replace, not append.
	if s.ActiveCount() != 1 {
		t.Errorf("expected 1 signal after update, got %d", s.ActiveCount())
	}
	if s.GetThresholdMultiplier("ns") != 0.5 {
		t.Errorf("expected updated multiplier 0.5, got %f", s.GetThresholdMultiplier("ns"))
	}
}

func TestAmplificationStore_Snapshot(t *testing.T) {
	s := newAmplificationStore()
	s.Add(newSig("ns1", "node-1", 0.6, time.Hour))
	s.Add(newSig("ns2", "node-2", 0.7, -time.Millisecond)) // expired

	snap := s.Snapshot()
	if len(snap) != 1 {
		t.Errorf("expected 1 active signal in snapshot, got %d", len(snap))
	}
	if snap[0].Namespace != "ns1" {
		t.Errorf("expected ns1 in snapshot, got %s", snap[0].Namespace)
	}
}

func TestAmplificationStore_ActiveCount(t *testing.T) {
	s := newAmplificationStore()
	if s.ActiveCount() != 0 {
		t.Error("empty store: ActiveCount should be 0")
	}
	s.Add(newSig("ns1", "n1", 0.6, time.Hour))
	s.Add(newSig("ns2", "n2", 0.7, time.Hour))
	if s.ActiveCount() != 2 {
		t.Errorf("expected 2, got %d", s.ActiveCount())
	}
}
