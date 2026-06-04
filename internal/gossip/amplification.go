package gossip

import (
	"sync"
	"time"
)

// amplificationTTLDefault is how long a cross-node alert amplification signal
// remains active on peer nodes. Short by design — attack pressure is transient.
const amplificationTTLDefault = 10 * time.Minute

// defaultThresholdMultiplier is the anomaly sensitivity boost applied to a
// namespace that has an active amplification signal. 0.6 means the anomaly
// threshold is lowered to 60% of its normal value, making the detector more
// sensitive during a confirmed attack on a peer node.
const defaultThresholdMultiplier = 0.6

// AmplificationSignal is broadcast by a node when a critical alert fires.
// Receiving nodes temporarily lower their anomaly detection threshold for
// the same Kubernetes namespace, so related lateral-movement activity is
// caught even if it falls below the normal anomaly score threshold.
type AmplificationSignal struct {
	// Namespace is the Kubernetes namespace of the attacked workload.
	Namespace string `json:"namespace"`
	// RuleID is the rule that triggered the originating alert.
	RuleID string `json:"rule_id"`
	// Severity of the originating alert.
	Severity string `json:"severity"`
	// Source is the node name that produced the alert.
	Source string `json:"source"`
	// ThresholdMultiplier is the suggested anomaly threshold multiplier [0,1).
	// Receiving nodes multiply their base threshold by this value.
	// A lower value = higher sensitivity (e.g. 0.6 = 40% more sensitive).
	ThresholdMultiplier float64 `json:"threshold_multiplier"`
	// ExpiresAt is when this signal should be discarded.
	ExpiresAt time.Time `json:"expires_at"`
}

// AmplificationStore is a thread-safe, TTL-aware store for amplification signals.
type AmplificationStore struct {
	mu      sync.RWMutex
	signals []AmplificationSignal
}

func newAmplificationStore() *AmplificationStore {
	return &AmplificationStore{}
}

// Add inserts or refreshes a signal. If a signal from the same source+namespace
// pair already exists, it is replaced.
func (s *AmplificationStore) Add(sig AmplificationSignal) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, existing := range s.signals {
		if existing.Namespace == sig.Namespace && existing.Source == sig.Source {
			s.signals[i] = sig
			return
		}
	}
	s.signals = append(s.signals, sig)
}

// GetThresholdMultiplier returns the lowest (most sensitive) threshold
// multiplier for the given namespace across all active signals. Returns 1.0
// (no boost) when no active signals apply to the namespace.
func (s *AmplificationStore) GetThresholdMultiplier(namespace string) float64 {
	if namespace == "" {
		return 1.0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	min := 1.0
	for _, sig := range s.signals {
		if sig.Namespace == namespace && now.Before(sig.ExpiresAt) {
			if sig.ThresholdMultiplier < min {
				min = sig.ThresholdMultiplier
			}
		}
	}
	return min
}

// IsAmplified returns true if the namespace has any active amplification signal.
func (s *AmplificationStore) IsAmplified(namespace string) bool {
	return s.GetThresholdMultiplier(namespace) < 1.0
}

// ActiveCount returns the number of currently active (non-expired) signals.
func (s *AmplificationStore) ActiveCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	n := 0
	for _, sig := range s.signals {
		if now.Before(sig.ExpiresAt) {
			n++
		}
	}
	return n
}

// Snapshot returns all active (non-expired) signals.
func (s *AmplificationStore) Snapshot() []AmplificationSignal {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	var out []AmplificationSignal
	for _, sig := range s.signals {
		if now.Before(sig.ExpiresAt) {
			out = append(out, sig)
		}
	}
	return out
}

// CleanExpired removes all expired signals. Returns how many were removed.
func (s *AmplificationStore) CleanExpired() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	active := s.signals[:0]
	removed := 0
	for _, sig := range s.signals {
		if now.Before(sig.ExpiresAt) {
			active = append(active, sig)
		} else {
			removed++
		}
	}
	s.signals = active
	return removed
}
