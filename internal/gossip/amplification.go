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

// deduplicationTTLDefault is the default window during which a fingerprint
// received from a peer suppresses the same alert on the local node.
const deduplicationTTLDefault = 5 * time.Minute

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
	// Fingerprint is the SHA-256 fingerprint of the originating alert
	// (types.Alert.Fingerprint). Receiving nodes store it in their dedup seen
	// map so that the same alert is not re-raised cluster-wide.
	Fingerprint string `json:"fingerprint,omitempty"`
}

// AmplificationStore is a thread-safe, TTL-aware store for amplification signals.
// It also maintains a cluster-level deduplication index: fingerprints received
// from peer nodes are kept in seen for dedupTTL so the local correlator can
// suppress re-raising the same alert.
type AmplificationStore struct {
	mu      sync.RWMutex
	signals []AmplificationSignal
	// seen maps alert fingerprint → expiry time for cluster deduplication.
	seen     map[string]time.Time
	dedupTTL time.Duration
}

// newAmplificationStore creates an empty store.
// dedupTTL controls how long a fingerprint received from a peer suppresses the
// local alert. Pass 0 to use deduplicationTTLDefault (5 minutes).
func newAmplificationStore(dedupTTL time.Duration) *AmplificationStore {
	if dedupTTL <= 0 {
		dedupTTL = deduplicationTTLDefault
	}
	return &AmplificationStore{
		seen:     make(map[string]time.Time),
		dedupTTL: dedupTTL,
	}
}

// MarkSeen records an alert fingerprint as observed from a peer. Any
// subsequent call to IsDuplicate within dedupTTL will return true, allowing
// the local correlator to suppress the same alert.
// No-op for empty fingerprints.
func (s *AmplificationStore) MarkSeen(fingerprint string) {
	if fingerprint == "" {
		return
	}
	s.mu.Lock()
	s.seen[fingerprint] = time.Now().Add(s.dedupTTL)
	s.mu.Unlock()
}

// IsDuplicate returns true if fingerprint was received from a peer within
// the dedupTTL window. A true result means the local alert should be
// suppressed to avoid cluster-wide alert storms.
func (s *AmplificationStore) IsDuplicate(fingerprint string) bool {
	if fingerprint == "" {
		return false
	}
	s.mu.RLock()
	expiry, ok := s.seen[fingerprint]
	s.mu.RUnlock()
	return ok && time.Now().Before(expiry)
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

// CleanExpired removes all expired signals and expired deduplication entries.
// Returns how many signals were removed.
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
	for fp, expiry := range s.seen {
		if !now.Before(expiry) {
			delete(s.seen, fp)
		}
	}
	return removed
}
