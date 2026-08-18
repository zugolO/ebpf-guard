// Package correlator provides event correlation and rule-based detection.
package correlator

import (
	"sync"
	"time"
)

// burstMaxSamples bounds the ring buffer per (rule, pid) key. Threshold rules
// target bursts of tens of matches (port scans, cron-triggered probe bursts);
// this is comfortably above realistic legitimate spikes while bounding memory
// for a single hot key.
const burstMaxSamples = 256

// BurstTracker counts rule-condition matches per (ruleID, group) key within a
// caller-supplied sliding window. It backs the count/burst rule operator
// (5.8g): a rule's own base condition can be individually plausible (one
// short TCP connection, one probe) but only a burst of N such matches from
// the same group within window T is the actual signal — see
// net_portscan_indicator's own description ("combine with count-based
// alerting"). Mirrors ConnFrequencyTracker's ring-buffer/sliding-window
// design, keyed by (ruleID, group) instead of (pid, dport).
//
// group is an opaque uint64 so the same tracker serves both grouping modes of
// RuleThreshold: the PID itself for group_by: pid, and a process-chain
// identity for group_by: chain (see RuleEngine.chainGroupFn). The tracker
// itself does not care which — it only needs keys that are equal exactly when
// two matches belong to the same burst.
type BurstTracker struct {
	mu    sync.Mutex
	state map[burstKey]*burstState
}

type burstKey struct {
	ruleID string
	group  uint64
}

type burstState struct {
	ring []time.Time
	head int
	size int
}

// NewBurstTracker creates an empty tracker.
func NewBurstTracker() *BurstTracker {
	return &BurstTracker{state: make(map[burstKey]*burstState)}
}

// globalBurstTracker is the package-level tracker used by matchesTyped to
// evaluate rule.Threshold, mirroring globalConnFrequency.
var globalBurstTracker = NewBurstTracker()

// Record registers a match for (ruleID, group) at time now and returns the
// number of matches (including this one) within the trailing window.
func (b *BurstTracker) Record(ruleID string, group uint64, now time.Time, window time.Duration) int {
	key := burstKey{ruleID: ruleID, group: group}

	b.mu.Lock()
	defer b.mu.Unlock()

	st, ok := b.state[key]
	if !ok {
		st = &burstState{ring: make([]time.Time, burstMaxSamples)}
		b.state[key] = st
	}

	cutoff := now.Add(-window)
	for st.size > 0 && st.ring[st.head].Before(cutoff) {
		st.head = (st.head + 1) % burstMaxSamples
		st.size--
	}

	tail := (st.head + st.size) % burstMaxSamples
	st.ring[tail] = now
	if st.size < burstMaxSamples {
		st.size++
	} else {
		// Ring is full: overwrite the oldest slot and advance head so the
		// window keeps sliding instead of freezing at the cap.
		st.head = (st.head + 1) % burstMaxSamples
	}

	return st.size
}

// Cleanup removes tracked keys with no activity in the last maxAge, bounding
// memory growth from short-lived PIDs and chains. Called periodically from the
// same engine.go ticker that drives ConnFrequencyTracker.Cleanup.
func (b *BurstTracker) Cleanup(maxAge time.Duration) int {
	cutoff := time.Now().Add(-maxAge)
	b.mu.Lock()
	defer b.mu.Unlock()

	removed := 0
	for key, st := range b.state {
		if st.size == 0 || st.ring[(st.head+st.size-1)%burstMaxSamples].Before(cutoff) {
			delete(b.state, key)
			removed++
		}
	}
	return removed
}
