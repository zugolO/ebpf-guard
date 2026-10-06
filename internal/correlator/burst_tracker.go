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
	*timeRing
	// window is the widest sliding window any Record call used for this key;
	// Cleanup may drop the key once its newest match is older than that.
	window time.Duration
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
		st = &burstState{timeRing: newTimeRing(burstMaxSamples)}
		b.state[key] = st
	}
	st.window = max(st.window, window)

	st.prune(now.Add(-window))
	st.push(now)
	return st.size
}

// Cleanup removes tracked keys with no activity in the last maxAge, bounding
// memory growth from short-lived PIDs and chains. Called periodically from the
// same engine.go ticker that drives ConnFrequencyTracker.Cleanup.
//
// A key is also removed once its newest match is older than twice its own
// window: every sample is then outside any window Record would count, so the
// next match starts from one either way. The factor of two is slack for event
// timestamps lagging wall time while the queues are backed up (stage E: up to
// ~9 s at 53k queued events). Without this, a key lived the full maxAge
// (10 minutes) after a one-match process exited.
func (b *BurstTracker) Cleanup(maxAge time.Duration) int {
	now := time.Now()
	cutoff := now.Add(-maxAge)
	b.mu.Lock()
	defer b.mu.Unlock()

	removed := 0
	for key, st := range b.state {
		last, ok := st.newest()
		if !ok || last.Before(cutoff) || (st.window > 0 && last.Before(now.Add(-2*st.window))) {
			delete(b.state, key)
			removed++
		}
	}
	return removed
}
