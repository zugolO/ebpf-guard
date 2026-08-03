// Package correlator provides event correlation and rule-based detection.
package correlator

import (
	"strconv"
	"sync"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// connFreqWindow is the sliding window used to count connection attempts per
// (pid, dport) key. 60s matches the "N requests/minute" framing used by the
// brute-force attack scripts this detector targets (see ATTACK 6 in
// deploy/docker-test-setup/attacks/bruteforce-attacks.sh).
const connFreqWindow = 60 * time.Second

// connFreqMaxSamples bounds the ring buffer per key. Brute-force/credential
// stuffing tools issue tens to hundreds of connections per minute; 1024 is
// comfortably above realistic legitimate bursts (e.g. browser preconnects)
// while bounding memory for a single hot key.
const connFreqMaxSamples = 1024

// ConnFrequencyTracker counts TCP connection attempts per (pid, dport) key
// within a sliding window. It exists to give the rule engine a behavioral
// signal for high-frequency connection patterns (password spraying,
// credential-stuffing, brute-force login attempts) that never surface at the
// syscall/file level — see docs/detection-coverage-l7.md for why L7 payload
// content (the actual failed-login response) is out of reach without a
// TLS-uprobe payload parser.
type ConnFrequencyTracker struct {
	mu    sync.Mutex
	state map[connFreqKey]*connFreqState
}

type connFreqKey struct {
	pid   uint32
	dport uint16
}

type connFreqState struct {
	ring []time.Time
	head int
	size int
}

// NewConnFrequencyTracker creates an empty tracker.
func NewConnFrequencyTracker() *ConnFrequencyTracker {
	return &ConnFrequencyTracker{state: make(map[connFreqKey]*connFreqState)}
}

// globalConnFrequency is the package-level tracker used by getFieldValue to
// evaluate the "conn_rate_1m" computed field, mirroring globalDNSAnalyzer.
var globalConnFrequency = NewConnFrequencyTracker()

// Record registers a connection attempt at time now and returns the number of
// attempts (including this one) for the same (pid, dport) within the
// trailing window.
func (c *ConnFrequencyTracker) Record(pid uint32, dport uint16, now time.Time) int {
	key := connFreqKey{pid: pid, dport: dport}

	c.mu.Lock()
	defer c.mu.Unlock()

	st, ok := c.state[key]
	if !ok {
		st = &connFreqState{ring: make([]time.Time, connFreqMaxSamples)}
		c.state[key] = st
	}

	cutoff := now.Add(-connFreqWindow)
	for st.size > 0 && st.ring[st.head].Before(cutoff) {
		st.head = (st.head + 1) % connFreqMaxSamples
		st.size--
	}

	tail := (st.head + st.size) % connFreqMaxSamples
	st.ring[tail] = now
	if st.size < connFreqMaxSamples {
		st.size++
	} else {
		// Ring is full: overwrite the oldest slot and advance head so the
		// window keeps sliding instead of freezing at the cap.
		st.head = (st.head + 1) % connFreqMaxSamples
	}

	return st.size
}

// Rate returns the number of attempts for (pid, dport) within the trailing
// window as of now, without recording a new attempt. Rule evaluation uses this
// so that a single connection is counted once regardless of how many rules
// reference conn_rate_1m; Record is called once per event by the engine.
func (c *ConnFrequencyTracker) Rate(pid uint32, dport uint16, now time.Time) int {
	key := connFreqKey{pid: pid, dport: dport}

	c.mu.Lock()
	defer c.mu.Unlock()

	st, ok := c.state[key]
	if !ok {
		return 0
	}

	// Expire out-of-window samples so a key that stops receiving connections
	// reports a decaying rate rather than a frozen one.
	cutoff := now.Add(-connFreqWindow)
	for st.size > 0 && st.ring[st.head].Before(cutoff) {
		st.head = (st.head + 1) % connFreqMaxSamples
		st.size--
	}
	return st.size
}

// Cleanup removes tracked keys with no activity in the last maxAge, bounding
// memory growth from short-lived PIDs. Intended to be called periodically
// (e.g. alongside RateLimiter.Cleanup).
func (c *ConnFrequencyTracker) Cleanup(maxAge time.Duration) int {
	cutoff := time.Now().Add(-maxAge)
	c.mu.Lock()
	defer c.mu.Unlock()

	removed := 0
	for key, st := range c.state {
		if st.size == 0 || st.ring[(st.head+st.size-1)%connFreqMaxSamples].Before(cutoff) {
			delete(c.state, key)
			removed++
		}
	}
	return removed
}

// eventTime converts an event's BPF timestamp to wall-clock time, falling back
// to time.Now() when the timestamp is absent. Without the fallback a zero
// timestamp maps to 1970, which sits outside every sliding window and makes the
// rate collapse to 1 for every event — silently disabling frequency rules on
// any path where the timestamp is not populated (synthetic collector, replayed
// events, tests).
func eventTime(e types.Event) time.Time {
	if e.Timestamp == 0 {
		return time.Now()
	}
	return time.Unix(0, int64(e.Timestamp))
}

// formatConnRate formats a connection count as a decimal string for use as a
// rule condition field value.
func formatConnRate(count int) string {
	return strconv.Itoa(count)
}
