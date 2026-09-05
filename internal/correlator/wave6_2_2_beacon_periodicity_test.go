package correlator

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Wave 6.2.2, findings №230/№231: c2_periodic_beacon_pattern promised
// periodicity in its name and description but checked only port+comm, so a
// single one-off control-plane connection (k3s-server → 6443/10250/2379/2380)
// matched it exactly like a real beacon — 602 matches in the 6.2.1 window,
// 71% of everything the run measured, none of them repeated. Both halves are
// asserted here, as rule В of "Перенос в 6.1…6.4" requires: the one-off
// connection must go silent, and a connection that actually recurs at a
// regular cadence must still alert.
//
// Internal test (package correlator) because it primes globalBeaconInterval,
// package-level state the rule's conn_periodic_count_5m/conn_periodic_cv_5m
// fields read — an external test cannot reach it.

func w622Beacon(comm string, dport uint16, daddr string) types.Event {
	e := types.Event{Type: types.EventTCPConnect, PID: 5150, Network: &types.NetworkEvent{Dport: dport, Family: types.AFInet}}
	copy(e.Comm[:], comm)
	copy(e.Network.Daddr[:], net.ParseIP(daddr).To4())
	return e
}

func TestWave6_2_2_C2PeriodicBeaconPattern(t *testing.T) {
	globalBeaconInterval = NewBeaconIntervalTracker()
	t.Cleanup(func() { globalBeaconInterval = NewBeaconIntervalTracker() })

	rules, err := LoadRulesFromFile("../../rules/command-and-control.yaml")
	require.NoError(t, err)
	var rule Rule
	found := false
	for i := range rules {
		if rules[i].ID == "c2_periodic_beacon_pattern" {
			rule = rules[i]
			found = true
		}
	}
	require.True(t, found, "c2_periodic_beacon_pattern not found in rules/command-and-control.yaml")
	engine := NewRuleEngine([]Rule{rule})

	t.Run("single control-plane connect does not alert", func(t *testing.T) {
		// Exactly the shape from server-logs/collect-6.2.1: one k3s-server
		// connect to the apiserver port, never repeated within the window.
		e := w622Beacon("k3s-server", 6443, "10.0.0.1")
		e.Timestamp = uint64(time.Now().UnixNano())
		globalBeaconInterval.Record(e.PID, e.Network.Daddr, e.Network.Dport, eventTime(e))
		assert.Empty(t, engine.Evaluate(e),
			"a single one-off connection must not be treated as a periodic beacon")
	})

	t.Run("regular-cadence connections to the same destination alert", func(t *testing.T) {
		globalBeaconInterval = NewBeaconIntervalTracker()
		e := w622Beacon("evil-implant", 4444, "203.0.113.9")
		base := time.Now()
		// Four connections, 30s apart, to the same destination: the canonical
		// fixed-interval beacon this rule exists to catch.
		var last []types.Alert
		for i := 0; i < 4; i++ {
			now := base.Add(time.Duration(i) * 30 * time.Second)
			e.Timestamp = uint64(now.UnixNano())
			globalBeaconInterval.Record(e.PID, e.Network.Daddr, e.Network.Dport, now)
			last = engine.Evaluate(e)
		}
		assert.NotEmpty(t, last, "a regular-cadence repeated connection to one destination must still alert")
	})

	t.Run("irregular repeated connections do not alert", func(t *testing.T) {
		globalBeaconInterval = NewBeaconIntervalTracker()
		e := w622Beacon("chatty-app", 8081, "198.51.100.4")
		base := time.Now()
		gaps := []time.Duration{2 * time.Second, 47 * time.Second, 5 * time.Second}
		now := base
		var last []types.Alert
		for i, gap := range gaps {
			if i > 0 {
				now = now.Add(gap)
			}
			e.Timestamp = uint64(now.UnixNano())
			globalBeaconInterval.Record(e.PID, e.Network.Daddr, e.Network.Dport, now)
			last = engine.Evaluate(e)
		}
		assert.Empty(t, last, "repeated but irregularly-spaced connections are not a periodic beacon")
	})
}

func TestBeaconIntervalTracker_InsufficientDataFailsClosed(t *testing.T) {
	tr := NewBeaconIntervalTracker()
	now := time.Now()
	var daddr [16]byte
	copy(daddr[:], net.ParseIP("203.0.113.9").To4())

	tr.Record(1, daddr, 4444, now)
	count, cv := tr.Stats(1, daddr, 4444, now)
	assert.Equal(t, 1, count)
	assert.Equal(t, beaconInsufficientDataCV, cv, "one sample must not report a real coefficient of variation")

	tr.Record(1, daddr, 4444, now.Add(10*time.Second))
	count, cv = tr.Stats(1, daddr, 4444, now.Add(10*time.Second))
	assert.Equal(t, 2, count)
	assert.Equal(t, beaconInsufficientDataCV, cv, "two samples (one interval) give no variance and must fail closed")
}

// The tracker keys on (pid, daddr, dport) — one key per DESTINATION, not per
// port as ConnFrequencyTracker does — so its ring grows on demand and its key
// count is capped. Both are memory decisions taken against the 256 MiB
// DaemonSet limit (finding №244); these tests hold them to behaving like a
// plain sliding window regardless.

func TestBeaconIntervalTracker_RingGrowsWithoutLosingCadence(t *testing.T) {
	tr := NewBeaconIntervalTracker()
	var daddr [16]byte
	copy(daddr[:], net.ParseIP("203.0.113.9").To4())
	base := time.Now()

	// Well past beaconInitialSamples and beaconMaxSamples, at a perfectly
	// regular cadence: the ring must keep sliding and still report cv ≈ 0.
	const beats = beaconMaxSamples * 2
	var now time.Time
	for i := 0; i < beats; i++ {
		now = base.Add(time.Duration(i) * time.Second)
		tr.Record(7, daddr, 4444, now)
	}
	count, cv := tr.Stats(7, daddr, 4444, now)
	assert.Equal(t, beaconMaxSamples, count, "ring must cap at beaconMaxSamples, not grow unbounded")
	assert.InDelta(t, 0.0, cv, 1e-9, "a fixed one-second cadence must read as perfectly regular after the ring wraps")

	// A ragged tail must move the coefficient of variation off zero.
	tr.Record(7, daddr, 4444, now.Add(37*time.Second))
	_, cv = tr.Stats(7, daddr, 4444, now.Add(37*time.Second))
	assert.Greater(t, cv, 0.0, "an outlier interval must raise the coefficient of variation")
}

func TestBeaconIntervalTracker_KeyCapDropsAndCountsInsteadOfGrowing(t *testing.T) {
	tr := NewBeaconIntervalTracker()
	now := time.Now()
	mkAddr := func(i int) [16]byte {
		var a [16]byte
		a[0], a[1], a[2], a[3] = 10, byte(i>>16), byte(i>>8), byte(i)
		return a
	}

	// Fill past the cap in one instant, so no key is stale enough to evict.
	for i := 0; i < beaconMaxKeys+100; i++ {
		tr.Record(9, mkAddr(i), 4444, now)
	}
	tr.mu.Lock()
	keys := len(tr.state)
	tr.mu.Unlock()
	assert.LessOrEqual(t, keys, beaconMaxKeys, "the tracker must not grow past its key cap")

	// Once the window has passed, stale keys are evicted to make room again.
	later := now.Add(beaconWindow + time.Minute)
	tr.Record(9, mkAddr(999999), 4444, later)
	count, _ := tr.Stats(9, mkAddr(999999), 4444, later)
	assert.Equal(t, 1, count, "a key recorded after the old ones aged out must be tracked")
}

func TestBeaconIntervalTracker_StatsDoesNotAllocate(t *testing.T) {
	tr := NewBeaconIntervalTracker()
	var daddr [16]byte
	copy(daddr[:], net.ParseIP("203.0.113.9").To4())
	base := time.Now()
	for i := 0; i < 16; i++ {
		tr.Record(11, daddr, 4444, base.Add(time.Duration(i)*time.Second))
	}
	now := base.Add(16 * time.Second)

	// Stats runs once per rule condition on every TCP-connect event; the rule
	// carries two such conditions, so an allocation here is an allocation on
	// the network hot path.
	allocs := testing.AllocsPerRun(200, func() { tr.Stats(11, daddr, 4444, now) })
	assert.Zero(t, allocs, "Stats must not allocate on the hot path")
}
