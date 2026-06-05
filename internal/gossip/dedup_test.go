package gossip

// Unit tests for cluster-level alert deduplication via AmplificationStore.seen.
//
// The key invariant: when N nodes all see the same container-escape event, the
// cluster should produce exactly 1 alert rather than N identical ones. This is
// achieved by:
//   1. The originating node broadcasts an AmplificationSignal carrying the
//      alert's SHA-256 Fingerprint.
//   2. Every receiving node calls MarkSeen(fingerprint) and returns true from
//      IsDuplicate, allowing the local correlator to suppress the alert.
//   3. Only the originating node (which never receives its own signal through
//      the peer path) will not suppress the alert.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// ---------------------------------------------------------------------------
// AmplificationStore deduplication unit tests
// ---------------------------------------------------------------------------

func TestAmplificationStore_IsDuplicate_EmptyFP(t *testing.T) {
	s := newAmplificationStore(deduplicationTTLDefault)
	// Empty fingerprint should never be considered a duplicate.
	assert.False(t, s.IsDuplicate(""))
	s.MarkSeen("") // no-op
	assert.False(t, s.IsDuplicate(""))
}

func TestAmplificationStore_MarkSeenAndIsDuplicate(t *testing.T) {
	s := newAmplificationStore(deduplicationTTLDefault)
	fp := "sha256:abc123deadbeef"

	assert.False(t, s.IsDuplicate(fp), "before MarkSeen: not a duplicate")

	s.MarkSeen(fp)

	assert.True(t, s.IsDuplicate(fp), "after MarkSeen: is a duplicate within TTL")
}

func TestAmplificationStore_DedupExpires(t *testing.T) {
	s := newAmplificationStore(10 * time.Millisecond) // very short TTL
	fp := "sha256:expirysoon"

	s.MarkSeen(fp)
	assert.True(t, s.IsDuplicate(fp), "should be duplicate immediately after MarkSeen")

	time.Sleep(15 * time.Millisecond)
	assert.False(t, s.IsDuplicate(fp), "should not be duplicate after TTL expires")
}

func TestAmplificationStore_CleanExpired_PrunesSeen(t *testing.T) {
	s := newAmplificationStore(10 * time.Millisecond)
	s.MarkSeen("sha256:gone-soon")
	s.MarkSeen("sha256:stays-long")

	// Override the second entry with a long TTL by re-marking it.
	// (MarkSeen always resets the expiry to now+dedupTTL, so we need to
	// manipulate the map directly for the test.)
	s.mu.Lock()
	s.seen["sha256:stays-long"] = time.Now().Add(time.Hour)
	s.mu.Unlock()

	time.Sleep(15 * time.Millisecond)
	s.CleanExpired()

	assert.False(t, s.IsDuplicate("sha256:gone-soon"), "expired dedup entry removed")
	assert.True(t, s.IsDuplicate("sha256:stays-long"), "live dedup entry kept")
}

func TestAmplificationStore_MarkSeenRefreshesTTL(t *testing.T) {
	s := newAmplificationStore(50 * time.Millisecond)
	fp := "sha256:refresh"

	s.MarkSeen(fp)
	time.Sleep(30 * time.Millisecond)
	s.MarkSeen(fp) // refresh — should extend the TTL
	time.Sleep(30 * time.Millisecond)
	// If TTL wasn't refreshed, the entry would have expired after ~50 ms total.
	assert.True(t, s.IsDuplicate(fp), "TTL should be refreshed by second MarkSeen")
}

// ---------------------------------------------------------------------------
// Manager-level two-node deduplication test
// ---------------------------------------------------------------------------

// TestTwoNodes_SameFingerprint_OnlyOneAlert is the primary acceptance test for
// the cluster deduplication feature.
//
// Scenario:
//   - Node A (originator) sees a container-escape event and broadcasts an
//     AmplificationSignal with a fingerprint.
//   - Node B (peer) receives the signal via MergeAmplificationsFromPeer.
//   - Node B's correlator then queries IsDuplicateAlert before emitting the
//     same alert — it returns true, so the alert is suppressed.
//   - Node A was the originator and never received its own signal through the
//     peer path, so IsDuplicateAlert returns false for A.
//   - Net result: exactly 1 alert cluster-wide.
func TestTwoNodes_SameFingerprint_OnlyOneAlert(t *testing.T) {
	nodeA := newTestManager()
	nodeB := newTestManager()

	fingerprint := "sha256:container-escape-f0a1b2c3"

	alert := types.Alert{
		RuleID:      "container_escape_mount",
		Severity:    types.SeverityCritical,
		Fingerprint: fingerprint,
		Enrichment:  types.EnrichmentInfo{Namespace: "production"},
		Event:       types.Event{Type: types.EventSyscall},
	}

	// Node A processes the alert and enqueues the amplification signal.
	nodeA.BroadcastAlert(alert)

	// Extract the signal that node A would push to peers.
	nodeA.ampDeltaMu.Lock()
	signals := make([]AmplificationSignal, len(nodeA.ampDelta))
	copy(signals, nodeA.ampDelta)
	nodeA.ampDeltaMu.Unlock()

	require.Len(t, signals, 1, "BroadcastAlert should enqueue exactly one signal")
	assert.Equal(t, fingerprint, signals[0].Fingerprint, "signal must carry the alert fingerprint")

	// Node B receives the signal from node A (simulates gossip fan-out).
	nodeB.MergeAmplificationsFromPeer(signals)

	// Count how many alerts the cluster would raise:
	//   - Node A: was the originator, fingerprint NOT in its own seen map → raises alert.
	//   - Node B: fingerprint IS in seen map → suppresses alert.
	clusterAlerts := 0
	if !nodeA.IsDuplicateAlert(fingerprint) {
		clusterAlerts++
	}
	if !nodeB.IsDuplicateAlert(fingerprint) {
		clusterAlerts++
	}

	assert.Equal(t, 1, clusterAlerts,
		"cluster of 2 nodes with identical fingerprint should produce exactly 1 alert")
}

// TestTwoNodes_DifferentFingerprints_TwoAlerts verifies that deduplication
// only fires for matching fingerprints — distinct alerts are not suppressed.
func TestTwoNodes_DifferentFingerprints_TwoAlerts(t *testing.T) {
	nodeA := newTestManager()
	nodeB := newTestManager()

	fpA := "sha256:event-on-node-a"
	fpB := "sha256:event-on-node-b"

	sigFromA := AmplificationSignal{
		Namespace:           "production",
		Source:              "node-a",
		ThresholdMultiplier: 0.6,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
		Fingerprint:         fpA,
	}
	sigFromB := AmplificationSignal{
		Namespace:           "staging",
		Source:              "node-b",
		ThresholdMultiplier: 0.6,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
		Fingerprint:         fpB,
	}

	nodeB.MergeAmplificationsFromPeer([]AmplificationSignal{sigFromA})
	nodeA.MergeAmplificationsFromPeer([]AmplificationSignal{sigFromB})

	// Node B received fpA from Node A → B suppresses fpA.
	assert.True(t, nodeB.IsDuplicateAlert(fpA))
	// Node A received fpB from Node B → A suppresses fpB.
	assert.True(t, nodeA.IsDuplicateAlert(fpB))

	// Each node's own fingerprint (which it originated) is NOT in its seen map.
	assert.False(t, nodeA.IsDuplicateAlert(fpA), "originator must not suppress its own alert")
	assert.False(t, nodeB.IsDuplicateAlert(fpB), "originator must not suppress its own alert")
}

// TestIsDuplicateAlert_DisabledManager verifies that a disabled gossip manager
// never suppresses alerts (dedup is a no-op when gossip is off).
func TestIsDuplicateAlert_DisabledManager(t *testing.T) {
	cfg := Config{Enabled: false}
	m, err := NewManager(cfg, nil)
	require.NoError(t, err)

	m.ampStore.MarkSeen("sha256:shouldnotmatter")
	assert.False(t, m.IsDuplicateAlert("sha256:shouldnotmatter"),
		"disabled manager must never suppress alerts")
}

// TestMergeAmplificationsFromPeer_ExpiredSignalNotSeen verifies that an already-
// expired signal does not mark its fingerprint as seen (prevents stale dedup).
func TestMergeAmplificationsFromPeer_ExpiredSignalNotSeen(t *testing.T) {
	m := newTestManager()
	fp := "sha256:expired-signal"

	expired := AmplificationSignal{
		Namespace:           "production",
		Source:              "node-x",
		ThresholdMultiplier: 0.6,
		ExpiresAt:           time.Now().Add(-time.Millisecond), // already expired
		Fingerprint:         fp,
	}

	m.MergeAmplificationsFromPeer([]AmplificationSignal{expired})

	assert.False(t, m.IsDuplicateAlert(fp),
		"expired signal must not add fingerprint to seen map")
}
