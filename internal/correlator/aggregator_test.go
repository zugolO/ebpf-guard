package correlator

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

func testAlert(ruleID, comm, namespace, podName string) types.Alert {
	return types.Alert{
		RuleID: ruleID,
		Comm:   comm,
		Enrichment: types.EnrichmentInfo{
			Namespace: namespace,
			PodName:   podName,
		},
	}
}

func TestAlertAggregator_DisabledPassesThrough(t *testing.T) {
	agg := NewAlertAggregator(AlertAggregationConfig{Enabled: false, Window: time.Minute})
	in := []types.Alert{testAlert("r1", "systemd", "ns", "pod")}
	out := agg.Ingest(in, time.Now())
	require.Len(t, out, 1)
	assert.Equal(t, 0, out[0].Count) // untouched — disabled means no aggregation fields set
}

func TestAlertAggregator_FirstOccurrenceEmittedImmediately(t *testing.T) {
	agg := NewAlertAggregator(AlertAggregationConfig{Enabled: true, Window: time.Minute})
	now := time.Now()
	out := agg.Ingest([]types.Alert{testAlert("container_escape_proc_write", "systemd", "default", "pod-1")}, now)
	require.Len(t, out, 1)
	assert.Equal(t, 1, out[0].Count)
	assert.Equal(t, now, out[0].FirstSeen)
	assert.Equal(t, now, out[0].LastSeen)
}

func TestAlertAggregator_RepeatsWithinWindowAreFoldedNotForwarded(t *testing.T) {
	agg := NewAlertAggregator(AlertAggregationConfig{Enabled: true, Window: time.Minute})
	now := time.Now()
	alert := testAlert("container_escape_proc_write", "systemd", "default", "pod-1")

	first := agg.Ingest([]types.Alert{alert}, now)
	require.Len(t, first, 1)

	// 215 more occurrences of the same key within the window must not be
	// forwarded individually.
	for i := 0; i < 215; i++ {
		out := agg.Ingest([]types.Alert{alert}, now.Add(time.Duration(i+1)*time.Millisecond))
		assert.Empty(t, out)
	}

	// Reaping before the window closes must not yet return anything.
	assert.Empty(t, agg.Reap(now.Add(time.Second)))

	// Once the window closes, exactly one aggregated alert comes back with
	// the full count and first/last seen timestamps.
	closed := agg.Reap(now.Add(time.Minute + time.Millisecond))
	require.Len(t, closed, 1)
	assert.Equal(t, 216, closed[0].Count)
	assert.Equal(t, now, closed[0].FirstSeen)
}

func TestAlertAggregator_DistinctKeysDoNotCollapse(t *testing.T) {
	agg := NewAlertAggregator(AlertAggregationConfig{Enabled: true, Window: time.Minute})
	now := time.Now()

	cases := []types.Alert{
		testAlert("rule_a", "systemd", "default", "pod-1"),
		testAlert("rule_b", "systemd", "default", "pod-1"), // different rule
		testAlert("rule_a", "bash", "default", "pod-1"),    // different comm
		testAlert("rule_a", "systemd", "other", "pod-1"),   // different namespace
		testAlert("rule_a", "systemd", "default", "pod-2"), // different pod
	}
	out := agg.Ingest(cases, now)
	assert.Len(t, out, len(cases), "each distinct key must be forwarded on first occurrence")
}

func TestAlertAggregator_NewWindowAfterExpiry(t *testing.T) {
	agg := NewAlertAggregator(AlertAggregationConfig{Enabled: true, Window: time.Second})
	now := time.Now()
	alert := testAlert("rule_a", "systemd", "default", "pod-1")

	require.Len(t, agg.Ingest([]types.Alert{alert}, now), 1)
	require.Empty(t, agg.Ingest([]types.Alert{alert}, now.Add(500*time.Millisecond)))

	// A repeat arriving after the window has expired opens a brand new
	// window and is forwarded immediately again.
	later := now.Add(2 * time.Second)
	out := agg.Ingest([]types.Alert{alert}, later)
	require.Len(t, out, 1)
	assert.Equal(t, 1, out[0].Count)
	assert.Equal(t, later, out[0].FirstSeen)
}

func TestAlertAggregator_ReapDropsKeysWithNoRepeats(t *testing.T) {
	agg := NewAlertAggregator(AlertAggregationConfig{Enabled: true, Window: time.Second})
	now := time.Now()
	agg.Ingest([]types.Alert{testAlert("rule_a", "systemd", "default", "pod-1")}, now)

	// No repeats were folded in, so Reap must not manufacture a second alert.
	assert.Empty(t, agg.Reap(now.Add(2*time.Second)))
}

func TestNormalizePathPrefix(t *testing.T) {
	cases := map[string]string{
		"":                    "",
		"/etc/passwd":         "/etc/passwd",
		"/etc/shadow":         "/etc/shadow",
		"/proc/1234/mem":      "/proc/*",
		"/proc/5678/mem":      "/proc/*",
		"/var/lib/docker/foo": "/var/lib",
	}
	for in, want := range cases {
		assert.Equal(t, want, normalizePathPrefix(in), "path=%q", in)
	}
}

func TestAggregationKey_PathPrefixCollapsesNumericSegments(t *testing.T) {
	a1 := testAlert("container_escape_proc_write", "systemd", "default", "pod-1")
	a1.Event = types.Event{File: &types.FileEvent{FDPath: "/proc/1111/mem"}}
	a2 := testAlert("container_escape_proc_write", "systemd", "default", "pod-1")
	a2.Event = types.Event{File: &types.FileEvent{FDPath: "/proc/2222/mem"}}

	assert.Equal(t, aggregationKey(a1), aggregationKey(a2))
}
