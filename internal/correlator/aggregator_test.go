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

// TestAlertAggregator_DifferentBaseRuleIDsDoNotCollapse is the regression
// test for wave 6.3.L item 3 (№415): two different base rules renamed by
// Rego to the same reported RuleID (e.g. dns_dga_ngram and
// dns_dga_high_entropy both -> "dga_domain") must land in different
// aggregation buckets — the product must not report them as repeats of one
// detect.
func TestAlertAggregator_DifferentBaseRuleIDsDoNotCollapse(t *testing.T) {
	agg := NewAlertAggregator(AlertAggregationConfig{Enabled: true, Window: time.Minute})
	now := time.Now()

	a := testAlert("dga_domain", "coredns", "default", "pod-1")
	a.Details = map[string]interface{}{types.BaseRuleIDDetailsKey: "dns_dga_ngram"}
	b := testAlert("dga_domain", "coredns", "default", "pod-1")
	b.Details = map[string]interface{}{types.BaseRuleIDDetailsKey: "dns_dga_high_entropy"}

	out := agg.Ingest([]types.Alert{a, b}, now)
	assert.Len(t, out, 2, "different base_rule_id must forward as distinct detects, even under the same reported RuleID")
}

func TestAlertAggregator_NewWindowAfterExpiry(t *testing.T) {
	agg := NewAlertAggregator(AlertAggregationConfig{Enabled: true, Window: time.Second})
	now := time.Now()
	alert := testAlert("rule_a", "systemd", "default", "pod-1")

	require.Len(t, agg.Ingest([]types.Alert{alert}, now), 1)

	// A repeat arriving after the window has expired — with no earlier repeat
	// folded in, so the expired entry still has Count==1 and nothing to flush —
	// opens a brand new window and is forwarded immediately again.
	later := now.Add(2 * time.Second)
	out := agg.Ingest([]types.Alert{alert}, later)
	require.Len(t, out, 1)
	assert.Equal(t, 1, out[0].Count)
	assert.Equal(t, later, out[0].FirstSeen)
}

// TestAlertAggregator_IngestFlushesExpiredAggregate is the regression test for
// issue #305: a repeat of a key that arrives after windowEnd but before Reap's
// ticker fires must not silently discard the accumulated count. Ingest itself
// has to flush the expired aggregate on the same path Reap would have taken.
func TestAlertAggregator_IngestFlushesExpiredAggregate(t *testing.T) {
	agg := NewAlertAggregator(AlertAggregationConfig{Enabled: true, Window: time.Second})
	now := time.Now()
	alert := testAlert("rule_a", "systemd", "default", "pod-1")

	// First occurrence opens the window and is forwarded.
	require.Len(t, agg.Ingest([]types.Alert{alert}, now), 1)
	// A repeat within the window is folded (Count becomes 2), not forwarded.
	require.Empty(t, agg.Ingest([]types.Alert{alert}, now.Add(500*time.Millisecond)))

	// A third occurrence lands just after the window closes but before Reap
	// runs. Ingest must return two alerts: the flushed aggregate (count=2)
	// for the closed window, followed by the head of the new window (count=1).
	later := now.Add(time.Second + time.Millisecond)
	out := agg.Ingest([]types.Alert{alert}, later)
	require.Len(t, out, 2)

	flushed, head := out[0], out[1]
	assert.Equal(t, 2, flushed.Count, "closed-window aggregate must carry the accumulated count")
	assert.Equal(t, now, flushed.FirstSeen)
	assert.Equal(t, 1, head.Count, "new window head starts a fresh count")
	assert.Equal(t, later, head.FirstSeen)

	// Reap must not re-emit the already-flushed aggregate: only the new
	// window remains, and it has no repeats yet.
	assert.Empty(t, agg.Reap(later.Add(2*time.Second)))
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

// Волна 6.3.L.1, item 4 (№425): слой включается НА ХОДУ, и метка 6.3L1.4
// читает его работу по полю count в сторе. Проверяется вся цепочка тумблера:
// выключенный слой не сворачивает и ничего не накапливает, включённый на ходу
// сворачивает повторы, и выключенный обратно перестаёт отдавать агрегаты —
// измеритель обязан уметь вернуть продукт в исходное состояние.
//
// Отдельно закрепляется то, на чём смок 21.09 споткнулся: count>1 появляется
// ТОЛЬКО после закрытия окна (Reap), а не в момент повтора. Чтение стора
// раньше этого момента — вердикт о тайминге, а не о слое.
func TestAlertAggregator_RuntimeSwitchFoldsAndStops(t *testing.T) {
	agg := NewAlertAggregator(AlertAggregationConfig{Enabled: false, Window: time.Minute})
	now := time.Now()
	alert := testAlert("dns_dga_ngram", "dig", "default", "")

	require.False(t, agg.Enabled())
	out := agg.Ingest([]types.Alert{alert, alert}, now)
	assert.Len(t, out, 2, "выключенный слой пропускает всё как есть")

	agg.SetEnabled(true)
	first := agg.Ingest([]types.Alert{alert}, now.Add(time.Second))
	require.Len(t, first, 1)
	assert.Equal(t, 1, first[0].Count, "первое вхождение уходит немедленно с count=1")
	for i := 0; i < 4; i++ {
		assert.Empty(t, agg.Ingest([]types.Alert{alert}, now.Add(time.Duration(8*(i+1))*time.Second)))
	}
	assert.Empty(t, agg.Reap(now.Add(30*time.Second)), "до закрытия окна дожимать нечего — ровно то, что прочитал смок")

	closed := agg.Reap(now.Add(2 * time.Minute))
	require.Len(t, closed, 1)
	assert.Equal(t, 5, closed[0].Count)

	// Выключенный обратно слой не отдаёт агрегатов и не сворачивает.
	agg.SetEnabled(false)
	after := agg.Ingest([]types.Alert{alert, alert}, now.Add(3*time.Minute))
	assert.Len(t, after, 2)
	assert.Empty(t, agg.Reap(now.Add(4*time.Minute)))
}
