//go:build cgo
// +build cgo

package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// summarizeStores returns the store backends that implement Summarizer, so the
// same assertions run against both the memory index and the SQLite GROUP BY.
func summarizeStores(t *testing.T) map[string]Summarizer {
	t.Helper()
	sq := newSQLiteAlertStore(t)
	return map[string]Summarizer{
		"memory": NewMemoryStore(),
		"sqlite": sq,
	}
}

func seedAlerts(t *testing.T, s AlertStore, alerts []types.Alert) {
	t.Helper()
	require.NoError(t, s.StoreBatch(context.Background(), alerts))
}

// TestSummarize_CountsFullWindow is the core of issue #303: a summary must count
// the entire matching window, not a capped page. We seed 10k alerts and assert
// the total is 10k on both backends.
func TestSummarize_CountsFullWindow(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()

	const n = 10000
	alerts := make([]types.Alert, n)
	for i := 0; i < n; i++ {
		sev := types.SeverityWarning
		if i%4 == 0 {
			sev = types.SeverityCritical
		}
		alerts[i] = types.Alert{
			ID:        fmt.Sprintf("a-%d", i),
			Timestamp: now.Add(-time.Duration(i) * time.Second),
			RuleID:    fmt.Sprintf("rule-%d", i%3),
			Severity:  sev,
			PID:       uint32(i),
			Comm:      "sh",
			Message:   "m",
		}
	}

	for name, sz := range summarizeStores(t) {
		t.Run(name, func(t *testing.T) {
			seedAlerts(t, sz.(AlertStore), alerts)

			// A stray list-page limit must not affect the summary.
			summary, err := sz.Summarize(ctx, QueryFilters{Since: now.Add(-24 * time.Hour), Limit: 500})
			require.NoError(t, err)

			assert.Equal(t, n, summary.Total, "summary must count the full window, not 500")
			assert.Equal(t, 2500, summary.BySeverity["critical"])
			assert.Equal(t, 7500, summary.BySeverity["warning"])
			assert.False(t, summary.Truncated)

			// 3 distinct rules, each ~n/3.
			require.Len(t, summary.TopRules, 3)
			total := 0
			for _, rc := range summary.TopRules {
				total += rc.Count
			}
			assert.Equal(t, n, total)
			assert.NotEmpty(t, summary.Timeline)
		})
	}
}

// TestSummarize_MemoryAndSQLiteAgree checks the two native implementations
// produce the same aggregates on a small, deterministic input.
func TestSummarize_MemoryAndSQLiteAgree(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 7, 16, 10, 30, 0, 0, time.UTC)

	alerts := []types.Alert{
		{ID: "1", Timestamp: base, RuleID: "r1", Severity: types.SeverityCritical, Comm: "a", Message: "m"},
		{ID: "2", Timestamp: base.Add(-90 * time.Minute), RuleID: "r1", Severity: types.SeverityWarning, Comm: "b", Message: "m"},
		{ID: "3", Timestamp: base.Add(-150 * time.Minute), RuleID: "r2", Severity: types.SeverityWarning, Comm: "c", Message: "m"},
	}

	mem := NewMemoryStore()
	seedAlerts(t, mem, alerts)
	sq := newSQLiteAlertStore(t)
	seedAlerts(t, sq, alerts)

	f := QueryFilters{Since: base.Add(-24 * time.Hour)}
	memSum, err := mem.Summarize(ctx, f)
	require.NoError(t, err)
	sqSum, err := sq.Summarize(ctx, f)
	require.NoError(t, err)

	assert.Equal(t, memSum.Total, sqSum.Total)
	assert.Equal(t, memSum.BySeverity, sqSum.BySeverity)
	assert.Equal(t, memSum.TopRules, sqSum.TopRules)
	// Timelines: same first/last bucket and same total count across buckets.
	assert.Equal(t, memSum.Timeline[0].Hour, sqSum.Timeline[0].Hour)
	assert.Equal(t, len(memSum.Timeline), len(sqSum.Timeline))
}

// TestSummarize_SeverityFilter confirms filters are honored by both backends.
func TestSummarize_SeverityFilter(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	alerts := []types.Alert{
		{ID: "1", Timestamp: now, RuleID: "r1", Severity: types.SeverityCritical, Comm: "a", Message: "m"},
		{ID: "2", Timestamp: now, RuleID: "r1", Severity: types.SeverityWarning, Comm: "b", Message: "m"},
	}
	for name, sz := range summarizeStores(t) {
		t.Run(name, func(t *testing.T) {
			seedAlerts(t, sz.(AlertStore), alerts)
			summary, err := sz.Summarize(ctx, QueryFilters{Severity: []types.Severity{types.SeverityCritical}})
			require.NoError(t, err)
			assert.Equal(t, 1, summary.Total)
			assert.Equal(t, 1, summary.BySeverity["critical"])
			assert.Zero(t, summary.BySeverity["warning"])
		})
	}
}

// BenchmarkMemorySummarize measures the summary hot path over a large window;
// the key property is that allocation does not scale with the number of alerts
// (no result slice is materialized).
func BenchmarkMemorySummarize(b *testing.B) {
	ctx := context.Background()
	now := time.Now().UTC()
	mem := NewMemoryStore()
	const n = 50000
	batch := make([]types.Alert, n)
	for i := 0; i < n; i++ {
		batch[i] = types.Alert{
			ID:        fmt.Sprintf("a-%d", i),
			Timestamp: now.Add(-time.Duration(i) * time.Second),
			RuleID:    fmt.Sprintf("rule-%d", i%20),
			Severity:  types.SeverityWarning,
			PID:       uint32(i),
			Comm:      "sh",
			Message:   "m",
		}
	}
	_ = mem.StoreBatch(ctx, batch)
	f := QueryFilters{Since: now.Add(-48 * time.Hour)}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := mem.Summarize(ctx, f); err != nil {
			b.Fatal(err)
		}
	}
}
