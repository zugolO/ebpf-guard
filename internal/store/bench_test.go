package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// BenchmarkStore_Store benchmarks single alert insertion.
func BenchmarkStore_Store(b *testing.B) {
	store := NewMemoryStore()
	ctx := context.Background()

	alert := types.Alert{
		ID:        "bench-alert",
		Timestamp: time.Now(),
		RuleID:    "rule-bench",
		Severity:  types.SeverityWarning,
		PID:       1234,
		Comm:      "bench",
		Message:   "Benchmark alert",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		alert.ID = fmt.Sprintf("bench-%d", i)
		if err := store.Store(ctx, alert); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkStore_StoreBatch benchmarks batch alert insertion.
// A fresh store is created each iteration so that the sort cost is independent
// of b.N — this gives a stable measurement of inserting a 300-alert batch into
// an empty store, matching the acceptance criterion (≤ 5 ms/op).
func BenchmarkStore_StoreBatch(b *testing.B) {
	ctx := context.Background()

	const batchSize = 300
	alerts := make([]types.Alert, batchSize)
	for i := 0; i < batchSize; i++ {
		alerts[i] = types.Alert{
			ID:        fmt.Sprintf("bench-%d", i),
			Timestamp: time.Now(),
			RuleID:    "rule-bench",
			Severity:  types.SeverityWarning,
			PID:       uint32(i),
			Comm:      "bench",
			Message:   "Benchmark alert",
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		store := NewMemoryStore()
		// Refresh IDs so each iteration stores unique alerts.
		for j := range alerts {
			alerts[j].ID = fmt.Sprintf("bench-%d-%d", i, j)
		}
		b.StartTimer()

		if err := store.StoreBatch(ctx, alerts); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkStore_Query benchmarks alert querying.
func BenchmarkStore_Query(b *testing.B) {
	store := NewMemoryStore()
	ctx := context.Background()

	// Pre-populate with 10k alerts
	for i := 0; i < 10000; i++ {
		alert := types.Alert{
			ID:        fmt.Sprintf("alert-%d", i),
			Timestamp: time.Now().Add(-time.Duration(i) * time.Second),
			RuleID:    fmt.Sprintf("rule-%d", i%10),
			Severity:  []types.Severity{types.SeverityWarning, types.SeverityCritical}[i%2],
			PID:       uint32(i % 100),
			Comm:      fmt.Sprintf("proc-%d", i%20),
			Message:   fmt.Sprintf("Alert message %d", i),
			Enrichment: types.EnrichmentInfo{
				Namespace: fmt.Sprintf("ns-%d", i%5),
				PodName:   fmt.Sprintf("pod-%d", i%50),
			},
		}
		if err := store.Store(ctx, alert); err != nil {
			b.Fatal(err)
		}
	}

	filters := QueryFilters{
		Since:     time.Now().Add(-time.Hour),
		Severity:  []types.Severity{types.SeverityWarning},
		Namespace: "ns-0",
		Limit:     100,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := store.Query(ctx, filters)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkStore_QueryByID benchmarks single alert lookup by ID.
func BenchmarkStore_QueryByID(b *testing.B) {
	store := NewMemoryStore()
	ctx := context.Background()

	// Pre-populate with 10k alerts
	for i := 0; i < 10000; i++ {
		alert := types.Alert{
			ID:        fmt.Sprintf("alert-%d", i),
			Timestamp: time.Now(),
			RuleID:    "rule-bench",
			Severity:  types.SeverityWarning,
			PID:       1234,
			Comm:      "bench",
			Message:   "Benchmark alert",
		}
		if err := store.Store(ctx, alert); err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id := fmt.Sprintf("alert-%d", i%10000)
		_, err := store.QueryByID(ctx, id)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkStore_Count benchmarks alert counting.
func BenchmarkStore_Count(b *testing.B) {
	store := NewMemoryStore()
	ctx := context.Background()

	// Pre-populate with 10k alerts
	for i := 0; i < 10000; i++ {
		alert := types.Alert{
			ID:        fmt.Sprintf("alert-%d", i),
			Timestamp: time.Now().Add(-time.Duration(i) * time.Second),
			RuleID:    fmt.Sprintf("rule-%d", i%10),
			Severity:  []types.Severity{types.SeverityWarning, types.SeverityCritical}[i%2],
			PID:       uint32(i % 100),
			Comm:      "bench",
			Message:   "Benchmark alert",
		}
		if err := store.Store(ctx, alert); err != nil {
			b.Fatal(err)
		}
	}

	filters := QueryFilters{
		Since:    time.Now().Add(-time.Hour),
		Severity: []types.Severity{types.SeverityWarning},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := store.Count(ctx, filters)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkStore_Delete benchmarks the Delete operation in isolation.
// Setup (StoreBatch of 1000 alerts) is performed outside the timer so that
// alloc/op reflects only the Delete call — expected to be near zero since
// Delete reslices byTime and deletes map keys without allocating.
func BenchmarkStore_Delete(b *testing.B) {
	ctx := context.Background()

	// Build the setup batch once; reuse across b.N iterations.
	const setupCount = 1000
	setupAlerts := make([]types.Alert, setupCount)
	for j := 0; j < setupCount; j++ {
		setupAlerts[j] = types.Alert{
			ID:        fmt.Sprintf("alert-%d", j),
			Timestamp: time.Now().Add(-time.Duration(j*2) * time.Hour),
			RuleID:    "rule-bench",
			Severity:  types.SeverityWarning,
			PID:       1234,
			Comm:      "bench",
			Message:   "Benchmark alert",
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Setup outside the timer so alloc/op measures only Delete.
		b.StopTimer()
		store := NewMemoryStore()
		if err := store.StoreBatch(ctx, setupAlerts); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()

		if _, err := store.Delete(ctx, 24*time.Hour); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkMatchesFilters benchmarks filter matching.
func BenchmarkMatchesFilters(b *testing.B) {
	alert := types.Alert{
		ID:        "alert-1",
		Timestamp: time.Now(),
		RuleID:    "rule-001",
		Severity:  types.SeverityWarning,
		PID:       1234,
		Comm:      "test-process",
		Message:   "Test alert",
		Enrichment: types.EnrichmentInfo{
			PodName:   "test-pod",
			Namespace: "default",
		},
	}

	filters := QueryFilters{
		Since:     time.Now().Add(-time.Hour),
		Until:     time.Now().Add(time.Hour),
		PIDs:      []uint32{1234, 5678},
		Severity:  []types.Severity{types.SeverityWarning, types.SeverityCritical},
		RuleIDs:   []string{"rule-001", "rule-002"},
		PodName:   "test-pod",
		Namespace: "default",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = matchesFilters(alert, filters)
	}
}
