package correlator

import (
	"context"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// benchEngine builds a correlation engine with the default-ish config used in
// production: anomaly detection on, lineage tracking on (via the auto-created
// tracker), dedup on. Rate-limit windows are widened so the limiter never trips
// during the benchmark.
func benchEngine() *CorrelationEngine {
	cfg := DefaultCorrelationEngineConfig()
	cfg.Rules = []Rule{
		newSyscallRule("bench_rule", OpIn, []string{"1", "2", "3"}),
	}
	// Shorten the learning period so the anomaly detector exits learning quickly
	// and we exercise the scoring path, not just baseline folding.
	cfg.LearningPeriod = time.Nanosecond
	cfg.MinLearningSamples = 1
	return NewCorrelationEngineWithConfig(cfg)
}

// BenchmarkIngest_NoMatch_Syscall measures the full synchronous Ingest hot path
// on the dominant production case: a syscall event that matches no rule and
// produces no alert. Exercises buffer.Add, lineage Track + GetProcessTree, and
// anomaly ProcessEvent. PID varies so per-PID structures see realistic churn.
func BenchmarkIngest_NoMatch_Syscall(b *testing.B) {
	engine := benchEngine()
	defer engine.Close()
	ctx := context.Background()
	now := uint64(time.Now().UnixNano())

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ev := types.Event{
			Type:      types.EventSyscall,
			PID:       uint32(i&1023) + 1, // 1024 distinct PIDs
			PPID:      1,
			Timestamp: now,
			Syscall:   &types.SyscallEvent{Nr: 59}, // not in {1,2,3} → no match
		}
		engine.Ingest(ctx, ev)
	}
}

// BenchmarkIngest_Parallel_NoMatch measures the parallel async ingest path,
// where the PID-partitioned worker pool is supposed to scale across cores.
// A global lock anywhere on the per-event path (e.g. lineage Track) shows up
// here as poor scaling / high ns/op under -cpu=N.
func BenchmarkIngest_Parallel_NoMatch(b *testing.B) {
	engine := benchEngine()
	defer engine.Close()
	ctx := context.Background()
	now := uint64(time.Now().UnixNano())

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var i uint32
		for pb.Next() {
			i++
			ev := types.Event{
				Type:      types.EventSyscall,
				PID:       i & 4095, // wide PID spread across goroutines
				PPID:      1,
				Timestamp: now,
				Syscall:   &types.SyscallEvent{Nr: 59},
			}
			engine.IngestAsync(ctx, ev)
		}
	})
}
