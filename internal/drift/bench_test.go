package drift

import (
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// discardLogger returns a logger that discards all output, keeping benchmark
// timings clean of I/O from slog calls.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// BenchmarkDetector_Ingest measures the hot path: ingesting a single event into a
// locked baseline (drift-detection mode). This is called from the correlation
// engine on every event that carries Kubernetes enrichment.
//
// Target: < 5 µs/op under the race detector.
func BenchmarkDetector_Ingest(b *testing.B) {
	b.Run("SyscallKnown", func(b *testing.B) {
		d := lockedDetector(b)
		e := makeBenchSyscallEvent(0, "c0")
		b.ResetTimer()
		for range b.N {
			_ = d.Ingest(e)
		}
	})

	b.Run("SyscallUnknown_Drift", func(b *testing.B) {
		d := lockedDetector(b)
		e := makeBenchSyscallEvent(999, "c0")
		b.ResetTimer()
		for range b.N {
			_ = d.Ingest(e)
		}
	})

	b.Run("FileAccess_Exec_Known", func(b *testing.B) {
		d := lockedDetector(b)
		e := makeBenchFileEvent("/usr/bin/nginx", "c0")
		b.ResetTimer()
		for range b.N {
			_ = d.Ingest(e)
		}
	})

	b.Run("FileAccess_Exec_Drift", func(b *testing.B) {
		d := lockedDetector(b)
		e := makeBenchFileEvent("/usr/bin/curl", "c0")
		b.ResetTimer()
		for range b.N {
			_ = d.Ingest(e)
		}
	})

	b.Run("NoEnrichment_FastPath", func(b *testing.B) {
		d := NewDetector(DetectorConfig{BaselineWindow: time.Millisecond, Logger: discardLogger()})
		var comm [16]byte
		e := types.Event{Type: types.EventSyscall, Comm: comm, Syscall: &types.SyscallEvent{Nr: 0}}
		b.ResetTimer()
		for range b.N {
			_ = d.Ingest(e)
		}
	})
}

// BenchmarkDetector_Ingest_Parallel measures contention across multiple goroutines
// ingesting events for different containers, simulating a busy node.
func BenchmarkDetector_Ingest_Parallel(b *testing.B) {
	const containers = 16

	d := NewDetector(DetectorConfig{BaselineWindow: time.Millisecond, Logger: discardLogger()})
	// Pre-create and lock baselines for all containers.
	for i := range containers {
		cid := fmt.Sprintf("c%d", i)
		e := makeBenchSyscallEvent(int64(i), cid)
		_ = d.Ingest(e)
	}
	time.Sleep(5 * time.Millisecond)
	// Trigger lock on each.
	for i := range containers {
		cid := fmt.Sprintf("c%d", i)
		_ = d.Ingest(makeBenchSyscallEvent(int64(i), cid))
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var i int
		for pb.Next() {
			cid := fmt.Sprintf("c%d", i%containers)
			_ = d.Ingest(makeBenchSyscallEvent(int64(i%containers), cid))
			i++
		}
	})
}

// BenchmarkBaseline_RecordSyscall measures the baseline learning path, which
// runs on every event during the learning window.
func BenchmarkBaseline_RecordSyscall(b *testing.B) {
	bl := newContainerBaseline("bench-cid", "default", "bench-pod", time.Hour)
	b.ResetTimer()
	for i := range b.N {
		bl.recordSyscall(int64(i % 400)) // realistic syscall number range
	}
}

// BenchmarkBaseline_RecordSyscall_Parallel measures concurrent writes to a single
// baseline (multiple goroutines ingesting events for the same container).
func BenchmarkBaseline_RecordSyscall_Parallel(b *testing.B) {
	bl := newContainerBaseline("bench-cid", "default", "bench-pod", time.Hour)
	b.RunParallel(func(pb *testing.PB) {
		var i int64
		for pb.Next() {
			bl.recordSyscall(i % 400)
			i++
		}
	})
}

// BenchmarkPurgeStale measures the cost of pruning expired baselines, which runs
// in the background cleanup goroutine.
func BenchmarkPurgeStale(b *testing.B) {
	const n = 1000

	b.ResetTimer()
	for range b.N {
		b.StopTimer()
		d := NewDetector(DetectorConfig{BaselineWindow: time.Millisecond, Logger: discardLogger()})
		for i := range n {
			_ = d.Ingest(makeBenchSyscallEvent(0, fmt.Sprintf("c%d", i)))
		}
		time.Sleep(5 * time.Millisecond) // let windows expire
		b.StartTimer()
		_ = d.PurgeStale(0)
	}
}

// --- helpers ---

// lockedDetector returns a Detector with one pre-populated, locked baseline.
// It records syscall 0 and file path /usr/bin/nginx during the learning window.
func lockedDetector(b *testing.B) *Detector {
	b.Helper()
	d := NewDetector(DetectorConfig{BaselineWindow: time.Millisecond, Logger: discardLogger()})
	_ = d.Ingest(makeBenchSyscallEvent(0, "c0"))
	_ = d.Ingest(makeBenchFileEvent("/usr/bin/nginx", "c0"))
	time.Sleep(5 * time.Millisecond) // wait for window to expire
	_ = d.Ingest(makeBenchSyscallEvent(0, "c0")) // trigger lock
	return d
}

func makeBenchSyscallEvent(nr int64, cid string) types.Event {
	var comm [16]byte
	copy(comm[:], "nginx")
	return types.Event{
		Type: types.EventSyscall,
		PID:  1234,
		Comm: comm,
		Enrichment: &types.EnrichmentInfo{
			ContainerID: cid,
			Namespace:   "default",
			PodName:     "bench-pod",
		},
		Syscall: &types.SyscallEvent{Nr: nr},
	}
}

func makeBenchFileEvent(path, cid string) types.Event {
	var comm [16]byte
	copy(comm[:], "nginx")
	var fn [256]byte
	copy(fn[:], path)
	return types.Event{
		Type: types.EventFileAccess,
		PID:  1234,
		Comm: comm,
		Enrichment: &types.EnrichmentInfo{
			ContainerID: cid,
			Namespace:   "default",
			PodName:     "bench-pod",
		},
		File: &types.FileEvent{Filename: fn},
	}
}
