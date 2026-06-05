// Package profiler provides behavioral profiling and anomaly detection benchmarks.
package profiler

import (
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// BenchmarkProcessEvent measures the performance of anomaly detection event processing.
// Target: p99 < 10µs at 10k events/sec sustained throughput.
func BenchmarkProcessEvent(b *testing.B) {
	// Create detector with short learning period so we test the hot path
	ad := NewAnomalyDetector(0.8, 1*time.Millisecond, 0.3)

	// Pre-populate some baseline data during learning
	learningEvent := types.Event{
		Type: types.EventTCPConnect,
		PID:  1234,
		Comm: [16]byte{'t', 'e', 's', 't'},
		Network: &types.NetworkEvent{
			Dport: 443,
			Daddr: [16]byte{1, 2, 3, 4},
		},
	}

	// Record events during learning phase
	for i := 0; i < 100; i++ {
		ad.ProcessEvent(learningEvent, false)
	}

	// Wait for learning to complete
	time.Sleep(2 * time.Millisecond)

	// Verify we're on the hot path (learning complete)
	if !ad.IsLearningComplete() {
		b.Fatal("learning should be complete for benchmark")
	}

	// Test event
	event := types.Event{
		Type: types.EventTCPConnect,
		PID:  1234,
		Comm: [16]byte{'t', 'e', 's', 't'},
		Network: &types.NetworkEvent{
			Dport: 8080, // New port to trigger anomaly calculation
			Daddr: [16]byte{5, 6, 7, 8},
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		result := ad.ProcessEvent(event, false)
		// Prevent compiler from optimizing away the result
		if result != nil && result.PID != 1234 {
			b.Fatal("unexpected PID")
		}
		if result != nil {
			ReleaseResult(result)
		}
	}
}

// BenchmarkProcessEventFileAccess benchmarks file access event processing.
func BenchmarkProcessEventFileAccess(b *testing.B) {
	ad := NewAnomalyDetector(0.8, 1*time.Millisecond, 0.3)

	// Pre-populate baseline
	learningEvent := types.Event{
		Type: types.EventFileAccess,
		PID:  1234,
		Comm: [16]byte{'t', 'e', 's', 't'},
		File: &types.FileEvent{
			Filename: [256]byte{'/', 'e', 't', 'c', '/', 'h', 'o', 's', 't', 's'},
			Op:       0,
		},
	}

	for i := 0; i < 100; i++ {
		ad.ProcessEvent(learningEvent, false)
	}

	time.Sleep(2 * time.Millisecond)

	event := types.Event{
		Type: types.EventFileAccess,
		PID:  1234,
		Comm: [16]byte{'t', 'e', 's', 't'},
		File: &types.FileEvent{
			Filename: [256]byte{'/', 'u', 's', 'r', '/', 's', 'h', 'a', 'r', 'e'},
			Op:       0,
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		result := ad.ProcessEvent(event, false)
		if result != nil && result.PID != 1234 {
			b.Fatal("unexpected PID")
		}
		if result != nil {
			ReleaseResult(result)
		}
	}
}

// BenchmarkProcessEventSyscall benchmarks syscall event processing.
func BenchmarkProcessEventSyscall(b *testing.B) {
	ad := NewAnomalyDetector(0.8, 1*time.Millisecond, 0.3)

	// Pre-populate baseline
	learningEvent := types.Event{
		Type: types.EventSyscall,
		PID:  1234,
		Comm: [16]byte{'t', 'e', 's', 't'},
		Syscall: &types.SyscallEvent{
			Nr: 0, // read
		},
	}

	for i := 0; i < 100; i++ {
		ad.ProcessEvent(learningEvent, false)
	}

	time.Sleep(2 * time.Millisecond)

	event := types.Event{
		Type: types.EventSyscall,
		PID:  1234,
		Comm: [16]byte{'t', 'e', 's', 't'},
		Syscall: &types.SyscallEvent{
			Nr: 59, // execve - uncommon
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		result := ad.ProcessEvent(event, false)
		if result != nil && result.PID != 1234 {
			b.Fatal("unexpected PID")
		}
		if result != nil {
			ReleaseResult(result)
		}
	}
}

// BenchmarkIsLearningComplete benchmarks the learning check hot path.
// This tests the atomic.Bool fast path performance.
func BenchmarkIsLearningComplete(b *testing.B) {
	ad := NewAnomalyDetector(0.8, 1*time.Millisecond, 0.3)

	// Record minimum samples and wait for learning to complete
	for i := 0; i < 110; i++ {
		ad.learner.RecordSample()
	}
	time.Sleep(2 * time.Millisecond)

	// Verify learning is complete
	if !ad.IsLearningComplete() {
		b.Fatal("learning should be complete")
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		if !ad.IsLearningComplete() {
			b.Fatal("should be complete")
		}
	}
}

// BenchmarkProcessEventParallel tests concurrent event processing.
func BenchmarkProcessEventParallel(b *testing.B) {
	ad := NewAnomalyDetector(0.8, 1*time.Millisecond, 0.3)

	// Pre-populate baseline for multiple PIDs
	for pid := uint32(1); pid <= 100; pid++ {
		learningEvent := types.Event{
			Type: types.EventTCPConnect,
			PID:  pid,
			Comm: [16]byte{'t', 'e', 's', 't'},
			Network: &types.NetworkEvent{
				Dport: 443,
				Daddr: [16]byte{1, 2, 3, 4},
			},
		}
		for i := 0; i < 10; i++ {
			ad.ProcessEvent(learningEvent, false)
		}
	}

	time.Sleep(2 * time.Millisecond)

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		pid := uint32(1)
		event := types.Event{
			Type: types.EventTCPConnect,
			PID:  pid,
			Comm: [16]byte{'t', 'e', 's', 't'},
			Network: &types.NetworkEvent{
				Dport: 8080,
				Daddr: [16]byte{5, 6, 7, 8},
			},
		}

		for pb.Next() {
			result := ad.ProcessEvent(event, false)
			if result != nil && result.PID != pid {
				b.Fatal("unexpected PID")
			}
			if result != nil {
				ReleaseResult(result)
			}
		}
	})
}
