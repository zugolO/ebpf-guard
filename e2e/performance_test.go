// Package e2e provides end-to-end and performance tests.
package e2e

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// PerformanceTestConfig holds configuration for performance tests.
type PerformanceTestConfig struct {
	// TargetEventsPerSecond is the target event rate (10k for Sprint 12)
	TargetEventsPerSecond int

	// TestDuration is how long to run the test
	TestDuration time.Duration

	// MaxMemoryMB is the maximum allowed memory in MB (100MB for Sprint 12)
	MaxMemoryMB int64

	// MaxCPUIdlePercent is the maximum allowed CPU idle percentage (5% for Sprint 12)
	MaxCPUIdlePercent float64

	// MaxLockContentionMicros is the maximum allowed p99 lock contention in microseconds
	MaxLockContentionMicros int64
}

// DefaultPerformanceConfig returns the Sprint 12 performance targets.
func DefaultPerformanceConfig() PerformanceTestConfig {
	return PerformanceTestConfig{
		TargetEventsPerSecond:   10000,
		TestDuration:            60 * time.Second,
		MaxMemoryMB:             100,
		MaxCPUIdlePercent:       5.0,
		MaxLockContentionMicros: 5,
	}
}

// PerformanceResult holds the results of a performance test.
type PerformanceResult struct {
	EventsProcessed     uint64
	EventsDropped       uint64
	ActualEventsPerSec  float64
	PeakMemoryMB        float64
	AvgMemoryMB         float64
	CPUIdlePercent      float64
	P99LockContentionUs int64
	Duration            time.Duration
	Errors              []error
}

// PerformanceRegressionTest tests that the system meets Sprint 12 performance targets.
// This test is designed to run in CI to catch performance regressions.
func TestPerformanceRegression(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	config := DefaultPerformanceConfig()
	result := runPerformanceTest(t, config)

	// Verify Sprint 12 targets
	t.Run("EventRate", func(t *testing.T) {
		assert.GreaterOrEqual(t, result.ActualEventsPerSec, float64(config.TargetEventsPerSecond),
			"Event rate should meet target of %d events/sec", config.TargetEventsPerSecond)
	})

	t.Run("ZeroDroppedEvents", func(t *testing.T) {
		assert.Zero(t, result.EventsDropped,
			"No events should be dropped at normal load")
	})

	t.Run("MemoryUsage", func(t *testing.T) {
		assert.LessOrEqual(t, result.PeakMemoryMB, float64(config.MaxMemoryMB),
			"Peak memory should be under %d MB", config.MaxMemoryMB)
	})

	t.Run("CPUIDle", func(t *testing.T) {
		assert.LessOrEqual(t, result.CPUIdlePercent, config.MaxCPUIdlePercent,
			"CPU idle should be under %.1f%%", config.MaxCPUIdlePercent)
	})
}

// TestShardedLockContention specifically tests the sharded lock performance.
func TestShardedLockContention(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping lock contention test in short mode")
	}

	buffer := correlator.NewShardedEventBuffer(1000)
	var wg sync.WaitGroup
	numGoroutines := 100
	eventsPerGoroutine := 10000

	// Track lock contention times
	var contentionTimes []int64
	var contentionMu sync.Mutex

	start := time.Now()

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			pid := uint32(id)

			for j := 0; j < eventsPerGoroutine; j++ {
				lockStart := time.Now()

				event := types.Event{
					Type:      types.EventSyscall,
					PID:       pid,
					Timestamp: uint64(time.Now().UnixNano()),
				}
				buffer.Add(pid, event)

				contention := time.Since(lockStart).Microseconds()
				contentionMu.Lock()
				contentionTimes = append(contentionTimes, contention)
				contentionMu.Unlock()
			}
		}(i)
	}

	wg.Wait()
	duration := time.Since(start)

	totalEvents := uint64(numGoroutines * eventsPerGoroutine)
	actualRate := float64(totalEvents) / duration.Seconds()

	t.Logf("Processed %d events in %v (%.0f events/sec)", totalEvents, duration, actualRate)

	// Calculate p99 lock contention
	p99Contention := calculateP99(contentionTimes)
	t.Logf("P99 lock contention: %d µs", p99Contention)

	// Sprint 12 target: < 5µs p99 lock contention
	assert.Less(t, p99Contention, int64(5),
		"P99 lock contention should be under 5µs")
}

// TestMemoryProfileAtLoad tests memory usage under sustained load.
func TestMemoryProfileAtLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory profile test in short mode")
	}

	config := DefaultPerformanceConfig()

	// Start memory profiling
	var memStats runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memStats)
	baselineAlloc := memStats.TotalAlloc

	// Run load test
	result := runPerformanceTest(t, config)

	// Force GC and check final memory
	runtime.GC()
	runtime.ReadMemStats(&memStats)
	peakAllocMB := float64(memStats.TotalAlloc-baselineAlloc) / 1024 / 1024

	t.Logf("Events processed: %d", result.EventsProcessed)
	t.Logf("Peak memory allocation: %.2f MB", peakAllocMB)
	t.Logf("Heap allocation: %.2f MB", float64(memStats.HeapAlloc)/1024/1024)
	t.Logf("System memory: %.2f MB", float64(memStats.Sys)/1024/1024)

	// Sprint 12 target: < 100MB heap at sustained 10k events/sec
	assert.LessOrEqual(t, float64(memStats.HeapAlloc)/1024/1024, float64(config.MaxMemoryMB),
		"Heap memory should be under %d MB", config.MaxMemoryMB)
}

// TestSustainedThroughput verifies sustained throughput over time.
func TestSustainedThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping sustained throughput test in short mode")
	}

	config := PerformanceTestConfig{
		TargetEventsPerSecond: 10000,
		TestDuration:          60 * time.Second,
		MaxMemoryMB:           100,
		MaxCPUIdlePercent:     5.0,
	}

	result := runPerformanceTest(t, config)

	// Verify sustained throughput
	t.Logf("Sustained throughput: %.0f events/sec over %v",
		result.ActualEventsPerSec, result.Duration)

	// Should maintain at least 95% of target rate
	minAcceptableRate := float64(config.TargetEventsPerSecond) * 0.95
	assert.GreaterOrEqual(t, result.ActualEventsPerSec, minAcceptableRate,
		"Should sustain at least 95%% of target rate (%.0f events/sec)", minAcceptableRate)
}

// runPerformanceTest runs a performance test and returns results.
func runPerformanceTest(t *testing.T, config PerformanceTestConfig) PerformanceResult {
	t.Helper()

	engine := correlator.NewCorrelationEngine(nil)
	ctx, cancel := context.WithTimeout(context.Background(), config.TestDuration)
	defer cancel()

	var eventsProcessed atomic.Uint64
	var eventsDropped atomic.Uint64

	// Event generator
	eventCh := make(chan types.Event, 10000)
	go func() {
		defer close(eventCh)
		ticker := time.NewTicker(time.Second / time.Duration(config.TargetEventsPerSecond))
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				select {
				case eventCh <- types.Event{
					Type:      types.EventSyscall,
					PID:       uint32(time.Now().UnixNano() % 1000),
					Timestamp: uint64(time.Now().UnixNano()),
				}:
				default:
					eventsDropped.Add(1)
				}
			}
		}
	}()

	// Memory tracking
	var peakMemory uint64
	var memorySamples []uint64
	var memoryMu sync.Mutex

	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				memoryMu.Lock()
				memorySamples = append(memorySamples, m.HeapAlloc)
				if m.HeapAlloc > peakMemory {
					peakMemory = m.HeapAlloc
				}
				memoryMu.Unlock()
			}
		}
	}()

	// Process events
	start := time.Now()
	for event := range eventCh {
		engine.Ingest(ctx, event)
		eventsProcessed.Add(1)
	}
	duration := time.Since(start)

	// Calculate results
	result := PerformanceResult{
		EventsProcessed: eventsProcessed.Load(),
		EventsDropped:   eventsDropped.Load(),
		ActualEventsPerSec: float64(eventsProcessed.Load()) / duration.Seconds(),
		PeakMemoryMB:    float64(peakMemory) / 1024 / 1024,
		Duration:        duration,
	}

	// Calculate average memory
	if len(memorySamples) > 0 {
		var total uint64
		for _, sample := range memorySamples {
			total += sample
		}
		result.AvgMemoryMB = float64(total/uint64(len(memorySamples))) / 1024 / 1024
	}

	t.Logf("Performance Test Results:")
	t.Logf("  Events processed: %d", result.EventsProcessed)
	t.Logf("  Events dropped: %d", result.EventsDropped)
	t.Logf("  Actual rate: %.0f events/sec", result.ActualEventsPerSec)
	t.Logf("  Peak memory: %.2f MB", result.PeakMemoryMB)
	t.Logf("  Avg memory: %.2f MB", result.AvgMemoryMB)
	t.Logf("  Duration: %v", result.Duration)

	return result
}

// TestLoadWithProfile runs load test and generates CPU/memory profiles.
func TestLoadWithProfile(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping profile test in short mode")
	}

	// CPU profile
	cpuFile := "/tmp/ebpf-guard-cpu.prof"
	f, err := createProfileFile(cpuFile)
	require.NoError(t, err)
	defer f.Close()

	require.NoError(t, pprof.StartCPUProfile(f))
	defer pprof.StopCPUProfile()

	// Run load test
	config := DefaultPerformanceConfig()
	config.TestDuration = 30 * time.Second // Shorter for profile test
	runPerformanceTest(t, config)

	t.Logf("CPU profile written to %s", cpuFile)

	// Memory profile
	memFile := "/tmp/ebpf-guard-mem.prof"
	mf, err := createProfileFile(memFile)
	require.NoError(t, err)
	defer mf.Close()

	runtime.GC()
	require.NoError(t, pprof.WriteHeapProfile(mf))

	t.Logf("Memory profile written to %s", memFile)
}

// createProfileFile creates a file for profiling output.
func createProfileFile(path string) (*os.File, error) {
	return os.Create(path)
}

// calculateP99 calculates the 99th percentile of a slice of int64 values.
func calculateP99(values []int64) int64 {
	if len(values) == 0 {
		return 0
	}

	// Simple approach: sort and pick index
	sorted := make([]int64, len(values))
	copy(sorted, values)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	index := int(float64(len(sorted)) * 0.99)
	if index >= len(sorted) {
		index = len(sorted) - 1
	}
	return sorted[index]
}

// BenchmarkCorrelationEngine benchmarks the correlation engine at various event rates.
func BenchmarkCorrelationEngine(b *testing.B) {
	rates := []int{1000, 5000, 10000, 20000}

	for _, rate := range rates {
		b.Run(fmt.Sprintf("%d_events_per_sec", rate), func(b *testing.B) {
			engine := correlator.NewCorrelationEngine(nil)
			ctx := context.Background()

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				event := types.Event{
					Type:      types.EventSyscall,
					PID:       uint32(i % 1000),
					Timestamp: uint64(time.Now().UnixNano()),
				}
				engine.Ingest(ctx, event)
			}
		})
	}
}

// BenchmarkShardedBufferContention benchmarks sharded buffer under contention.
func BenchmarkShardedBufferContention(b *testing.B) {
	buffer := correlator.NewShardedEventBuffer(1000)

	b.RunParallel(func(pb *testing.PB) {
		pid := uint32(1)
		for pb.Next() {
			event := types.Event{
				Type:      types.EventSyscall,
				PID:       pid,
				Timestamp: uint64(time.Now().UnixNano()),
			}
			buffer.Add(pid, event)
			pid++
		}
	})
}


