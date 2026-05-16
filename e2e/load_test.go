// Package e2e provides load testing for ebpf-guard.
package e2e

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// LoadTestConfig defines load test parameters.
type LoadTestConfig struct {
	// TargetEventsPerSecond is the target event generation rate
	TargetEventsPerSecond int
	// TestDuration is how long to run the load test
	TestDuration time.Duration
	// ConcurrentClients is the number of concurrent HTTP clients
	ConcurrentClients int
}

// DefaultLoadTestConfig returns a default load test configuration.
func DefaultLoadTestConfig() LoadTestConfig {
	return LoadTestConfig{
		TargetEventsPerSecond: 1000,
		TestDuration:          30 * time.Second,
		ConcurrentClients:     10,
	}
}

// LoadTestResult contains the results of a load test.
type LoadTestResult struct {
	TotalRequests   int64
	SuccessfulReqs  int64
	FailedReqs      int64
	AvgResponseTime time.Duration
	MaxResponseTime time.Duration
	MinResponseTime time.Duration
	EventsPerSecond float64
	MemoryUsageMB   float64
}

// TestLoad verifies the system can handle high event throughput.
func TestLoad(t *testing.T) {
	if os.Getenv("RUN_LOAD_TESTS") != "1" {
		t.Skip("Skipping load tests. Set RUN_LOAD_TESTS=1 to enable.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	config := DefaultLoadTestConfig()

	// Start the container
	req := testcontainers.ContainerRequest{
		FromDockerfile: testcontainers.FromDockerfile{
			Context:       "..",
			Dockerfile:    "Dockerfile",
			PrintBuildLog: true,
		},
		ExposedPorts: []string{"9090/tcp"},
		WaitingFor:   wait.ForHTTP("/health").WithPort("9090"),
		Privileged:   true,
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)
	defer container.Terminate(ctx)

	ip, err := container.Host(ctx)
	require.NoError(t, err)

	port, err := container.MappedPort(ctx, "9090")
	require.NoError(t, err)

	baseURL := fmt.Sprintf("http://%s:%s", ip, port.Port())

	// Run load test
	result := runLoadTest(ctx, t, baseURL, config)

	// Verify results
	t.Logf("Load test results:")
	t.Logf("  Total requests: %d", result.TotalRequests)
	t.Logf("  Successful: %d", result.SuccessfulReqs)
	t.Logf("  Failed: %d", result.FailedReqs)
	t.Logf("  Avg response time: %v", result.AvgResponseTime)
	t.Logf("  Events/sec: %.2f", result.EventsPerSecond)

	// Assert performance requirements
	assert.Greater(t, result.EventsPerSecond, 100.0, "Should handle at least 100 events/sec")
	assert.Less(t, result.AvgResponseTime, 100*time.Millisecond, "Avg response time should be < 100ms")
	assert.Equal(t, int64(0), result.FailedReqs, "Should have no failed requests")
}

// runLoadTest executes the load test and returns results.
func runLoadTest(ctx context.Context, t *testing.T, baseURL string, config LoadTestConfig) LoadTestResult {
	var (
		totalRequests  int64
		successfulReqs int64
		failedReqs     int64
		totalDuration  time.Duration
		maxDuration    time.Duration
		minDuration    = time.Hour
		mu             sync.Mutex
	)

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// Create a channel to distribute work
	workCh := make(chan struct{}, config.ConcurrentClients)

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < config.ConcurrentClients; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range workCh {
				start := time.Now()
				resp, err := client.Get(baseURL + "/metrics")
				duration := time.Since(start)

				mu.Lock()
				totalRequests++
				totalDuration += duration
				if duration > maxDuration {
					maxDuration = duration
				}
				if duration < minDuration {
					minDuration = duration
				}
				if err == nil && resp.StatusCode == http.StatusOK {
					successfulReqs++
				} else {
					failedReqs++
				}
				mu.Unlock()

				if resp != nil {
					resp.Body.Close()
				}

				// Check context
				select {
				case <-ctx.Done():
					return
				default:
				}
			}
		}()
	}

	// Generate load
	ticker := time.NewTicker(time.Second / time.Duration(config.TargetEventsPerSecond/config.ConcurrentClients))
	defer ticker.Stop()

	testCtx, cancel := context.WithTimeout(ctx, config.TestDuration)
	defer cancel()

loop:
	for {
		select {
		case <-testCtx.Done():
			break loop
		case <-ticker.C:
			select {
			case workCh <- struct{}{}:
			default:
			}
		}
	}

	close(workCh)
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()

	avgDuration := time.Duration(0)
	if totalRequests > 0 {
		avgDuration = totalDuration / time.Duration(totalRequests)
	}

	eventsPerSecond := float64(totalRequests) / config.TestDuration.Seconds()

	return LoadTestResult{
		TotalRequests:   totalRequests,
		SuccessfulReqs:  successfulReqs,
		FailedReqs:      failedReqs,
		AvgResponseTime: avgDuration,
		MaxResponseTime: maxDuration,
		MinResponseTime: minDuration,
		EventsPerSecond: eventsPerSecond,
	}
}

// BenchmarkEventProcessing benchmarks event processing performance.
func BenchmarkEventProcessing(b *testing.B) {
	if os.Getenv("RUN_BENCHMARKS") != "1" {
		b.Skip("Skipping benchmarks. Set RUN_BENCHMARKS=1 to enable.")
	}

	// This is a placeholder for actual event processing benchmarks
	// Real implementation would inject events and measure throughput
	b.Run("ParseSyscallEvent", func(b *testing.B) {
		// Benchmark syscall event parsing
		b.SetBytes(104) // Size of SyscallEvent
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Event parsing logic here
		}
	})

	b.Run("ParseNetworkEvent", func(b *testing.B) {
		// Benchmark network event parsing
		b.SetBytes(53) // Size of NetworkEvent
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Event parsing logic here
		}
	})

	b.Run("ParseFileEvent", func(b *testing.B) {
		// Benchmark file event parsing
		b.SetBytes(305) // Size of FileaccessEvent
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Event parsing logic here
		}
	})
}
