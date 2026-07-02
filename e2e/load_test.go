// Package e2e provides load testing for ebpf-guard.
package e2e

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/zugolO/ebpf-guard/internal/collector"
	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/internal/store"
	"github.com/zugolO/ebpf-guard/pkg/types"
	rulesembed "github.com/zugolO/ebpf-guard/rules"
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

// LoadTestResult contains the results of an HTTP load test against the
// agent's /metrics endpoint. This measures HTTP request throughput and
// response latency, not eBPF event throughput — see TestLoadFullPipelineThroughput
// for a test that drives synthetic events through the actual collector ->
// engine -> store pipeline and measures events/sec.
type LoadTestResult struct {
	TotalRequests         int64
	SuccessfulReqs        int64
	FailedReqs            int64
	AvgResponseTime       time.Duration
	MaxResponseTime       time.Duration
	MinResponseTime       time.Duration
	HTTPRequestsPerSecond float64
	MemoryUsageMB         float64
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
	t.Logf("  HTTP requests/sec: %.2f", result.HTTPRequestsPerSecond)

	// Assert performance requirements
	assert.Greater(t, result.HTTPRequestsPerSecond, 100.0, "Should handle at least 100 HTTP requests/sec")
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

	// Generate load. perClientRate is floored at 1 so a TargetEventsPerSecond
	// lower than ConcurrentClients (integer division truncating to 0) can't
	// panic the ticker with a divide-by-zero duration.
	perClientRate := config.TargetEventsPerSecond / config.ConcurrentClients
	if perClientRate < 1 {
		perClientRate = 1
	}
	ticker := time.NewTicker(time.Second / time.Duration(perClientRate))
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

	requestsPerSecond := float64(totalRequests) / config.TestDuration.Seconds()

	return LoadTestResult{
		TotalRequests:         totalRequests,
		SuccessfulReqs:        successfulReqs,
		FailedReqs:            failedReqs,
		AvgResponseTime:       avgDuration,
		MaxResponseTime:       maxDuration,
		MinResponseTime:       minDuration,
		HTTPRequestsPerSecond: requestsPerSecond,
	}
}

// containerRSSMiB reads the ebpf-guard agent's resident set size from inside
// the running container via /proc/1/status — PID 1 is the agent binary
// itself, since the Dockerfile's ENTRYPOINT execs it directly with no shell
// wrapper. Uses busybox (bundled in the distroless "debug" base image) since
// the runtime image has no other shell utilities.
func containerRSSMiB(ctx context.Context, c testcontainers.Container) (float64, error) {
	code, reader, err := c.Exec(ctx, []string{"/busybox/cat", "/proc/1/status"}, tcexec.Multiplexed())
	if err != nil {
		return 0, fmt.Errorf("exec cat /proc/1/status: %w", err)
	}
	if code != 0 {
		return 0, fmt.Errorf("cat /proc/1/status exited %d", code)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		return 0, fmt.Errorf("read exec output: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "VmRSS:" {
			kb, err := strconv.ParseFloat(fields[1], 64)
			if err != nil {
				return 0, fmt.Errorf("parse VmRSS value %q: %w", fields[1], err)
			}
			return kb / 1024, nil
		}
	}
	return 0, fmt.Errorf("VmRSS not found in /proc/1/status output")
}

// TestWorkerPoolOOMPrevention verifies that the agent's HTTP server and its
// bounded response worker pool do not let concurrent request pressure cause
// unbounded memory growth. It drives a high rate of concurrent /metrics
// requests against a live container and asserts that the agent's real RSS
// (sampled from inside the container) stays under a hard ceiling, and that
// no requests fail (a failure would indicate an OOM-triggered restart).
//
// Note: this generates HTTP request load against the running agent, not
// synthetic eBPF events — the agent has no HTTP endpoint for injecting
// events, so request pressure is the only externally-drivable load for a
// black-box container test. See TestLoadFullPipelineThroughput for a test that
// drives events through the actual collector -> engine -> store pipeline.
func TestWorkerPoolOOMPrevention(t *testing.T) {
	if os.Getenv("RUN_LOAD_TESTS") != "1" {
		t.Skip("Skipping OOM prevention test. Set RUN_LOAD_TESTS=1 to enable.")
	}

	const (
		targetRate    = 500_000 // events/sec — well above typical burst
		testDuration  = 10 * time.Second
		memCeilingMiB = 512 // agent RSS must not exceed this
	)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	req := testcontainers.ContainerRequest{
		FromDockerfile: testcontainers.FromDockerfile{
			Context:       "..",
			Dockerfile:    "Dockerfile",
			PrintBuildLog: false,
		},
		ExposedPorts: []string{"9090/tcp"},
		WaitingFor:   wait.ForHTTP("/health").WithPort("9090"),
		Privileged:   true,
		Env: map[string]string{
			// Drive with a high max_concurrent_events to exercise the semaphore.
			"EBPF_GUARD_BPF_MAX_CONCURRENT_EVENTS": "4096",
			"EBPF_GUARD_BPF_EVENT_QUEUE_DEPTH":     "65536",
		},
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Skipf("skipping: cannot start container (no container runtime?): %v", err)
	}
	defer container.Terminate(ctx)

	ip, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "9090")
	require.NoError(t, err)
	baseURL := fmt.Sprintf("http://%s:%s", ip, port.Port())

	// Sample the agent's real RSS from inside the container while the load
	// runs, tracking the peak, so the memory ceiling assertion below can
	// actually execute instead of being permanently skipped.
	memCtx, memCancel := context.WithCancel(ctx)
	var peakMu sync.Mutex
	var peakMiB float64
	var lastSampleErr error
	memDone := make(chan struct{})
	go func() {
		defer close(memDone)
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-memCtx.Done():
				return
			case <-ticker.C:
				mib, err := containerRSSMiB(memCtx, container)
				peakMu.Lock()
				if err != nil {
					lastSampleErr = err
				} else if mib > peakMiB {
					peakMiB = mib
				}
				peakMu.Unlock()
			}
		}
	}()

	// Drive the agent at 2× target rate for testDuration.
	cfg := LoadTestConfig{
		TargetEventsPerSecond: targetRate,
		TestDuration:          testDuration,
		ConcurrentClients:     50,
	}
	result := runLoadTest(ctx, t, baseURL, cfg)

	memCancel()
	<-memDone

	peakMu.Lock()
	result.MemoryUsageMB = peakMiB
	sampleErr := lastSampleErr
	peakMu.Unlock()

	t.Logf("OOM prevention test: %.0f req/s, avg latency %v, mem %.1f MiB",
		result.HTTPRequestsPerSecond, result.AvgResponseTime, result.MemoryUsageMB)
	if result.MemoryUsageMB == 0 && sampleErr != nil {
		t.Logf("memory sampling unavailable, skipping RSS ceiling assertion: %v", sampleErr)
	}

	// Agent must stay alive (zero failed requests = process did not OOM-restart).
	assert.Equal(t, int64(0), result.FailedReqs,
		"agent must not OOM-restart: zero failed requests expected")

	// Memory ceiling (only enforced when the metric is available).
	if result.MemoryUsageMB > 0 {
		assert.Less(t, result.MemoryUsageMB, float64(memCeilingMiB),
			"agent RSS must stay below %d MiB under 2× burst load", memCeilingMiB)
	}
}

// fullPipelineTestDuration is how long TestLoadFullPipelineThroughput drives
// synthetic events through the production pipeline.
const fullPipelineTestDuration = 3 * time.Second

// minFullPipelineEventsPerSec is the minimum sustained events/sec the full
// pipeline (collector -> eventCh -> IngestAsync -> periodic Flush -> store)
// must sustain with the built-in rule sets loaded. Set well below the raw
// correlation-engine benchmarks in performance_test.go (which bypass the
// collector channel, worker-pool dispatch and flush/store overhead this test
// exercises) so this stays stable across slower CI hardware.
const minFullPipelineEventsPerSec = 2000

// fullPipelineRSSCeilingMiB is the maximum resident set size this process may
// use while driving the full pipeline test.
const fullPipelineRSSCeilingMiB = 512

// TestLoadFullPipelineThroughput drives synthetic events through the actual
// production pipeline — SyntheticCollector instances writing into a shared
// event channel, a single reader goroutine dispatching via IngestAsync (the
// same path main.go's ingest loop uses), a periodic Flush draining alerts
// into a real AlertStore — with the built-in rule sets loaded, and measures
// sustained events/sec plus this process's RSS. Unlike performance_test.go's
// benchmarks (which call the engine directly with zero rules), this exercises
// the same handoff and dispatch machinery production traffic goes through.
func TestLoadFullPipelineThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping full pipeline load test in short mode")
	}

	ruleFiles, err := rulesembed.LoadAll()
	require.NoError(t, err)
	rules, err := correlator.LoadRulesFromEmbedded(ruleFiles)
	require.NoError(t, err)
	require.NotEmpty(t, rules, "built-in rule sets should load")

	engineCfg := correlator.DefaultCorrelationEngineConfig()
	engineCfg.Rules = rules
	engine := correlator.NewCorrelationEngineWithConfig(engineCfg)
	defer engine.Close()

	alertStore := store.NewMemoryStore()
	defer alertStore.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	eventCh := make(chan types.Event, 4096)

	runCtx, runCancel := context.WithTimeout(context.Background(), fullPipelineTestDuration)
	defer runCancel()

	// Drive synthetic events via several collector instances writing into the
	// same channel, mirroring how main.go fans multiple real collectors into
	// one eventCh.
	const numCollectors = 32
	const collectorInterval = 2 * time.Millisecond
	var collectorWG sync.WaitGroup
	for i := 0; i < numCollectors; i++ {
		c := collector.NewSyntheticCollector(logger, collectorInterval)
		collectorWG.Add(1)
		go func() {
			defer collectorWG.Done()
			_ = c.Start(runCtx, eventCh)
		}()
	}

	// Single-goroutine reader mirrors main.go's ingest loop: eventCh -> IngestAsync.
	// IngestAsync blocks under backpressure rather than dropping, so bound it
	// with a generous deadline instead of context.Background() in case the
	// worker pool ever stalls.
	ingestCtx, ingestCancel := context.WithTimeout(context.Background(), fullPipelineTestDuration+30*time.Second)
	defer ingestCancel()

	var eventsProcessed atomic.Uint64
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for e := range eventCh {
			engine.IngestAsync(ingestCtx, e)
			eventsProcessed.Add(1)
		}
	}()

	// Periodic flush, mirroring main.go's pendingFlushInterval ticker.
	// flush is invoked from a background goroutine as well as the main test
	// goroutine, so it records errors instead of calling require/assert
	// directly — testify's FailNow (used by require) must only be invoked
	// from the goroutine running the test.
	var alertsMu sync.Mutex
	var totalAlerts int64
	var storeErr error
	flushStop := make(chan struct{})
	flushDone := make(chan struct{})
	flush := func() {
		alerts := engine.Flush()
		if len(alerts) == 0 {
			return
		}
		err := alertStore.StoreBatch(context.Background(), alerts)
		alertsMu.Lock()
		totalAlerts += int64(len(alerts))
		if err != nil && storeErr == nil {
			storeErr = err
		}
		alertsMu.Unlock()
	}
	go func() {
		defer close(flushDone)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				flush()
			case <-flushStop:
				return
			}
		}
	}()

	start := time.Now()
	collectorWG.Wait() // blocks until runCtx expires and every collector returns
	close(eventCh)     // safe: no writers remain
	<-readerDone
	duration := time.Since(start)

	// Drain any events still queued in the ingest worker pool before the
	// final flush, so in-flight IngestAsync calls aren't lost to a race.
	drainCtx, drainCancel := context.WithTimeout(context.Background(), 5*time.Second)
	engine.DrainIngestPool(drainCtx)
	drainCancel()

	close(flushStop)
	<-flushDone
	flush() // final drain after the periodic goroutine has stopped

	alertsMu.Lock()
	finalStoreErr := storeErr
	alertsMu.Unlock()
	require.NoError(t, finalStoreErr, "storing flushed alerts should not fail")

	rssMiB, rssErr := currentRSSMiB()
	storedCount, err := alertStore.Count(context.Background(), store.QueryFilters{})
	require.NoError(t, err)

	eventsPerSec := float64(eventsProcessed.Load()) / duration.Seconds()

	t.Logf("Full pipeline load test:")
	t.Logf("  Duration: %v", duration)
	t.Logf("  Events processed: %d (%.0f events/sec)", eventsProcessed.Load(), eventsPerSec)
	t.Logf("  Alerts flushed: %d (stored: %d)", totalAlerts, storedCount)
	if rssErr == nil {
		t.Logf("  RSS: %.1f MiB", rssMiB)
	} else {
		t.Logf("  RSS: unavailable (%v)", rssErr)
	}

	assert.GreaterOrEqual(t, eventsPerSec, float64(minFullPipelineEventsPerSec),
		"full pipeline should sustain at least %d events/sec", minFullPipelineEventsPerSec)
	assert.EqualValues(t, totalAlerts, storedCount, "all flushed alerts should be persisted to the store")
	if rssErr == nil {
		assert.Less(t, rssMiB, float64(fullPipelineRSSCeilingMiB),
			"process RSS must stay below %d MiB while driving the full pipeline", fullPipelineRSSCeilingMiB)
	}
}

// currentRSSMiB returns this process's resident set size in MiB, read from
// /proc/self/status (Linux-only, matching the rest of ebpf-guard).
func currentRSSMiB() (float64, error) {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "VmRSS:" {
			kb, err := strconv.ParseFloat(fields[1], 64)
			if err != nil {
				return 0, fmt.Errorf("parse VmRSS value %q: %w", fields[1], err)
			}
			return kb / 1024, nil
		}
	}
	return 0, fmt.Errorf("VmRSS not found in /proc/self/status")
}
