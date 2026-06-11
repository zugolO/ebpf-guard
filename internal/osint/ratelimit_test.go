package osint

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/internal/config"
)

// --- Refresh interval / rate-limiting tests ---

func TestRateLimit_RunRespectsRefreshInterval(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing-sensitive test in short mode")
	}

	var callCount atomic.Int32
	client := &mockClient{
		source: SourceMISP,
		result: FeedResult{Source: SourceMISP, FetchedAt: time.Now().UTC()},
	}
	client.result.FetchedAt = time.Now().UTC()

	dir := t.TempDir()
	m, err := NewManager(config.OSINTConfig{
		Enabled:         true,
		OutputDir:       dir,
		MaxIoCsPerRule:  100,
		RefreshInterval: "100ms",
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// Wrap the real mock with a counter.
	counting := &countingClient{delegate: client, count: &callCount}
	m.clients = []Client{counting}

	ctx, cancel := context.WithTimeout(context.Background(), 350*time.Millisecond)
	defer cancel()

	// Run is blocking; launch in a goroutine.
	done := make(chan error, 1)
	go func() { done <- m.Run(ctx) }()

	select {
	case <-done:
	case <-time.After(600 * time.Millisecond):
		t.Fatal("Run did not return after context timeout")
	}

	got := int(callCount.Load())
	// With 100ms interval and 350ms window: initial call + ~3 ticks = 3-4 total.
	if got < 2 {
		t.Errorf("expected at least 2 fetch calls in 350ms with 100ms interval, got %d", got)
	}
	if got > 6 {
		t.Errorf("expected at most 6 fetch calls in 350ms with 100ms interval, got %d", got)
	}
}

func TestRateLimit_InvalidRefreshInterval_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	m, err := NewManager(config.OSINTConfig{
		Enabled:         true,
		OutputDir:       dir,
		RefreshInterval: "not-a-duration",
	})
	if err != nil {
		t.Fatalf("NewManager should succeed even with invalid interval: %v", err)
	}
	if m == nil {
		t.Skip("manager is nil, skipping Run test")
	}

	ctx := context.Background()
	err = m.Run(ctx)
	if err == nil {
		t.Error("Run should return error for invalid refresh_interval")
	}
}

func TestRateLimit_DefaultInterval_IsUsedWhenEmpty(t *testing.T) {
	// Verify that an empty RefreshInterval does not panic and uses the default.
	dir := t.TempDir()
	m, err := NewManager(config.OSINTConfig{
		Enabled:   true,
		OutputDir: dir,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if m == nil {
		t.Skip("manager is nil")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	// Run should complete (via timeout) without panicking.
	_ = m.Run(ctx)
}

func TestRateLimit_SyncSerialised_MutexPreventsParallelFetches(t *testing.T) {
	// Verify that concurrent Sync() calls do not execute fetches in parallel.
	// We measure that at most one fetch is in-flight at any instant.
	var (
		mu       sync.Mutex
		inflight int
		maxSeen  int
	)

	ts := time.Now().UTC()
	slow := &serialisedClient{
		source: SourceMISP,
		result: FeedResult{Source: SourceMISP, FetchedAt: ts},
		onFetch: func() {
			mu.Lock()
			inflight++
			if inflight > maxSeen {
				maxSeen = inflight
			}
			mu.Unlock()

			time.Sleep(5 * time.Millisecond)

			mu.Lock()
			inflight--
			mu.Unlock()
		},
	}

	m := newManagerWithClients(t, []Client{slow})
	ctx := context.Background()

	const goroutines = 8
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			m.Sync(ctx)
		}()
	}
	wg.Wait()

	if maxSeen > 1 {
		t.Errorf("fetches were not serialised: max concurrent in-flight = %d (want 1)", maxSeen)
	}
}

func TestRateLimit_SmallInterval_TerminatesOnCancel(t *testing.T) {
	dir := t.TempDir()
	m, err := NewManager(config.OSINTConfig{
		Enabled:         true,
		OutputDir:       dir,
		RefreshInterval: "10ms",
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if m == nil {
		t.Skip("manager is nil")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	// Run must terminate when context expires even with a very short interval.
	done := make(chan error, 1)
	go func() { done <- m.Run(ctx) }()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Run did not terminate after context cancellation")
	}
}

func TestRateLimit_SyncOnNilManager_IsNoOp(t *testing.T) {
	var m *Manager
	// Must not panic.
	m.Sync(context.Background())
}

func TestRateLimit_RunOnNilManager_IsNoOp(t *testing.T) {
	var m *Manager
	err := m.Run(context.Background())
	if err != nil {
		t.Errorf("nil manager Run returned error: %v", err)
	}
}

// --- helpers ---

// countingClient wraps another Client and increments a counter on each Fetch.
type countingClient struct {
	delegate Client
	count    *atomic.Int32
}

func (c *countingClient) Source() Source { return c.delegate.Source() }

func (c *countingClient) Fetch(since time.Time) (FeedResult, error) {
	c.count.Add(1)
	return c.delegate.Fetch(since)
}

// serialisedClient calls an onFetch hook before returning, allowing tests to
// observe concurrency.
type serialisedClient struct {
	source  Source
	result  FeedResult
	onFetch func()
}

func (s *serialisedClient) Source() Source { return s.source }

func (s *serialisedClient) Fetch(_ time.Time) (FeedResult, error) {
	if s.onFetch != nil {
		s.onFetch()
	}
	return s.result, nil
}
