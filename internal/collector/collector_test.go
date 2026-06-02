package collector

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSyscallCollector(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	c, err := NewSyscallCollector(logger)
	require.NoError(t, err)
	assert.NotNil(t, c)
	assert.Equal(t, "syscall", c.Name())
}

func TestNewNetworkCollector(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	c, err := NewNetworkCollector(logger)
	require.NoError(t, err)
	assert.NotNil(t, c)
	assert.Equal(t, "network", c.Name())
}

func TestNewFileaccessCollector(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	c, err := NewFileaccessCollector(logger)
	require.NoError(t, err)
	assert.NotNil(t, c)
	assert.Equal(t, "fileaccess", c.Name())
}

// mockCollector is a mock collector for testing partial failure scenarios
type mockCollector struct {
	name     string
	startErr error
	closeErr error
	events   []types.Event
	mu       sync.Mutex
	started  bool
	closed   bool
}

func (m *mockCollector) Start(ctx context.Context, out chan<- types.Event) error {
	m.mu.Lock()
	m.started = true
	m.mu.Unlock()

	if m.startErr != nil {
		return m.startErr
	}

	// Send events until context is cancelled
	for _, event := range m.events {
		select {
		case out <- event:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	<-ctx.Done()
	return ctx.Err()
}

func (m *mockCollector) Name() string {
	return m.name
}

func (m *mockCollector) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return m.closeErr
}

func (m *mockCollector) IsStarted() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.started
}

func (m *mockCollector) IsClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

// TestPartialFailure_OneCollectorFails asserts that when one collector fails to start,
// other collectors continue to function and the event channel remains live.
func TestPartialFailure_OneCollectorFails(t *testing.T) {
	// Create collectors: one will fail, others will succeed
	failingCollector := &mockCollector{
		name:     "failing",
		startErr: errors.New("failed to attach eBPF program"),
	}
	workingCollector1 := &mockCollector{
		name: "working1",
		events: []types.Event{
			{Type: types.EventSyscall, PID: 1},
		},
	}
	workingCollector2 := &mockCollector{
		name: "working2",
		events: []types.Event{
			{Type: types.EventTCPConnect, PID: 2},
		},
	}

	collectors := []Collector{failingCollector, workingCollector1, workingCollector2}

	// Create event channel with buffer
	eventCh := make(chan types.Event, 10)

	// Start all collectors concurrently
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	for _, c := range collectors {
		wg.Add(1)
		go func(col Collector) {
			defer wg.Done()
			// Ignore errors - we want to see if channel remains live
			_ = col.Start(ctx, eventCh)
			// Close is called separately in shutdown sequence
			_ = col.Close()
		}(c)
	}

	// Give collectors time to start
	time.Sleep(100 * time.Millisecond)

	// Verify working collectors started
	assert.True(t, workingCollector1.IsStarted(), "working collector 1 should be started")
	assert.True(t, workingCollector2.IsStarted(), "working collector 2 should be started")

	// Collect events from working collectors
	var receivedEvents []types.Event
	collectDone := make(chan struct{})
	go func() {
		for {
			select {
			case event := <-eventCh:
				receivedEvents = append(receivedEvents, event)
			case <-time.After(200 * time.Millisecond):
				close(collectDone)
				return
			}
		}
	}()

	// Wait for event collection or timeout
	select {
	case <-collectDone:
		// Success
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for events")
	}

	// Cancel context to stop collectors
	cancel()
	wg.Wait()

	// Verify we received events from working collectors
	assert.GreaterOrEqual(t, len(receivedEvents), 1, "should receive at least one event from working collectors")

	// Verify working collectors were properly closed
	assert.True(t, workingCollector1.IsClosed(), "working collector 1 should be closed")
	assert.True(t, workingCollector2.IsClosed(), "working collector 2 should be closed")
}

// TestPartialFailure_AllCollectorsFail asserts graceful handling when all collectors fail.
func TestPartialFailure_AllCollectorsFail(t *testing.T) {
	collectors := []Collector{
		&mockCollector{name: "coll1", startErr: errors.New("error 1")},
		&mockCollector{name: "coll2", startErr: errors.New("error 2")},
		&mockCollector{name: "coll3", startErr: errors.New("error 3")},
	}

	eventCh := make(chan types.Event, 10)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	for _, c := range collectors {
		wg.Add(1)
		go func(col Collector) {
			defer wg.Done()
			_ = col.Start(ctx, eventCh)
		}(c)
	}

	// Give time for collectors to attempt start
	time.Sleep(100 * time.Millisecond)

	// Cancel and wait
	cancel()
	wg.Wait()

	// Channel should still be valid (not closed)
	select {
	case <-eventCh:
		t.Fatal("should not receive any events when all collectors fail")
	default:
		// Expected: no events
	}
}

// TestPartialFailure_ChannelFull asserts that collectors handle full channel gracefully.
func TestPartialFailure_ChannelFull(t *testing.T) {
	// Create a collector that sends many events
	collector := &mockCollector{
		name: "high-volume",
		events: []types.Event{
			{Type: types.EventSyscall, PID: 1},
			{Type: types.EventSyscall, PID: 2},
			{Type: types.EventSyscall, PID: 3},
			{Type: types.EventSyscall, PID: 4},
			{Type: types.EventSyscall, PID: 5},
		},
	}

	// Create a channel with very small buffer to simulate saturation
	eventCh := make(chan types.Event, 1)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// Start collector - it should block but not panic
	done := make(chan struct{})
	go func() {
		_ = collector.Start(ctx, eventCh)
		close(done)
	}()

	// Give collector time to send some events
	time.Sleep(100 * time.Millisecond)

	// Cancel context - collector should unblock and exit
	cancel()

	select {
	case <-done:
		// Success - collector exited cleanly
	case <-time.After(2 * time.Second):
		t.Fatal("collector did not exit after context cancellation")
	}
}
