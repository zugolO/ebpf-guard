package collector

import (
	"bytes"
	"context"
	"encoding/json"
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

// TestRunReadLoop_WaitsForReadLoopBeforeCallerClosesChannel reproduces the
// 5.8d panic (finding №20): "send on closed channel" on graceful shutdown.
//
// Before the fix, a collector's Start did `go c.readLoop(ctx, out);
// <-ctx.Done(); return nil` — returning as soon as ctx was cancelled while
// readLoop could still be blocked in a ring buffer Read(), about to send.
// PriorityEventCollector.Start closes its hand-off channel immediately after
// the wrapped collector's Start returns, so a readLoop that unblocked and
// sent right after that close would panic. This test models exactly that
// caller contract — close `out` as soon as the Start-equivalent returns —
// against runReadLoop, and requires zero panics whether the simulated
// readLoop is mid-send (under load) or idle (quiet) at cancellation time.
func TestRunReadLoop_WaitsForReadLoopBeforeCallerClosesChannel(t *testing.T) {
	for _, tc := range []struct {
		name        string
		underLoad   bool
		shutdownDur time.Duration
	}{
		{name: "under load: event pending when ctx is cancelled", underLoad: true},
		{name: "quiet: no event pending when ctx is cancelled", underLoad: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			out := make(chan types.Event, 1)

			releaseBlockedRead := make(chan struct{})
			readLoopStarted := make(chan struct{})

			// Simulates a collector's readLoop: parked in a blocking Read()
			// (releaseBlockedRead models Close() unblocking it, which in the
			// real agent happens strictly after ctx is already Done), then —
			// same as fileaccess/syscall/network/dns/tls/http/kmod readLoop —
			// sends on `out` via the shared strategy switch in sendEvent.
			readLoop := func() {
				close(readLoopStarted)
				<-releaseBlockedRead
				if tc.underLoad {
					sendEvent(ctx, out, types.Event{}, StrategyDrop, func() {})
				}
			}

			// Start-equivalent: matches every fixed collector's Start body.
			startDone := make(chan struct{})
			go func() {
				defer close(startDone)
				readLoopDone := runReadLoop(readLoop)
				<-ctx.Done()
				<-readLoopDone
			}()

			<-readLoopStarted
			cancel() // ctx.Done() fires; readLoop is still blocked in "Read()"

			// Give the Start-equivalent goroutine a chance to reach <-ctx.Done()
			// and start waiting on readLoopDone before the read unblocks —
			// exercises the actual ordering from the panic (ctx cancels well
			// before Close() runs and unblocks the reader).
			time.Sleep(20 * time.Millisecond)
			close(releaseBlockedRead) // models Close() unblocking Read()

			select {
			case <-startDone:
			case <-time.After(2 * time.Second):
				t.Fatal("Start-equivalent did not return after readLoop finished")
			}

			// PriorityEventCollector's contract: close the hand-off channel
			// immediately once Start returns. Must not panic — runReadLoop
			// guarantees readLoop already stopped calling sendEvent.
			require.NotPanics(t, func() { close(out) })
		})
	}
}

// TestMalformedLogger_RecordDoesNotDuplicateCollectorKey guards against
// finding #127 (5.9.9.F.2g): record() used to add its own "collector" attr
// on top of a logger already bound with one via .With (the convention every
// collector's c.logger follows), producing
// {"msg":"malformed event record","collector":"syscall","collector":"syscall",...}
// — a duplicate JSON key that strict parsers reject. json.Unmarshal into a
// map silently keeps the last value and would not catch this, so the test
// walks the raw token stream instead, where every key shows up once per
// occurrence regardless of value collisions.
func TestMalformedLogger_RecordDoesNotDuplicateCollectorKey(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil)).With(slog.String("collector", "syscall"))

	m := newMalformedLogger(0)
	m.record(logger, "nr_not_monitored", []byte{0x01, 0x02, 0x03})

	line := buf.Bytes()
	require.NotEmpty(t, line)

	var generic map[string]any
	require.NoError(t, json.Unmarshal(line, &generic), "record must emit valid JSON: %s", line)
	assert.Equal(t, "syscall", generic["collector"])
	assert.Equal(t, "nr_not_monitored", generic["reason"])

	dec := json.NewDecoder(bytes.NewReader(line))
	tok, err := dec.Token()
	require.NoError(t, err)
	require.Equal(t, json.Delim('{'), tok)

	seen := map[string]int{}
	for dec.More() {
		keyTok, err := dec.Token()
		require.NoError(t, err)
		key, ok := keyTok.(string)
		require.True(t, ok)
		seen[key]++

		var discard json.RawMessage
		require.NoError(t, dec.Decode(&discard))
	}

	assert.Equal(t, 1, seen["collector"], "collector key must appear exactly once, got record: %s", line)
}

// TestDropLogger_RecordDoesNotDuplicateCollectorKeyAndDistinguishesHops guards
// against finding #149/#150 (5.9.9.F.4h): record() used to take a
// collectorName argument and add its own "collector" attr on top of a
// logger already bound with one via .With (the same duplicate-key bug fixed
// for malformedLogger at #127), and it used to log byte-identical lines for
// the ringbuf_to_router and router_to_queue drop hops of the same
// collector, making the two indistinguishable in the log even though the
// dropped_by_collector_and_hop metric already tells them apart.
func TestDropLogger_RecordDoesNotDuplicateCollectorKeyAndDistinguishesHops(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil)).With(slog.String("collector", "fileaccess"))

	d := newDropLogger(0)
	d.record(logger, "ringbuf_to_router")

	line := buf.Bytes()
	require.NotEmpty(t, line)

	var generic map[string]any
	require.NoError(t, json.Unmarshal(line, &generic), "record must emit valid JSON: %s", line)
	assert.Equal(t, "fileaccess", generic["collector"])
	assert.Equal(t, "ringbuf_to_router", generic["hop"])

	dec := json.NewDecoder(bytes.NewReader(line))
	tok, err := dec.Token()
	require.NoError(t, err)
	require.Equal(t, json.Delim('{'), tok)

	seen := map[string]int{}
	for dec.More() {
		keyTok, err := dec.Token()
		require.NoError(t, err)
		key, ok := keyTok.(string)
		require.True(t, ok)
		seen[key]++

		var discard json.RawMessage
		require.NoError(t, dec.Decode(&discard))
	}
	assert.Equal(t, 1, seen["collector"], "collector key must appear exactly once, got record: %s", line)

	buf.Reset()
	d2 := newDropLogger(0)
	d2.record(logger, "router_to_queue")
	var second map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &second))
	assert.Equal(t, "router_to_queue", second["hop"])
	assert.NotEqual(t, generic["hop"], second["hop"], "the two hops of the same collector must be distinguishable in the log")
}

// BenchmarkEventPool measures the overhead of the pool acquire/fill/release cycle.
// Target: 0 allocs/op once the pool is warm. Run with -benchmem to verify.
func BenchmarkEventPool(b *testing.B) {
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			e := eventPool.Get().(*types.Event)
			e.Type = types.EventSyscall
			e.PID = 1234
			_ = *e // simulate sendEvent value copy
			e.Reset()
			eventPool.Put(e)
		}
	})
}
