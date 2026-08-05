package collector

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// fakeCollector emits a fixed set of events, then blocks until ctx is done.
type fakeCollector struct {
	name   string
	events []types.Event
	// sent is closed once every event has been handed to the channel.
	sent chan struct{}
	once sync.Once
}

func newFakeCollector(name string, events ...types.Event) *fakeCollector {
	return &fakeCollector{name: name, events: events, sent: make(chan struct{})}
}

func (f *fakeCollector) Name() string { return f.name }
func (f *fakeCollector) Close() error { return nil }

func (f *fakeCollector) Start(ctx context.Context, out chan<- types.Event) error {
	for _, e := range f.events {
		select {
		case out <- e:
		case <-ctx.Done():
			return nil
		}
	}
	f.once.Do(func() { close(f.sent) })
	<-ctx.Done()
	return nil
}

// TestPriorityRouting_SplitsByEventType is the core P0-25 guarantee: the file
// stream must land in a different queue from everything else, so it cannot
// consume the capacity that network/dns events need.
func TestPriorityRouting_SplitsByEventType(t *testing.T) {
	hi := make(chan types.Event, 16)
	lo := make(chan types.Event, 16)

	fc := newFakeCollector("fake",
		types.Event{Type: types.EventTCPConnect},
		types.Event{Type: types.EventDNS},
		types.Event{Type: types.EventFileAccess},
		types.Event{Type: types.EventSyscall},
		types.Event{Type: types.EventFileAccess},
	)

	p := NewPriorityEventCollector(fc, hi, lo, StrategyDrop, nil, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = p.Start(ctx, lo) }()

	select {
	case <-fc.sent:
	case <-time.After(2 * time.Second):
		t.Fatal("collector did not emit events in time")
	}
	// Allow the router goroutine to forward the last event.
	require.Eventually(t, func() bool { return len(hi) == 3 && len(lo) == 2 },
		2*time.Second, 5*time.Millisecond,
		"expected 3 protected (tcp, dns, syscall) and 2 bulk (file) events, got hi=%d lo=%d", len(hi), len(lo))

	// Syscall must be protected: P0-25 requires syscall loss < 1%, which is
	// unreachable if syscall shares a queue with the file flood.
	got := map[types.EventType]int{}
	for len(hi) > 0 {
		got[(<-hi).Type]++
	}
	assert.Equal(t, 1, got[types.EventTCPConnect])
	assert.Equal(t, 1, got[types.EventDNS])
	assert.Equal(t, 1, got[types.EventSyscall], "syscall events must not share the bulk queue with file events")

	for len(lo) > 0 {
		assert.Equal(t, types.EventFileAccess, (<-lo).Type, "bulk queue must carry only file events")
	}
}

// TestPriorityRouting_FileFloodDoesNotDropNetwork reproduces the run #4 failure
// mode in miniature: a saturated file stream must not cost a single network
// event. Before the split, both shared one channel and network lost 52%.
func TestPriorityRouting_FileFloodDoesNotDropNetwork(t *testing.T) {
	// Bulk queue is deliberately tiny and never drained, so file events overflow.
	hi := make(chan types.Event, 64)
	lo := make(chan types.Event, 1)

	events := make([]types.Event, 0, 1000)
	for i := 0; i < 990; i++ {
		events = append(events, types.Event{Type: types.EventFileAccess})
	}
	for i := 0; i < 10; i++ {
		events = append(events, types.Event{Type: types.EventTCPConnect})
	}

	var hiDrops, loDrops atomic.Int64
	dropFn := func(_ string, isHigh bool) {
		if isHigh {
			hiDrops.Add(1)
		} else {
			loDrops.Add(1)
		}
	}

	fc := newFakeCollector("flood", events...)
	p := NewPriorityEventCollector(fc, hi, lo, StrategyDrop, dropFn, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = p.Start(ctx, lo) }()

	select {
	case <-fc.sent:
	case <-time.After(5 * time.Second):
		t.Fatal("collector did not emit events in time")
	}

	require.Eventually(t, func() bool { return len(hi) == 10 },
		2*time.Second, 5*time.Millisecond, "all 10 network events must arrive, got %d", len(hi))

	assert.Zero(t, hiDrops.Load(), "P0-25 criterion: zero network loss even under a file flood")
	assert.Positive(t, loDrops.Load(), "the file flood should have overflowed the bulk queue (test would be vacuous otherwise)")
}

// TestPriorityRouting_ReportsDropsAndAccepts covers the loss-fraction inputs:
// a drop count without a denominator cannot express "52% of network events".
func TestPriorityRouting_ReportsDropsAndAccepts(t *testing.T) {
	hi := make(chan types.Event, 2)
	lo := make(chan types.Event, 8)

	var accepted, dropped atomic.Int64
	fc := newFakeCollector("counting",
		types.Event{Type: types.EventTCPConnect},
		types.Event{Type: types.EventTCPConnect},
		types.Event{Type: types.EventTCPConnect}, // overflows the 2-slot queue
	)

	p := NewPriorityEventCollector(fc, hi, lo, StrategyDrop,
		func(_ string, _ bool) { dropped.Add(1) },
		func(_ string, _ bool) { accepted.Add(1) },
		nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = p.Start(ctx, lo) }()

	require.Eventually(t, func() bool { return accepted.Load() == 2 && dropped.Load() == 1 },
		2*time.Second, 5*time.Millisecond,
		"expected 2 accepted / 1 dropped, got %d/%d", accepted.Load(), dropped.Load())
}

// TestPriorityRouting_BlockStrategyUnblocksOnCancel guards against the router
// parking forever on a full queue: with StrategyBlock, sendEvent must observe
// the collector's context, not a background one.
func TestPriorityRouting_BlockStrategyUnblocksOnCancel(t *testing.T) {
	hi := make(chan types.Event) // unbuffered and never drained
	lo := make(chan types.Event, 4)

	fc := newFakeCollector("blocking", types.Event{Type: types.EventTCPConnect})
	p := NewPriorityEventCollector(fc, hi, lo, StrategyBlock, nil, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Start(ctx, lo) }()

	// Give the router time to park on the unbuffered channel, then cancel.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after context cancellation — router is wedged on a full queue")
	}
}

func TestDefaultEventPriority(t *testing.T) {
	// Only the flood source is demoted; everything else keeps the protected queue.
	assert.False(t, defaultEventPriority(types.EventFileAccess))

	for _, et := range []types.EventType{
		types.EventTCPConnect, types.EventDNS, types.EventNetClose,
		types.EventTLS, types.EventSyscall, types.EventPrivesc,
	} {
		assert.True(t, defaultEventPriority(et), "event type %v must be protected", et)
	}
}
