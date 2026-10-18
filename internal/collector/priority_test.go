package collector

import (
	"context"
	"fmt"
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
	hi := make(chan *types.Event, 16)
	lo := make(chan *types.Event, 16)

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
	go func() { _ = p.Start(ctx, nil) }()

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
	hi := make(chan *types.Event, 64)
	lo := make(chan *types.Event, 1)

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
	go func() { _ = p.Start(ctx, nil) }()

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
	hi := make(chan *types.Event, 2)
	lo := make(chan *types.Event, 8)

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
	go func() { _ = p.Start(ctx, nil) }()

	require.Eventually(t, func() bool { return accepted.Load() == 2 && dropped.Load() == 1 },
		2*time.Second, 5*time.Millisecond,
		"expected 2 accepted / 1 dropped, got %d/%d", accepted.Load(), dropped.Load())
}

// TestPriorityRouting_BlockStrategyUnblocksOnCancel guards against the router
// parking forever on a full queue: with StrategyBlock, sendEvent must observe
// the collector's context, not a background one.
func TestPriorityRouting_BlockStrategyUnblocksOnCancel(t *testing.T) {
	hi := make(chan *types.Event) // unbuffered and never drained
	lo := make(chan *types.Event, 4)

	fc := newFakeCollector("blocking", types.Event{Type: types.EventTCPConnect})
	p := NewPriorityEventCollector(fc, hi, lo, StrategyBlock, nil, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Start(ctx, nil) }()

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

// strategyFakeCollector hands events to the wrapper through sendEvent with a
// chosen first-hop strategy, as the real readers do.
type strategyFakeCollector struct {
	n        int
	strategy BackpressureStrategy
	lost     atomic.Int64
	done     chan struct{}
}

func (f *strategyFakeCollector) Name() string { return "fake" }
func (f *strategyFakeCollector) Close() error { return nil }
func (f *strategyFakeCollector) Start(ctx context.Context, out chan<- types.Event) error {
	for i := 0; i < f.n; i++ {
		sendEvent(ctx, out, types.Event{Type: types.EventSyscall, PID: uint32(i)}, f.strategy, func() { f.lost.Add(1) })
	}
	close(f.done)
	<-ctx.Done()
	return nil
}

// TestFirstHopBlock_BurstIsWaitedNotLost: a burst larger than the hand-off
// channel (1024) against a slow downstream queue. With StrategyBlock on the
// first hop the reader waits and every event arrives in order; with Drop
// (control) the same burst loses events. Wave 8.1 №534.
func TestFirstHopBlock_BurstIsWaitedNotLost(t *testing.T) {
	const n = 5000
	run := func(strategy BackpressureStrategy) (got []uint32, lost int64) {
		hi := make(chan *types.Event, 16)
		lo := make(chan *types.Event, 16)
		fc := &strategyFakeCollector{n: n, strategy: strategy, done: make(chan struct{})}
		// router strategy stays Drop; the downstream queue is drained slowly
		// enough that the router, not the reader, is never the one parked.
		p := NewPriorityEventCollector(fc, hi, lo, StrategyBlock, nil, nil, nil)
		ctx, cancel := context.WithCancel(context.Background())
		go func() { _ = p.Start(ctx, nil) }()
		timeout := time.After(20 * time.Second)
		for len(got) < n {
			select {
			case e := <-hi:
				got = append(got, e.PID)
				if len(got)%64 == 0 {
					time.Sleep(time.Millisecond)
				}
			case <-fc.done:
				if strategy == StrategyDrop {
					// drain what is left and stop
					for {
						select {
						case e := <-hi:
							got = append(got, e.PID)
						case <-time.After(200 * time.Millisecond):
							cancel()
							return got, fc.lost.Load()
						}
					}
				}
			case <-timeout:
				cancel()
				t.Fatalf("strategy %s: timed out with %d/%d events", strategy, len(got), n)
			}
		}
		cancel()
		return got, fc.lost.Load()
	}

	got, lost := run(StrategyBlock)
	require.Equal(t, int64(0), lost, "block must not count a loss")
	require.Len(t, got, n)
	for i, pid := range got {
		require.Equal(t, uint32(i), pid, "order must be preserved")
	}

	_, lostDrop := run(StrategyDrop)
	assert.Greater(t, lostDrop, int64(0), "control: drop on the same burst loses events")
}

// Wave 8.2, C1 (№539): the queues carry pooled *types.Event. A consumer copies
// the event out and returns the slot at once, so the slot is recycled while the
// copy is still being processed. Identity: with slots recycled continuously
// (queue depth 8 against 20 000 events), every event must arrive intact — the
// same PID/payload pairs, none overwritten by a later event reusing its slot,
// none lost on the Block path.
func TestPriorityRouting_PooledSlotsKeepEventIdentity(t *testing.T) {
	hi := make(chan *types.Event, 8)
	lo := make(chan *types.Event, 8)

	const n = 20000
	events := make([]types.Event, 0, n)
	for i := 0; i < n; i++ {
		e := types.Event{PID: uint32(i + 1)}
		if i%5 == 0 {
			e.Type = types.EventTCPConnect
			e.Network = &types.NetworkEvent{Dport: uint16(i%60000 + 1)}
		} else {
			e.Type = types.EventFileAccess
			fe := &types.FileEvent{}
			fe.Filename = fmt.Sprintf("/f/%d", i+1)
			e.File = fe
		}
		events = append(events, e)
	}

	fc := newFakeCollector("pool", events...)
	p := NewPriorityEventCollector(fc, hi, lo, StrategyBlock, nil, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = p.Start(ctx, nil) }()

	var bad, got atomic.Int64
	check := func(slot *types.Event) {
		e := *slot
		types.PutEvent(slot) // recycled before the copy is inspected, as in main.go
		got.Add(1)
		switch e.Type {
		case types.EventTCPConnect:
			if e.Network == nil || int(e.Network.Dport) != int((e.PID-1)%60000)+1 || e.File != nil {
				bad.Add(1)
			}
		case types.EventFileAccess:
			if e.File == nil || e.Network != nil || e.File.Filename != fmt.Sprintf("/f/%d", e.PID) {
				bad.Add(1)
			}
		default:
			bad.Add(1)
		}
	}
	var wg sync.WaitGroup
	for _, ch := range []chan *types.Event{hi, lo} {
		wg.Add(1)
		go func(ch chan *types.Event) {
			defer wg.Done()
			for {
				select {
				case s := <-ch:
					check(s)
				case <-ctx.Done():
					return
				}
			}
		}(ch)
	}

	require.Eventually(t, func() bool { return got.Load() == n },
		10*time.Second, 5*time.Millisecond, "received %d of %d", got.Load(), n)
	cancel()
	wg.Wait()
	assert.Zero(t, bad.Load(), "events corrupted by slot reuse")
}

func fileEv(op uint8) types.Event {
	return types.Event{Type: types.EventFileAccess, File: &types.FileEvent{Op: op}}
}

// Волна 8.8: при полной bulk-очереди open и мутации файла уходят в protected-очередь,
// read/write — теряются (они и есть объём).
func TestPriorityRouting_FullBulkQueueKeepsOpenAndMutations(t *testing.T) {
	hi := make(chan *types.Event, 64)
	lo := make(chan *types.Event, 1) // never drained

	events := []types.Event{fileEv(1)} // read fills the one slot
	for i := 0; i < 20; i++ {
		events = append(events, fileEv(1)) // read: overflow, dropped
	}
	events = append(events, fileEv(0), fileEv(4), fileEv(5)) // open, unlink, rename: kept via hi
	events = append(events, fileEv(2))                       // write: dropped

	var loDrops atomic.Int64
	fc := newFakeCollector("keep", events...)
	p := NewPriorityEventCollector(fc, hi, lo, StrategyDrop, func(_ string, high bool) {
		if !high {
			loDrops.Add(1)
		}
	}, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = p.Start(ctx, nil) }()
	select {
	case <-fc.sent:
	case <-time.After(5 * time.Second):
		t.Fatal("collector did not emit events in time")
	}
	require.Eventually(t, func() bool { return len(hi) == 3 }, 2*time.Second, 5*time.Millisecond,
		"open+unlink+rename must reach the protected queue, got %d", len(hi))
	for i := 0; i < 3; i++ {
		e := <-hi
		assert.NotEqual(t, uint8(1), e.File.Op)
		assert.NotEqual(t, uint8(2), e.File.Op)
	}
	assert.EqualValues(t, 21, loDrops.Load(), "all reads/writes beyond the slot are dropped (20 reads + 1 write)")
}

func TestFileEventMustKeep(t *testing.T) {
	for op, want := range map[uint8]bool{0: true, 1: false, 2: false, 3: true, 4: true, 5: true, 6: true, 7: true} {
		e := fileEv(op)
		assert.Equal(t, want, fileEventMustKeep(&e), "op %d", op)
	}
	n := types.Event{Type: types.EventTCPConnect}
	assert.False(t, fileEventMustKeep(&n))
	assert.False(t, fileEventMustKeep(&types.Event{Type: types.EventFileAccess}))
}
