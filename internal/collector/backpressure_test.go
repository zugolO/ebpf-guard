package collector

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ebpf-guard/ebpf-guard/pkg/types"
)

// TestSendEvent_Drop verifies that StrategyDrop calls the dropped callback
// when the channel is full and does not block.
func TestSendEvent_Drop(t *testing.T) {
	out := make(chan types.Event, 1)
	out <- types.Event{} // fill channel

	var dropped atomic.Int64
	ctx := context.Background()

	start := time.Now()
	sendEvent(ctx, out, types.Event{PID: 42}, StrategyDrop, func() { dropped.Add(1) })
	elapsed := time.Since(start)

	if elapsed > 10*time.Millisecond {
		t.Errorf("StrategyDrop blocked for %v, expected non-blocking", elapsed)
	}
	if dropped.Load() != 1 {
		t.Errorf("expected 1 drop, got %d", dropped.Load())
	}
}

// TestSendEvent_Block verifies that StrategyBlock pauses the caller until
// the channel drains, then delivers the event.
func TestSendEvent_Block(t *testing.T) {
	out := make(chan types.Event, 1)
	out <- types.Event{} // fill channel

	var dropped atomic.Int64
	ctx := context.Background()
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		sendEvent(ctx, out, types.Event{PID: 99}, StrategyBlock, func() { dropped.Add(1) })
	}()

	// Give the goroutine time to block
	time.Sleep(20 * time.Millisecond)
	if dropped.Load() != 0 {
		t.Error("StrategyBlock should not call dropped while blocked")
	}

	// Drain the channel — goroutine should unblock and send
	<-out
	wg.Wait()

	if dropped.Load() != 0 {
		t.Error("StrategyBlock should not call dropped after channel drains")
	}

	// Verify the event was delivered
	select {
	case e := <-out:
		if e.PID != 99 {
			t.Errorf("expected PID 99, got %d", e.PID)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("event not delivered after channel drained")
	}
}

// TestSendEvent_BlockCancelled verifies that StrategyBlock exits cleanly
// when the context is cancelled while blocked.
func TestSendEvent_BlockCancelled(t *testing.T) {
	out := make(chan types.Event, 1)
	out <- types.Event{} // fill channel

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		sendEvent(ctx, out, types.Event{PID: 7}, StrategyBlock, func() {})
	}()

	time.Sleep(10 * time.Millisecond)
	cancel()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Error("StrategyBlock goroutine did not exit after context cancellation")
	}
}

// TestSendEvent_Sample verifies that StrategySample drops ~50% of events
// over a large sample, and the drop counter increments for dropped events.
func TestSendEvent_Sample(t *testing.T) {
	const iterations = 1000
	out := make(chan types.Event, iterations) // large enough to never block on delivery
	ctx := context.Background()

	var dropped atomic.Int64
	for i := 0; i < iterations; i++ {
		sendEvent(ctx, out, types.Event{PID: uint32(i)}, StrategySample, func() { dropped.Add(1) })
	}

	delivered := len(out)
	total := int(dropped.Load()) + delivered
	if total != iterations {
		t.Errorf("total events (%d) != iterations (%d)", total, iterations)
	}

	// Expect 30–70% delivered (sample rate is 50%)
	ratio := float64(delivered) / iterations
	if ratio < 0.30 || ratio > 0.70 {
		t.Errorf("StrategySample delivered ratio %.2f outside expected range [0.30, 0.70]", ratio)
	}
}

// TestSendEvent_DropCounterIncrement verifies the drop counter is incremented
// via the dropped callback (integration with exporter.RecordDropped pattern).
func TestSendEvent_DropCounterIncrement(t *testing.T) {
	out := make(chan types.Event, 0) // unbuffered — always full

	var count int
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		sendEvent(ctx, out, types.Event{}, StrategyDrop, func() { count++ })
	}

	if count != 5 {
		t.Errorf("expected 5 drop callbacks, got %d", count)
	}
}

// TestBlockStrategySlowsUnderLoad verifies that StrategyBlock measurably delays
// the sender when the event channel is at 95%+ capacity, while StrategyDrop
// returns immediately and increments the drop counter.
func TestBlockStrategySlowsUnderLoad(t *testing.T) {
	const cap = 100
	out := make(chan types.Event, cap)

	// Fill channel to 95% capacity.
	for i := 0; i < 95; i++ {
		out <- types.Event{}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// --- StrategyDrop: should return immediately even when channel is nearly full ---
	var dropped atomic.Int64
	start := time.Now()
	// Fill remaining 5 slots then attempt 10 more — all extras must drop immediately.
	for i := 0; i < 15; i++ {
		sendEvent(ctx, out, types.Event{PID: uint32(i)}, StrategyDrop, func() { dropped.Add(1) })
	}
	dropElapsed := time.Since(start)

	if dropElapsed > 50*time.Millisecond {
		t.Errorf("StrategyDrop blocked for %v under high load, expected < 50ms", dropElapsed)
	}
	if dropped.Load() == 0 {
		t.Error("expected drop counter > 0 when channel was full")
	}

	// Drain channel for the block test.
	for len(out) > 0 {
		<-out
	}

	// --- StrategyBlock: sender goroutine must block until consumer drains ---
	out2 := make(chan types.Event, cap)
	for i := 0; i < cap; i++ {
		out2 <- types.Event{}
	}

	sendDone := make(chan time.Duration, 1)
	go func() {
		t0 := time.Now()
		sendEvent(ctx, out2, types.Event{PID: 77}, StrategyBlock, func() {})
		sendDone <- time.Since(t0)
	}()

	// Give goroutine time to block before draining.
	time.Sleep(10 * time.Millisecond)

	// Drain one slot — goroutine should unblock.
	<-out2
	var blockElapsed time.Duration
	select {
	case blockElapsed = <-sendDone:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("StrategyBlock goroutine did not unblock after channel drained")
	}

	// The goroutine was blocked for at least the 10ms sleep.
	if blockElapsed < time.Millisecond {
		t.Errorf("StrategyBlock returned too quickly (%v), expected > 1ms under full channel", blockElapsed)
	}
}
