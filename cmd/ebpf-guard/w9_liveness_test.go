package main

import (
	"testing"
	"time"
)

func TestW9_PipelineStall(t *testing.T) {
	var processed uint64
	backlog := 0
	clock := time.Unix(1000, 0)
	p := newPipelineStall(func() uint64 { return processed }, func() int { return backlog })
	p.now = func() time.Time { return clock }
	p.lastMove = clock

	clock = clock.Add(10 * time.Minute) // idle node: empty queue, no progress — alive
	if err := p.check(); err != nil {
		t.Fatalf("idle: %v", err)
	}
	backlog = 100
	processed += 5
	clock = clock.Add(2 * time.Minute) // overload: backlog but moving — alive
	if err := p.check(); err != nil {
		t.Fatalf("moving: %v", err)
	}
	clock = clock.Add(59 * time.Second) // backlog, no progress, below the threshold
	if err := p.check(); err != nil {
		t.Fatalf("below threshold: %v", err)
	}
	clock = clock.Add(2 * time.Second) // wedged
	if err := p.check(); err == nil {
		t.Fatal("wedged pipeline must fail liveness")
	}
	processed++
	if err := p.check(); err != nil {
		t.Fatalf("recovered: %v", err)
	}
}
