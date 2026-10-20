package main

import (
	"fmt"
	"sync"
	"time"
)

// pipelineStall is the liveness signal of /health/live (волна 9): the event pipeline is
// wedged when there is a backlog and the ingest workers have not handled a single event
// for stallAfter. An empty queue without progress is an idle node, not a stall; a slow
// but moving pipeline (overload, CFS throttling) is alive — killing it only zeroes its
// counters and restarts the overload (pod×8, заход B).
type pipelineStall struct {
	processed  func() uint64
	backlog    func() int
	stallAfter time.Duration
	now        func() time.Time

	mu       sync.Mutex
	last     uint64
	lastMove time.Time
}

const pipelineStallAfter = 60 * time.Second

func newPipelineStall(processed func() uint64, backlog func() int) *pipelineStall {
	p := &pipelineStall{processed: processed, backlog: backlog, stallAfter: pipelineStallAfter, now: time.Now}
	p.last, p.lastMove = processed(), p.now()
	return p
}

// check returns an error when the pipeline is stalled.
func (p *pipelineStall) check() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	now, n := p.now(), p.processed()
	if n != p.last || p.backlog() == 0 {
		p.last, p.lastMove = n, now
		return nil
	}
	if idle := now.Sub(p.lastMove); idle >= p.stallAfter {
		return fmt.Errorf("ingest stalled: %d events queued, no progress for %s", p.backlog(), idle.Round(time.Second))
	}
	return nil
}
