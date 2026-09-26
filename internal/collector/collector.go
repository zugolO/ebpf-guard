// Package collector provides eBPF-based event collection from the kernel.
package collector

import (
	"context"
	"encoding/hex"
	"log/slog"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Collector defines the interface for eBPF event collectors.
// Each collector attaches specific eBPF programs and streams events
// to the provided channel.
type Collector interface {
	// Start attaches eBPF programs and begins sending events.
	// Blocks until ctx is cancelled.
	Start(ctx context.Context, out chan<- types.Event) error
	// Name returns a short identifier (e.g. "syscall", "network").
	Name() string
	// Close releases all eBPF resources.
	Close() error
}

// BackpressureStrategy controls collector behaviour when the event channel is full.
type BackpressureStrategy string

const (
	// StrategyDrop silently drops the event and increments the drop counter (default).
	StrategyDrop BackpressureStrategy = "drop"
	// StrategyBlock blocks the collector goroutine until the channel drains.
	StrategyBlock BackpressureStrategy = "block"
	// StrategySample drops with 50% probability, preserving approximate event rate.
	StrategySample BackpressureStrategy = "sample"
)

// runReadLoop starts fn (a collector's readLoop) in a goroutine and blocks
// until it returns.
//
// Each collector's Start used to do `go c.readLoop(ctx, out); <-ctx.Done();
// return nil` — returning as soon as ctx was cancelled, without waiting for
// readLoop to actually stop. readLoop can still be parked in a blocking ring
// buffer Read() at that point; it only unblocks once Close() runs, which
// happens later, after ctx is already done (cmd/ebpf-guard's gracefulShutdown
// closes collectors after the context is cancelled). The caller of Start
// (PriorityEventCollector) closes its hand-off channel as soon as Start
// returns, so a readLoop still in flight would send on a closed channel —
// exactly the "send on closed channel" panic on graceful shutdown (5.8d,
// finding №20). Start must not return until readLoop has actually stopped
// calling sendEvent on `out`.
func runReadLoop(fn func()) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	return done
}

// sendEvent sends an event to the output channel according to the configured
// backpressure strategy. It is called from each collector's readLoop.
func sendEvent(ctx context.Context, out chan<- types.Event, e types.Event, strategy BackpressureStrategy, dropped func()) {
	switch strategy {
	case StrategyBlock:
		select {
		case out <- e:
		case <-ctx.Done():
		}
	case StrategySample:
		if rand.Intn(2) == 0 { //nolint:gosec // fast non-crypto sampling
			select {
			case out <- e:
			default:
				dropped()
			}
		} else {
			dropped()
		}
	default: // StrategyDrop
		select {
		case out <- e:
		default:
			dropped()
		}
	}
}

// dropLogger throttles "event dropped" log lines to at most one per interval,
// aggregating the drop count so operators see "dropped N events in last 5s"
// instead of one log line per dropped event (which itself causes CPU overhead).
//
// The window is CLOSED BY A TIMER, not by the next drop (№474). The earlier
// design compared "now" with a zero-initialised lastLogTime on every drop, so
// the very first drop always logged alone (dropped_count=1) and the rest sat
// in pending until a LATER drop happened after the interval — a burst that
// ended within a fraction of a second was reported as 1 of 3656 and the other
// 3655 were never printed. Now the first drop of a window arms a one-shot
// timer; when it fires it prints everything accumulated. Nothing is left
// behind, and a window is always closed within one interval.
type dropLogger struct {
	interval time.Duration
	armed    atomic.Bool  // a flush timer is pending for the current window
	pending  atomic.Int64 // events dropped since last log
	// site remembers the logger and hop of the drop that ARMED the current
	// window, so flushOnClose can print the window when the process stops
	// before the timer fires (wave 6.6 revision item 6). record receives both
	// per call and the struct otherwise kept neither, so a shutdown had nothing
	// to print with. Stored only on arming — at most one allocation per
	// interval, not one per dropped event.
	site atomic.Pointer[dropSite]
}

// dropSite is the logger/hop pair of the drop that opened a window.
type dropSite struct {
	logger *slog.Logger
	hop    string
}

func newDropLogger(interval time.Duration) *dropLogger {
	return &dropLogger{interval: interval}
}

// flushOnClose prints whatever the current window has accumulated. It is called
// from a collector's Close(): the window is closed by a 5s timer, so a process
// exiting sooner than that after its last drop used to lose the count entirely —
// the losses were in the metric but never in the log, and the log is the only
// place the HOP of the loss is named (№474). Flushing at Close makes the log's
// sample of the cause complete for the run, without making it a counter.
//
// Safe to call twice and safe to call on a dropLogger that never recorded
// anything: the count is swapped to zero and an empty window prints nothing.
func (d *dropLogger) flushOnClose() {
	site := d.site.Load()
	if site == nil {
		// Nothing was ever recorded through this dropLogger, so there is no
		// logger to print with — and, by the same token, nothing to print.
		return
	}
	// Disarm so a pending timer that fires after Close finds an empty window
	// rather than printing a second line for the same drops.
	d.armed.Store(false)
	d.flush(site.logger, site.hop)
}

// record increments the pending drop counter. The first drop of a window arms
// a timer that logs the aggregated count when the interval elapses; drops in
// between only bump the counter. A non-positive interval logs synchronously.
//
// logger is expected to already carry a "collector" attribute (bound via
// .With, the same convention every collector's c.logger already follows) —
// record does not add its own, since doing so on top of an already-bound
// logger duplicated the "collector" key in the emitted JSON (finding #149,
// the same class of bug fixed for malformedLogger.record at #127).
//
// hop names the stage where the drop happened (e.g. "ringbuf_to_router",
// "router_to_queue") — the same values exporter.RecordEventDrop's hop
// argument uses. Two different hops for the same collector previously
// logged byte-identical lines through this function; hop is what a human
// reading the log needs to tell them apart (finding #150).
func (d *dropLogger) record(logger *slog.Logger, hop string) {
	d.pending.Add(1)

	if d.interval <= 0 {
		d.flush(logger, hop)
		return
	}
	if !d.armed.CompareAndSwap(false, true) {
		return
	}
	// The window is open: remember where it came from so Close() can print it.
	d.site.Store(&dropSite{logger: logger, hop: hop})
	time.AfterFunc(d.interval, func() {
		// Disarm BEFORE swapping the counter: a drop landing between the two
		// re-arms a fresh timer instead of being stranded in pending.
		d.armed.Store(false)
		d.flush(logger, hop)
	})
}

func (d *dropLogger) flush(logger *slog.Logger, hop string) {
	count := d.pending.Swap(0)
	if count > 0 {
		logger.Warn("event channel full, dropping events",
			slog.String("hop", hop),
			slog.Int64("dropped_count", count),
			slog.String("window", d.interval.String()))
	}
}

// malformedLogger throttles hex-dump diagnostic warnings for one
// malformed-record reason (see exporter.EventsMalformed) to at most one line
// per interval, keeping the most recent offending sample. Wave 5.9.2c
// (finding #40): the counter alone says a reason fired; the sample is what
// lets a human confirm which hypothesis it actually is, without flooding the
// log at ring-buffer rate.
type malformedLogger struct {
	interval    time.Duration
	lastLogTime atomic.Int64
	pending     atomic.Int64

	mu         sync.Mutex
	lastSample []byte
	// lastExtra holds the structured fields (5.9.6g, №65) passed alongside
	// the last recorded sample — e.g. DNS's direction/payload_len. Kept
	// next to lastSample under the same lock so the fields logged when the
	// throttle window opens describe the SAME occurrence as sample_hex,
	// not a stale one from an earlier call that happened to lose the race.
	lastExtra []slog.Attr
}

func newMalformedLogger(interval time.Duration) *malformedLogger {
	return &malformedLogger{interval: interval}
}

// record notes one occurrence of reason, keeping up to the first 48 bytes of
// raw as the sample logged when the throttle window next opens. extra is an
// optional set of structured fields describing this specific occurrence
// (5.9.6g) — e.g. the DNS event's direction and payload_len, which the
// caller already parsed from the fixed header before the payload itself
// failed to decode, and which a hex dump alone forces a human to re-derive
// by hand. Existing callers (syscall.go) pass none and are unaffected.
//
// logger is expected to already carry a "collector" attribute (bound via
// .With, the same convention every collector's c.logger already follows)
// — record does not add its own, since doing so on top of an already-bound
// logger duplicated the "collector" key in the emitted JSON (finding #127).
func (m *malformedLogger) record(logger *slog.Logger, reason string, raw []byte, extra ...slog.Attr) {
	m.pending.Add(1)

	n := len(raw)
	if n > 48 {
		n = 48
	}
	m.mu.Lock()
	m.lastSample = append(m.lastSample[:0], raw[:n]...)
	m.lastExtra = append([]slog.Attr(nil), extra...)
	m.mu.Unlock()

	now := time.Now().UnixNano()
	last := m.lastLogTime.Load()
	if now-last < m.interval.Nanoseconds() {
		return
	}
	if !m.lastLogTime.CompareAndSwap(last, now) {
		return
	}
	count := m.pending.Swap(0)
	if count == 0 {
		return
	}
	m.mu.Lock()
	sample := hex.EncodeToString(m.lastSample)
	lastExtra := m.lastExtra
	m.mu.Unlock()
	args := []any{
		slog.String("reason", reason),
		slog.Int64("count", count),
		slog.String("window", m.interval.String()),
		slog.String("sample_hex", sample),
	}
	for _, a := range lastExtra {
		args = append(args, a)
	}
	logger.Warn("malformed event record", args...)
}
