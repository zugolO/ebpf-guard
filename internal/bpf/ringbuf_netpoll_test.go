package bpf

import (
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"
)

// fakeRing plays a scripted sequence of ReadInto outcomes. os.ErrDeadlineExceeded
// is what cilium's reader reports once the mmap'd ring is drained and a deadline
// is set — the signal the netpoll path turns into a park.
type fakeRing struct {
	seq        []error // nil = a record is delivered
	calls      int
	deadlines  []time.Time
	closed     bool
	sampleByID bool
}

func (f *fakeRing) ReadInto(rec *ringbuf.Record) error {
	defer func() { f.calls++ }()
	var err error
	if f.calls < len(f.seq) {
		err = f.seq[f.calls]
	}
	if err != nil {
		return err
	}
	rec.RawSample = []byte{byte(f.calls)}
	return nil
}

func (f *fakeRing) Read() (ringbuf.Record, error) {
	var rec ringbuf.Record
	return rec, f.ReadInto(&rec)
}

func (f *fakeRing) SetDeadline(t time.Time) { f.deadlines = append(f.deadlines, t) }
func (f *fakeRing) Close() error            { f.closed = true; return nil }
func (f *fakeRing) lastDeadline() time.Time { return f.deadlines[len(f.deadlines)-1] }

type fakeWaiter struct {
	waits  int
	err    error
	closed bool
}

func (w *fakeWaiter) Wait() error {
	w.waits++
	return w.err
}

func (w *fakeWaiter) Close() error { w.closed = true; return nil }

type fallback struct {
	reason string
	detail string
	count  int
}

func netpollOpts(parks *int, fb *fallback) RingbufReaderOptions {
	return RingbufReaderOptions{
		Name:    "syscall",
		Netpoll: true,
		OnWait:  func() { *parks++ },
		OnFallback: func(reason, detail string) {
			fb.reason, fb.detail = reason, detail
			fb.count++
		},
	}
}

func okWaiter(w *fakeWaiter) func(int) (ringWaiter, error) {
	return func(int) (ringWaiter, error) { return w, nil }
}

// TestRingbufReader_BlockingPathUntouched: the default reader must be exactly
// what it was before wave 8.1 item 6 — no deadline, no waiter, and the mode a
// reading of the runtime rather than of the flag.
func TestRingbufReader_BlockingPathUntouched(t *testing.T) {
	ring := &fakeRing{seq: []error{nil}}
	r := newRingbufReader(ring, 7, RingbufReaderOptions{Name: "syscall"}, func(int) (ringWaiter, error) {
		t.Fatal("waiter must not be created when Netpoll is false")
		return nil, nil
	})

	if r.Mode() != RingbufWaitModeBlocking {
		t.Fatalf("mode = %q, want %q", r.Mode(), RingbufWaitModeBlocking)
	}
	if len(ring.deadlines) != 0 {
		t.Fatalf("blocking path set a deadline: %v", ring.deadlines)
	}
	var rec ringbuf.Record
	if err := r.ReadInto(&rec); err != nil {
		t.Fatalf("ReadInto: %v", err)
	}
}

// TestRingbufReader_NetpollParksOnEmptyRing: an empty ring parks instead of
// returning os.ErrDeadlineExceeded to the collector, and the park is counted —
// the series that tells "the netpoll branch ran" from "the netpoll branch was
// requested" ([[toggle-needs-both-branches-counted]]).
func TestRingbufReader_NetpollParksOnEmptyRing(t *testing.T) {
	ring := &fakeRing{seq: []error{os.ErrDeadlineExceeded, os.ErrDeadlineExceeded, nil}}
	waiter := &fakeWaiter{}
	parks := 0
	fb := &fallback{}
	r := newRingbufReader(ring, 7, netpollOpts(&parks, fb), okWaiter(waiter))

	if r.Mode() != RingbufWaitModeNetpoll {
		t.Fatalf("mode = %q, want %q", r.Mode(), RingbufWaitModeNetpoll)
	}
	if len(ring.deadlines) != 1 || !ring.lastDeadline().Equal(ringNoBlockDeadline) {
		t.Fatalf("netpoll path must hold a past deadline, got %v", ring.deadlines)
	}
	if ring.lastDeadline().IsZero() {
		t.Fatal("deadline is the zero time, which means no deadline at all")
	}

	var rec ringbuf.Record
	if err := r.ReadInto(&rec); err != nil {
		t.Fatalf("ReadInto: %v", err)
	}
	if waiter.waits != 2 || parks != 2 {
		t.Fatalf("waits = %d, parks counted = %d, want 2 and 2", waiter.waits, parks)
	}
	if fb.count != 0 {
		t.Fatalf("unexpected fallback: %+v", fb)
	}
	if len(rec.RawSample) == 0 {
		t.Fatal("record was not delivered after the park")
	}
}

// TestRingbufReader_FallsBackOnWaitError: a waiter that cannot poll this fd
// must cost the stream nothing. The reader downgrades ONCE, restores the
// blocking reader (deadline cleared, waiter closed) and still returns the
// record the caller asked for.
func TestRingbufReader_FallsBackOnWaitError(t *testing.T) {
	ring := &fakeRing{seq: []error{os.ErrDeadlineExceeded, nil, nil}}
	waiter := &fakeWaiter{err: fmt.Errorf("%w: wait: waiting for unsupported file type", errRingWaitUnsupported)}
	parks := 0
	fb := &fallback{}
	r := newRingbufReader(ring, 7, netpollOpts(&parks, fb), okWaiter(waiter))

	var rec ringbuf.Record
	if err := r.ReadInto(&rec); err != nil {
		t.Fatalf("ReadInto: %v", err)
	}
	if r.Mode() != RingbufWaitModeBlocking {
		t.Fatalf("mode after fallback = %q, want %q", r.Mode(), RingbufWaitModeBlocking)
	}
	if !waiter.closed {
		t.Fatal("waiter was not closed on fallback")
	}
	if !ring.lastDeadline().IsZero() {
		t.Fatalf("deadline not cleared on fallback: %v", ring.lastDeadline())
	}
	if fb.count != 1 || fb.reason != RingbufFallbackWaitError {
		t.Fatalf("fallback = %+v, want one %q", fb, RingbufFallbackWaitError)
	}
	if parks != 0 {
		t.Fatalf("a failed wait counted as a park: %d", parks)
	}

	// Second read goes straight through the blocking path, and the fallback is
	// not reported twice.
	if err := r.ReadInto(&rec); err != nil {
		t.Fatalf("second ReadInto: %v", err)
	}
	if fb.count != 1 {
		t.Fatalf("fallback reported %d times, want 1", fb.count)
	}
}

// TestRingbufReader_CloseUnblocksWithErrClosed: Close must be the thing that
// ends a park, and os.ErrClosed must reach the collector as itself — it is how
// readLoop tells shutdown from a read failure. A downgrade here would be a
// reader trying to resume the stream of a closed ring.
func TestRingbufReader_CloseUnblocksWithErrClosed(t *testing.T) {
	ring := &fakeRing{seq: []error{os.ErrDeadlineExceeded}}
	waiter := &fakeWaiter{err: os.ErrClosed}
	parks := 0
	fb := &fallback{}
	r := newRingbufReader(ring, 7, netpollOpts(&parks, fb), okWaiter(waiter))

	var rec ringbuf.Record
	err := r.ReadInto(&rec)
	if !errors.Is(err, os.ErrClosed) {
		t.Fatalf("ReadInto err = %v, want os.ErrClosed", err)
	}
	if fb.count != 0 {
		t.Fatalf("close reported as a fallback: %+v", fb)
	}
	if r.Mode() != RingbufWaitModeNetpoll {
		t.Fatalf("close downgraded the reader: mode = %q", r.Mode())
	}

	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !ring.closed || !waiter.closed {
		t.Fatalf("Close left something open: ring=%v waiter=%v", ring.closed, waiter.closed)
	}
}

// TestRingbufReader_ConstructionFallbackIsCounted: an fd or a platform that
// cannot be polled must leave a reading behind ("unsupported"), not a silently
// blocking reader that an A/B would then label as the ON window
// ([[entry-guard-must-read-runtime-not-config]]).
func TestRingbufReader_ConstructionFallbackIsCounted(t *testing.T) {
	ring := &fakeRing{seq: []error{nil}}
	parks := 0
	fb := &fallback{}
	r := newRingbufReader(ring, 7, netpollOpts(&parks, fb), func(int) (ringWaiter, error) {
		return nil, errRingWaitUnsupported
	})

	if r.Mode() != RingbufWaitModeBlocking {
		t.Fatalf("mode = %q, want %q", r.Mode(), RingbufWaitModeBlocking)
	}
	if fb.count != 1 || fb.reason != RingbufFallbackUnsupported {
		t.Fatalf("fallback = %+v, want one %q", fb, RingbufFallbackUnsupported)
	}
	if len(ring.deadlines) != 0 {
		t.Fatalf("deadline set although the netpoll path never started: %v", ring.deadlines)
	}
}

// TestNewRingWaiter_RejectsBadFD keeps the platform shim honest: on Linux a
// negative fd must be refused as unsupported rather than dup'd, and off Linux
// every fd is unsupported. Either way the error must be matchable, because that
// is what turns into a fallback instead of a dead collector.
func TestNewRingWaiter_RejectsBadFD(t *testing.T) {
	w, err := newRingWaiter(-1)
	if err == nil {
		_ = w.Close()
		t.Fatal("newRingWaiter(-1) returned a waiter")
	}
	if !errors.Is(err, errRingWaitUnsupported) {
		t.Fatalf("err = %v, want errRingWaitUnsupported", err)
	}
}
