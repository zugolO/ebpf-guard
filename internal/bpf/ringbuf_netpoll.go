package bpf

import (
	"errors"
	"time"

	"github.com/cilium/ebpf/ringbuf"
)

// -----------------------------------------------------------------------
// Ring buffer readiness wait (wave 8.1 item 6)
// -----------------------------------------------------------------------
//
// WHY THIS EXISTS. The agent made ~2678 nanosleep(2)/s on an idle node, 94% of
// them from ONE thread: runtime.usleep <- runtime.sysmon <- mstart, costing
// 16,8% of the agent's CPU (26,4 s of 157 s over 1005 s of life, stand measure
// of 03.10.2026). The hypothesis carried by item 6 — that /proc syscalls from
// the container-id resolver (item 2) kept sysmon hot — was WRONG: after item 2
// cut openat to 14/s, sysmon kept spinning at the same rate.
//
// The mechanism is in the runtime, and it is not "retake" (the second guess
// written down in plan.md) either. sysmon's sleep ramps 20us -> 10ms and it can
// only reach deep sleep while sched.npidle == gomaxprocs; and whoever calls
// entersyscall while sysmon IS deep asleep wakes it through
// entersyscallWakeSysmon, which sets syscallWake, which resets idle = 0 and
// delay = 20us (runtime/proc.go, sysmon and reentersyscall). A reset costs a
// full ramp back to 10ms: 51 iterations at 20us plus the doubling, ~60 wakeups
// over ~21 ms. At one reset per ~1,7 ms — our ~587 blocking epoll_wait/s —
// sysmon never reaches deep sleep again, and 60 wakeups per 21 ms is 2857/s:
// the measured 2678/s, which is the arithmetic of this ramp and not of any
// amount of /proc reading.
//
// The producers of those entersyscall events are the ring buffer readers:
// cilium/ebpf's ringbuf.Reader waits for samples in
// unix.EpollWait(epollFd, events, -1) (internal/epoll/poller.go), a blocking
// raw syscall inside a Go goroutine. Each one also parks its P in _Psyscall
// until sysmon retakes it, which is where the agent's futex churn (2000/s)
// comes from.
//
// THE FIX. Wait for the ring to become readable on Go's own netpoller instead
// of in a blocking syscall:
//
//   - the ring buffer map fd is dup'd, put in non-blocking mode and handed to
//     os.NewFile, which registers it with the runtime poller (epoll, EPOLLET);
//   - the reader keeps a permanently past deadline, so ringbuf.ReadInto never
//     blocks: it drains the mmap'd ring (no syscalls per record) and reports
//     os.ErrDeadlineExceeded once the ring is empty;
//   - on an empty ring the goroutine parks via syscall.RawConn.Read, i.e. in
//     gopark/netpoll, not in a syscall.
//
// A netpoll wakeup does NOT wake sysmon (injectglist has no sysmonnote
// notification; only entersyscall, exitsyscall and startTheWorld do), and the
// one cheap epoll_wait(0) the drain still costs is issued while this P is
// running — sysmon cannot be deep asleep at that instant, so it is never the
// wake that resets the ramp.
//
// NOT JUDGED BY THIS CODE. Whether the stand's nanosleep rate actually falls is
// an A/B pair on one binary ([[run-to-run-variance-beats-code-attribution]],
// [[ab-toggle-measures-the-restart]]), which is why this path is a toggle that
// defaults to OFF and why both branches are readable from /metrics
// ([[toggle-needs-both-branches-counted]]): ebpf_guard_ringbuf_wait_mode says
// which branch a collector is running, ebpf_guard_ringbuf_netpoll_parks_total
// proves the new branch actually parked, and
// ebpf_guard_ringbuf_netpoll_fallback_total says it gave up and when.
//
// THE LOST WAKEUP (defect found live on the stand 03.10.2026, first version of
// this file). Checking "is the ring empty?" BEFORE asking the waiter to park
// stalls a busy reader for good, and the stand showed it in one minute:
// events_total froze at 17 640 while events_emitted_kernel_total kept climbing
// (+5038 in 30 s), and the rings overflowed — 194 288 fileaccess records and
// 13 742 syscall records dropped as ringbuf_full.
//
// Two facts meet:
//
//   - the kernel notifies ONLY on the empty→non-empty transition.
//     bpf_ringbuf_commit queues its irq_work when cons_pos == rec_pos, i.e.
//     when the consumer is caught up; a commit made while the reader is behind
//     wakes nobody, by design.
//   - internal/poll's RawRead calls pd.prepareRead FIRST, and that is
//     runtime_pollReset, which stores pdNil over the descriptor's readiness.
//     A notification latched by epoll before the call is therefore DISCARDED.
//
// So: drain to empty → a record is committed (consumer caught up, so the kernel
// does notify, and epoll latches it) → the reader calls the waiter → pollReset
// throws that latch away → the reader parks → and the next commit finds the
// consumer behind, so there is no second notification. Parked forever.
//
// The order has to be arm-then-check: the emptiness check runs INSIDE the
// RawRead callback, which internal/poll invokes after prepareRead and before
// waiting. Then the record that arrived before the reset is taken by that very
// call, and a record committed after it finds the consumer caught up — so its
// notification reaches the armed descriptor. This is why ringWaiter takes a
// `try` function instead of offering a bare Wait().
//
// SAFETY. This is the event path of the whole product, so every failure of the
// netpoll path is a fallback to the blocking path, never a lost event stream:
// an unsupported fd, a failed dup, a wait error — all of them downgrade the
// reader once, loudly, and keep reading. A STALL, however, is not a failure the
// reader can see from inside; it is what the stand's smoke is for, and what
// ebpf_guard_ringbuf_netpoll_parks_total against events_emitted_kernel_total
// makes readable from outside.

// ringbufWaitMode* are the two values of the wait_mode gauge and of
// RingbufReader.Mode.
const (
	RingbufWaitModeBlocking = "blocking"
	RingbufWaitModeNetpoll  = "netpoll"
)

// RingbufFallback* are the bounded reasons handed to
// RingbufReaderOptions.OnFallback. "unsupported" means the netpoll path never
// started (platform, fd, dup or poller registration); "wait_error" means it
// started, failed mid-run and the reader downgraded itself. The free-form error
// text travels beside them as detail, for the log, not for a metric label.
const (
	RingbufFallbackUnsupported = "unsupported"
	RingbufFallbackWaitError   = "wait_error"
)

// errRingWaitUnsupported means this platform (or this fd) cannot be waited on
// through the runtime netpoller. It is not an error of the read path: the
// caller falls back to the blocking reader.
var errRingWaitUnsupported = errors.New("ringbuf: readiness wait is not supported for this fd")

// ringNoBlockDeadline is the deadline held by a reader on the netpoll path. Any
// instant in the past makes cilium's poller compute a zero epoll timeout; it
// must not be the zero time.Time, which means "no deadline" and blocks forever.
var ringNoBlockDeadline = time.Unix(1, 0)

// ringWaiter parks the calling goroutine until the ring buffer is readable.
type ringWaiter interface {
	// WaitUntil parks until try reports that the ring has data.
	//
	// try MUST be the emptiness check itself, and the waiter MUST call it at
	// least once AFTER arming the poller — see "THE LOST WAKEUP" above. It
	// returns (true, nil) when it took a record, (false, nil) while the ring
	// is still empty, and (false, err)/(true, err) to abort the park.
	//
	// Returns nil once try reported data, os.ErrClosed after Close, and
	// errRingWaitUnsupported if this fd cannot be polled at all.
	WaitUntil(try func() (bool, error)) error
	Close() error
}

// ringbufCore is the part of *ringbuf.Reader this package uses. It is an
// interface so the park loop can be tested without a kernel: there is no way
// to construct a real ringbuf.Reader on a machine without BPF, and the loop is
// exactly the piece that must not be judged by a green fixture elsewhere
// ([[self-test-fixtures-miss-live-log-shape]]).
type ringbufCore interface {
	Read() (ringbuf.Record, error)
	ReadInto(rec *ringbuf.Record) error
	SetDeadline(t time.Time)
	Close() error
}
