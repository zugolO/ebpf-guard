//go:build linux

package bpf

import (
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestNewRingWaiter_ParksAndWakes exercises the real waiter — dup,
// O_NONBLOCK, os.NewFile, syscall.RawConn — on a pipe, which is pollable for
// the same reason a BPF ring buffer map is: the kernel's poll handler answers
// EPOLLIN. Without this, the whole chain is only ever exercised on the stand,
// and a wrong link in it reads there as "the fix did not help" instead of "the
// fix never ran".
func TestNewRingWaiter_ParksAndWakes(t *testing.T) {
	var fds [2]int
	if err := unix.Pipe2(fds[:], unix.O_CLOEXEC); err != nil {
		t.Fatalf("pipe2: %v", err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])

	w, err := newRingWaiter(fds[0])
	if err != nil {
		t.Fatalf("newRingWaiter: %v", err)
	}
	defer w.Close()

	// try stands in for "drain the ring": it reads non-blockingly and reports
	// whether it got anything. It must be called once before the park (and come
	// back empty) and again when the fd becomes readable.
	var tries int32
	try := func() (bool, error) {
		atomic.AddInt32(&tries, 1)
		var b [1]byte
		n, err := unix.Read(fds[0], b[:])
		if n > 0 {
			return true, nil
		}
		if err != nil && err != unix.EAGAIN && err != unix.EWOULDBLOCK {
			return true, err
		}
		return false, nil
	}

	done := make(chan error, 1)
	go func() { done <- w.WaitUntil(try) }()

	// The wait must actually park: nothing is readable yet, and try said empty.
	select {
	case err := <-done:
		t.Fatalf("WaitUntil returned %v before the fd was readable", err)
	case <-time.After(100 * time.Millisecond):
	}
	if atomic.LoadInt32(&tries) == 0 {
		t.Fatal("try was never called inside the armed window — the record that arrives before the park would be lost")
	}

	if _, err := unix.Write(fds[1], []byte{1}); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("WaitUntil after write: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("WaitUntil did not return after the fd became readable")
	}
	if atomic.LoadInt32(&tries) < 2 {
		t.Fatalf("try called %d times, want at least 2 (before the park and on readiness)", tries)
	}
}

// TestNewRingWaiter_TakesDataLatchedBeforeArming is the pipe-level version of
// the stand's defect: the data is already there when WaitUntil is called, and
// nothing will ever become readable afterwards. The call must still return,
// because try runs inside the armed window; a waiter that only waited for an
// epoll event would hang here, exactly as both busy readers hung on the stand.
func TestNewRingWaiter_TakesDataLatchedBeforeArming(t *testing.T) {
	var fds [2]int
	if err := unix.Pipe2(fds[:], unix.O_CLOEXEC); err != nil {
		t.Fatalf("pipe2: %v", err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])

	w, err := newRingWaiter(fds[0])
	if err != nil {
		t.Fatalf("newRingWaiter: %v", err)
	}
	defer w.Close()

	if _, err := unix.Write(fds[1], []byte{1}); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Let any readiness notification be delivered and then discarded by the
	// reset that WaitUntil's prepareRead does.
	time.Sleep(50 * time.Millisecond)

	done := make(chan error, 1)
	go func() {
		done <- w.WaitUntil(func() (bool, error) {
			var b [1]byte
			n, _ := unix.Read(fds[0], b[:])
			return n > 0, nil
		})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("WaitUntil: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("WaitUntil hung on data that was latched before arming — the stall is back")
	}
}

// TestNewRingWaiter_CloseUnblocks: Close is the only thing that ends a park, so
// a collector's Stop must be able to end it. A waiter that ignored Close would
// leave readLoop parked for the life of the process.
func TestNewRingWaiter_CloseUnblocks(t *testing.T) {
	var fds [2]int
	if err := unix.Pipe2(fds[:], unix.O_CLOEXEC); err != nil {
		t.Fatalf("pipe2: %v", err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])

	w, err := newRingWaiter(fds[0])
	if err != nil {
		t.Fatalf("newRingWaiter: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- w.WaitUntil(func() (bool, error) { return false, nil }) }()
	time.Sleep(50 * time.Millisecond)
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case err := <-done:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("WaitUntil after Close = %v, want os.ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not unblock the park")
	}
}

// TestNewRingWaiter_RejectsUnpollableFD: a regular file is not epollable, and
// the refusal has to arrive at construction. os.NewFile swallows a failed
// poller registration, so without the probe this fd would reach the collector
// and fail on its first wait.
func TestNewRingWaiter_RejectsUnpollableFD(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "ring")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	defer f.Close()

	w, werr := newRingWaiter(int(f.Fd()))
	if werr == nil {
		_ = w.Close()
		t.Skip("this kernel accepts a regular file in an epoll set; nothing to assert")
	}
	if !errors.Is(werr, errRingWaitUnsupported) {
		t.Fatalf("err = %v, want errRingWaitUnsupported", werr)
	}
}
