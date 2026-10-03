//go:build linux

package bpf

import (
	"errors"
	"os"
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

	done := make(chan error, 1)
	go func() { done <- w.Wait() }()

	// The wait must actually park: nothing is readable yet.
	select {
	case err := <-done:
		t.Fatalf("Wait returned %v before the fd was readable", err)
	case <-time.After(100 * time.Millisecond):
	}

	if _, err := unix.Write(fds[1], []byte{1}); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Wait after write: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Wait did not return after the fd became readable")
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
	go func() { done <- w.Wait() }()
	time.Sleep(50 * time.Millisecond)
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case err := <-done:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("Wait after Close = %v, want os.ErrClosed", err)
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
