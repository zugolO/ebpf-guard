//go:build linux

package bpf

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// newRingWaiter registers a copy of the ring buffer map fd with the Go runtime
// netpoller and returns a waiter that parks on it. See ringbuf_netpoll.go for
// why the wait must not happen in a blocking syscall.
//
// The fd is dup'd: the original belongs to the ebpf.Map and is closed by it,
// while this one is closed by the os.File (and by its finalizer), and a double
// close of a BPF map fd would be a use-after-close of whatever number the
// kernel handed out next.
func newRingWaiter(fd int) (ringWaiter, error) {
	if fd < 0 {
		return nil, fmt.Errorf("%w: invalid fd %d", errRingWaitUnsupported, fd)
	}

	dup, err := unix.FcntlInt(uintptr(fd), syscall.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: dup ring fd: %v", errRingWaitUnsupported, err)
	}

	// Probe with our own epoll instance before handing the fd to os.NewFile.
	// os.NewFile swallows a failed poller registration — it just leaves the
	// file in blocking mode — and the failure would then surface as an opaque
	// "waiting for unsupported file type" on the first wait, i.e. after the
	// collector is already running. Same fd, same flags Go uses, so this probe
	// answers the same question the runtime will ask.
	if err := probeEpollable(dup); err != nil {
		unix.Close(dup)
		return nil, err
	}

	// os.NewFile only puts an fd on the netpoller when it already is in
	// non-blocking mode (os/file_unix.go newFile: pollable = ... || nonBlocking).
	// Nothing ever read(2)s this fd — the records come out of the mmap'd ring —
	// so O_NONBLOCK here is purely the signal that makes the file pollable.
	if err := unix.SetNonblock(dup, true); err != nil {
		unix.Close(dup)
		return nil, fmt.Errorf("%w: set O_NONBLOCK on ring fd: %v", errRingWaitUnsupported, err)
	}

	f := os.NewFile(uintptr(dup), "bpf-ringbuf")
	rc, err := f.SyscallConn()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("%w: syscall conn: %v", errRingWaitUnsupported, err)
	}

	return &netpollRingWaiter{file: f, conn: rc}, nil
}

// probeEpollable answers whether the kernel accepts this fd in an epoll set
// with the flags the runtime poller uses. A BPF ring buffer map answers
// EPOLLIN from its poll handler; a map of any other type, or a kernel without
// that handler, is rejected here instead of silently busy-looping later.
func probeEpollable(fd int) error {
	ep, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return fmt.Errorf("%w: epoll_create1: %v", errRingWaitUnsupported, err)
	}
	defer unix.Close(ep)

	ev := unix.EpollEvent{Events: unix.EPOLLIN | unix.EPOLLET, Fd: int32(fd)}
	if err := unix.EpollCtl(ep, unix.EPOLL_CTL_ADD, fd, &ev); err != nil {
		return fmt.Errorf("%w: epoll_ctl: %v", errRingWaitUnsupported, err)
	}
	return nil
}

// netpollRingWaiter waits for EPOLLIN on the ring buffer fd through the runtime
// poller.
type netpollRingWaiter struct {
	file *os.File
	conn syscall.RawConn
}

// Wait parks until the ring fd is readable.
//
// RawConn.Read calls the callback first and only waits when it returns false
// (internal/poll FD.RawRead), so the callback declines once to force the park
// and accepts on the next pass. Readiness is latched by the poller, so a sample
// committed between the caller's "ring is empty" and this park is not lost: the
// epoll event is already in the ready list and the park returns at once.
func (w *netpollRingWaiter) Wait() error {
	parked := false
	err := w.conn.Read(func(uintptr) bool {
		if !parked {
			parked = true
			return false
		}
		return true
	})
	if err != nil {
		if errors.Is(err, os.ErrClosed) || errors.Is(err, os.ErrDeadlineExceeded) {
			return err
		}
		// Anything else (notably the runtime's "waiting for unsupported file
		// type", which has no sentinel to match on) means this fd is not
		// usable with the poller after all. Report it as unsupported so the
		// reader downgrades to the blocking path instead of failing.
		return fmt.Errorf("%w: wait: %v", errRingWaitUnsupported, err)
	}
	return nil
}

func (w *netpollRingWaiter) Close() error {
	return w.file.Close()
}
