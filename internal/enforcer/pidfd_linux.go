//go:build linux

package enforcer

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// checkPidfdSupport probes the kernel for pidfd_open availability by attempting
// to open a pidfd for PID 1 (init). On kernels < 5.1 this returns ENOSYS.
func checkPidfdSupport() bool {
	fd, err := unix.PidfdOpen(1, 0)
	if err != nil {
		return false
	}
	syscall.Close(fd)
	return true
}

// killViaPidfd sends SIGKILL using pidfd_open(2) + pidfd_send_signal(2).
// This provides an atomic handle to a specific process instance, making
// PID-reuse races technically impossible.
func killViaPidfd(pid uint32) error {
	fd, err := unix.PidfdOpen(int(pid), 0)
	if err != nil {
		return fmt.Errorf("pidfd_open(%d): %w", pid, err)
	}
	defer syscall.Close(fd)

	if err := unix.PidfdSendSignal(fd, syscall.SIGKILL, nil, 0); err != nil {
		return fmt.Errorf("pidfd_send_signal(%d): %w", pid, err)
	}
	return nil
}
