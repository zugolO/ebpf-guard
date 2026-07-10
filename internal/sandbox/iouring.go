package sandbox

import (
	"os"
	"strings"
)

// io_uring escape-vector detection (issue #277 P0).
//
// io_uring is the single biggest hole in an LSM-based enforce mode: a sandboxed
// task can submit openat/connect/read/write through an io_uring ring — and,
// under IORING_SETUP_SQPOLL, have a kernel worker thread execute them — which on
// several kernels sidesteps the cgroup-scoped file_open/socket_connect checks
// the sandbox relies on. The kernel-side fix is the uring_* LSM hooks
// (internal to bpf/lsm.bpf.c); this file is the userspace half: detecting
// whether io_uring is reachable at all, so the Manager can refuse to claim
// enforcement on a kernel that lacks those hooks and has io_uring enabled.

// ioUringDisabledPath is the kernel sysctl (5.19+ as a knob, honoured for
// gating since 6.6) that controls io_uring availability. A package var so tests
// can point it at a fixture.
var ioUringDisabledPath = "/proc/sys/kernel/io_uring_disabled"

// ioUringExposed reports whether io_uring is reachable by an ordinary
// (unprivileged) sandboxed task on this host. It reads kernel.io_uring_disabled:
//
//	0 — enabled for everyone                     -> exposed
//	1 — disabled except for CAP_SYS_ADMIN tasks  -> not exposed (an unprivileged
//	    agent cannot use it; a CAP_SYS_ADMIN agent is already refused enforcement
//	    by AssessProcess, which flags CAP_SYS_ADMIN as tamper-capable)
//	2 — disabled for everyone                    -> not exposed
//
// When the sysctl is absent (kernels without the knob) io_uring is reachable
// whenever it is compiled in, so we conservatively treat it as exposed. A
// present-but-unparseable value is likewise treated as exposed — this gate fails
// closed: "exposed" is what drives the enforce-mode downgrade, so an unknown
// state must not silently read as safe.
func ioUringExposed() bool {
	data, err := os.ReadFile(ioUringDisabledPath)
	if err != nil {
		// Absent sysctl or unreadable: assume io_uring is available.
		return true
	}
	switch strings.TrimSpace(string(data)) {
	case "1", "2":
		return false
	default:
		return true
	}
}
