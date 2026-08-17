//go:build !linux

package enforcer

import "errors"

// ErrPidfdUnsupported is returned by killViaPidfd on platforms without
// pidfd_open(2)/pidfd_send_signal(2) — i.e. everything except Linux 5.1+.
var ErrPidfdUnsupported = errors.New("pidfd: unsupported on this platform (Linux 5.1+ only)")

// checkPidfdSupport always reports false off Linux, so executeKill takes the
// killViaProc path (comm recheck + syscall.Kill), which is portable.
func checkPidfdSupport() bool { return false }

// killViaPidfd is unreachable off Linux because pidfdSupported is false; it
// exists so kill.go compiles unchanged on every platform.
func killViaPidfd(_ uint32) error { return ErrPidfdUnsupported }
