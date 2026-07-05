//go:build amd64

package main

// nativeAuditArch is AUDIT_ARCH_X86_64 — the seccomp filter kills any syscall
// issued under a different ABI (e.g. i386 / x32) so the number-based denylist
// cannot be evaded by switching syscall tables.
const (
	nativeAuditArch      uint32 = 0xC000003E
	seccompArchSupported        = true
)
