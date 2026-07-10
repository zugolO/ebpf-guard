//go:build arm64

package main

// nativeAuditArch is AUDIT_ARCH_AARCH64 — the seccomp filter kills any syscall
// issued under a different ABI so the number-based denylist cannot be evaded by
// switching syscall tables.
const (
	nativeAuditArch      uint32 = 0xC00000B7
	seccompArchSupported        = true
)
