//go:build !amd64 && !arm64

package main

// On architectures without an AUDIT_ARCH mapping wired up here, the default
// seccomp profile is unavailable and applyDefaultSeccomp fails closed with a
// clear error; `ebpf-guard run` logs a warning and continues with the remaining
// boundaries (cgroup/LSM, no_new_privs, namespaces). The project targets
// linux/amd64 and linux/arm64.
const (
	nativeAuditArch      uint32 = 0
	seccompArchSupported        = false
)
