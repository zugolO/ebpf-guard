package sandbox

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Privilege / anti-tamper assessment (issue #259, item 7).
//
// ebpf-guard enforces the ai_sandbox policy with in-kernel BPF LSM hooks. That
// boundary only holds if the sandboxed workload cannot reach the enforcer: a
// process that carries CAP_BPF / CAP_SYS_ADMIN / CAP_SYS_PTRACE, or that can
// write /sys/fs/bpf or /sys/fs/cgroup, can detach the LSM links, rewrite the
// sandbox_* maps, or move itself out of its cgroup — defeating enforcement
// entirely. For such a target `enforce` is a false sense of security.
//
// AssessProcess reports whether a target process tree is safe to enforce. The
// Manager uses it to fail closed: it refuses to claim kernel_enforced=true for a
// privileged target and downgrades that target to audit-only with an explicit
// reason (see Manager.GuardTarget / KernelEnforced).

// Linux capability bit positions (see <linux/capability.h>). Only the ones that
// let a workload tamper with the enforcer are listed here.
const (
	capSysPtrace = 19 // CAP_SYS_PTRACE — attach to / manipulate the agent process
	capSysAdmin  = 21 // CAP_SYS_ADMIN — bpf(), mount, setns, cgroup moves, ...
	capBPF       = 39 // CAP_BPF — load BPF, write maps, detach links (5.8+)
)

// dangerousCaps maps each tamper-relevant capability bit to its name for logs.
var dangerousCaps = []struct {
	bit  uint
	name string
}{
	{capBPF, "CAP_BPF"},
	{capSysAdmin, "CAP_SYS_ADMIN"},
	{capSysPtrace, "CAP_SYS_PTRACE"},
}

// tamperMounts are kernel interfaces that, if writable from inside the sandbox,
// let the workload undo enforcement (unpin maps/links, edit its own cgroup).
var tamperMounts = []string{"/sys/fs/bpf", "/sys/fs/cgroup"}

// EnforcementSafety is the verdict for a candidate enforce target. Safe is true
// only when nothing about the target lets it tamper with the enforcer; Reasons
// explains every disqualifying finding when Safe is false.
type EnforcementSafety struct {
	Safe    bool
	Reasons []string
}

// AssessProcess evaluates whether pid (an ai_sandbox enforce target, or a proxy
// for the process tree it heads) is safe to enforce. It is conservative: if the
// target's capability set cannot be read, it returns unsafe rather than
// assuming an unprivileged workload — never claim enforcement we cannot verify.
func AssessProcess(pid int) EnforcementSafety {
	reasons := assessCaps(pid)
	reasons = append(reasons, assessTamperMounts(accessWritable)...)
	return EnforcementSafety{Safe: len(reasons) == 0, Reasons: reasons}
}

// assessCaps reads /proc/<pid>/status and returns a reason for each dangerous
// capability held in the effective set. An unreadable/unparseable status is
// itself a reason (fail closed).
func assessCaps(pid int) []string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return []string{fmt.Sprintf("cannot read /proc/%d/status to verify capabilities: %v", pid, err)}
	}
	capEff, ok := parseCapEff(string(data))
	if !ok {
		return []string{fmt.Sprintf("cannot parse CapEff from /proc/%d/status", pid)}
	}
	return capReasons(capEff)
}

// capReasons returns a human-readable reason for each tamper-relevant capability
// present in the given effective capability bitmask.
func capReasons(capEff uint64) []string {
	var reasons []string
	for _, c := range dangerousCaps {
		if capEff&(uint64(1)<<c.bit) != 0 {
			reasons = append(reasons, "target holds "+c.name)
		}
	}
	return reasons
}

// parseCapEff extracts the CapEff hex bitmask from /proc/<pid>/status content.
func parseCapEff(status string) (uint64, bool) {
	for _, line := range strings.Split(status, "\n") {
		rest, ok := strings.CutPrefix(line, "CapEff:")
		if !ok {
			continue
		}
		v, err := strconv.ParseUint(strings.TrimSpace(rest), 16, 64)
		if err != nil {
			return 0, false
		}
		return v, true
	}
	return 0, false
}

// accessWritable reports whether path is writable by the current process. It is
// a package var so tests can stub the filesystem probe.
var accessWritable = func(path string) bool {
	// A writable bpffs/cgroupfs is only a tamper vector if it exists; a missing
	// mount cannot be written, so treat "not present" as not-writable.
	return unix.Access(path, unix.W_OK) == nil
}

// assessTamperMounts returns a reason for each tamper-relevant kernel mount that
// is writable, using the supplied writability probe.
func assessTamperMounts(writable func(string) bool) []string {
	var reasons []string
	for _, m := range tamperMounts {
		if writable(m) {
			reasons = append(reasons, "target can write "+m)
		}
	}
	return reasons
}
