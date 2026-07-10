package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"

	"github.com/zugolO/ebpf-guard/internal/sandbox"
)

// sandboxChildCmdName is the hidden subcommand `ebpf-guard run` re-execs itself
// as, to layer child-side hardening around the wrapped command before handing
// control to it (issue #277 P2, `ebpf-guard run` defense-in-depth).
//
// The cgroup/LSM sandbox is one boundary; PR_SET_NO_NEW_PRIVS and a default
// seccomp filter are two more, so bypassing one does not collapse the whole
// containment. Both can only be installed from inside the child between fork and
// exec — os/exec cannot run code there — so `run` re-execs this trampoline,
// which applies them and then execve's the real target. NNP and seccomp filters
// are preserved across execve, so they bound the target too; the process keeps
// its PID, so signal forwarding from the `run` parent still reaches it.
const sandboxChildCmdName = "__sandbox-child"

// Seccomp return actions (see <linux/seccomp.h>). Kept local so the exact wire
// values are visible next to the filter that emits them.
const (
	seccompRetKillProcess = uint32(unix.SECCOMP_RET_KILL_PROCESS)
	seccompRetAllow       = uint32(unix.SECCOMP_RET_ALLOW)
	// SECCOMP_RET_ERRNO with EPERM in the low 16 bits: deny with -EPERM, the same
	// posture the ai_sandbox LSM hooks use, rather than killing the task outright.
	seccompRetDenyEPERM = uint32(unix.SECCOMP_RET_ERRNO) | uint32(unix.EPERM)
)

// seccomp_data field offsets (struct passed to a seccomp cBPF filter).
const (
	seccompDataNROffset   = 0 // offsetof(struct seccomp_data, nr)
	seccompDataArchOffset = 4 // offsetof(struct seccomp_data, arch)
)

// newSandboxChildCmd builds the hidden trampoline command. It is never invoked
// by a user directly — `ebpf-guard run` execs it via /proc/self/exe.
func newSandboxChildCmd() *cobra.Command {
	var (
		noNewPrivs bool
		seccompOn  bool
		dropCaps   bool
	)
	cmd := &cobra.Command{
		Use:    sandboxChildCmdName + " [flags] -- COMMAND [ARGS...]",
		Hidden: true,
		Args:   cobra.MinimumNArgs(1),
		// Internal re-exec target: never print usage/errors on the exec path.
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(_ *cobra.Command, args []string) error {
			return sandboxChildExec(childHardening{noNewPrivs: noNewPrivs, seccomp: seccompOn, dropCaps: dropCaps}, args)
		},
	}
	cmd.Flags().BoolVar(&noNewPrivs, "no-new-privs", true, "set PR_SET_NO_NEW_PRIVS before exec")
	cmd.Flags().BoolVar(&seccompOn, "seccomp", true, "install the default seccomp filter before exec")
	cmd.Flags().BoolVar(&dropCaps, "drop-caps", true, "drop CAP_BPF/CAP_SYS_ADMIN/CAP_SYS_PTRACE before exec")
	return cmd
}

// sandboxChildExec applies the requested child-side hardening and then execve's
// the real command (args[0] plus args[1:]). It only returns on failure — on
// success syscall.Exec replaces this process image.
func sandboxChildExec(h childHardening, args []string) error {
	// Resolve the target before locking down: execve needs a concrete path, and
	// exec.LookPath's stat() calls happen here rather than under the filter.
	path, err := exec.LookPath(args[0])
	if err != nil {
		return fmt.Errorf("resolve %q: %w", args[0], err)
	}

	// no_new_privs must precede seccomp: the kernel lets an unprivileged process
	// install a filter only when it has CAP_SYS_ADMIN or NO_NEW_PRIVS is set, and
	// NNP independently blocks re-gaining privileges through a setuid binary.
	if h.noNewPrivs {
		if err := applyNoNewPrivs(); err != nil {
			return fmt.Errorf("set no_new_privs: %w", err)
		}
	}
	// Drop the tamper-relevant capabilities before seccomp/exec. Fail closed: a
	// child that kept CAP_BPF/CAP_SYS_ADMIN/CAP_SYS_PTRACE could defeat the very
	// enforcement `--enforce` promises, so a failed drop must abort the run
	// rather than exec a still-privileged workload.
	if h.dropCaps {
		if err := applyCapDrop(); err != nil {
			return fmt.Errorf("drop tamper capabilities: %w", err)
		}
	}
	if h.seccomp {
		if err := applyDefaultSeccomp(); err != nil {
			return fmt.Errorf("install seccomp filter: %w", err)
		}
	}

	// args[0]/args[1:] are the operator-supplied COMMAND for `ebpf-guard run`
	// to exec inside the sandbox; that is this trampoline's entire purpose,
	// not an injection risk.
	execErr := syscall.Exec(path, args, os.Environ()) // #nosec G204
	if execErr != nil {
		return fmt.Errorf("exec %q: %w", path, execErr)
	}
	return nil // unreachable on success
}

// applyNoNewPrivs sets PR_SET_NO_NEW_PRIVS on the calling thread/process. It is
// permitted for unprivileged processes and is inherited across execve and fork.
func applyNoNewPrivs() error {
	return unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
}

// applyCapDrop removes the tamper-relevant capabilities (CAP_BPF, CAP_SYS_ADMIN,
// CAP_SYS_PTRACE — sandbox.TamperCapBits) from the child before it execs the
// wrapped command. Without this the sandboxed agent inherits the guard's full
// privileges and could detach the LSM links, rewrite the sandbox_* maps, or
// ptrace the guard — defeating the enforcement `--enforce` claims (issue #259
// item 7). The run wrapper assesses the child against the same set
// (sandbox.AssessProcessAfterCapDrop) so enforce is no longer force-downgraded
// merely because the guard itself must hold CAP_BPF to attach the programs.
//
// Each capability is cleared from the effective, permitted, and inheritable sets
// via capset — a permitted-set drop is irrevocable for the process and survives
// execve — and from the bounding set via PR_CAPBSET_DROP so it cannot be
// re-acquired through a file-capability execve. The capset drop is the hard
// guarantee and its failure is fatal; the bounding-set drop is best-effort
// (it needs CAP_SETPCAP, which a root guard has but a minimal one may not).
func applyCapDrop() error {
	drop := sandbox.TamperCapBits()

	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3, Pid: 0} // pid 0 == self
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capget: %w", err)
	}
	for _, c := range drop {
		word := c >> 5 // 32 capability bits per CapUserData word
		bit := uint32(1) << (c & 31)
		data[word].Effective &^= bit
		data[word].Permitted &^= bit
		data[word].Inheritable &^= bit
	}
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capset: %w", err)
	}
	// Bounding-set drop: prevents re-gaining the cap via a setuid/file-cap
	// execve. Best-effort — the permitted-set clear above already removes it
	// from this process tree regardless.
	for _, c := range drop {
		_ = unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0)
	}
	return nil
}

// applyDefaultSeccomp installs defaultSeccompFilter for every thread of the
// process (SECCOMP_FILTER_FLAG_TSYNC). It requires either CAP_SYS_ADMIN or that
// no_new_privs is already set, so callers set NNP first.
func applyDefaultSeccomp() error {
	if !seccompArchSupported {
		return fmt.Errorf("default seccomp profile unavailable on this architecture")
	}
	filter := defaultSeccompFilter()
	prog := &unix.SockFprog{
		Len:    uint16(len(filter)), // #nosec G115 -- filter is our fixed, small denylist program, always far under uint16/BPF_MAXINSNS
		Filter: &filter[0],
	}
	// unix has no SockFprog-taking wrapper for SYS_SECCOMP with TSYNC, so this
	// goes through the raw syscall; prog outlives the call on our stack frame.
	progPtr := uintptr(unsafe.Pointer(prog)) // #nosec G103 -- required to pass a *SockFprog to SYS_SECCOMP directly; prog is stack-local and outlives the call
	if _, _, errno := unix.Syscall(unix.SYS_SECCOMP,
		uintptr(unix.SECCOMP_SET_MODE_FILTER),
		uintptr(unix.SECCOMP_FILTER_FLAG_TSYNC),
		progPtr); errno != 0 {
		return errno
	}
	return nil
}

// deniedSyscalls is the default denylist: exotic syscalls whose only realistic
// use inside an AI-agent sandbox is escape, so the wrapper shuts them regardless
// of the profile. io_uring is the headline entry — it can drive file/socket
// operations around the LSM file/socket hooks (issue #277 P0), so denying its
// setup path here is a second, kernel-version-independent lever against that
// bypass. The rest (kernel module load/unload, kexec) can never be legitimate
// for a sandboxed userspace agent.
func deniedSyscalls() []int {
	return []int{
		unix.SYS_IO_URING_SETUP,
		unix.SYS_IO_URING_ENTER,
		unix.SYS_IO_URING_REGISTER,
		unix.SYS_INIT_MODULE,
		unix.SYS_FINIT_MODULE,
		unix.SYS_DELETE_MODULE,
		unix.SYS_KEXEC_LOAD,
		unix.SYS_KEXEC_FILE_LOAD,
	}
}

// x32SyscallBit is __X32_SYSCALL_BIT: on x86_64 the x32 ABI shares
// AUDIT_ARCH_X86_64 with the 64-bit ABI but OR's this bit into every syscall
// number, so an arch-equality check alone does not separate them. A number-based
// denylist could then be evaded by issuing the same call under x32
// (e.g. io_uring_setup as 0x40000000|425). We reject any number carrying this
// bit outright. On non-x86_64 arches no native syscall number reaches this
// value, so the guard is a harmless no-op there.
const x32SyscallBit = uint32(0x40000000)

// defaultSeccompFilter assembles the classic-BPF seccomp program: reject any
// syscall issued under a non-native ABI (closes the i386 compat route), reject
// x32 numbers (the x32 ABI shares the native audit arch), deny each denylist
// entry with -EPERM, and allow everything else.
func defaultSeccompFilter() []unix.SockFilter {
	const (
		bpfLdW  = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS
		bpfJeqK = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
		bpfJgeK = unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K
		bpfRetK = unix.BPF_RET | unix.BPF_K
	)
	denied := deniedSyscalls()
	filter := make([]unix.SockFilter, 0, len(denied)*2+6)

	// Load arch; if it is not the native ABI, kill the process.
	filter = append(filter,
		unix.SockFilter{Code: bpfLdW, K: seccompDataArchOffset},
		unix.SockFilter{Code: bpfJeqK, K: nativeAuditArch, Jt: 1, Jf: 0},
		unix.SockFilter{Code: bpfRetK, K: seccompRetKillProcess},
	)

	// Load the syscall number. Reject any x32-flagged number (native audit arch
	// but a different call table) before the number-based denylist below.
	filter = append(filter,
		unix.SockFilter{Code: bpfLdW, K: seccompDataNROffset},
		unix.SockFilter{Code: bpfJgeK, K: x32SyscallBit, Jt: 0, Jf: 1},
		unix.SockFilter{Code: bpfRetK, K: seccompRetKillProcess},
	)
	for _, nr := range denied {
		filter = append(filter,
			// nr == denied → fall through to the EPERM return; else skip it.
			unix.SockFilter{Code: bpfJeqK, K: uint32(nr), Jt: 0, Jf: 1}, // #nosec G115 -- nr is one of the small, fixed unix.SYS_* constants in deniedSyscalls
			unix.SockFilter{Code: bpfRetK, K: seccompRetDenyEPERM},
		)
	}

	// Default: allow.
	filter = append(filter, unix.SockFilter{Code: bpfRetK, K: seccompRetAllow})
	return filter
}
