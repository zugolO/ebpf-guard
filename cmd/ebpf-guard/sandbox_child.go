package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
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
	)
	cmd := &cobra.Command{
		Use:    sandboxChildCmdName + " [flags] -- COMMAND [ARGS...]",
		Hidden: true,
		Args:   cobra.MinimumNArgs(1),
		// Internal re-exec target: never print usage/errors on the exec path.
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(_ *cobra.Command, args []string) error {
			return sandboxChildExec(childHardening{noNewPrivs: noNewPrivs, seccomp: seccompOn}, args)
		},
	}
	cmd.Flags().BoolVar(&noNewPrivs, "no-new-privs", true, "set PR_SET_NO_NEW_PRIVS before exec")
	cmd.Flags().BoolVar(&seccompOn, "seccomp", true, "install the default seccomp filter before exec")
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
	if h.seccomp {
		if err := applyDefaultSeccomp(); err != nil {
			return fmt.Errorf("install seccomp filter: %w", err)
		}
	}

	if err := syscall.Exec(path, args, os.Environ()); err != nil {
		return fmt.Errorf("exec %q: %w", path, err)
	}
	return nil // unreachable on success
}

// applyNoNewPrivs sets PR_SET_NO_NEW_PRIVS on the calling thread/process. It is
// permitted for unprivileged processes and is inherited across execve and fork.
func applyNoNewPrivs() error {
	return unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
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
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}
	if _, _, errno := unix.Syscall(unix.SYS_SECCOMP,
		uintptr(unix.SECCOMP_SET_MODE_FILTER),
		uintptr(unix.SECCOMP_FILTER_FLAG_TSYNC),
		uintptr(unsafe.Pointer(prog))); errno != 0 {
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

// defaultSeccompFilter assembles the classic-BPF seccomp program: reject any
// syscall issued under a non-native ABI (closes the x86 compat / x32 route where
// a number means a different call than the one filtered), deny each denylist
// entry with -EPERM, and allow everything else.
func defaultSeccompFilter() []unix.SockFilter {
	const (
		bpfLdW  = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS
		bpfJeqK = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
		bpfRetK = unix.BPF_RET | unix.BPF_K
	)
	denied := deniedSyscalls()
	filter := make([]unix.SockFilter, 0, len(denied)*2+4)

	// Load arch; if it is not the native ABI, kill the process.
	filter = append(filter,
		unix.SockFilter{Code: bpfLdW, K: seccompDataArchOffset},
		unix.SockFilter{Code: bpfJeqK, K: nativeAuditArch, Jt: 1, Jf: 0},
		unix.SockFilter{Code: bpfRetK, K: seccompRetKillProcess},
	)

	// Load the syscall number and deny each denylist entry with -EPERM.
	filter = append(filter, unix.SockFilter{Code: bpfLdW, K: seccompDataNROffset})
	for _, nr := range denied {
		filter = append(filter,
			// nr == denied → fall through to the EPERM return; else skip it.
			unix.SockFilter{Code: bpfJeqK, K: uint32(nr), Jt: 0, Jf: 1},
			unix.SockFilter{Code: bpfRetK, K: seccompRetDenyEPERM},
		)
	}

	// Default: allow.
	filter = append(filter, unix.SockFilter{Code: bpfRetK, K: seccompRetAllow})
	return filter
}
