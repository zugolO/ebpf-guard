package main

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestChildExecTarget(t *testing.T) {
	cmd := []string{"bash", "-c", "echo hi"}

	t.Run("no hardening execs directly", func(t *testing.T) {
		name, argv := childExecTarget("/proc/self/exe", cmd, childHardening{})
		if name != "bash" {
			t.Fatalf("name = %q, want bash", name)
		}
		if strings.Join(argv, " ") != "-c echo hi" {
			t.Fatalf("argv = %v, want [-c echo hi]", argv)
		}
	})

	t.Run("nnp routes through trampoline", func(t *testing.T) {
		name, argv := childExecTarget("/proc/self/exe", cmd, childHardening{noNewPrivs: true})
		if name != "/proc/self/exe" {
			t.Fatalf("name = %q, want /proc/self/exe", name)
		}
		want := []string{sandboxChildCmdName, "--no-new-privs=true", "--seccomp=false", "--", "bash", "-c", "echo hi"}
		if strings.Join(argv, "\x00") != strings.Join(want, "\x00") {
			t.Fatalf("argv = %v, want %v", argv, want)
		}
	})

	t.Run("seccomp routes through trampoline", func(t *testing.T) {
		name, argv := childExecTarget("/proc/self/exe", cmd, childHardening{seccomp: true})
		if name != "/proc/self/exe" {
			t.Fatalf("name = %q, want /proc/self/exe", name)
		}
		if argv[0] != sandboxChildCmdName || argv[1] != "--no-new-privs=false" || argv[2] != "--seccomp=true" {
			t.Fatalf("unexpected trampoline argv: %v", argv)
		}
	})
}

func TestChildHardeningCloneFlags(t *testing.T) {
	if f := (childHardening{}).cloneFlags(); f != 0 {
		t.Fatalf("empty hardening cloneFlags = %#x, want 0", f)
	}
	if f := (childHardening{unshareNet: true}).cloneFlags(); f&syscall.CLONE_NEWNET == 0 {
		t.Fatalf("unshareNet did not set CLONE_NEWNET: %#x", f)
	}
	if f := (childHardening{unshareMount: true}).cloneFlags(); f&syscall.CLONE_NEWNS == 0 {
		t.Fatalf("unshareMount did not set CLONE_NEWNS: %#x", f)
	}
	both := (childHardening{unshareNet: true, unshareMount: true}).cloneFlags()
	if both&syscall.CLONE_NEWNET == 0 || both&syscall.CLONE_NEWNS == 0 {
		t.Fatalf("combined flags missing a namespace: %#x", both)
	}
}

func TestDefaultSeccompFilter(t *testing.T) {
	if !seccompArchSupported {
		t.Skip("seccomp filter not built for this architecture")
	}
	filter := defaultSeccompFilter()

	// 3 arch-check instructions + 1 load-nr + 2 per denied syscall + 1 default allow.
	denied := deniedSyscalls()
	if want := 5 + len(denied)*2; len(filter) != want {
		t.Fatalf("filter length = %d, want %d", len(filter), want)
	}

	// First instruction loads the arch word; the third rejects a foreign ABI.
	if filter[0].K != seccompDataArchOffset {
		t.Fatalf("first instr loads offset %d, want arch offset %d", filter[0].K, seccompDataArchOffset)
	}
	if filter[2].K != seccompRetKillProcess {
		t.Fatalf("arch mismatch action = %#x, want kill-process %#x", filter[2].K, seccompRetKillProcess)
	}
	// Last instruction is the default allow.
	if last := filter[len(filter)-1]; last.K != seccompRetAllow {
		t.Fatalf("default action = %#x, want allow %#x", last.K, seccompRetAllow)
	}

	// Every denied syscall must appear as a JEQ comparand guarding an EPERM deny.
	seen := make(map[uint32]bool)
	for i, ins := range filter {
		if ins.K == seccompRetDenyEPERM && i > 0 {
			seen[filter[i-1].K] = true
		}
	}
	for _, nr := range denied {
		if !seen[uint32(nr)] {
			t.Errorf("syscall %d is not denied by the filter", nr)
		}
	}
}

// TestSandboxChildIntegration re-execs the test binary through the trampoline
// helper and confirms the hardening actually landed on the final process
// (no_new_privs + seccomp filter mode in /proc/self/status) and that io_uring is
// denied. Runs unprivileged: no_new_privs lets an unprivileged process install
// the filter.
func TestSandboxChildIntegration(t *testing.T) {
	if !seccompArchSupported {
		t.Skip("seccomp filter not built for this architecture")
	}

	t.Run("no_new_privs and seccomp applied across execve", func(t *testing.T) {
		out := runHelper(t, "status", "1", "1")
		if !strings.Contains(out, "NoNewPrivs:\t1") {
			t.Errorf("child status missing NoNewPrivs=1:\n%s", out)
		}
		// Seccomp: 2 == SECCOMP_MODE_FILTER.
		if !strings.Contains(out, "Seccomp:\t2") {
			t.Errorf("child status missing Seccomp=2 (filter mode):\n%s", out)
		}
	})

	t.Run("no_new_privs only, no seccomp", func(t *testing.T) {
		out := runHelper(t, "status", "1", "0")
		if !strings.Contains(out, "NoNewPrivs:\t1") {
			t.Errorf("expected NoNewPrivs=1:\n%s", out)
		}
		if !strings.Contains(out, "Seccomp:\t0") {
			t.Errorf("expected Seccomp=0 (no filter):\n%s", out)
		}
	})

	t.Run("io_uring_setup denied under the filter", func(t *testing.T) {
		out := runHelper(t, "iouring", "1", "1")
		if !strings.Contains(out, "IOURING_DENIED_EPERM") {
			t.Errorf("io_uring_setup was not denied with EPERM:\n%s", out)
		}
	})
}

// runHelper re-execs this test binary in TestHelperProcess mode, applies the
// requested hardening, and returns its combined output.
func runHelper(t *testing.T, mode, nnp, seccomp string) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess", "--", mode)
	cmd.Env = append(os.Environ(),
		"GO_WANT_SANDBOX_HELPER=1",
		"HELPER_NNP="+nnp,
		"HELPER_SECCOMP="+seccomp,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper failed: %v\n%s", err, out)
	}
	return string(out)
}

// TestHelperProcess is the child side of runHelper. It is not a real test: it
// only runs when GO_WANT_SANDBOX_HELPER=1, applies the hardening, and either
// execs `cat /proc/self/status` (mode=status) or probes io_uring (mode=iouring).
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_SANDBOX_HELPER") != "1" {
		return
	}
	args := os.Args
	for i, a := range args {
		if a == "--" {
			args = args[i+1:]
			break
		}
	}
	mode := ""
	if len(args) > 0 {
		mode = args[0]
	}

	if os.Getenv("HELPER_NNP") == "1" {
		if err := applyNoNewPrivs(); err != nil {
			t.Fatalf("applyNoNewPrivs: %v", err)
		}
	}
	if os.Getenv("HELPER_SECCOMP") == "1" {
		if err := applyDefaultSeccomp(); err != nil {
			t.Fatalf("applyDefaultSeccomp: %v", err)
		}
	}

	switch mode {
	case "status":
		path, err := exec.LookPath("cat")
		if err != nil {
			t.Fatalf("find cat: %v", err)
		}
		// Exec so the reported status reflects the post-execve process, proving
		// the boundaries survive execve.
		if err := syscall.Exec(path, []string{"cat", "/proc/self/status"}, os.Environ()); err != nil {
			t.Fatalf("exec cat: %v", err)
		}
	case "iouring":
		var params [120]byte
		_, _, errno := syscall.Syscall(unix.SYS_IO_URING_SETUP, 1, uintptr(unsafe.Pointer(&params)), 0)
		if errno == syscall.EPERM {
			os.Stdout.WriteString("IOURING_DENIED_EPERM\n")
		} else {
			os.Stdout.WriteString("IOURING_ALLOWED errno=" + errno.Error() + "\n")
		}
		os.Exit(0)
	default:
		t.Fatalf("unknown helper mode %q", mode)
	}
}
