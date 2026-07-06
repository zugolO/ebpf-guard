package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/spf13/cobra"
	"github.com/zugolO/ebpf-guard/internal/audit"
	"github.com/zugolO/ebpf-guard/internal/bpf"
	"github.com/zugolO/ebpf-guard/internal/collector"
	"github.com/zugolO/ebpf-guard/internal/config"
	"github.com/zugolO/ebpf-guard/internal/sandbox"
)

// newRunCmd implements `ebpf-guard run` (issue #255, sub-task 3): the local
// entry point for wrapping a coding agent (Claude Code, Aider, a shell) in an
// ai_sandbox profile without Kubernetes. It creates a fresh cgroup, installs
// the profile's allow-lists for that cgroup ID, execs the child inside it, and
// tears the cgroup down on exit.
func newRunCmd(cfgPath *string) *cobra.Command {
	var (
		profileName string
		enforce     bool
		auditLog    string
		hardening   childHardening
	)

	cmd := &cobra.Command{
		Use:   "run [flags] -- COMMAND [ARGS...]",
		Short: "Run a command inside an AI-agent sandbox profile",
		Long: "Wrap COMMAND in a deny-by-default ai_sandbox profile scoped to a fresh cgroup.\n" +
			"The child (and any process it spawns) may only exec / read / write / connect to\n" +
			"what the profile allow-lists. Defaults to audit mode; pass --enforce to deny.\n\n" +
			"Defence in depth: on top of the cgroup/LSM sandbox the child also runs with\n" +
			"PR_SET_NO_NEW_PRIVS and a default seccomp filter (denies io_uring/module-load/\n" +
			"kexec), and can optionally be placed in a private network/mount namespace.",
		Example: "  ebpf-guard run --profile ai-agent -- claude\n" +
			"  ebpf-guard run --profile ai-agent --enforce -- bash -c 'cat ~/.ssh/id_rsa'\n" +
			"  ebpf-guard run --profile ai-agent --unshare-net -- ./build.sh",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			err := runSandboxed(*cfgPath, profileName, enforce, auditLog, hardening, args)
			// A non-zero *exitCodeError just mirrors the wrapped command's own
			// exit code (already visible via its inherited stdout/stderr) — not
			// an ebpf-guard error, so don't let cobra print "Error: ..." for it.
			var ec *exitCodeError
			if errors.As(err, &ec) {
				cmd.SilenceErrors = true
			}
			return err
		},
	}

	cmd.Flags().StringVar(&profileName, "profile", "", "ai_sandbox profile to apply (default: selector.default_profile)")
	cmd.Flags().BoolVar(&enforce, "enforce", false, "deny violations (-EPERM) instead of audit-only logging")
	cmd.Flags().StringVar(&auditLog, "audit-log", "", "path to write sandbox audit events (default: stderr)")
	cmd.Flags().BoolVar(&hardening.noNewPrivs, "no-new-privs", true, "set PR_SET_NO_NEW_PRIVS on the child (blocks setuid privilege re-gain)")
	cmd.Flags().BoolVar(&hardening.seccomp, "seccomp", true, "apply a default seccomp filter to the child (denies io_uring/module-load/kexec)")
	cmd.Flags().BoolVar(&hardening.dropCaps, "drop-caps", true, "drop CAP_BPF/CAP_SYS_ADMIN/CAP_SYS_PTRACE from the child so it cannot tamper with the enforcer (required for --enforce to hold)")
	cmd.Flags().BoolVar(&hardening.unshareNet, "unshare-net", false, "run the child in a private network namespace (isolates loopback; blocks all egress — requires privilege)")
	cmd.Flags().BoolVar(&hardening.unshareMount, "unshare-mount", false, "run the child in a private mount namespace (requires privilege)")
	return cmd
}

// childHardening carries the defence-in-depth boundaries `ebpf-guard run` layers
// around the wrapped command in addition to the cgroup/LSM sandbox (issue #277
// P2). no_new_privs, seccomp, and the tamper-capability drop are applied by the
// in-process trampoline (sandbox_child.go); the namespaces are requested at
// clone time.
type childHardening struct {
	noNewPrivs   bool
	seccomp      bool
	dropCaps     bool
	unshareNet   bool
	unshareMount bool
}

// needsTrampoline reports whether the child must be re-exec'd through the
// hidden trampoline command to install no_new_privs / seccomp / cap-drop.
// Namespaces alone are set at clone time and need no trampoline.
func (h childHardening) needsTrampoline() bool { return h.noNewPrivs || h.seccomp || h.dropCaps }

// cloneFlags returns the CLONE_* namespace flags to place on the child.
func (h childHardening) cloneFlags() uintptr {
	var f uintptr
	if h.unshareNet {
		f |= syscall.CLONE_NEWNET
	}
	if h.unshareMount {
		f |= syscall.CLONE_NEWNS
	}
	return f
}

// childExecTarget returns the executable and argv to run: either the command
// directly, or the /proc/self/exe trampoline wrapping it when no_new_privs,
// seccomp, or the cap-drop is requested. self is the path to this binary
// (/proc/self/exe).
func childExecTarget(self string, args []string, h childHardening) (name string, argv []string) {
	if !h.needsTrampoline() {
		return args[0], args[1:]
	}
	trampoline := []string{
		sandboxChildCmdName,
		fmt.Sprintf("--no-new-privs=%t", h.noNewPrivs),
		fmt.Sprintf("--seccomp=%t", h.seccomp),
		fmt.Sprintf("--drop-caps=%t", h.dropCaps),
		"--",
	}
	trampoline = append(trampoline, args...)
	return self, trampoline
}

func runSandboxed(cfgPath, profileName string, enforce bool, auditLog string, hardening childHardening, args []string) error {
	cfgManager, err := config.NewManagerSkipPermCheck(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	cfg := cfgManager.Get()
	aiCfg := cfg.AISandbox

	// The `run` wrapper activates the sandbox even if ai_sandbox.enabled is
	// false in the file: opting in is the whole point of the command.
	aiCfg.Enabled = true
	if enforce {
		aiCfg.Mode = "enforce"
	} else if aiCfg.Mode == "" {
		aiCfg.Mode = "audit"
	}

	if profileName == "" {
		profileName = aiCfg.Selector.DefaultProfile
	}
	if profileName == "" {
		return errors.New("no profile: pass --profile or set ai_sandbox.selector.default_profile")
	}
	// Validate the config run is actually about to load — aiCfg carries the
	// enabled/mode overrides above, but cfg (shared with the Manager) does not.
	// Swap it in for validation, then restore: config.Config has an embedded
	// mutex, so it can't be value-copied to validate a modified clone instead.
	origAISandbox := cfg.AISandbox
	cfg.AISandbox = aiCfg
	err = config.ValidateConfig(cfg)
	cfg.AISandbox = origAISandbox
	if err != nil {
		return fmt.Errorf("invalid ai_sandbox config: %w", err)
	}

	logger := slog.Default()
	mgr, err := sandbox.New(aiCfg, logger)
	if err != nil {
		return err
	}
	if _, ok := mgr.Policy().ProfileID(profileName); !ok {
		return fmt.Errorf("profile %q not defined in ai_sandbox.profiles", profileName)
	}

	if err := mgr.Load(nil); err != nil {
		return fmt.Errorf("load sandbox: %w", err)
	}
	defer func() {
		if err := mgr.Close(); err != nil {
			logger.Warn("close sandbox manager", "error", err)
		}
	}()

	// Item 7 (issue #259): the sandboxed child would inherit this process's
	// capabilities, and if it kept CAP_BPF/CAP_SYS_ADMIN/CAP_SYS_PTRACE it could
	// detach the LSM hooks or rewrite the sandbox maps — enforcement would be a
	// lie. The trampoline drops exactly those caps before exec (childHardening.
	// dropCaps → applyCapDrop), so we assess the child's *post-drop* credentials
	// rather than this guard's — the guard necessarily holds CAP_BPF to attach
	// the programs, which would otherwise force every enforce run to downgrade.
	// With --drop-caps disabled the child really does inherit them, so fall back
	// to assessing the guard directly. Either way GuardChild/GuardTarget latches
	// audit-only when unsafe so KernelEnforced()==false. Fail closed.
	if enforce {
		var safety sandbox.EnforcementSafety
		if hardening.dropCaps {
			safety = mgr.GuardChildAfterCapDrop(os.Getpid(), sandbox.DangerousCapMask())
		} else {
			safety = mgr.GuardTarget(os.Getpid())
		}
		if !safety.Safe {
			remediation := "launch the agent unprivileged: drop CAP_BPF/CAP_SYS_ADMIN/" +
				"CAP_SYS_PTRACE and deny write access to /sys/fs/bpf and /sys/fs/cgroup"
			if !hardening.dropCaps {
				remediation = "keep --drop-caps enabled (it removes these caps from the child), or " + remediation
			}
			logger.Warn("ai_sandbox: --enforce downgraded to audit-only — the sandboxed "+
				"process would retain privileges that can defeat enforcement",
				"reasons", safety.Reasons, "remediation", remediation)
		}
	}

	if !mgr.KernelEnforced() && enforce {
		logger.Warn("kernel enforcement unavailable; --enforce degraded to audit-only " +
			"(requires kernel 5.7+ with CONFIG_BPF_LSM)")
	}

	// Fresh cgroup for this invocation; its inode is the cgroup ID the hooks key on.
	cg, err := sandbox.NewCgroup(fmt.Sprintf("run-%d", os.Getpid()))
	if err != nil {
		return fmt.Errorf("create sandbox cgroup: %w", err)
	}
	defer func() {
		if rmErr := cg.Remove(); rmErr != nil {
			logger.Warn("cleanup sandbox cgroup", "error", rmErr)
		}
	}()

	if err := mgr.RegisterCgroup(cg.ID(), profileName); err != nil {
		return fmt.Errorf("register cgroup: %w", err)
	}
	defer func() { _ = mgr.UnregisterCgroup(cg.ID()) }()

	// Drain the sandbox lsm_events ring buffer and record every sandbox_audit /
	// sandbox_deny decision the LSM hooks emit. Without this the documented
	// audit-first flow produced no output at all and --audit-log was dead
	// (issue #268). Best-effort: on an audit-only kernel LSMEvents() is nil and
	// there is nothing to drain.
	if evMap := mgr.LSMEvents(); evMap != nil {
		writeEntry, closeSink, sinkErr := openAuditSink(auditLog, logger)
		if sinkErr != nil {
			return fmt.Errorf("open audit sink: %w", sinkErr)
		}
		defer closeSink()

		reader, rErr := bpf.NewRingbufReader(evMap)
		if rErr != nil {
			return fmt.Errorf("open sandbox audit reader: %w", rErr)
		}
		drainCtx, stopDrain := context.WithCancel(context.Background())
		defer func() {
			stopDrain()
			_ = reader.Close()
		}()
		go drainSandboxAudit(drainCtx, reader, writeEntry, logger)
	} else if auditLog != "" {
		logger.Warn("ai_sandbox: --audit-log has no effect without kernel LSM enforcement "+
			"(audit-only mode); no lsm_events to drain", "audit_log", auditLog)
	}

	// DNS-pinned egress (item 6): resolve the profile's allowed_domains and keep
	// their A/AAAA records programmed as egress allow entries for the lifetime of
	// the wrapped command. Started only when a profile lists domains.
	if pinner, ok := sandbox.NewDNSPinner(aiCfg, mgr, nil, logger); ok {
		pinCtx, stopPin := context.WithCancel(context.Background())
		defer stopPin()
		// Program the initial allow-list synchronously, before the child is
		// exec'd below. A child that connects to an allowed_domains host
		// immediately must find its sandbox_net_v4/v6 entries already in place;
		// resolving in the background would race the first connection and yield a
		// transient -EPERM in enforce mode until the pinner caught up (issue #269).
		pinner.RefreshOnce(pinCtx)
		go pinner.RefreshLoop(pinCtx)
	}

	// Defence-in-depth boundaries layered on top of the cgroup/LSM sandbox
	// (issue #277 P2). seccomp needs a supported arch; warn and continue with the
	// other boundaries rather than failing the run if it is unavailable.
	if hardening.seccomp && !seccompArchSupported {
		logger.Warn("ai_sandbox: default seccomp filter unavailable on this architecture; " +
			"continuing without it (no_new_privs, cgroup/LSM sandbox, and namespaces still apply)")
		hardening.seccomp = false
	}

	logger.Info("sandbox active",
		"profile", profileName,
		"mode", mgr.Mode(),
		"kernel_enforced", mgr.KernelEnforced(),
		"exec_enforced", mgr.ExecEnforced(),
		"cgroup_id", cg.ID(),
		"no_new_privs", hardening.noNewPrivs,
		"seccomp", hardening.seccomp,
		"drop_caps", hardening.dropCaps,
		"unshare_net", hardening.unshareNet,
		"unshare_mount", hardening.unshareMount,
		"command", args[0])

	code, err := execInCgroup(cg, args, hardening)
	if err != nil {
		return err
	}
	if code != 0 {
		// Returned rather than os.Exit'd here: os.Exit skips every deferred
		// call on the goroutine's stack, including cg.Remove(), UnregisterCgroup,
		// mgr.Close(), and stopping the DNS pinner registered earlier in this
		// function. Propagating an error lets those run via the normal return/
		// unwind path; main() turns *exitCodeError back into the precise
		// os.Exit(code) once nothing more needs to unwind.
		return &exitCodeError{code: code}
	}
	return nil
}

// openAuditSink returns a writer for sandbox audit records. When path is
// non-empty it appends JSONL to that file via the shared audit.Logger (with
// rotation); otherwise it writes JSON lines to stderr — the documented default
// for `ebpf-guard run` (issue #268). The returned close function flushes/closes
// the underlying file (a no-op for stderr).
func openAuditSink(path string, logger *slog.Logger) (write func(audit.Entry), closeFn func(), err error) {
	if path == "" {
		enc := json.NewEncoder(os.Stderr)
		return func(e audit.Entry) {
			if encErr := enc.Encode(e); encErr != nil {
				logger.Warn("sandbox audit: write to stderr failed", "error", encErr)
			}
		}, func() {}, nil
	}
	al, alErr := audit.New(path)
	if alErr != nil {
		return nil, nil, alErr
	}
	return func(e audit.Entry) {
			if logErr := al.Log(e); logErr != nil {
				logger.Warn("sandbox audit: write to log failed", "path", path, "error", logErr)
			}
		}, func() {
			if cErr := al.Close(); cErr != nil {
				logger.Warn("sandbox audit: close log failed", "path", path, "error", cErr)
			}
		}, nil
}

// drainSandboxAudit reads the sandbox lsm_events ring buffer, decodes each
// sandbox_audit / sandbox_deny record, and hands it to write. It returns when
// the reader is closed or ctx is cancelled (both happen when the wrapped command
// exits).
func drainSandboxAudit(ctx context.Context, reader *bpf.RingbufReader, write func(audit.Entry), logger *slog.Logger) {
	for {
		rec, err := reader.Read()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			logger.Warn("sandbox audit: ring read error", "error", err)
			continue
		}
		entry, sandbox, ok, decErr := collector.DecodeLSMAuditRecord(rec.RawSample)
		if decErr != nil {
			logger.Warn("sandbox audit: decode error", "error", decErr)
			continue
		}
		if !ok || !sandbox {
			continue // enforcer LSM audit events are handled by the daemon, not here
		}
		write(entry)
	}
}

// exitCodeError carries a wrapped command's exit code through cobra's
// RunE → Execute() error return so the code can reach os.Exit in main()
// without an os.Exit call short-circuiting deferred cleanup along the way.
type exitCodeError struct{ code int }

func (e *exitCodeError) Error() string {
	return fmt.Sprintf("command exited with status %d", e.code)
}

// execInCgroup starts args placed directly into the cgroup at clone time via
// CLONE_INTO_CGROUP (Linux 5.7+), so the child is under policy before it runs
// a single instruction. It forwards signals and returns the child's exit code
// for the caller to act on after its own cleanup has run. h adds the
// defence-in-depth boundaries (no_new_privs, seccomp, namespaces).
func execInCgroup(cg *sandbox.Cgroup, args []string, h childHardening) (int, error) {
	return runChild(cg, args, h)
}

// runChild runs args inside cg and returns the child's exit code (0 on
// success or a non-exit-error failure, which is returned as err instead).
func runChild(cg *sandbox.Cgroup, args []string, h childHardening) (int, error) {
	cgFD, err := os.Open(cg.Path())
	if err != nil {
		return 0, fmt.Errorf("open cgroup dir: %w", err)
	}
	defer func() { _ = cgFD.Close() }()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// When no_new_privs / seccomp are requested the command is wrapped in the
	// /proc/self/exe trampoline, which installs them and execve's the target
	// (keeping the PID, so signal forwarding below still reaches it). Namespaces
	// are requested via Cloneflags and inherited across that execve.
	name, cmdArgs := childExecTarget("/proc/self/exe", args, h)

	// name/cmdArgs are the operator-supplied COMMAND for `ebpf-guard run`
	// to execute inside the sandbox (or the trampoline wrapping it); running an
	// arbitrary command is the purpose of this wrapper, not an injection risk.
	child := exec.CommandContext(ctx, name, cmdArgs...) // #nosec G204
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	child.SysProcAttr = &syscall.SysProcAttr{
		UseCgroupFD: true,
		CgroupFD:    int(cgFD.Fd()),
		Cloneflags:  h.cloneFlags(),
	}

	if err := child.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode(), nil
		}
		return 0, fmt.Errorf("run %q: %w", args[0], err)
	}
	return 0, nil
}
