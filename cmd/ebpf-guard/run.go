package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
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
	)

	cmd := &cobra.Command{
		Use:   "run [flags] -- COMMAND [ARGS...]",
		Short: "Run a command inside an AI-agent sandbox profile",
		Long: "Wrap COMMAND in a deny-by-default ai_sandbox profile scoped to a fresh cgroup.\n" +
			"The child (and any process it spawns) may only exec / read / write / connect to\n" +
			"what the profile allow-lists. Defaults to audit mode; pass --enforce to deny.",
		Example: "  ebpf-guard run --profile ai-agent -- claude\n" +
			"  ebpf-guard run --profile ai-agent --enforce -- bash -c 'cat ~/.ssh/id_rsa'",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			err := runSandboxed(*cfgPath, profileName, enforce, auditLog, args)
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
	return cmd
}

func runSandboxed(cfgPath, profileName string, enforce bool, auditLog string, args []string) error {
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

	// Item 7 (issue #259): the child inherits this process's capabilities, so
	// if we carry CAP_BPF/CAP_SYS_ADMIN/CAP_SYS_PTRACE (or bpffs/cgroupfs is
	// writable) the sandboxed child could detach the LSM hooks or rewrite the
	// sandbox maps — enforcement would be a lie. Assess before claiming it and
	// fail closed: GuardTarget latches audit-only so KernelEnforced()==false.
	if enforce {
		if safety := mgr.GuardTarget(os.Getpid()); !safety.Safe {
			logger.Warn("ai_sandbox: --enforce downgraded to audit-only — the sandboxed "+
				"process would inherit privileges that can defeat enforcement",
				"reasons", safety.Reasons,
				"remediation", "launch the agent unprivileged: drop CAP_BPF/CAP_SYS_ADMIN/"+
					"CAP_SYS_PTRACE and deny write access to /sys/fs/bpf and /sys/fs/cgroup")
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

	// DNS-pinned egress (item 6): resolve the profile's allowed_domains and keep
	// their A/AAAA records programmed as egress allow entries for the lifetime of
	// the wrapped command. Started only when a profile lists domains.
	if pinner, ok := sandbox.NewDNSPinner(aiCfg, mgr, nil, logger); ok {
		pinCtx, stopPin := context.WithCancel(context.Background())
		defer stopPin()
		go pinner.Run(pinCtx)
	}

	logger.Info("sandbox active",
		"profile", profileName,
		"mode", mgr.Mode(),
		"kernel_enforced", mgr.KernelEnforced(),
		"cgroup_id", cg.ID(),
		"command", args[0])

	code, err := execInCgroup(cg, args)
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
// for the caller to act on after its own cleanup has run.
func execInCgroup(cg *sandbox.Cgroup, args []string) (int, error) {
	return runChild(cg, args)
}

// runChild runs args inside cg and returns the child's exit code (0 on
// success or a non-exit-error failure, which is returned as err instead).
func runChild(cg *sandbox.Cgroup, args []string) (int, error) {
	cgFD, err := os.Open(cg.Path())
	if err != nil {
		return 0, fmt.Errorf("open cgroup dir: %w", err)
	}
	defer func() { _ = cgFD.Close() }()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// args[0]/args[1:] are the operator-supplied COMMAND for `ebpf-guard run`
	// to execute inside the sandbox; running an arbitrary command is the
	// purpose of this wrapper, not an injection risk.
	child := exec.CommandContext(ctx, args[0], args[1:]...) // #nosec G204
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	child.SysProcAttr = &syscall.SysProcAttr{
		UseCgroupFD: true,
		CgroupFD:    int(cgFD.Fd()),
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
