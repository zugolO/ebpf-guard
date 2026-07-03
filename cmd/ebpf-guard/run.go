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
			return runSandboxed(*cfgPath, profileName, enforce, auditLog, args)
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
	if err := config.ValidateConfig(cfg); err != nil {
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

	if err := mgr.Load(); err != nil {
		return fmt.Errorf("load sandbox: %w", err)
	}
	defer mgr.Close()

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

	logger.Info("sandbox active",
		"profile", profileName,
		"mode", mgr.Mode(),
		"kernel_enforced", mgr.KernelEnforced(),
		"cgroup_id", cg.ID(),
		"command", args[0])

	return execInCgroup(cg, args)
}

// execInCgroup starts args placed directly into the cgroup at clone time via
// CLONE_INTO_CGROUP (Linux 5.7+), so the child is under policy before it runs
// a single instruction. It forwards signals and the child's exit code.
func execInCgroup(cg *sandbox.Cgroup, args []string) error {
	cgFD, err := os.Open(cg.Path())
	if err != nil {
		return fmt.Errorf("open cgroup dir: %w", err)
	}
	defer cgFD.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	child := exec.CommandContext(ctx, args[0], args[1:]...)
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	child.SysProcAttr = &syscall.SysProcAttr{
		UseCgroupFD: true,
		CgroupFD:    int(cgFD.Fd()),
	}

	if err := child.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}
		return fmt.Errorf("run %q: %w", args[0], err)
	}
	return nil
}
