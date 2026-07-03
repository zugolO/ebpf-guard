package attacker

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"github.com/zugolO/ebpf-guard/internal/config"
	"github.com/zugolO/ebpf-guard/internal/sandbox"
)

// Containment acceptance harness (issue #255, sub-task 7).
//
// The AIAgentScenarios above exercise the *detection* ruleset (rules that fire
// on agent misbehaviour). This harness exercises the *containment* side: the
// deny-by-default ai_sandbox policy that the LSM hooks enforce. Each scenario is
// one escape vector an over-eager or prompt-injected agent might attempt —
// kill, map-write, cgroup-escape, dropped-binary exec — and the harness asserts
// the reference enforce profile denies it (and still allows the benign control,
// so the profile is not a degenerate "deny everything").
//
// Evaluation is against the userspace sandbox.Policy oracle, which is
// byte-for-byte the decision the kernel hooks make, so this runs in CI with no
// kernel — the same acceptance smoke test threat detection already gets.

// ContainmentScenario describes one escape vector the sandbox must contain.
type ContainmentScenario struct {
	// ID is the stable identifier used with --scenario.
	ID string
	// Name is the human-readable title.
	Name string
	// Vector is the escape class: kill | map-write | cgroup-escape |
	// dropped-binary-exec.
	Vector string
	// Description explains what the agent attempts.
	Description string
	// MITRETech is the primary MITRE ATT&CK technique.
	MITRETech string
	// Attempt returns (contained, detail): whether the reference enforce policy
	// denies the vector, and a human-readable explanation.
	Attempt func(pol *sandbox.Policy) (bool, string)
	// Benign returns (allowed, detail) for a legitimate action the same policy
	// must still permit, or nil when the vector has no benign counterpart (an
	// agent never legitimately calls bpf()/mount()/kill-supervisor).
	Benign func(pol *sandbox.Policy) (bool, string)
}

// ContainmentResult is the outcome of running one ContainmentScenario.
type ContainmentResult struct {
	Scenario ContainmentScenario
	// Passed is true when the vector was contained AND (if present) the benign
	// control was allowed.
	Passed        bool
	Contained     bool
	ContainDetail string
	BenignOK      bool
	BenignChecked bool
	BenignDetail  string
	Duration      time.Duration
}

// ReferenceContainmentProfile is the enforce-mode profile the containment
// scenarios evaluate against. It models a typical coding-agent sandbox: exec and
// read from system + workspace locations (read-only), write only to a scratch
// dir that is deliberately NOT executable, and one hash-pinned interpreter.
func ReferenceContainmentProfile() config.AISandboxConfig {
	// A deterministic digest for the pinned interpreter; the "dropped binary"
	// scenario presents a different digest at the same path.
	realPython := sha256.Sum256([]byte("the-real-python3"))
	return config.AISandboxConfig{
		Enabled: true,
		Mode:    "enforce",
		Profiles: []config.AISandboxProfile{{
			Name:              "ai-agent",
			AllowedExec:       []string{"/usr/bin", "/bin"},
			AllowedReadPaths:  []string{"/usr", "/bin", "/lib", "/etc/ssl", "/workspace"},
			AllowedWritePaths: []string{"/workspace/scratch"}, // writable, not under an exec prefix
			AllowedExecPins: []config.AISandboxExecPin{{
				Path:   "/usr/bin/python3",
				Sha256: hex.EncodeToString(realPython[:]),
			}},
			AllowedEgressCIDRs: []string{"140.82.112.0/20"},
			AllowedEgressPorts: []uint16{443},
		}},
		Selector: config.AISandboxSelector{DefaultProfile: "ai-agent"},
	}
}

const containmentProfile = "ai-agent"

// ContainmentScenarios returns the escape-vector acceptance scenarios.
func ContainmentScenarios() []ContainmentScenario {
	return []ContainmentScenario{
		containKillSupervisor(),
		containMapWrite(),
		containCgroupEscape(),
		containDroppedBinaryExec(),
	}
}

func containKillSupervisor() ContainmentScenario {
	return ContainmentScenario{
		ID:          "contain-kill-supervisor",
		Name:        "Containment: signal a protected process (kill)",
		Vector:      "kill",
		Description: "A sandboxed agent sends SIGKILL to the ebpf-guard/supervisor process to disable its own containment.",
		MITRETech:   "T1562.001",
		Attempt: func(pol *sandbox.Policy) (bool, string) {
			ok := pol.EscapeContained(sandbox.EscapeSignalProtected)
			return ok, "lsm_task_kill denies a sandboxed task signalling a protected PID"
		},
	}
}

func containMapWrite() ContainmentScenario {
	return ContainmentScenario{
		ID:          "contain-map-write",
		Name:        "Containment: bpf() map tampering (map-write)",
		Vector:      "map-write",
		Description: "A sandboxed agent calls bpf() to update/delete the sandbox_* maps or detach the LSM links that constrain it.",
		MITRETech:   "T1562.001",
		Attempt: func(pol *sandbox.Policy) (bool, string) {
			ok := pol.EscapeContained(sandbox.EscapeBPF)
			return ok, "lsm_sandbox_bpf denies the bpf() syscall for a sandboxed task"
		},
	}
}

func containCgroupEscape() ContainmentScenario {
	return ContainmentScenario{
		ID:          "contain-cgroup-escape",
		Name:        "Containment: mount/cgroup escape",
		Vector:      "cgroup-escape",
		Description: "A sandboxed agent calls mount(2) to remap its filesystem view and break out of the cgroup boundary.",
		MITRETech:   "T1611",
		Attempt: func(pol *sandbox.Policy) (bool, string) {
			ok := pol.EscapeContained(sandbox.EscapeMount)
			return ok, "lsm_sandbox_mount denies mount(2) for a sandboxed task"
		},
	}
}

func containDroppedBinaryExec() ContainmentScenario {
	// The agent downloads a payload and tries to run it. Two sub-cases the policy
	// must deny: (1) exec from a path outside allowed_exec, and the subtler
	// (2) a binary swapped in place of a hash-pinned interpreter.
	swapped := sha256.Sum256([]byte("malicious-payload"))
	genuine := sha256.Sum256([]byte("the-real-python3"))
	return ContainmentScenario{
		ID:          "contain-dropped-binary-exec",
		Name:        "Containment: dropped-binary exec",
		Vector:      "dropped-binary-exec",
		Description: "A sandboxed agent execs a binary it dropped in a writable dir, and tries to swap a payload in for a pinned interpreter.",
		MITRETech:   "T1105",
		Attempt: func(pol *sandbox.Policy) (bool, string) {
			// (1) exec of a binary dropped in the writable scratch dir.
			droppedDenied := !pol.ExecAllowed(containmentProfile, "/workspace/scratch/payload", swapped)
			// (2) payload swapped in at the pinned interpreter path.
			swapDenied := !pol.ExecAllowed(containmentProfile, "/usr/bin/python3", swapped)
			if droppedDenied && swapDenied {
				return true, "exec of /workspace/scratch/payload denied (outside allowed_exec) and hash-swapped /usr/bin/python3 denied (pin mismatch)"
			}
			return false, fmt.Sprintf("dropped-denied=%v swap-denied=%v (both must hold)", droppedDenied, swapDenied)
		},
		Benign: func(pol *sandbox.Policy) (bool, string) {
			// The genuine pinned interpreter (matching digest) must still run.
			ok := pol.ExecAllowed(containmentProfile, "/usr/bin/python3", genuine)
			return ok, "genuine /usr/bin/python3 (matching pin) is allowed"
		},
	}
}

// RunContainment evaluates every containment scenario against the reference
// enforce policy and returns their results. An invalid reference profile is a
// programming error and returns an error.
func RunContainment(scenarios []ContainmentScenario) ([]ContainmentResult, error) {
	if len(scenarios) == 0 {
		scenarios = ContainmentScenarios()
	}
	cfg := ReferenceContainmentProfile()
	if err := config.ValidateConfig(&config.Config{
		Server:      config.ServerConfig{BindAddress: ":9090"},
		Store:       config.StoreConfig{Backend: "memory"},
		Enforcement: config.EnforcementConfig{BlockBackend: "log"},
		AISandbox:   cfg,
	}); err != nil {
		return nil, fmt.Errorf("reference containment profile is invalid: %w", err)
	}
	pol, err := sandbox.Compile(cfg)
	if err != nil {
		return nil, fmt.Errorf("compile reference profile: %w", err)
	}

	results := make([]ContainmentResult, 0, len(scenarios))
	for _, sc := range scenarios {
		start := time.Now()
		contained, cdetail := sc.Attempt(pol)
		res := ContainmentResult{
			Scenario:      sc,
			Contained:     contained,
			ContainDetail: cdetail,
		}
		res.Passed = contained
		if sc.Benign != nil {
			res.BenignChecked = true
			res.BenignOK, res.BenignDetail = sc.Benign(pol)
			res.Passed = res.Passed && res.BenignOK
		}
		res.Duration = time.Since(start)
		results = append(results, res)
	}
	return results, nil
}

// PrintContainmentResults writes a formatted summary of containment results.
func PrintContainmentResults(results []ContainmentResult, w io.Writer) {
	passed, failed := 0, 0
	for _, r := range results {
		if r.Passed {
			passed++
		} else {
			failed++
		}
	}
	fmt.Fprintf(w, "\n=== AI-Agent Containment Acceptance ===\n")                              //nolint:errcheck
	fmt.Fprintf(w, "Vectors: %d  Contained: %d  Failed: %d\n\n", len(results), passed, failed) //nolint:errcheck
	for _, r := range results {
		status := "PASS"
		if !r.Passed {
			status = "FAIL"
		}
		fmt.Fprintf(w, "[%s] %-28s  vector=%-20s  mitre=%s\n", status, r.Scenario.ID, r.Scenario.Vector, r.Scenario.MITRETech) //nolint:errcheck
		fmt.Fprintf(w, "       contained: %v — %s\n", r.Contained, r.ContainDetail)                                            //nolint:errcheck
		if r.BenignChecked {
			fmt.Fprintf(w, "       benign allowed: %v — %s\n", r.BenignOK, r.BenignDetail) //nolint:errcheck
		}
	}
	fmt.Fprintln(w) //nolint:errcheck
}
