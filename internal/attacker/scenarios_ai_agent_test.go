package attacker

import (
	"context"
	"log/slog"
	"testing"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

const aiAgentRulesPath = "../../rules/ai-agent/ai-agent.yaml"

// TestAIAgentScenariosFireExpectedRules is the sub-task 7 smoke test: every
// agent-misbehavior scenario must trip its expected rule against the real
// ai-agent ruleset, mirroring how threat-detection scenarios are CI-verified.
func TestAIAgentScenariosFireExpectedRules(t *testing.T) {
	runner := NewRunner(AIAgentScenarios(), slog.Default())
	results, err := runner.RunSynthetic(context.Background(), aiAgentRulesPath)
	if err != nil {
		t.Fatalf("run ai-agent scenarios: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("no ai-agent scenarios ran")
	}
	for _, r := range results {
		if !r.Passed {
			t.Errorf("scenario %q did not fire expected rules %v (fired: %v)",
				r.Scenario.ID, r.Missing, r.Fired)
		}
	}
}

// TestAIAgentBenignWorkDoesNotFire pins the other half of the epic's acceptance
// criterion: benign agent activity must not trip the containment rules.
func TestAIAgentBenignWorkDoesNotFire(t *testing.T) {
	benign := []Scenario{
		{
			ID:   "benign-workspace-read",
			Name: "benign source read",
			Event: func() types.Event {
				return types.Event{
					Type:      types.EventFileAccess,
					Timestamp: ts(),
					PID:       99820,
					UID:       1000,
					Comm:      comm("claude"),
					File: &types.FileEvent{
						Filename: filename("/workspace/src/main.go"),
						Op:       1, // read
					},
				}
			},
		},
		{
			ID:   "benign-npm-test",
			Name: "benign npm test",
			Event: func() types.Event {
				return types.Event{
					Type:      types.EventSyscall,
					Timestamp: ts(),
					PID:       99821,
					Comm:      comm("npm"),
					ProcArgs:  "npm test --silent",
					Syscall:   &types.SyscallEvent{Nr: 59},
				}
			},
		},
	}

	runner := NewRunner(benign, slog.Default())
	results, err := runner.RunSynthetic(context.Background(), aiAgentRulesPath)
	if err != nil {
		t.Fatalf("run benign scenarios: %v", err)
	}
	for _, r := range results {
		if len(r.Fired) != 0 {
			t.Errorf("benign scenario %q unexpectedly fired rules: %v", r.Scenario.ID, r.Fired)
		}
	}
}
