package correlator

// Unit tests for rules/ebpf-subversion.yaml.
//
// Each test loads the YAML file, then fires synthetic events through the rule
// engine and asserts which rule IDs fire (or don't fire).
//
// BPF command values (linux/bpf.h):
//   BPF_MAP_DELETE_ELEM = 3
//   BPF_OBJ_PIN         = 6
//   BPF_PROG_DETACH     = 9
//   BPF_LINK_DETACH     = 33
//   BPF_PROG_LOAD       = 5  (benign — should not trigger rules)
//
// bpf(2) syscall number on x86-64 = 321

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

const ebpfSubversionRulesPath = "../../rules/ebpf-subversion.yaml"

// Destructive BPF command numbers from linux/bpf.h.
var destructiveBPFCmds = []struct {
	cmd  uint64
	name string
}{
	{3, "BPF_MAP_DELETE_ELEM"},
	{6, "BPF_OBJ_PIN"},
	{9, "BPF_PROG_DETACH"},
	{33, "BPF_LINK_DETACH"},
}

// makeBPFEvent builds an EventSyscall representing a bpf(2) call.
// cmd is placed in Args[0] (first argument), matching the kernel ABI.
func makeBPFEvent(cmd uint64, uid uint32, comm string) types.Event {
	e := types.Event{
		Type:      types.EventSyscall,
		Timestamp: 1,
		PID:       42,
		UID:       uid,
		Syscall: &types.SyscallEvent{
			Nr:   321, // bpf(2) on x86-64
			Args: [6]uint64{cmd},
		},
	}
	copy(e.Comm[:], comm)
	return e
}

// alertIDs returns the RuleID from each alert, for concise assertions.
func bpfAlertIDs(alerts []types.Alert) []string {
	ids := make([]string, 0, len(alerts))
	for _, a := range alerts {
		ids = append(ids, a.RuleID)
	}
	return ids
}

// TestEBPFSubversionRules_Load verifies the YAML parses cleanly and produces
// exactly the expected rule IDs with critical severity.
func TestEBPFSubversionRules_Load(t *testing.T) {
	rules, err := LoadRulesFromFile(ebpfSubversionRulesPath)
	require.NoError(t, err, "ebpf-subversion.yaml must load without error")
	require.Len(t, rules, 2, "expected exactly 2 ebpf-subversion rules")

	ids := map[string]bool{}
	for _, r := range rules {
		ids[r.ID] = true
		assert.Equal(t, types.SeverityCritical, r.Severity, "rule %s must be critical", r.ID)
		assert.Equal(t, ActionKill, r.Action, "rule %s must use kill action", r.ID)
	}
	assert.True(t, ids["ebpf_subversion_detach_nonroot"], "ebpf_subversion_detach_nonroot rule missing")
	assert.True(t, ids["ebpf_subversion_unauthorized_caller"], "ebpf_subversion_unauthorized_caller rule missing")
}

// TestEBPFSubversion_DetachNonRoot verifies that destructive BPF commands
// from non-root processes trigger ebpf_subversion_detach_nonroot.
func TestEBPFSubversion_DetachNonRoot(t *testing.T) {
	rules, err := LoadRulesFromFile(ebpfSubversionRulesPath)
	require.NoError(t, err)
	engine := NewRuleEngine(rules)

	t.Run("all_destructive_commands_fire", func(t *testing.T) {
		for _, tc := range destructiveBPFCmds {
			e := makeBPFEvent(tc.cmd, 1000, "malicious-tool")
			alerts := engine.Evaluate(e)
			assert.Contains(t, bpfAlertIDs(alerts), "ebpf_subversion_detach_nonroot",
				"%s (cmd=%d) from uid=1000 must trigger detach_nonroot", tc.name, tc.cmd)
		}
	})

	t.Run("root_caller_does_not_fire_rule1", func(t *testing.T) {
		for _, tc := range destructiveBPFCmds {
			e := makeBPFEvent(tc.cmd, 0, "malicious-tool")
			for _, a := range engine.Evaluate(e) {
				assert.NotEqual(t, "ebpf_subversion_detach_nonroot", a.RuleID,
					"%s from root (uid=0) must not trigger detach_nonroot", tc.name)
			}
		}
	})

	t.Run("benign_command_does_not_fire_rule1", func(t *testing.T) {
		// BPF_PROG_LOAD (5) from a non-root process is not in the destructive list.
		e := makeBPFEvent(5, 1000, "loader")
		for _, a := range engine.Evaluate(e) {
			assert.NotEqual(t, "ebpf_subversion_detach_nonroot", a.RuleID,
				"BPF_PROG_LOAD from non-root must not trigger detach_nonroot")
		}
	})

	t.Run("wrong_syscall_does_not_fire", func(t *testing.T) {
		e := types.Event{
			Type: types.EventSyscall,
			UID:  1000,
			Syscall: &types.SyscallEvent{
				Nr:   59, // execve — unrelated syscall
				Args: [6]uint64{9},
			},
		}
		copy(e.Comm[:], "malicious")
		alerts := engine.Evaluate(e)
		assert.Empty(t, alerts, "execve must not trigger any ebpf-subversion rule")
	})
}

// TestEBPFSubversion_UnauthorizedCaller verifies that destructive BPF commands
// from processes not in the whitelist trigger ebpf_subversion_unauthorized_caller,
// regardless of UID.
func TestEBPFSubversion_UnauthorizedCaller(t *testing.T) {
	rules, err := LoadRulesFromFile(ebpfSubversionRulesPath)
	require.NoError(t, err)
	engine := NewRuleEngine(rules)

	t.Run("unknown_comm_fires_rule2", func(t *testing.T) {
		for _, tc := range destructiveBPFCmds {
			// Root-owned tool that is not the agent.
			e := makeBPFEvent(tc.cmd, 0, "bpftool")
			assert.Contains(t, bpfAlertIDs(engine.Evaluate(e)), "ebpf_subversion_unauthorized_caller",
				"bpftool calling %s must trigger unauthorized_caller", tc.name)
		}
	})

	t.Run("ebpf_guard_agent_is_whitelisted", func(t *testing.T) {
		for _, tc := range destructiveBPFCmds {
			e := makeBPFEvent(tc.cmd, 0, "ebpf-guard")
			for _, a := range engine.Evaluate(e) {
				assert.NotEqual(t, "ebpf_subversion_unauthorized_caller", a.RuleID,
					"ebpf-guard calling %s must not trigger unauthorized_caller", tc.name)
			}
		}
	})

	t.Run("benign_command_from_unknown_comm_does_not_fire_rule2", func(t *testing.T) {
		// BPF_PROG_LOAD (5) is not in the destructive list for rule 2.
		e := makeBPFEvent(5, 1000, "bpftool")
		for _, a := range engine.Evaluate(e) {
			assert.NotEqual(t, "ebpf_subversion_unauthorized_caller", a.RuleID,
				"BPF_PROG_LOAD from bpftool must not trigger unauthorized_caller")
		}
	})
}

// TestEBPFSubversion_BothRulesFire verifies that a non-root, non-agent process
// issuing a destructive BPF command triggers BOTH rules simultaneously.
func TestEBPFSubversion_BothRulesFire(t *testing.T) {
	rules, err := LoadRulesFromFile(ebpfSubversionRulesPath)
	require.NoError(t, err)
	engine := NewRuleEngine(rules)

	// uid=1000 (non-root) + comm="bpftool" (not ebpf-guard) + BPF_PROG_DETACH
	e := makeBPFEvent(9, 1000, "bpftool")
	ids := bpfAlertIDs(engine.Evaluate(e))

	assert.Contains(t, ids, "ebpf_subversion_detach_nonroot",
		"uid=1000 bpftool must trigger detach_nonroot")
	assert.Contains(t, ids, "ebpf_subversion_unauthorized_caller",
		"uid=1000 bpftool must trigger unauthorized_caller")
}

// TestEBPFSubversion_SyscallFieldsExposed verifies that uid, comm, and arg0
// are accessible as rule condition fields for EventSyscall events.
func TestEBPFSubversion_SyscallFieldsExposed(t *testing.T) {
	engine := NewRuleEngine([]Rule{
		{
			ID:        "uid_check",
			Name:      "UID check",
			EventType: types.EventSyscall,
			Condition: RuleCondition{Field: "uid", Op: OpEquals, Values: []string{"1000"}},
			Severity:  types.SeverityWarning,
			Action:    ActionAlert,
		},
		{
			ID:        "comm_check",
			Name:      "Comm check",
			EventType: types.EventSyscall,
			Condition: RuleCondition{Field: "comm", Op: OpEquals, Values: []string{"attacker"}},
			Severity:  types.SeverityWarning,
			Action:    ActionAlert,
		},
		{
			ID:        "arg0_check",
			Name:      "Arg0 check",
			EventType: types.EventSyscall,
			Condition: RuleCondition{Field: "arg0", Op: OpEquals, Values: []string{"9"}},
			Severity:  types.SeverityWarning,
			Action:    ActionAlert,
		},
	})

	e := makeBPFEvent(9, 1000, "attacker")
	ids := bpfAlertIDs(engine.Evaluate(e))

	assert.Contains(t, ids, "uid_check", "uid field must be accessible for syscall events")
	assert.Contains(t, ids, "comm_check", "comm field must be accessible for syscall events")
	assert.Contains(t, ids, "arg0_check", "arg0 field must be accessible for syscall events")
}
