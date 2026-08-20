package correlator

// Unit tests for the two rules wave 5.9.4e rewrote in
// rules/rootkit-detection.yaml — rootkit_bpf_prog_load_suspicious and
// rootkit_bpf_map_create_suspicious (finding №56).
//
// Why this file exists. Both rules used to match a bare nr=321 gated only by
// a `comm not_in [ebpf-guard, bpftool, cilium-agent, falco]` whitelist. That
// matched every bpf(2) command, including bpftool's read-only introspection
// (BPF_PROG_GET_NEXT_ID etc.) — and simultaneously excluded, by name, the one
// process the stand's positive control runs as. 5.9.4e replaced the whitelist
// with a condition on the command itself (arg0). Nothing tested that change:
// the criterion ("both rules present in the detection set on замер №2.9.4")
// is only checkable on a live run, which is precisely how the original defect
// survived to a live run in the first place.
//
// bpf(2) commands (linux/bpf.h): BPF_MAP_CREATE=0, BPF_PROG_LOAD=5,
// BPF_PROG_GET_NEXT_ID=11, BPF_PROG_GET_FD_BY_ID=13, BPF_OBJ_GET_INFO_BY_FD=15
// — the last three are what `bpftool prog list` actually issues, confirmed by
// strace on the stand (plan.md 5.9.4e).

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

const rootkitRulesPath = "../../rules/rootkit-detection.yaml"

func rootkitBPFEngine(t *testing.T) *RuleEngine {
	t.Helper()
	rules, err := LoadRulesFromFile(rootkitRulesPath)
	require.NoError(t, err, "rootkit-detection.yaml must load without error")
	return NewRuleEngine(rules)
}

func firedRuleIDs(alerts []types.Alert) map[string]bool {
	out := make(map[string]bool, len(alerts))
	for _, a := range alerts {
		out[a.RuleID] = true
	}
	return out
}

func TestRootkitBPFRules_MatchCommandNotCaller(t *testing.T) {
	engine := rootkitBPFEngine(t)

	cases := []struct {
		name     string
		cmd      uint64
		comm     string
		wantFire string // rule that must fire; "" = neither may fire
	}{
		// Positive controls. bpftool is no longer excluded by name: the
		// `bpftool map create` step added to run_bpf_attack by 5.9.4e must
		// raise the map-create rule.
		{"map_create_by_bpftool", 0, "bpftool", "rootkit_bpf_map_create_suspicious"},
		{"map_create_by_unknown_tool", 0, "evil", "rootkit_bpf_map_create_suspicious"},
		{"prog_load_by_bpftool", 5, "bpftool", "rootkit_bpf_prog_load_suspicious"},
		{"prog_load_by_unknown_tool", 5, "evil", "rootkit_bpf_prog_load_suspicious"},

		// Negative controls: the read-only commands `bpftool prog list`
		// actually issues. Under the old comm-whitelist form these matched
		// on bare nr for any caller not in the whitelist; they must not now.
		{"prog_get_next_id", 11, "evil", ""},
		{"prog_get_fd_by_id", 13, "evil", ""},
		{"obj_get_info_by_fd", 15, "evil", ""},

		// The agent's own startup load stays excluded — that was the only
		// verified noise source, and the reason a whitelist existed at all.
		{"prog_load_by_agent", 5, "ebpf-guard", ""},
		{"map_create_by_agent", 0, "ebpf-guard", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fired := firedRuleIDs(engine.Evaluate(makeBPFEvent(tc.cmd, 0, tc.comm)))
			for _, id := range []string{"rootkit_bpf_map_create_suspicious", "rootkit_bpf_prog_load_suspicious"} {
				if id == tc.wantFire {
					require.True(t, fired[id], "%s (arg0=%d, comm=%s) must fire %s", tc.name, tc.cmd, tc.comm, id)
				} else {
					require.False(t, fired[id], "%s (arg0=%d, comm=%s) must not fire %s", tc.name, tc.cmd, tc.comm, id)
				}
			}
		})
	}
}
