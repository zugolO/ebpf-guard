package correlator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// driftNovelWorkloadSubset is the subset (б) of finding №193: escape/capture
// primitives for which a NEW workload's learning phase must not suppress a
// match at all — neither by its own baseline nor by the global fallback one.
//
// The list is spelled out rather than derived from a "container_escape_*"
// glob on purpose. container_escape_init_proc_daemon lives under the same
// prefix but is an info-severity rule for routine self-introspection by
// packaged daemons (prometheus/grafana/cron/pgrep); pulling it into the
// subset would alert on every newly started daemon for no detection gain.
// The pipeline preflight (run-6.0-pipeline.sh, "преflight: 6.0d") checks the
// same three ids against the YAML with awk; this test is the half that runs
// in `make test` and CI, where the stand is not involved.
var driftNovelWorkloadSubset = map[string]string{
	"drift_dangerous_syscall":     "../../rules/drift-rules.yaml",
	"container_escape_proc_write": "../../rules/container-escape.yaml",
	"container_escape_init_proc":  "../../rules/container-escape.yaml",
}

func TestDriftNovelWorkloadSubsetCarriesFlag(t *testing.T) {
	loaded := map[string][]Rule{}
	for _, path := range driftNovelWorkloadSubset {
		if _, ok := loaded[path]; ok {
			continue
		}
		rules, err := LoadRulesFromFile(path)
		require.NoErrorf(t, err, "load %s", path)
		loaded[path] = rules
	}

	for id, path := range driftNovelWorkloadSubset {
		var found *Rule
		for i := range loaded[path] {
			if loaded[path][i].ID == id {
				found = &loaded[path][i]
				break
			}
		}
		require.NotNilf(t, found, "rule %s not found in %s — it was renamed or removed without moving it out of the finding №193(б) subset", id, path)
		assert.Equalf(t, ClassDrift, found.EffectiveClass(),
			"rule %s must stay class: drift — the flag is only read on the drift path (engine.go: alert.Class == ClassDrift)", id)
		assert.Equalf(t, "alert", found.DriftNovelWorkload,
			"rule %s lost drift_novel_workload: alert — a new workload gets the learning-phase presumption of innocence back on an escape primitive (finding №193б), and control 6.0.6 will fail on the stand", id)
	}
}

// TestDriftNovelWorkloadDaemonVariantStaysOut pins the negative half: the
// deliberately excluded sibling must NOT acquire the flag by someone
// "completing the set" from the container_escape_* prefix.
func TestDriftNovelWorkloadDaemonVariantStaysOut(t *testing.T) {
	rules, err := LoadRulesFromFile("../../rules/container-escape.yaml")
	require.NoError(t, err)
	for i := range rules {
		if rules[i].ID == "container_escape_init_proc_daemon" {
			assert.Empty(t, rules[i].DriftNovelWorkload,
				"container_escape_init_proc_daemon is intentionally outside subset (б): it fires on routine daemon self-introspection, so removing its learning-phase suppression buys noise on every new daemon and no detection")
			return
		}
	}
	t.Fatal("container_escape_init_proc_daemon not found — if it was renamed, the exclusion rationale above needs to follow it")
}
