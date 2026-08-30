package exporter

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDebugStateDriftBaselineJSONShape pins the exact JSON paths the 6.0.4
// pipeline guard reads with jq. Measurement №6.0 asserted "our drift-pc seed is
// enforcing" while actually only comparing two aggregate numbers, and had no
// way to check the claim; the guard now reads
// .drift_baseline.workloads[] | select(.comm=="drift-pc") | .state, so a
// renamed json tag here would silently turn that guard back into a no-op.
func TestDebugStateDriftBaselineJSONShape(t *testing.T) {
	h := NewDebugHandler("test", nil)
	started := time.Now().Add(-20 * time.Minute)
	h.SetDriftBaselineProvider(func() *DriftBaselineState {
		return &DriftBaselineState{
			Profiles: 2, Learning: 1, Stuck: 1, Saturated: 0,
			Workloads: []DriftWorkloadState{
				{Workload: "drift-pc||", Comm: "drift-pc", State: "enforcing",
					Signatures: 4, Samples: 26, Reported: 2, StartedAt: started, LastSeen: time.Now()},
				{Workload: "rare||", Comm: "rare", State: "stuck",
					Signatures: 1, Samples: 1, StartedAt: started, LastSeen: time.Now()},
			},
		}
	})

	raw, err := json.Marshal(h.buildState())
	require.NoError(t, err)

	var got struct {
		DriftBaseline *struct {
			Profiles  int `json:"profiles"`
			Learning  int `json:"learning"`
			Stuck     int `json:"stuck"`
			Saturated int `json:"saturated"`
			Workloads []struct {
				Comm       string `json:"comm"`
				State      string `json:"state"`
				Signatures int    `json:"signatures"`
				Samples    int    `json:"samples"`
				Saturated  bool   `json:"saturated"`
				Reported   int    `json:"reported"`
			} `json:"workloads"`
		} `json:"drift_baseline"`
	}
	require.NoError(t, json.Unmarshal(raw, &got))
	require.NotNil(t, got.DriftBaseline, "drift_baseline must be present when a provider is wired")
	require.Len(t, got.DriftBaseline.Workloads, 2)

	byComm := map[string]string{}
	reported := map[string]int{}
	signatures := map[string]int{}
	for _, w := range got.DriftBaseline.Workloads {
		byComm[w.Comm] = w.State
		reported[w.Comm] = w.Reported
		signatures[w.Comm] = w.Signatures
	}
	assert.Equal(t, "enforcing", byComm["drift-pc"], "the guard selects by comm and compares state")
	assert.Equal(t, "stuck", byComm["rare"])
	assert.Equal(t, 1, got.DriftBaseline.Stuck)
	// The pipeline prints signatures and reported per workload at the idle-hour
	// open: together they are the pre-run predictor of drift alert volume, since
	// report-once makes volume track distinct new signatures rather than how
	// often they run.
	assert.Equal(t, 4, signatures["drift-pc"])
	assert.Equal(t, 2, reported["drift-pc"])
}

// TestDebugStateOmitsDriftBaselineWhenDisabled: a build with
// profiler.drift_baseline off must not grow an empty drift_baseline object,
// so the 6.0.4 guard's "no workloads section" die-path stays meaningful.
func TestDebugStateOmitsDriftBaselineWhenDisabled(t *testing.T) {
	h := NewDebugHandler("test", nil)
	raw, err := json.Marshal(h.buildState())
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "drift_baseline")
}
