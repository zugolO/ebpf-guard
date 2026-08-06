package correlator

import (
	"context"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/internal/profiler"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// emptyChainCounterValue reads the current value of
// ebpf_guard_incidents_empty_chain_total{verdict=v}.
func emptyChainCounterValue(t *testing.T, verdict string) float64 {
	t.Helper()
	c, err := incidentsEmptyChainTotal.GetMetricWithLabelValues(verdict)
	if err != nil {
		t.Fatalf("GetMetricWithLabelValues(%q): %v", verdict, err)
	}
	var m dto.Metric
	if err := c.(prometheus.Metric).Write(&m); err != nil {
		t.Fatalf("write metric: %v", err)
	}
	return m.GetCounter().GetValue()
}

// TestCorrelationEngine_LineageFillsProcessTree_P0_1 is the P0-1 acceptance
// test. It exercises the full pipeline from event ingestion through to the
// emitted alert: events carrying BPF-supplied PPID/ParentComm (the shape every
// collector emits after the bpf/common.h fix, or that the userspace /proc
// fallback in lineage.go derives when PPID is zero) must reach the alert with
// a populated ProcessTree, and the resulting incident must group the whole
// attack chain under a shared root.
//
// Before P0-1, this test failed at the first assertion: GetProcessTree
// returned nil for every event from the four main collectors because
// fill_process_info zeroed ppid and getParentInfo skipped the /proc fallback
// when e.PPID == 0. The symptom in production was 114/114 incidents with
// `in process chain unknown` and zero multi-PID incidents across four attack
// runs — exactly what this test guards against.
func TestCorrelationEngine_LineageFillsProcessTree_P0_1(t *testing.T) {
	// One rule that fires on every event so each link in the chain emits an
	// alert. The rule condition matches the syscall number used below.
	rule := Rule{
		ID:        "chain_probe",
		EventType: types.EventSyscall,
		Condition: RuleCondition{Field: "nr", Op: OpEquals, Values: []string{"1"}},
		Severity:  types.SeverityWarning,
		Action:    ActionAlert,
	}

	lt := profiler.NewLineageTracker(profiler.DefaultLineageConfig(), nil)

	cfg := DefaultCorrelationEngineConfig()
	cfg.Rules = []Rule{rule}
	cfg.EnableRateLimit = false
	cfg.EnableAnomaly = false
	cfg.EnableDedup = false
	cfg.LineageTracker = lt
	engine := NewCorrelationEngineWithConfig(cfg)
	defer engine.Close()

	ctx := context.Background()

	// Build the attack chain bash(100) → curl(200) → xmrig(300) by feeding
	// three events with BPF-supplied PPID/ParentComm. After P0-1 each event
	// produces an alert carrying the full ancestor chain.
	steps := []struct {
		pid        uint32
		ppid       uint32
		comm       string
		parentComm string
	}{
		{pid: 100, ppid: 1, comm: "bash", parentComm: "systemd"},
		{pid: 200, ppid: 100, comm: "curl", parentComm: "bash"},
		{pid: 300, ppid: 200, comm: "xmrig", parentComm: "curl"},
	}
	for _, s := range steps {
		engine.Ingest(ctx, types.Event{
			Type:       types.EventSyscall,
			PID:        s.pid,
			PPID:       s.ppid,
			Comm:       comm16(s.comm),
			ParentComm: comm16(s.parentComm),
			Syscall:    &types.SyscallEvent{Nr: 1},
		})
	}

	alerts := engine.Flush()
	require.Len(t, alerts, 3, "each chain link must emit an alert")

	// Every alert must carry a non-empty ProcessTree — the literal P0-1
	// regression signal. Empty trees here mean the lineage pipeline is
	// disconnected again (the four-run symptom).
	for i, a := range alerts {
		require.NotEmpty(t, a.ProcessTree,
			"alert %d (pid=%d comm=%s) has empty ProcessTree — P0-1 regressed",
			i, a.PID, a.Comm)
	}

	// The leaf alert must carry the full chain bash → curl → xmrig.
	leaf := alerts[len(alerts)-1]
	require.Equal(t, uint32(300), leaf.PID)
	chainComms := make([]string, 0, len(leaf.ProcessTree))
	for _, node := range leaf.ProcessTree {
		if node.Comm != "" {
			chainComms = append(chainComms, node.Comm)
		}
	}
	assert.Equal(t, []string{"bash", "curl", "xmrig"}, chainComms,
		"leaf alert must carry the full ancestor chain root → leaf")

	// Feeding the same chain's alerts into the incident tracker must group
	// them under a single incident rooted at PID 100. Before P0-1 each alert
	// got its own incident because the empty tree made rootPID == alert.PID.
	tr := engine.IncidentTracker()
	incidents := tr.GetAll("", "", 0)
	require.Len(t, incidents, 1, "whole chain must collapse into one incident")
	inc := incidents[0]
	assert.Equal(t, uint32(100), inc.RootPID, "incident root must be the chain root")
	assert.GreaterOrEqual(t, len(inc.ProcessChain), 3,
		"incident process_chain must contain at least the three chain links")
}

// TestCorrelationEngine_LineageFallbackPPIDZero_P0_1 verifies the userspace
// /proc fallback path added in lineage.go for the production condition where
// BPF left e.PPID == 0. This is the exact shape emitted by fill_process_info
// in bpf/common.h for the four main collectors (syscall, network, fileaccess,
// privesc) — the shape that produced the empty ProcessTree in attack runs
// 1–4.
//
// The fallback reads /proc/<pid>/status, so the test must run on a Linux host
// with the actual processes it references. It is skipped elsewhere to avoid
// false negatives from /proc being absent.
func TestCorrelationEngine_LineageFallbackPPIDZero_P0_1(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() == 0 {
		// Skip under root (containers) where /proc reads may behave differently
		// than the unprivileged production agent, and on non-Linux where /proc
		// does not exist.
		t.Skipf("skipping /proc fallback test on %s uid=%d", runtime.GOOS, os.Getuid())
	}

	lt := profiler.NewLineageTracker(profiler.DefaultLineageConfig(), nil)

	// Use the test process itself: its PID exists in /proc and its parent is
	// the test runner (go test). The /proc fallback must recover PPID even
	// though e.PPID is zero.
	selfPID := uint32(os.Getpid())
	require.Greater(t, selfPID, uint32(1), "test must have a real PID")

	lt.Track(types.Event{
		PID:  selfPID,
		PPID: 0, // production condition: BPF did not populate PPID
		Comm: comm16("go"),
	})

	tree := lt.GetProcessTree(selfPID)
	require.NotEmpty(t, tree,
		"/proc fallback did not recover ancestry for PID %d — P0-1 regressed",
		selfPID)
	// The recovered chain must include at least one ancestor (the test runner).
	assert.NotZero(t, tree[0].PPID, "recovered root must have a non-zero PPID")
}

// TestIncidentsEmptyChainMetric verifies the new
// ebpf_guard_incidents_empty_chain_total counter fires for attack incidents
// that are promoted without a process chain, and stays put for incidents that
// carry one. The metric is the operational surface that lets P0-1 health be
// observed from Prometheus instead of rediscovered on the fourth attack run.
func TestIncidentsEmptyChainMetric(t *testing.T) {
	tr := newIncidentTracker(60*time.Second, nil, scoringRules())

	beforeAttack := emptyChainCounterValue(t, "attack")

	// Burst that crosses the attack threshold, with NO process tree attached
	// — the run #4 shape: every alert came in with an empty ProcessTree. Uses
	// an untrusted comm (not sshd/cron) so the P1-13 trust gate added in wave 2
	// does not itself suppress the attack verdict — this test is about the
	// empty-chain metric, not the trust gate (see TestIncidentTracker_TrustGate*
	// for that).
	now := time.Now()
	for i, id := range []string{"r1", "r2", "r3", "r4", "r5"} {
		a := makeAlertWithComm(id, 4242, "prod", types.SeverityCritical,
			now.Add(time.Duration(i)*time.Second), "xmrig")
		// no ProcessTree: simulates the pre-fix condition
		tr.Add(a)
	}

	afterAttack := emptyChainCounterValue(t, "attack")
	assert.Equal(t, beforeAttack+1, afterAttack,
		"attack incident without process chain must bump empty_chain_total")

	// A second incident with a populated chain must NOT bump the counter.
	// This guards against the opposite regression: the metric losing
	// sensitivity by firing on every incident regardless of chain state.
	tree := types.ProcessTree{
		{PID: 5000, PPID: 1, Comm: "bash"},
		{PID: 5001, PPID: 5000, Comm: "curl"},
	}
	for i, id := range []string{"r1", "r2", "r3", "r4", "r5"} {
		a := makeAlertWithComm(id, 5001, "prod", types.SeverityCritical,
			now.Add(time.Duration(10+i)*time.Second), "curl")
		a.ProcessTree = tree
		tr.Add(a)
	}

	finalAttack := emptyChainCounterValue(t, "attack")
	assert.Equal(t, afterAttack, finalAttack,
		"attack incident WITH process chain must not bump empty_chain_total")
}

// trustedRootCounterValue reads ebpf_guard_incidents_trusted_root_total for a verdict.
func trustedRootCounterValue(t *testing.T, verdict string) float64 {
	t.Helper()
	c, err := incidentsTrustedRootTotal.GetMetricWithLabelValues(verdict)
	if err != nil {
		t.Fatalf("GetMetricWithLabelValues(%q): %v", verdict, err)
	}
	var m dto.Metric
	if err := c.(prometheus.Metric).Write(&m); err != nil {
		t.Fatalf("write metric: %v", err)
	}
	return m.GetCounter().GetValue()
}

// TestIncidentsTrustedRootMetric covers the first wave 2 gate criterion —
// "share of incidents on system daemons < 20%" — which until now had no metric
// at all and could only be computed by hand from an incidents snapshot. That is
// how P0-1 (100% of incidents on sshd) survived four runs: the number existed
// only in post-hoc analysis.
//
// incidents_trusted_root_total{verdict} / incidents_total{verdict} is the share.
// Asserted in both directions, so the metric cannot pass by firing on everything.
func TestIncidentsTrustedRootMetric(t *testing.T) {
	tr := newIncidentTracker(60*time.Second, nil, scoringRules())

	// Separate baselines per label: these are independent counters, and other
	// tests in the package share this process-global metric.
	before := trustedRootCounterValue(t, "suspicious")
	beforeAttack := trustedRootCounterValue(t, "attack")

	// sshd fanned out across five rules: the run #4 shape. The wave 2 trust
	// gate keeps this at "suspicious" rather than "attack", but it is still an
	// incident rooted at a daemon and must count towards the daemon share —
	// the gate is about which incidents exist, not only which are confirmed.
	now := time.Now()
	for i, id := range []string{"r1", "r2", "r3", "r4", "r5"} {
		tr.Add(makeAlertWithComm(id, 4242, "prod", types.SeverityCritical,
			now.Add(time.Duration(i)*time.Second), "sshd"))
	}

	after := trustedRootCounterValue(t, "suspicious")
	require.Equal(t, before+1, after,
		"incident rooted at a trusted daemon (sshd) must bump trusted_root_total")

	// An incident rooted at an untrusted process must not count: otherwise the
	// share would be 100% by construction and the gate meaningless.
	for i, id := range []string{"r1", "r2", "r3", "r4", "r5"} {
		tr.Add(makeAlertWithComm(id, 7777, "prod", types.SeverityCritical,
			now.Add(time.Duration(20+i)*time.Second), "xmrig"))
	}

	assert.Equal(t, after, trustedRootCounterValue(t, "suspicious"),
		"incident rooted at an untrusted process must not bump trusted_root_total")
	assert.Equal(t, beforeAttack, trustedRootCounterValue(t, "attack"),
		"the sshd incident was gated to suspicious; the attack-verdict counter must be untouched")
}
