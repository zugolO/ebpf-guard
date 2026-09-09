package correlator

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 6.2.6, item 4 (№283). anomaly_detection синтезируется движком в
// обход слоя YAML-правил (engine.go, ветка ProcessEvent), поэтому ни одна
// ось антиспуф-аппарата на него не действовала. Тест доказывает две
// половины постановки на живом CorrelationEngine с anomaly-детектором:
//
//  1. образ верифицированного демона (proc.exe_path) подавляет алерт и
//     объём переезжает в ebpf_guard_rule_exceptions_total, а не исчезает;
//  2. подделка ИМЕНИ демона (comm) без соответствующего образа алерт не
//     подавляет — ось exe_path, а не comm (позитивная половина 6.2.6.20).
type w626AnomalyExeResolver struct{ path string }

func (r w626AnomalyExeResolver) ResolveExePath(uint32) string { return r.path }

func newW626AnomalyEngine(t *testing.T) *CorrelationEngine {
	t.Helper()
	rules, err := LoadRulesFromFile("../../rules/anomaly.yaml")
	require.NoError(t, err, "rules/anomaly.yaml must load and validate as a synthetic rule")
	require.Len(t, rules, 1)
	require.True(t, rules[0].Synthetic)
	require.Equal(t, "anomaly_detection", rules[0].ID)

	cfg := DefaultCorrelationEngineConfig()
	cfg.Rules = rules
	cfg.EnableAnomaly = true
	cfg.AnomalyThreshold = 0.0 // any scored event is anomalous
	cfg.LearningPeriod = 1 * time.Millisecond
	cfg.MinLearningSamples = 10
	cfg.EWMAWeight = 0.5
	cfg.EnableRateLimit = false
	cfg.EnableDedup = false
	cfg.IngestWorkerCount = 0 // solo detector path

	ce := NewCorrelationEngineWithConfig(cfg)
	t.Cleanup(ce.Close)
	require.NotNil(t, ce.anomalyDetector)
	return ce
}

func w626TrainAnomalyDetector(t *testing.T, ce *CorrelationEngine, ctx context.Context, comm [16]byte, pid uint32) {
	t.Helper()
	for i := 0; i < 20; i++ {
		_ = ce.Ingest(ctx, types.Event{
			Type:    types.EventSyscall,
			PID:     pid,
			Comm:    comm,
			Syscall: &types.SyscallEvent{Nr: 1},
		})
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !ce.anomalyDetector.IsLearningComplete() {
		time.Sleep(time.Millisecond)
	}
	require.True(t, ce.anomalyDetector.IsLearningComplete())
}

func TestWave6_2_6AnomalyDetection_VerifiedDaemonImageSuppressed(t *testing.T) {
	prev, _ := exeResolver.Load().(exeResolverHolder)
	t.Cleanup(func() { SetExePathResolver(prev.r) })
	SetExePathResolver(w626AnomalyExeResolver{path: "/usr/sbin/sshd"})

	ce := newW626AnomalyEngine(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var comm [16]byte
	copy(comm[:], "sshd")
	const pid = 4242
	w626TrainAnomalyDetector(t, ce, ctx, comm, pid)

	before := testutil.ToFloat64(ruleExceptionsTotal.WithLabelValues("anomaly_detection", "verified-daemon-image"))

	alerts := ce.Ingest(ctx, types.Event{
		Type:    types.EventSyscall,
		PID:     pid,
		Comm:    comm,
		Syscall: &types.SyscallEvent{Nr: 1},
	})
	require.Empty(t, alerts,
		"a scored event whose proc.exe_path matches the verified-daemon-image exception must not raise anomaly_detection")

	after := testutil.ToFloat64(ruleExceptionsTotal.WithLabelValues("anomaly_detection", "verified-daemon-image"))
	require.Equal(t, before+1, after,
		"suppressed volume must move into ebpf_guard_rule_exceptions_total, not disappear silently ([[info-twin-renames-volume]])")
}

func TestWave6_2_6AnomalyDetection_SpoofedDaemonNameStillFires(t *testing.T) {
	prev, _ := exeResolver.Load().(exeResolverHolder)
	t.Cleanup(func() { SetExePathResolver(prev.r) })
	// comm claims to be sshd, but the image is not one of the verified paths —
	// exactly the `exec -a sshd /tmp/payload` antispoof scenario from
	// exepath.go's own doc comment.
	SetExePathResolver(w626AnomalyExeResolver{path: "/tmp/payload"})

	ce := newW626AnomalyEngine(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var comm [16]byte
	copy(comm[:], "sshd")
	const pid = 4343
	w626TrainAnomalyDetector(t, ce, ctx, comm, pid)

	alerts := ce.Ingest(ctx, types.Event{
		Type:    types.EventSyscall,
		PID:     pid,
		Comm:    comm,
		Syscall: &types.SyscallEvent{Nr: 1},
	})
	require.NotEmpty(t, alerts,
		"anomaly_detection must not be suppressible by comm alone — the exception axis is proc.exe_path, "+
			"a spoofed daemon name with an unverified image must still raise the anomaly")
	require.Equal(t, "anomaly_detection", alerts[0].RuleID)
}

// EvaluateNamedExceptions on a ruleID with nothing loaded (e.g. rules/
// anomaly.yaml absent from the configured rules directory) must degrade to
// "no exceptions", not silently drop every anomaly alert.
func TestRuleEngine_EvaluateNamedExceptions_UnknownRuleIDIsNoop(t *testing.T) {
	re := NewRuleEngine(nil)
	suppressed := re.EvaluateNamedExceptions("anomaly_detection", types.Event{Type: types.EventSyscall})
	require.False(t, suppressed)
}
