package correlator

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/internal/profiler"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 6.3.1, находка №353 (боевой прогон 17.09.2026, метка 6.3.1.2).
//
// Правка №342 переложила КЛЮЧ профиля на разрешённое имя, а правка №345 —
// лейбл серии profiler_anomaly_score. Поле Comm самого алерта осталось сырым
// e.Comm, и прогон напечатал ровно это: anomaly_detection{comm="(otd-news)"}
// в сторе при базе, заведённой под "50-motd-news" — алерт называл нагрузку,
// профиля для которой у профилировщика нет.
//
// Тест держится не на строке-константе, а на ПАРЕ: идентичность алерта равна
// имени профиля, а сырое предэкзековое имя остаётся в событии как улика.
type w631PreExecResolver map[uint32][]string

func (r w631PreExecResolver) ResolveNames(pid uint32) []string { return r[pid] }

func TestWave6_3_1_AnomalyAlertCarriesProfileComm(t *testing.T) {
	const pid = 5353
	profiler.SetPreExecCommResolver(w631PreExecResolver{pid: {"50-motd-news"}})
	t.Cleanup(func() { profiler.SetPreExecCommResolver(profiler.ProcPreExecCommResolver{}) })

	prev, _ := exeResolver.Load().(exeResolverHolder)
	t.Cleanup(func() { SetExePathResolver(prev.r) })
	SetExePathResolver(w626AnomalyExeResolver{path: "/tmp/payload"})

	ce := newW626AnomalyEngine(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var trained [16]byte
	copy(trained[:], "50-motd-news")
	w626TrainAnomalyDetector(t, ce, ctx, trained, pid)

	// Предэкзековый буфер systemd: «(» + хвост имени + «)».
	var preExec [16]byte
	copy(preExec[:], "(otd-news)")

	alerts := ce.Ingest(ctx, types.Event{
		Type:    types.EventSyscall,
		PID:     pid,
		Comm:    preExec,
		Syscall: &types.SyscallEvent{Nr: 42},
	})
	require.NotEmpty(t, alerts, "разрешённое предэкзековое имя баселайнится и должно оцениваться")

	var anomaly *types.Alert
	for i := range alerts {
		if alerts[i].RuleID == "anomaly_detection" {
			anomaly = &alerts[i]
		}
	}
	require.NotNil(t, anomaly, "ожидался синтезированный алерт anomaly_detection")

	require.Equal(t, "50-motd-news", anomaly.Comm,
		"идентичность алерта — comm ОЦЕНЁННОГО профиля, а не сырое обрезанное имя (№353)")
	require.NotEqual(t, byte('('), anomaly.Comm[0],
		"ни один алерт не вправе называть нагрузку скобочным обрезком (критерий 6.3.1.2)")

	rawInEvent := string(anomaly.Event.Comm[:len("(otd-news)")])
	require.Equal(t, "(otd-news)", rawInEvent,
		"сырое предэкзековое имя не теряется: оно остаётся в событии как улика того, что видело ядро")
}
