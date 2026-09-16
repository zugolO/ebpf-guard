package profiler

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 6.3.1, item 3, находка №342 (архив collect-6.3-ab).
//
// stripPreExecCommParens (wave 6.0d, №197) снимало скобки безусловно — верно
// для имён короче буфера systemd (8 символов хвоста, память
// drift-workload-key-is-comm), но для более длинных ложно превращало обрезок
// в чужое или несуществующее имя: «(ystemctl)» → «ystemctl», нагрузка,
// которой не существует. Матрица длин 4/8/9/12/15 — именно та, которой не
// было у проверки №197.

// fakeExeResolver отвечает заранее заданным списком имён по pid, не трогая
// /proc (которого на mac и на CI без root всё равно нет). Список — ровно тот,
// что отдаёт ProcPreExecCommResolver: сперва post-exec comm (/proc/<pid>/comm),
// потом basename(/proc/<pid>/exe).
type fakeExeResolver map[uint32][]string

func (f fakeExeResolver) ResolveNames(pid uint32) []string { return f[pid] }

func withPreExecResolver(t *testing.T, r PreExecCommResolver) {
	t.Helper()
	prev, _ := preExecResolver.Load().(preExecResolverHolder)
	SetPreExecCommResolver(r)
	t.Cleanup(func() {
		if prev.r != nil {
			SetPreExecCommResolver(prev.r)
		} else {
			preExecResolver.Store(preExecResolverHolder{})
		}
	})
}

func commEvent(pid uint32, comm string) types.Event {
	var b [16]byte
	copy(b[:], comm)
	return types.Event{PID: pid, Comm: b}
}

func TestWave6_3_1_PreExecComm_LengthMatrix(t *testing.T) {
	tests := []struct {
		name       string
		realName   string // full post-exec name
		pid        uint32
		resolver   fakeExeResolver
		wantKey    string
		wantMetric string // outcome expected to have incremented, "" = none (below cap)
	}{
		{
			// len(tail) = 4 < preExecTailCap: buffer had room, tail IS the
			// whole name — no ambiguity, no resolver consulted.
			name:     "4 chars — under cap, no resolver needed",
			realName: "find",
			pid:      100004,
			resolver: nil,
			wantKey:  "find",
		},
		{
			// len(tail) = 8 == preExecTailCap: ambiguous (could be an exact
			// 8-byte name or a truncated tail); resolver confirms it's exact.
			name:     "8 chars — at cap, resolver confirms exact name",
			realName: "abcdefgh",
			pid:      100008,
			resolver: fakeExeResolver{100008: {"abcdefgh"}},
			wantKey:  "abcdefgh", wantMetric: "resolved",
		},
		{
			// len(tail) = 9: genuinely truncated. Matches memory's own
			// example ("systemctl" -> "(ystemctl)").
			name:     "9 chars — truncated, resolver recovers real name",
			realName: "systemctl",
			pid:      100009,
			resolver: fakeExeResolver{100009: {"systemctl"}},
			wantKey:  "systemctl", wantMetric: "resolved",
		},
		{
			// len = 12: the finding's own worked example.
			name:     "12 chars — truncated, matches finding №342's own example",
			realName: "50-motd-news",
			pid:      100012,
			resolver: fakeExeResolver{100012: {"50-motd-news", "dash"}},
			wantKey:  "50-motd-news", wantMetric: "resolved",
		},
		{
			name:     "15 chars — truncated, resolver recovers real name",
			realName: "abcdefghijklmno",
			pid:      100015,
			resolver: fakeExeResolver{100015: {"abcdefghijklmno"}},
			wantKey:  "abcdefghijklmno", wantMetric: "resolved",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tail := tt.realName
			if len(tail) > preExecTailCap {
				tail = tail[len(tail)-preExecTailCap:]
			}
			preExec := commEvent(tt.pid, "("+tail+")")

			if tt.resolver != nil {
				withPreExecResolver(t, tt.resolver)
			} else {
				withPreExecResolver(t, nil)
			}

			var before float64
			if tt.wantMetric != "" {
				before = testutil.ToFloat64(commPreExecNormalizedTotal.WithLabelValues(tt.wantMetric))
			}

			k := WorkloadKeyFromEvent(preExec)
			assert.Equal(t, tt.wantKey, k.Comm)

			postExec := commEvent(tt.pid, tt.realName)
			kPost := WorkloadKeyFromEvent(postExec)
			assert.Equal(t, kPost, k,
				"pre-exec and post-exec observations of the same process must share one workload key")

			if tt.wantMetric != "" {
				assert.Greater(t, testutil.ToFloat64(commPreExecNormalizedTotal.WithLabelValues(tt.wantMetric)), before)
			}
		})
	}
}

// Ambiguous tail (>= cap) with no resolver installed, or a resolver that
// cannot confirm the name, must NOT be guessed into a name that doesn't
// exist — it stays in its parenthesized form, isolated from any real
// workload's baseline, and the "unresolved" outcome counts it.
func TestWave6_3_1_PreExecComm_UnresolvedStaysIsolated(t *testing.T) {
	t.Run("no resolver installed", func(t *testing.T) {
		withPreExecResolver(t, nil)
		before := testutil.ToFloat64(commPreExecNormalizedTotal.WithLabelValues("unresolved"))
		e := commEvent(200001, "(ystemctl)")
		k := WorkloadKeyFromEvent(e)
		assert.Equal(t, "(ystemctl)", k.Comm,
			"an unresolved truncated tail must not be merged into a guessed name")
		assert.Greater(t, testutil.ToFloat64(commPreExecNormalizedTotal.WithLabelValues("unresolved")), before)
	})

	t.Run("resolver has no answer for this pid", func(t *testing.T) {
		withPreExecResolver(t, fakeExeResolver{})
		e := commEvent(200002, "(ystemctl)")
		k := WorkloadKeyFromEvent(e)
		assert.Equal(t, "(ystemctl)", k.Comm)
	})

	t.Run("resolver returns a name that does not suffix-match", func(t *testing.T) {
		// A real answer that does NOT end in the observed tail must not be
		// trusted either — it would silently attribute the pre-exec sample
		// to an unrelated process that happens to share a PID slot.
		withPreExecResolver(t, fakeExeResolver{200003: {"unrelated-proc"}})
		e := commEvent(200003, "(ystemctl)")
		k := WorkloadKeyFromEvent(e)
		assert.Equal(t, "(ystemctl)", k.Comm)
	})
}

// Волна 6.3.1, аудит item 3: РАЗДЕЛЬНЫЕ роли двух источников резолвера.
// Одного источника не хватает ни в ту, ни в другую сторону, и каждая
// половина закрывает слепую зону другой.
func TestWave6_3_1_PreExecComm_BothResolverSourcesAreNeeded(t *testing.T) {
	t.Run("script: only /proc/comm answers, exe basename is the interpreter", func(t *testing.T) {
		// /etc/update-motd.d/50-motd-news — пример самой находки №342.
		// execve'ится интерпретатор, поэтому basename(/proc/<pid>/exe) это
		// «dash», и суффиксного совпадения с «otd-news» у него нет НИКОГДА
		// ([[shebang-control-comm-is-interpreter]]). Имя задаёт только
		// post-exec comm.
		withPreExecResolver(t, fakeExeResolver{300012: {"50-motd-news", "dash"}})
		k := WorkloadKeyFromEvent(commEvent(300012, "(otd-news)"))
		assert.Equal(t, "50-motd-news", k.Comm)
	})

	t.Run("exe only: /proc/comm answers but is itself truncated at the head", func(t *testing.T) {
		// Имя длиннее TASK_COMM_LEN-1 (15): ядро режет ГОЛОВУ в скобочном
		// буфере systemd и ХВОСТ в /proc/<pid>/comm — то есть comm не
		// содержит наблюдаемого хвоста вовсе, и разрешить может только
		// неусечённый basename(exe).
		const realName = "very-long-daemon-name"
		truncatedComm := realName[:15] // "very-long-daemo"
		tail := realName[len(realName)-preExecTailCap:]
		withPreExecResolver(t, fakeExeResolver{300021: {truncatedComm, realName}})
		k := WorkloadKeyFromEvent(commEvent(300021, "("+tail+")"))
		assert.Equal(t, realName, k.Comm,
			"усечённый /proc/comm не несёт хвоста; ответить обязан basename(exe)")
	})
}

// Волна 6.3.1, критерий 6.3.1.2: неразрешённый предэкзековый обрезок НЕ
// СОЗДАЁТ НАГРУЗКИ. Изолированного ключа мало — фантом всё равно был бы
// всегда новым, всегда в learning и всегда аномальным, то есть гарантированным
// ложным детектом с именем «(ystemctl)» на алерте и на серии
// profiler_anomaly_score.
func TestWave6_3_1_UnresolvedPreExecCommCreatesNoWorkload(t *testing.T) {
	withPreExecResolver(t, nil) // резолвер не установлен → хвост неразрешим

	ad := NewAnomalyDetectorWithSamples(t.Context(), 0.5, time.Millisecond, 0.3, 1, 1024)
	ad.learningComplete.Store(true)

	e := commEvent(400001, "(ystemctl)")
	e.Type = types.EventSyscall
	e.Syscall = &types.SyscallEvent{Nr: 59}

	for i := 0; i < 10; i++ {
		assert.Nil(t, ad.ProcessEvent(e, false),
			"фантомная нагрузка не должна ни оцениваться, ни заводиться")
	}
	_, ok := workloadKeyFromEventResolved(e)
	assert.False(t, ok, "ключ обязан быть помечен неразрешённым")
	assert.Nil(t, ad.profileManager.GetByKey(WorkloadKeyFromEvent(e)),
		"профиль под скобочным ключом не должен существовать вовсе")

	// Контроль-близнец: тот же процесс ПОСЛЕ exec'а нагрузку заводит.
	post := commEvent(400001, "systemctl")
	post.Type = types.EventSyscall
	post.Syscall = &types.SyscallEvent{Nr: 59}
	ad.ProcessEvent(post, false)
	assert.NotNil(t, ad.profileManager.GetByKey(WorkloadKeyFromEvent(post)),
		"обычное имя обязано заводить профиль — иначе тест доказывает не то")
}
