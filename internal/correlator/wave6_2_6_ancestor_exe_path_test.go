package correlator

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 6.2.6, item 5 (№261 → №277 → №285).
//
// Живой разбор на ebaka2 09.09.2026 назвал причину утечки числом: cron форкает
// задачу в ДВА поколения — cron(667, демон) → джоб-обёртка → сам процесс
// задачи, — и алертует ВТОРОЕ поколение. Ни verified-daemon-image (свой
// exe_path гоночно пуст), ни verified-daemon-lineage в виде хопа на PPID
// (непосредственный родитель — сам короткоживущий и уже мёртв) до живого
// образа не дотягиваются: между алертующим процессом и стабильным демоном ДВА
// хопа, а обе оси смотрят на один.
//
// Ось proc.ancestor_exe_path идёт дальше родителя ТОЛЬКО по непрерывному
// участку одного comm. Это не эвристика: comm назначается ядром по образу в
// execve и наследуется форком, поэтому участок цепочки с одним comm — набор
// процессов, ни один из которых с форка не звал execve, то есть делящих один
// mm->exe_file. Ось не «доверяет предку», она восстанавливает СОБСТВЕННЫЙ
// образ алертующего процесса у живого родственника с тем же inode.
//
// Отсюда деление тестов: (1) — что правка вообще делает; (2)–(5) — что она
// не покупает это ценой детекта; (6)–(7) — приборность и цена.

const (
	// Двухпоколенный форк из разбора №285: 3167144 (алертует, мёртв) →
	// 3167143 (джоб-обёртка, мёртв) → 667 (демон cron, жив часами).
	w626LeafPID    uint32 = 3167144
	w626WrapperPID uint32 = 3167143
	w626DaemonPID  uint32 = 667
	// Посторонний живой процесс, чей образ — не демон.
	w626ShellPID uint32 = 4242
)

// w626Ancestry — родословная из карты, как её отдаёт LineageTracker: ключ —
// pid, значение — (ppid, comm РОДИТЕЛЯ). Ровно тот контракт, что у
// profiler.LineageTracker.ParentOf.
type w626Ancestry map[uint32]struct {
	ppid       uint32
	parentComm string
}

func (a w626Ancestry) ParentOf(pid uint32) (uint32, string, bool) {
	v, ok := a[pid]
	if !ok || v.ppid == 0 {
		return 0, "", false
	}
	return v.ppid, v.parentComm, true
}

func w626Link(ppid uint32, parentComm string) struct {
	ppid       uint32
	parentComm string
} {
	return struct {
		ppid       uint32
		parentComm string
	}{ppid: ppid, parentComm: parentComm}
}

func w626WithAncestry(t *testing.T, a w626Ancestry) {
	t.Helper()
	prev, _ := ancestryResolver.Load().(ancestryResolverHolder)
	SetAncestryResolver(a)
	t.Cleanup(func() { SetAncestryResolver(prev.r) })
}

// w626ExeResolver отдаёт образ по pid явной картой: тесты этой волны говорят
// не про «настоящий демон вообще», а про КОНКРЕТНОЕ поколение форка, живое
// или мёртвое. Отсутствие ключа = процесс мёртв = "" (проигранная гонка).
type w626ExeResolver struct {
	paths map[uint32]string
	n     int
}

func (r *w626ExeResolver) ResolveExePath(pid uint32) string {
	r.n++
	return r.paths[pid]
}

func w626WithExe(t *testing.T, paths map[uint32]string) *w626ExeResolver {
	t.Helper()
	r := &w626ExeResolver{paths: paths}
	prev, _ := exeResolver.Load().(exeResolverHolder)
	SetExePathResolver(r)
	t.Cleanup(func() { SetExePathResolver(prev.r) })
	return r
}

// w626Event — файловое событие второго поколения форка: и pid, и ppid мертвы,
// comm и parent_comm унаследованы от демона (execve не было ни разу).
func w626Event(pid, ppid uint32, comm, parentComm, path string, op uint8) types.Event {
	e := types.Event{Type: types.EventFileAccess, PID: pid, PPID: ppid, File: &types.FileEvent{Op: op}}
	copy(e.Comm[:], comm)
	copy(e.ParentComm[:], parentComm)
	copy(e.File.Filename[:], path)
	return e
}

// w626Cases — те же два cron-правила, на которых волна 6.2.5 завела ось
// родословной (w624LineageCases): именно они дали 10 алертов comm=cron в окне.
func w626Cases(t *testing.T) []w624Case {
	t.Helper()
	return w624LineageCases(t)
}

// (1) ПОЗИТИВНАЯ ПОЛОВИНА №285. Двухпоколенный форк cron: алертующий процесс и
// его родитель мертвы, жив только демон через ДВА хопа. До этой правки правило
// срабатывало — это и есть измеренная утечка. Теперь обязано молчать.
func TestWave6_2_6AncestorAxisSuppressesTwoGenerationDaemonFork(t *testing.T) {
	for _, c := range w626Cases(t) {
		t.Run(c.name, func(t *testing.T) {
			w626WithExe(t, map[uint32]string{
				// Мёртвые поколения отсутствуют в карте: гонка проиграна.
				w626DaemonPID: "/usr/sbin/cron",
			})
			w626WithAncestry(t, w626Ancestry{
				w626LeafPID:    w626Link(w626WrapperPID, "cron"),
				w626WrapperPID: w626Link(w626DaemonPID, "cron"),
			})
			e := w624Engine(t, c.file, c.twin, c.parent)
			ev := w626Event(w626LeafPID, w626WrapperPID, "cron", "cron", c.path, c.op)
			assert.Emptyf(t, w624Fired(e, ev),
				"второе поколение форка cron (свой exe_path и родительский оба "+
					"гоночно пусты, демон жив через два хопа) обязано быть снято "+
					"verified-daemon-lineage: это утечка, измеренная в окне 6.2.5 (%s)", c.twin)
		})
	}
}

// (2) ЦЕНА ПО ДЕТЕКТУ, ГЛАВНАЯ ПОЛОВИНА: разрыв comm. Цепочка
// cron(демон) → bash → процесс, переименовавший себя в "cron"
// (prctl(PR_SET_NAME) / `exec -a cron`). Участок НЕ непрерывен: между
// алертующим процессом и демоном стоит процесс с другим образом. Обход обязан
// остановиться на разрыве, правило — СРАБОТАТЬ.
//
// Без этой половины ось предка была бы ровно тем, чего боится
// [[comm-not-in-is-a-mute-bypass]]: «найди cron где-нибудь у себя в предках и
// получи молчание».
func TestWave6_2_6AncestorAxisStopsAtCommBreak(t *testing.T) {
	for _, c := range w626Cases(t) {
		t.Run(c.name, func(t *testing.T) {
			w626WithExe(t, map[uint32]string{
				// И bash, и демон живы; мёртв только сам подделыватель.
				w626ShellPID:  "/bin/bash",
				w626DaemonPID: "/usr/sbin/cron",
			})
			w626WithAncestry(t, w626Ancestry{
				w626LeafPID:  w626Link(w626ShellPID, "bash"),
				w626ShellPID: w626Link(w626DaemonPID, "cron"),
			})
			e := w624Engine(t, c.file, c.twin, c.parent)
			// parent_comm="bash" ≠ comm="cron" — участок рвётся на первом же
			// звене, до демона обход не доходит.
			ev := w626Event(w626LeafPID, w626ShellPID, "cron", "bash", c.path, c.op)
			assert.Containsf(t, w624Fired(e, ev), c.twin,
				"процесс с подделанным comm, чей предок-cron отделён процессом "+
					"ДРУГОГО образа (bash), обязан поднять %s: непрерывность "+
					"участка — единственное, что делает ось предка не обходом", c.twin)
		})
	}
}

// (3) ЦЕНА ПО ДЕТЕКТУ: непрерывный участок есть, но укоренён не в демоне.
// Атакующий форкает сам себя дважды из бинаря /tmp/w626/cron — comm вдоль всей
// цепочки одинаков, обход дойдёт до корня, но образ корня в списке не значится.
func TestWave6_2_6AncestorAxisRejectsRunRootedOutsideDaemonImage(t *testing.T) {
	for _, c := range w626Cases(t) {
		t.Run(c.name, func(t *testing.T) {
			w626WithExe(t, map[uint32]string{
				w626ShellPID: "/tmp/w626/cron",
			})
			w626WithAncestry(t, w626Ancestry{
				w626LeafPID:    w626Link(w626WrapperPID, "cron"),
				w626WrapperPID: w626Link(w626ShellPID, "cron"),
			})
			e := w624Engine(t, c.file, c.twin, c.parent)
			ev := w626Event(w626LeafPID, w626WrapperPID, "cron", "cron", c.path, c.op)
			assert.Containsf(t, w624Fired(e, ev), c.twin,
				"непрерывный участок, укоренённый в /tmp/w626/cron, обязан поднять "+
					"%s — ось остаётся образом, а не именем", c.twin)
		})
	}
}

// (4) ЦЕНА ПО ДЕТЕКТУ: предел глубины. Даже непрерывный участок не даёт
// молчания, если демон дальше maxAncestorExePathHops. Предел зафиксирован
// тестом, а не только константой: снятие предела — это переход от «форк-глубина
// cron с запасом» к «где угодно в родословной», и он обязан ломать сборку.
func TestWave6_2_6AncestorWalkIsDepthBounded(t *testing.T) {
	for _, c := range w626Cases(t) {
		t.Run(c.name, func(t *testing.T) {
			// Цепочка мёртвых форков длиннее предела; демон — за ним.
			const base uint32 = 500000
			ancestry := w626Ancestry{}
			last := w626LeafPID
			for i := 0; i <= maxAncestorExePathHops+1; i++ {
				next := base + uint32(i)
				ancestry[last] = w626Link(next, "cron")
				last = next
			}
			ancestry[last] = w626Link(w626DaemonPID, "cron")
			w626WithExe(t, map[uint32]string{w626DaemonPID: "/usr/sbin/cron"})
			w626WithAncestry(t, ancestry)

			e := w624Engine(t, c.file, c.twin, c.parent)
			ev := w626Event(w626LeafPID, base, "cron", "cron", c.path, c.op)
			assert.Containsf(t, w624Fired(e, ev), c.twin,
				"демон дальше %d хопов не обязан давать молчание: предел глубины — "+
					"часть контракта оси (%s)", maxAncestorExePathHops, c.twin)
		})
	}
}

// (5) РЕГРЕССИЯ ОСИ 6.2.5: значение ancestor_exe_path — строгое НАДМНОЖЕСТВО
// parent_exe_path. Там, где родитель разрешался, ось обязана вернуть ТО ЖЕ
// значение и не спрашивать родословную вовсе. Иначе правка, задуманная как
// расширение, оказалась бы сужением, и волна 6.2.5 молча регрессировала бы.
func TestWave6_2_6AncestorAxisIsSupersetOfParentAxis(t *testing.T) {
	res := w626WithExe(t, map[uint32]string{w626WrapperPID: "/usr/sbin/cron"})
	// Родословной нет вовсе — хоп 1 обязан работать без неё.
	w626WithAncestry(t, w626Ancestry{})

	got := resolveAncestorExePath(w626LeafPID, w626WrapperPID, "cron", "cron")
	assert.Equal(t, "/usr/sbin/cron", got,
		"разрешимый родитель обязан отдаваться хопом 1, как это делал parent_exe_path")
	assert.Equal(t, 1, res.n,
		"разрешимый родитель обязан стоить РОВНО один readlink: обход дальше "+
			"начинается только после проигранной гонки на родителе")
}

// (6) ПРИБОРНОСТЬ (сторож ложного нуля, идиома волн 6.2.4/6.2.5). Исход
// "ancestor" — единственная величина, отличающая работающую правку от
// задеплоенной и не сработавшей: во всех остальных исходах ось ведёт себя как
// старый parent_exe_path. Ноль здесь при непустых остальных = item 5 не даёт
// того, ради чего сделан.
func TestWave6_2_6AncestorWalkOutcomeIsCounted(t *testing.T) {
	before := testutil.ToFloat64(exePathAncestorWalks.WithLabelValues(ancestorOutcomeAncestor))

	w626WithExe(t, map[uint32]string{w626DaemonPID: "/usr/sbin/cron"})
	w626WithAncestry(t, w626Ancestry{
		w626LeafPID:    w626Link(w626WrapperPID, "cron"),
		w626WrapperPID: w626Link(w626DaemonPID, "cron"),
	})

	require.Equal(t, "/usr/sbin/cron",
		resolveAncestorExePath(w626LeafPID, w626WrapperPID, "cron", "cron"))

	after := testutil.ToFloat64(exePathAncestorWalks.WithLabelValues(ancestorOutcomeAncestor))
	assert.Equal(t, before+1, after,
		"разрешение на хопе ≥2 обязано быть напечатано в "+
			"ebpf_guard_exe_path_ancestor_walk_total{outcome=\"ancestor\"}")
}

// (7) ПРИБОРНОСТЬ: одно вычисление поля — один инкремент exe_path_lookups_total
// по своей оси, сколько бы хопов обход ни сделал. Иначе доля unresolved по оси
// ancestor_exe_path считала бы ХОПЫ, а не поля, — ровно та подмена величины,
// из-за которой №277 и появился (один счётчик на две оси).
func TestWave6_2_6AncestorFieldCountsFieldsNotHops(t *testing.T) {
	labels := []string{"resolved", exePathFieldAncestor}
	before := testutil.ToFloat64(exePathLookups.WithLabelValues(labels...))

	w626WithExe(t, map[uint32]string{w626DaemonPID: "/usr/sbin/cron"})
	w626WithAncestry(t, w626Ancestry{
		w626LeafPID:    w626Link(w626WrapperPID, "cron"),
		w626WrapperPID: w626Link(w626DaemonPID, "cron"),
	})

	require.Equal(t, "/usr/sbin/cron",
		resolveAncestorExePath(w626LeafPID, w626WrapperPID, "cron", "cron"))

	after := testutil.ToFloat64(exePathLookups.WithLabelValues(labels...))
	assert.Equal(t, before+1, after,
		"обход из двух хопов обязан дать РОВНО один инкремент по оси "+
			"ancestor_exe_path, а не по одному на хоп")
}

// (8) Пустой parent_comm (BPF не заполнил поле) не открывает обход: сравнивать
// пустую строку не с чем, и считать её совпадением значило бы пускать обход
// именно там, где про цепочку ничего не известно. Деградация — в сторону шума.
func TestWave6_2_6EmptyParentCommDoesNotOpenTheWalk(t *testing.T) {
	w626WithExe(t, map[uint32]string{w626DaemonPID: "/usr/sbin/cron"})
	// Родословная знает цепочку, но comm родителя в событии пуст И трекер про
	// сам алертующий pid ничего не записал.
	w626WithAncestry(t, w626Ancestry{
		w626WrapperPID: w626Link(w626DaemonPID, "cron"),
	})

	got := resolveAncestorExePath(w626LeafPID, w626WrapperPID, "cron", "")
	assert.Empty(t, got,
		"пустой parent_comm обязан останавливать обход: неизвестная цепочка "+
			"не может быть признана непрерывной")
}
