package profiler

import (
	"log/slog"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/zugolO/ebpf-guard/internal/procinfo"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// fakeTable — подставная таблица процессов ядра. Задаёт и состав записей, и исход чтения.
type fakeTable struct {
	mu      sync.Mutex
	recs    map[uint32]procinfo.Record
	res     map[uint32]procinfo.Result // принудительный исход (Expired/Error) для pid
	lookups int
}

func newFakeTable() *fakeTable {
	return &fakeTable{recs: map[uint32]procinfo.Record{}, res: map[uint32]procinfo.Result{}}
}

// proc добавляет запись. start — нс старта; exited — процесс вышел.
func (f *fakeTable) proc(pid, ppid uint32, comm string, start uint64, exited bool) *fakeTable {
	r := procinfo.Record{PID: pid, PPID: ppid, Comm: comm, StartBoottimeNs: start}
	if exited {
		r.ExitTS = 1
	}
	f.recs[pid] = r
	return f
}

func (f *fakeTable) Lookup(pid uint32) (procinfo.Record, procinfo.Result) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lookups++
	if res, ok := f.res[pid]; ok {
		return procinfo.Record{}, res
	}
	r, ok := f.recs[pid]
	if !ok {
		return procinfo.Record{}, procinfo.Absent
	}
	return r, procinfo.Found
}

func newTableTracker(t *testing.T, depth int, src procinfo.Source) *LineageTracker {
	t.Helper()
	lt := NewLineageTracker(LineageConfig{Enabled: true, MaxDepth: depth}, slog.Default())
	lt.SetProcSource(src)
	return lt
}

func comms(tree types.ProcessTree) []string {
	out := make([]string, len(tree))
	for i, n := range tree {
		out[i] = n.Comm
	}
	return out
}

func eq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func chainCount(consumer string, o procinfo.Outcome) float64 {
	return testutil.ToFloat64(lineageChainReads.WithLabelValues(consumer, string(o)))
}

// Контроль мс-цепочки: nginx → bash → curl, bash и curl уже вышли — цепочка полная.
func TestW85_P1_ShortLivedChainSurvivesDeathOfBash(t *testing.T) {
	ft := newFakeTable().
		proc(1, 0, "systemd", 10, false).
		proc(100, 1, "nginx", 1_000, false).
		proc(7001, 100, "bash", 5_000_000, true). // мгновенный bash: вышел
		proc(7002, 7001, "curl", 5_000_100, true) // curl вышел
	lt := newTableTracker(t, 8, ft)
	before := chainCount(chainConsumerTree, procinfo.OutcomeResolved)
	tree := lt.GetProcessTree(7002)
	if !eq(comms(tree), []string{"nginx", "bash", "curl"}) {
		t.Fatalf("цепочка = %v, want [nginx bash curl]", comms(tree))
	}
	if tree[0].PID != 100 || tree[2].PID != 7002 || tree[1].PPID != 100 {
		t.Fatalf("pid/ppid узлов: %+v", tree)
	}
	if chainCount(chainConsumerTree, procinfo.OutcomeResolved)-before != 1 {
		t.Fatal("исход resolved не посчитан")
	}
}

// pid 1 в цепочку не входит (конвенция прежнего трекера): корень — ребёнок init.
func TestW85_P1_Pid1NotInChain_KthreaddIs(t *testing.T) {
	ft := newFakeTable().
		proc(1, 0, "systemd", 10, false).
		proc(2, 0, "kthreadd", 11, false).
		proc(50, 2, "kworker", 12, false).
		proc(300, 1, "cron", 20, false).
		proc(301, 300, "sh", 30, false)
	lt := newTableTracker(t, 8, ft)
	if got := comms(lt.GetProcessTree(301)); !eq(got, []string{"cron", "sh"}) {
		t.Fatalf("ребёнок init: %v", got)
	}
	if got := comms(lt.GetProcessTree(50)); !eq(got, []string{"kthreadd", "kworker"}) {
		t.Fatalf("ядерный поток: %v", got)
	}
	if got := lt.GetProcessTree(1); got != nil {
		t.Fatalf("pid 1: %v", got)
	}
}

// pid переиспользован: «родитель» моложе потомка — цепочка рвётся ПЕРЕД ним, исход broken.
func TestW85_P1_PidReuseBreaksTheChain(t *testing.T) {
	ft := newFakeTable().
		proc(1, 0, "systemd", 10, false).
		proc(200, 1, "daemon", 1_000_000_000, false).
		proc(450, 200, "worker", 2_000_000_000, false).
		// pid 200 умер и достался чужому процессу, запущенному ПОСЛЕ worker'а
		proc(200, 1, "intruder", 9_000_000_000, false)
	lt := newTableTracker(t, 8, ft)
	before := chainCount(chainConsumerTree, procinfo.OutcomeBroken)
	tree := lt.GetProcessTree(450)
	if !eq(comms(tree), []string{"worker"}) {
		t.Fatalf("после реюза остаться должен только лист, got %v", comms(tree))
	}
	if chainCount(chainConsumerTree, procinfo.OutcomeBroken)-before != 1 {
		t.Fatal("исход broken не посчитан")
	}
	if _, _, ok := lt.ParentOf(450); ok {
		t.Fatal("ParentOf отдал родителя, чей pid переиспользован")
	}
}

// Допуск тика: родитель, засеянный из /proc (округление вниз до 10 мс), не «моложе» потомка.
func TestW85_P1_SeededParentWithinTickIsNotBroken(t *testing.T) {
	ft := newFakeTable().
		proc(300, 1, "cron", 5_000_000_000, false).
		proc(301, 300, "sh", 5_000_000_000-1, false) // потомок «старше» на 1 нс — округление
	lt := newTableTracker(t, 8, ft)
	if got := comms(lt.GetProcessTree(301)); !eq(got, []string{"cron", "sh"}) {
		t.Fatalf("got %v", got)
	}
	ft.proc(301, 300, "sh", 5_000_000_000-procinfo.StartToleranceNs-1, false)
	if got := comms(lt.GetProcessTree(301)); !eq(got, []string{"sh"}) {
		t.Fatalf("за допуском цепочка должна рваться: %v", got)
	}
}

// Запись звена отсутствует (вытеснена/истёк TTL/старше агента): частичная цепочка с листа, исход evicted.
func TestW85_P1_MissingHopGivesPartialChainAndEvicted(t *testing.T) {
	ft := newFakeTable().
		proc(100, 50, "nginx", 1_000, false). // родителя 50 в таблице нет
		proc(7001, 100, "bash", 5_000, true).
		proc(7002, 7001, "curl", 5_100, true)
	lt := newTableTracker(t, 8, ft)
	before := chainCount(chainConsumerTree, procinfo.OutcomeEvicted)
	if got := comms(lt.GetProcessTree(7002)); !eq(got, []string{"nginx", "bash", "curl"}) {
		t.Fatalf("got %v", got)
	}
	if chainCount(chainConsumerTree, procinfo.OutcomeEvicted)-before != 1 {
		t.Fatal("исход evicted не посчитан")
	}
	// истёкший TTL и сбой чтения — тоже «evicted», а не тишина и не нулевая цепочка с ложным корнем
	ft.res[7001] = procinfo.Expired
	if got := comms(lt.GetProcessTree(7002)); !eq(got, []string{"curl"}) {
		t.Fatalf("истёкшее звено: %v", got)
	}
	ft.res[7001] = procinfo.Error
	if got := comms(lt.GetProcessTree(7002)); !eq(got, []string{"curl"}) {
		t.Fatalf("ошибка чтения: %v", got)
	}
	// листа нет вовсе — nil
	if got := lt.GetProcessTree(9999); got != nil {
		t.Fatalf("неизвестный pid: %v", got)
	}
}

// Предел глубины: с листовой стороны, как у прежнего трекера; исход exhausted.
func TestW85_P1_DepthLimitKeepsLeafSideAndCountsExhausted(t *testing.T) {
	ft := newFakeTable()
	prev := uint32(1)
	for i := uint32(0); i < 12; i++ {
		pid := 100 + i
		ft.proc(pid, prev, string(rune('a'+i)), uint64(1000+i), false)
		prev = pid
	}
	lt := newTableTracker(t, 8, ft)
	before := chainCount(chainConsumerTree, procinfo.OutcomeExhausted)
	tree := lt.GetProcessTree(111)
	if len(tree) != 8 || tree[7].PID != 111 || tree[0].PID != 104 {
		t.Fatalf("глубина 8 с листовой стороны: %+v", tree)
	}
	if chainCount(chainConsumerTree, procinfo.OutcomeExhausted)-before != 1 {
		t.Fatal("исход exhausted не посчитан")
	}
}

// Цикл в таблице (порча) — broken, а не бесконечный обход.
func TestW85_P1_CycleIsBrokenNotInfinite(t *testing.T) {
	ft := newFakeTable().
		proc(200, 201, "a", 1000, false).
		proc(201, 200, "b", 1000, false)
	lt := newTableTracker(t, 16, ft)
	before := chainCount(chainConsumerTree, procinfo.OutcomeBroken)
	_ = lt.GetProcessTree(200)
	if chainCount(chainConsumerTree, procinfo.OutcomeBroken)-before != 1 {
		t.Fatal("цикл не помечен broken")
	}
}

// Track с таблицей не делает ничего: ни Go-карт, ни /proc, ни обращения к таблице.
func TestW85_P1_TrackIsANoOpAndNeverReadsProc(t *testing.T) {
	ft := newFakeTable()
	lt := newTableTracker(t, 8, ft)
	procBefore := testutil.ToFloat64(lineageProcReads)
	for i := uint32(0); i < 2000; i++ {
		// PPID == 0 — на старом пути это /proc-чтение на каждый новый pid
		lt.Track(types.Event{PID: 4_000_000 + i})
	}
	if got := testutil.ToFloat64(lineageProcReads) - procBefore; got != 0 {
		t.Fatalf("чтений /proc с таблицей: %v, want 0", got)
	}
	for _, sh := range lt.shards {
		if len(sh.lineage)+len(sh.ancestry)+len(sh.procCache) != 0 {
			t.Fatal("Go-карты наполнились при активной таблице")
		}
	}
	if ft.lookups != 0 {
		t.Fatalf("Track ходит в таблицу: %d lookup", ft.lookups)
	}
}

// Мутация-страж: БЕЗ источника тот же Track идёт в /proc (прежний путь) — счётчик растёт.
// Без этого предыдущий тест был бы вакуумным (счётчик, который не растёт нигде).
func TestW85_P1_WithoutSourceTheProcPathStillCounts(t *testing.T) {
	lt := NewLineageTracker(LineageConfig{Enabled: true, MaxDepth: 8}, slog.Default())
	before := testutil.ToFloat64(lineageProcReads)
	for i := uint32(0); i < 50; i++ {
		lt.Track(types.Event{PID: 4_100_000 + i})
	}
	if testutil.ToFloat64(lineageProcReads)-before < 50 {
		t.Fatal("прежний путь не считает чтения /proc — счётчик 8.5.5 слеп")
	}
}

// ParentOf: родитель и его comm; родителя нет в таблице — номер отдаётся, comm пуст.
func TestW85_P1_ParentOf(t *testing.T) {
	ft := newFakeTable().
		proc(100, 1, "cron", 1000, false).
		proc(101, 100, "sh", 2000, false).
		proc(102, 77, "orphan", 3000, false)
	lt := newTableTracker(t, 8, ft)
	if ppid, comm, ok := lt.ParentOf(101); !ok || ppid != 100 || comm != "cron" {
		t.Fatalf("ParentOf(101) = %d %q %v", ppid, comm, ok)
	}
	if ppid, comm, ok := lt.ParentOf(102); !ok || ppid != 77 || comm != "" {
		t.Fatalf("ParentOf(102) = %d %q %v", ppid, comm, ok)
	}
	if _, _, ok := lt.ParentOf(555); ok {
		t.Fatal("ParentOf неизвестного pid вернул ok")
	}
}

// Update с таблицей: паттерн ловится по parent_comm из события; и по таблице, если ядро не проставило.
func TestW85_P1_UpdateDetectsPatternsWithoutStoring(t *testing.T) {
	ft := newFakeTable().
		proc(100, 1, "nginx", 1000, false).
		proc(101, 100, "bash", 2000, false)
	lt := NewLineageTracker(DefaultLineageConfig(), slog.Default())
	lt.SetProcSource(ft)
	e := types.Event{PID: 101, PPID: 100}
	copy(e.Comm[:], "bash")
	if m := lt.Update(e); m == nil || m.Pattern.Name != "web_shell_spawn" {
		t.Fatalf("паттерн по таблице: %+v", m)
	}
	e2 := types.Event{PID: 101, PPID: 100}
	copy(e2.Comm[:], "bash")
	copy(e2.ParentComm[:], "nginx")
	if m := lt.Update(e2); m == nil {
		t.Fatal("паттерн по parent_comm события не пойман")
	}
	if _, ok := lt.GetLineage(101); ok {
		t.Fatal("Update сохранил запись в Go-карту")
	}
	if len(lt.shardFor(101).ancestry) != 0 {
		t.Fatal("Update построил ancestry в Go-карте")
	}
}

// AncestorChain: предки без самого pid, от корня к родителю; обрыв отрезает корневую сторону.
func TestW85_P1_AncestorChain(t *testing.T) {
	ft := newFakeTable().
		proc(300, 1, "dpkg", 1000, false).
		proc(301, 300, "sh", 2000, false).
		proc(302, 301, "perl", 3000, false).
		proc(303, 302, "systemctl", 4000, false)
	lt := newTableTracker(t, 8, ft)
	anc, out, ok := lt.AncestorChain(303)
	if !ok || out != procinfo.OutcomeResolved || len(anc) != 3 || anc[0].Comm != "dpkg" || anc[2].Comm != "perl" {
		t.Fatalf("anc=%+v out=%s ok=%v", anc, out, ok)
	}
	// разрыв посередине: корневая сторона (dpkg) НЕ возвращается — на неё опереться нельзя
	ft.res[301] = procinfo.Absent
	anc, out, _ = lt.AncestorChain(303)
	if len(anc) != 1 || anc[0].Comm != "perl" || out != procinfo.OutcomeEvicted {
		t.Fatalf("после разрыва: anc=%+v out=%s", anc, out)
	}
	// без таблицы — ok=false
	lt2 := NewLineageTracker(LineageConfig{Enabled: true}, slog.Default())
	if _, _, ok := lt2.AncestorChain(303); ok {
		t.Fatal("без таблицы AncestorChain обязан сказать ok=false")
	}
}

// Эквивалентность прежнему трекеру: на одинаковых данных дерево то же (корень → лист).
func TestW85_P1_TreeMatchesLegacyTrackerOnTheSameProcessModel(t *testing.T) {
	type pr struct {
		pid, ppid uint32
		comm      string
	}
	model := []pr{
		{100, 1, "nginx"}, {101, 100, "nginx-worker"}, {7001, 100, "bash"}, {7002, 7001, "curl"},
		{200, 1, "cron"}, {201, 200, "cron"}, {202, 201, "sh"}, {203, 202, "python3"},
		{300, 2, "kworker"},
	}
	byPid := map[uint32]pr{1: {1, 0, "systemd"}, 2: {2, 0, "kthreadd"}}
	ft := newFakeTable().proc(1, 0, "systemd", 1, false).proc(2, 0, "kthreadd", 1, false)
	legacy := NewLineageTracker(LineageConfig{Enabled: true, MaxDepth: 8}, slog.Default())
	for i, p := range model {
		byPid[p.pid] = p
		ft.proc(p.pid, p.ppid, p.comm, uint64(1000+i), false)
	}
	for _, p := range model { // события в порядке «родитель раньше потомка»
		e := types.Event{PID: p.pid, PPID: p.ppid}
		copy(e.Comm[:], p.comm)
		copy(e.ParentComm[:], byPid[p.ppid].comm)
		legacy.Track(e)
	}
	tbl := newTableTracker(t, 8, ft)
	for _, p := range model {
		old, now := comms(legacy.GetProcessTree(p.pid)), comms(tbl.GetProcessTree(p.pid))
		if len(old) == 0 {
			t.Fatalf("pid %d: прежний трекер пуст — фикстура негодна", p.pid)
		}
		if !eq(old, now) {
			t.Errorf("pid %d: прежний %v, таблица %v", p.pid, old, now)
		}
	}
}

// Гонка SetProcSource против чтений (под -race).
func TestW85_P1_SetProcSourceIsRaceFree(t *testing.T) {
	ft := newFakeTable().proc(100, 1, "a", 1, false).proc(101, 100, "b", 2, false)
	lt := NewLineageTracker(LineageConfig{Enabled: true, MaxDepth: 8}, slog.Default())
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				_ = lt.GetProcessTree(101)
				lt.Track(types.Event{PID: 101, PPID: 100})
				_, _, _ = lt.ParentOf(101)
			}
		}()
	}
	for i := 0; i < 200; i++ {
		lt.SetProcSource(ft)
		lt.SetProcSource(nil)
	}
	wg.Wait()
}

// Цена прежнего пути в куче Go — числом (A4 офлайн): Track 20 000 процессов (по четыре звена цепочки на процесс),
// затем та же нагрузка при активной таблице ядра. Печатает обе величины; тест требует, чтобы путь с таблицей
// не держал в куче Go ничего, пропорционального числу процессов.
func TestW85_P1_GoHeapPerTrackedProcess_LegacyVsTable(t *testing.T) {
	const n = 20000
	heap := func() uint64 {
		runtime.GC()
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return m.HeapAlloc
	}
	feed := func(lt *LineageTracker) {
		for i := uint32(0); i < n; i++ {
			pid := 100000 + i*4
			for hop := uint32(0); hop < 4; hop++ {
				e := types.Event{PID: pid + hop, PPID: pid + hop - 1}
				if hop == 0 {
					e.PPID = 1
				}
				copy(e.Comm[:], "worker")
				copy(e.ParentComm[:], "parent")
				lt.Track(e)
			}
		}
	}
	base := heap()
	legacy := NewLineageTracker(LineageConfig{Enabled: true, MaxDepth: 8, TTL: time.Hour}, slog.Default())
	feed(legacy)
	legacyBytes := int64(heap()) - int64(base)
	runtime.KeepAlive(legacy)
	legacy = nil
	base2 := heap()
	tbl := newTableTracker(t, 8, newFakeTable())
	feed(tbl)
	tableBytes := int64(heap()) - int64(base2)
	runtime.KeepAlive(tbl)
	t.Logf("куча Go после Track %d процессов (×4 звена): прежний путь %+d Б (≈ %d Б на процесс), таблица ядра %+d Б",
		n, legacyBytes, legacyBytes/n, tableBytes)
	if legacyBytes < 1<<20 {
		t.Fatalf("прежний путь не накопил состояния (%d Б) — измерение пустое", legacyBytes)
	}
	if tableBytes > legacyBytes/20 {
		t.Fatalf("с таблицей куча выросла на %d Б (прежний %d Б)", tableBytes, legacyBytes)
	}
}
