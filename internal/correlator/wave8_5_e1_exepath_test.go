package correlator

import (
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/internal/procinfo"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 8.5, E1: exe_path берётся по dev/ino образа из таблицы процессов ядра, а не по readlink
// /proc/<pid>/exe. Тесты на настоящем наборе правил: мс-процесс (readlink мёртв) получает исключение
// virt-detect-self; спуфы оси (comm, exec -a, копия бинаря, заменённый файл) — срабатывают.

type w85e1Table map[uint32]procinfo.Record

func (t w85e1Table) Lookup(pid uint32) (procinfo.Record, procinfo.Result) {
	r, ok := t[pid]
	if !ok {
		return procinfo.Record{}, procinfo.Absent
	}
	return r, procinfo.Found
}

// w85e1FS — «файловая система» кэша образов: путь → {dev, ino}; /proc/<pid>/exe читать нечем.
type w85e1FS struct{ ids map[string][2]uint64 }

func (f *w85e1FS) stat(p string) (uint32, uint64, bool) {
	v, ok := f.ids[p]
	return uint32(v[0]), v[1], ok
}
func (f *w85e1FS) link(string) (string, error) { return "", errors.New("ENOENT") }

// w85e1Setup подставляет таблицу, кэш образов с подставной ФС и резолвер readlink, который не
// видит ни одного процесса (все мс-процессы уже вышли). Возвращает движок и «ФС».
func w85e1Setup(t *testing.T, tab w85e1Table, withTable bool) (*RuleEngine, *w85e1FS, *w85e1Readlink) {
	t.Helper()
	fs := &w85e1FS{ids: map[string][2]uint64{}}
	prevCache := lineageImages
	lineageImages = procinfo.NewImageCacheWith(64, fs.stat, fs.link)
	rl := &w85e1Readlink{paths: map[uint32]string{}}
	prev, _ := exeResolver.Load().(exeResolverHolder)
	SetExePathResolver(rl)
	prevSrc, _ := exeImageSource.Load().(exeImageHolder)
	if withTable {
		SetExeImageSource(tab)
	} else {
		SetExeImageSource(nil)
	}
	t.Cleanup(func() {
		lineageImages = prevCache
		SetExePathResolver(prev.r)
		SetExeImageSource(prevSrc.src)
	})
	return NewRuleEngine(w549Rules(t)), fs, rl
}

type w85e1Readlink struct {
	paths map[uint32]string
	calls int
}

func (r *w85e1Readlink) ResolveExePath(pid uint32) string { r.calls++; return r.paths[pid] }

func w85e1DMIEvent(pid uint32) types.Event {
	e := w81FileEvent(pid, "systemd-detect-", "/sys/class/dmi/id/sys_vendor", 0)
	e.File.Flags = w549OCloexec
	return e
}

const (
	w85e1Rule = "mitre_vm_detect_dmi_read"
	w85e1Exc  = "virt-detect-self"
)

func w85e1Rec(dev uint32, ino uint64, filename string) procinfo.Record {
	return procinfo.Record{ExeDev: dev, ExeIno: ino, Filename: filename, ExitTS: 9, Comm: "systemd-detect-"}
}

// Мс-процесс: к разбору правила он уже вышел, readlink пуст, образ — из таблицы. ДО (без таблицы) то же
// событие срабатывало — это и есть дефект «virt-detect-self — 0 подавлений».
func TestW85_E1_ShortLivedProcessImageComesFromTable(t *testing.T) {
	tab := w85e1Table{98600: w85e1Rec(7, 555, "/usr/bin/systemd-detect-virt")}

	// ДО: таблицы нет — readlink пуст — исключение не применяется
	engine, fs, _ := w85e1Setup(t, tab, false)
	fs.ids["/usr/bin/systemd-detect-virt"] = [2]uint64{7, 555}
	assert.True(t, w81Fired(engine.Evaluate(w85e1DMIEvent(98600)))[w85e1Rule],
		"без таблицы образ мс-процесса не разрешается и правило срабатывает (прежнее поведение)")

	// ПОСЛЕ: таблица — исключение применено, readlink не нужен
	engine, fs, rl := w85e1Setup(t, tab, true)
	fs.ids["/usr/bin/systemd-detect-virt"] = [2]uint64{7, 555}
	exc := w81ExcCount(w85e1Rule, w85e1Exc)
	viaTable := testutil.ToFloat64(exePathImage.WithLabelValues(procinfo.ImageFilename))
	unres := testutil.ToFloat64(exePathLookups.WithLabelValues("unresolved", exePathFieldSelf))
	assert.False(t, w81Fired(engine.Evaluate(w85e1DMIEvent(98600)))[w85e1Rule])
	assert.Greater(t, w81ExcCount(w85e1Rule, w85e1Exc), exc, "подавление считается")
	assert.Equal(t, viaTable+1, testutil.ToFloat64(exePathImage.WithLabelValues(procinfo.ImageFilename)))
	assert.Equal(t, unres, testutil.ToFloat64(exePathLookups.WithLabelValues("unresolved", exePathFieldSelf)),
		"мс-процесс больше не попадает в unresolved")
	assert.Zero(t, rl.calls, "образ получен без readlink")
}

// Спуфы оси exe_path: образ процесс себе не выбирает.
func TestW85_E1_ExePathSpoofsStillFire(t *testing.T) {
	for _, c := range []struct {
		name     string
		rec      procinfo.Record
		fsEntry  map[string][2]uint64
		viaTable bool
	}{
		// prctl(PR_SET_NAME) меняет comm, образ — прежний (копия бинаря в /tmp)
		{"comm-спуф", procinfo.Record{ExeDev: 7, ExeIno: 600, Filename: "/tmp/dv", Comm: "systemd-detect-", ExitTS: 9},
			map[string][2]uint64{"/tmp/dv": {7, 600}}, true},
		// exec -a systemd-detect-virt /tmp/evil: argv[0] другой, filename — путь настоящего образа
		{"exec -a", procinfo.Record{ExeDev: 7, ExeIno: 601, Filename: "/tmp/evil", Comm: "systemd-detect-", ExitTS: 9},
			map[string][2]uint64{"/tmp/evil": {7, 601}}, true},
		// копия бинаря под тем же именем в другом каталоге: свой inode — свой путь
		{"копия под тем же именем", procinfo.Record{ExeDev: 7, ExeIno: 602, Filename: "/var/tmp/systemd-detect-virt", Comm: "systemd-detect-", ExitTS: 9},
			map[string][2]uint64{"/var/tmp/systemd-detect-virt": {7, 602}}, true},
		// образа с проверяемым путём нет (файл удалён после exec): не образ — исключения нет
		{"удалённый образ", procinfo.Record{ExeDev: 7, ExeIno: 603, Filename: "/usr/bin/systemd-detect-virt", Comm: "systemd-detect-", ExitTS: 9},
			map[string][2]uint64{}, true},
		// filename указывает на настоящий образ, но ЧУЖОЙ inode (подмена файла по пути): сверка по inode
		{"путь настоящего образа, inode чужой", procinfo.Record{ExeDev: 7, ExeIno: 604, Filename: "/usr/bin/systemd-detect-virt", Comm: "systemd-detect-", ExitTS: 9},
			map[string][2]uint64{"/usr/bin/systemd-detect-virt": {7, 555}}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			engine, fs, _ := w85e1Setup(t, w85e1Table{98700: c.rec}, c.viaTable)
			for k, v := range c.fsEntry {
				fs.ids[k] = v
			}
			assert.True(t, w81Fired(engine.Evaluate(w85e1DMIEvent(98700)))[w85e1Rule], c.name+": обязано сработать")
		})
	}
}

// Замена файла по тому же пути: старый процесс (старый inode) не получает исключение, новый — получает.
func TestW85_E1_ReplacedFileInvalidatesTheCachedPath(t *testing.T) {
	const exe = "/usr/bin/systemd-detect-virt"
	tab := w85e1Table{
		98800: w85e1Rec(7, 555, exe), // старый образ
		98801: w85e1Rec(7, 556, exe), // новый образ по тому же пути
	}
	engine, fs, rl := w85e1Setup(t, tab, true)
	fs.ids[exe] = [2]uint64{7, 555}
	assert.False(t, w81Fired(engine.Evaluate(w85e1DMIEvent(98800)))[w85e1Rule], "до замены — исключение")
	require.Equal(t, 1, lineageImages.Len())

	fs.ids[exe] = [2]uint64{7, 556} // пакет обновил файл: новый inode по прежнему пути
	assert.True(t, w81Fired(engine.Evaluate(w85e1DMIEvent(98800)))[w85e1Rule],
		"старый inode больше не лежит по этому пути: исключения нет (ядро показало бы «(deleted)»)")
	assert.GreaterOrEqual(t, rl.calls, 1, "запасной readlink — со счётчиком")
	assert.False(t, w81Fired(engine.Evaluate(w85e1DMIEvent(98801)))[w85e1Rule],
		"процесс из нового файла получает новый путь и исключение")
}

// Таблицы нет / записи нет / образ без inode — прежний readlink, и это видно в счётчике.
func TestW85_E1_ReadlinkIsTheCountedFallback(t *testing.T) {
	tab := w85e1Table{98900: {ExeDev: 0, ExeIno: 0, Comm: "kthreadd"}}
	_, _, rl := w85e1Setup(t, tab, true)
	rl.paths[98900] = "/usr/bin/x"
	rl.paths[98901] = "/usr/bin/y"
	fbRes := testutil.ToFloat64(exePathReadlinkFallback.WithLabelValues("resolved"))
	fbUn := testutil.ToFloat64(exePathReadlinkFallback.WithLabelValues("unresolved"))
	noInode := testutil.ToFloat64(exePathImage.WithLabelValues(exeImageNoInode))
	noRec := testutil.ToFloat64(exePathImage.WithLabelValues(exeImageNoRecord))

	assert.Equal(t, "/usr/bin/x", resolveExePath(98900, exePathFieldSelf), "запись без inode → readlink")
	assert.Equal(t, "/usr/bin/y", resolveExePath(98901, exePathFieldSelf), "записи нет → readlink")
	assert.Equal(t, "", resolveExePath(98902, exePathFieldSelf))

	assert.Equal(t, noInode+1, testutil.ToFloat64(exePathImage.WithLabelValues(exeImageNoInode)))
	assert.Equal(t, noRec+2, testutil.ToFloat64(exePathImage.WithLabelValues(exeImageNoRecord)))
	assert.Equal(t, fbRes+2, testutil.ToFloat64(exePathReadlinkFallback.WithLabelValues("resolved")))
	assert.Equal(t, fbUn+1, testutil.ToFloat64(exePathReadlinkFallback.WithLabelValues("unresolved")))
}

// Живой процесс с известным образом: после первого разрешения повторные идут из кэша без /proc.
func TestW85_E1_RepeatedLookupsHitTheCache(t *testing.T) {
	tab := w85e1Table{99000: w85e1Rec(7, 700, "/usr/sbin/cron")}
	_, fs, rl := w85e1Setup(t, tab, true)
	fs.ids["/usr/sbin/cron"] = [2]uint64{7, 700}
	cached := testutil.ToFloat64(exePathImage.WithLabelValues(procinfo.ImageCached))
	for i := 0; i < 50; i++ {
		require.Equal(t, "/usr/sbin/cron", resolveExePath(99000, exePathFieldSelf))
	}
	assert.Equal(t, cached+49, testutil.ToFloat64(exePathImage.WithLabelValues(procinfo.ImageCached)))
	assert.Zero(t, rl.calls)
}
