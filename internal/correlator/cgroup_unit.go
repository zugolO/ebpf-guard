package correlator

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// --- Долги 8.1, остаток №549 (10.10.2026): ось systemd-юнита ДЛЯ ПРАВИЛ.
//
// ЧТО ИЗМЕРЕНО. Смок w81-h4 (09.10.2026) и ночь H4: исключение virt-detect-self
// по образу /usr/bin/systemd-detect-virt подавило 0 раз — процесс живёт
// миллисекунды, readlink("/proc/<pid>/exe") к моменту разбора правил уже
// пуст (память short-lived-detect-virt-exe-unresolved). Тот же процесс под
// esm-cache.service (ночь H4, 03:17:19) прочитал /proc/1/environ и поднял
// container_escape_init_proc — правило с тегом container-escape, твёрдую
// улику, которую correlator.trusted_units прощать не вправе.
//
// ПОЧЕМУ CGROUP_ID, А НЕ /proc/<pid>/cgroup. Юнит корня инцидента (unit.go)
// читается по pid — для мс-процесса это та же проигранная гонка. Но cgroup
// юнита живёт, пока жив юнит (главный процесс esm-cache — секунды), а его id
// ядро кладёт в КАЖДОЕ событие (types.Event.CgroupID, item 10 волны 6.6). В
// cgroup v2 этот id — номер inode каталога cgroup, поэтому разрешение — поиск
// каталога с этим inode, без /proc и без гонки с умершим процессом.
//
// ПОЧЕМУ ТОЛЬКО system.slice. Каталог в system.slice создаёт systemd PID 1,
// писать в cgroup.procs там может только root. Под user.slice юниты заводит
// пользовательский менеджер: `systemd-run --user --unit=apt-daily.service`
// без всяких прав даёт /user.slice/user-1000.slice/user@1000.service/
// app.slice/apt-daily.service — имя совпадает, а ось обязана его не признать.
// Поэтому поле — имя каталога ПРЯМО под system.slice, и для всего остального
// (user.slice, kubepods, init.scope, корень) оно пусто.
//
// ЧЕГО ОСЬ НЕ ДАЁТ. Против root она не защищает (root может создать каталог и
// переложить процесс), как и exe_path против root, переписывающего /usr/bin.
// Пустое значение — «юнит не определён» — исключение не применяет: отказ в
// шум, как у exe_path.

// systemdUnitLookups считает вычисления поля proc.systemd_unit по исходу.
var systemdUnitLookups = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "ebpf_guard_systemd_unit_lookups_total",
		Help: "proc.systemd_unit resolutions attempted by rule conditions, by result (resolved, unresolved, no_resolver).",
	},
	[]string{"result"},
)

func init() {
	// С нуля, как exe_path_lookups_total: «resolved = 0» обязано отличаться
	// от «бинарь про ось не знает».
	for _, result := range []string{"resolved", "unresolved", "no_resolver"} {
		systemdUnitLookups.WithLabelValues(result)
	}
}

// CgroupUnitResolver возвращает имя юнита system.slice, которому принадлежит
// cgroup с данным id, или "" если такого нет.
type CgroupUnitResolver interface {
	ResolveCgroupUnit(cgroupID uint64) string
}

// cgroupUnitRescanInterval ограничивает пересканирование system.slice на
// промахе. Промах — это cgroup не из system.slice (контейнер, сессия) или
// юнит, стартовавший после прошлого скана. 100 мс успевают за юнитом,
// стартовавшим за доли секунды до своего первого события.
//
// Цена скана ИЗМЕРЕНА (волна 8.2, под на k3s, 90 с): ≈255 КБ аллокаций на
// скан, не «десятки записей» — WalkDir идёт по всему поддереву каждого
// юнита, а на ноде их сотни каталогов. При потоке промахов (kubepods, сессии —
// большинство событий) 10 сканов/с давали 230 из 414 МБ всех аллокаций.
const cgroupUnitRescanInterval = 100 * time.Millisecond

// cgroupUnitMissTTL — сколько помнится ПОВТОРНЫЙ промах id без нового скана.
// Id нового юнита в отрицательном кэше не бывает, поэтому он разрешается на
// первом же своём событии (после rescan-интервала), как и раньше.
//
// Первый промах id не подавляет ничего (только rescan-интервал): каталог юнита
// мог появиться уже ПОСЛЕ того, как скан прочитал system.slice, и тогда запись
// «промах» на 30 с оставила бы живой юнит неразрешённым. Подавление включается
// на втором промахе подряд — то есть id, которого после двух сканов всё ещё нет
// (kubepods, сессии), стоит два скана на TTL, а не десять в секунду.
const cgroupUnitMissTTL = 30 * time.Second

// cgroupUnitMissCap ограничивает отрицательный кэш; при переполнении
// вытесняются самые старые записи.
const cgroupUnitMissCap = 4096

// systemdUnitScans считает сканы system.slice.
var systemdUnitScans = promauto.NewCounter(prometheus.CounterOpts{
	Name: "ebpf_guard_systemd_unit_scans_total",
	Help: "Full scans of system.slice performed by the proc.systemd_unit resolver.",
})

// systemdUnitTopScans считает сканы ВЕРХНЕГО уровня system.slice (U1, волна 8.5):
// один ReadDir и по lstat на запись, без обхода поддеревьев юнитов. Отдельная
// серия от systemd_unit_scans_total: та по-прежнему считает полный обход
// (запасной путь для записей без unit_cgroup_id) и на живом пути обязана
// стоять около нуля.
var systemdUnitTopScans = promauto.NewCounter(prometheus.CounterOpts{
	Name: "ebpf_guard_systemd_unit_top_scans_total",
	Help: "Top-level scans (one ReadDir) of system.slice by the proc.systemd_unit resolver for events carrying the in-kernel unit cgroup id.",
})

// SystemSliceUnitResolver разрешает cgroup id через inode каталогов под
// <root>/system.slice. Карта строится сканом целиком и целиком же
// заменяется, поэтому её размер ограничен числом живых cgroup system.slice —
// ушедшие юниты из неё выпадают на следующем скане.
//
// Скан идёт БЕЗ удержания мьютекса (оценка правил на горячем пути), не более
// одного одновременно; остальные промахи на время скана получают "".
type SystemSliceUnitResolver struct {
	root string

	mu       sync.RWMutex
	byID     map[uint64]string
	miss     map[uint64]unitMiss // id → промах после скана
	lastScan time.Time
	now      func() time.Time

	scanning atomic.Bool

	// U1: id каталога-предка уровня 2 (из события ядра) → имя юнита. Верхний
	// уровень system.slice, без вложенных каталогов; свои отрицательный кэш и
	// пауза пересканирования — тот же расчёт, что у полного обхода.
	top         map[uint64]string
	topMiss     map[uint64]unitMiss
	lastTopScan time.Time
	topScanning atomic.Bool
}

// unitMiss — запись отрицательного кэша: strikes — число подряд промахов после
// скана; подавляет повторный скан только со второго.
type unitMiss struct {
	at      time.Time
	strikes int
}

// NewSystemSliceUnitResolver возвращает резолвер над корнем cgroup2 root
// (на хосте — /sys/fs/cgroup).
func NewSystemSliceUnitResolver(root string) *SystemSliceUnitResolver {
	return &SystemSliceUnitResolver{
		root:    root,
		byID:    map[uint64]string{},
		miss:    map[uint64]unitMiss{},
		top:     map[uint64]string{},
		topMiss: map[uint64]unitMiss{},
		now:     time.Now,
	}
}

// ResolveCgroupUnit implements CgroupUnitResolver.
func (r *SystemSliceUnitResolver) ResolveCgroupUnit(cgroupID uint64) string {
	if cgroupID <= 1 { // 0 — старый BPF-объект, 1 — корень cgroup2
		return ""
	}
	now := r.now()
	r.mu.RLock()
	unit, ok := r.byID[cgroupID]
	miss, missed := r.miss[cgroupID]
	recent := !r.lastScan.IsZero() && now.Sub(r.lastScan) < cgroupUnitRescanInterval
	r.mu.RUnlock()
	if ok {
		return unit
	}
	if missed && miss.strikes >= 2 && now.Sub(miss.at) < cgroupUnitMissTTL {
		return ""
	}
	if recent || !r.scanning.CompareAndSwap(false, true) {
		return ""
	}
	defer r.scanning.Store(false)

	systemdUnitScans.Inc()
	byID := scanSystemSlice(r.root)

	r.mu.Lock()
	defer r.mu.Unlock()
	r.byID = byID
	r.lastScan = now
	unit, ok = byID[cgroupID]
	if ok {
		delete(r.miss, cgroupID)
		return unit
	}
	r.rememberMissLocked(cgroupID, now)
	return ""
}

// ResolveUnitID разрешает id каталога-предка уровня 2, записанный ядром в
// событие (U1): либо это каталог юнита прямо под system.slice, либо его нет в
// карте верхнего уровня (kubepods.slice/…, user.slice/…) и ответ пуст — отказ в
// шум. Цена промаха — один ReadDir, а не обход поддеревьев всех юнитов.
func (r *SystemSliceUnitResolver) ResolveUnitID(unitID uint64) string {
	if unitID <= 1 {
		return ""
	}
	now := r.now()
	r.mu.RLock()
	unit, ok := r.top[unitID]
	miss, missed := r.topMiss[unitID]
	recent := !r.lastTopScan.IsZero() && now.Sub(r.lastTopScan) < cgroupUnitRescanInterval
	r.mu.RUnlock()
	if ok {
		return unit
	}
	if missed && miss.strikes >= 2 && now.Sub(miss.at) < cgroupUnitMissTTL {
		return ""
	}
	if recent || !r.topScanning.CompareAndSwap(false, true) {
		return ""
	}
	defer r.topScanning.Store(false)

	systemdUnitTopScans.Inc()
	top := scanSystemSliceTop(r.root)

	r.mu.Lock()
	defer r.mu.Unlock()
	r.top = top
	r.lastTopScan = now
	unit, ok = top[unitID]
	if ok {
		delete(r.topMiss, unitID)
		return unit
	}
	r.topMiss = rememberMiss(r.topMiss, unitID, now)
	return ""
}

// rememberMiss — отрицательный кэш верхнего уровня (та же политика, что
// rememberMissLocked для полного обхода): ограничен cgroupUnitMissCap,
// вытесняет просроченные, затем самые старые; подавляет со второго промаха.
func rememberMiss(m map[uint64]unitMiss, id uint64, now time.Time) map[uint64]unitMiss {
	if len(m) >= cgroupUnitMissCap {
		for k, v := range m {
			if now.Sub(v.at) >= cgroupUnitMissTTL {
				delete(m, k)
			}
		}
		for len(m) >= cgroupUnitMissCap {
			var oldestK uint64
			var oldestT time.Time
			first := true
			for k, v := range m {
				if first || v.at.Before(oldestT) {
					oldestK, oldestT, first = k, v.at, false
				}
			}
			delete(m, oldestK)
		}
	}
	strikes := 1
	if _, again := m[id]; again {
		strikes = 2
	}
	m[id] = unitMiss{at: now, strikes: strikes}
	return m
}

// scanSystemSliceTop строит inode → имя юнита ТОЛЬКО для каталогов-юнитов прямо
// под system.slice: один ReadDir и по lstat на запись (DirEntry.Info).
func scanSystemSliceTop(root string) map[uint64]string {
	out := map[uint64]string{}
	entries, err := os.ReadDir(filepath.Join(root, "system.slice"))
	if err != nil {
		return out
	}
	for _, ent := range entries {
		name := ent.Name()
		if !ent.IsDir() || !isUnitDirName(name) {
			continue
		}
		info, err := ent.Info()
		if err != nil {
			continue
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			out[uint64(st.Ino)] = name
		}
	}
	return out
}

// rememberMissLocked заносит id в отрицательный кэш, вытесняя при переполнении
// просроченные, а затем самые старые записи.
func (r *SystemSliceUnitResolver) rememberMissLocked(id uint64, now time.Time) {
	r.miss = rememberMiss(r.miss, id, now)
}

// scanSystemSlice строит inode → имя юнита для каждого каталога под
// system.slice. Вложенные cgroup (foo.service/payload, делегированные
// поддеревья) получают имя своего юнита верхнего уровня.
func scanSystemSlice(root string) map[uint64]string {
	out := map[uint64]string{}
	slice := filepath.Join(root, "system.slice")
	entries, err := os.ReadDir(slice)
	if err != nil {
		return out
	}
	for _, ent := range entries {
		name := ent.Name()
		if !ent.IsDir() || !isUnitDirName(name) {
			continue
		}
		_ = filepath.WalkDir(filepath.Join(slice, name), func(p string, d os.DirEntry, err error) error {
			if err != nil || !d.IsDir() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			if st, ok := info.Sys().(*syscall.Stat_t); ok {
				out[uint64(st.Ino)] = name
			}
			return nil
		})
	}
	return out
}

func isUnitDirName(name string) bool {
	return strings.HasSuffix(name, ".service") || strings.HasSuffix(name, ".scope")
}

var cgroupUnitResolver atomic.Value // cgroupUnitResolverHolder

type cgroupUnitResolverHolder struct{ r CgroupUnitResolver }

// SetCgroupUnitResolver включает поле proc.systemd_unit. Пока резолвер не
// установлен, поле пусто у всех событий и исключения на нём не применяются.
func SetCgroupUnitResolver(r CgroupUnitResolver) {
	cgroupUnitResolver.Store(cgroupUnitResolverHolder{r: r})
}

// unitIDResolver — резолвер, понимающий id каталога-предка из события (U1).
type unitIDResolver interface {
	ResolveUnitID(unitCgroupID uint64) string
}

// resolveSystemdUnit — значение поля proc.systemd_unit для события.
// unitCgroupID — id каталога-предка уровня 2, записанный ядром (U1; 0 — запись
// без него: старый объект, коллектор без поля, задача выше уровня 2) — идёт
// дешёвым путём верхнего уровня; без него — прежний путь по cgroupID.
func resolveSystemdUnit(cgroupID, unitCgroupID uint64) string {
	h, _ := cgroupUnitResolver.Load().(cgroupUnitResolverHolder)
	if h.r == nil {
		systemdUnitLookups.WithLabelValues("no_resolver").Inc()
		return ""
	}
	var u string
	if ur, ok := h.r.(unitIDResolver); ok && unitCgroupID != 0 {
		u = ur.ResolveUnitID(unitCgroupID)
	} else {
		u = h.r.ResolveCgroupUnit(cgroupID)
	}
	if u == "" {
		systemdUnitLookups.WithLabelValues("unresolved").Inc()
		return ""
	}
	systemdUnitLookups.WithLabelValues("resolved").Inc()
	return u
}
