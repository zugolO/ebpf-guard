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
// юнит, стартовавший после прошлого скана. Скан — readdir одного каталога и
// stat его поддерева (десятки записей на ноде); 100 мс держат цену в
// единицах миллисекунд в секунду при потоке промахов и при этом успевают за
// юнитом, стартовавшим за доли секунды до своего первого события.
const cgroupUnitRescanInterval = 100 * time.Millisecond

// SystemSliceUnitResolver разрешает cgroup id через inode каталогов под
// <root>/system.slice. Карта строится сканом целиком и целиком же
// заменяется, поэтому её размер ограничен числом живых cgroup system.slice —
// ушедшие юниты из неё выпадают на следующем скане.
type SystemSliceUnitResolver struct {
	root string

	mu       sync.RWMutex
	byID     map[uint64]string
	lastScan time.Time
	now      func() time.Time
}

// NewSystemSliceUnitResolver возвращает резолвер над корнем cgroup2 root
// (на хосте — /sys/fs/cgroup).
func NewSystemSliceUnitResolver(root string) *SystemSliceUnitResolver {
	return &SystemSliceUnitResolver{root: root, byID: map[uint64]string{}, now: time.Now}
}

// ResolveCgroupUnit implements CgroupUnitResolver.
func (r *SystemSliceUnitResolver) ResolveCgroupUnit(cgroupID uint64) string {
	if cgroupID <= 1 { // 0 — старый BPF-объект, 1 — корень cgroup2
		return ""
	}
	r.mu.RLock()
	unit, ok := r.byID[cgroupID]
	r.mu.RUnlock()
	if ok {
		return unit
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if unit, ok := r.byID[cgroupID]; ok {
		return unit
	}
	now := r.now()
	if !r.lastScan.IsZero() && now.Sub(r.lastScan) < cgroupUnitRescanInterval {
		return ""
	}
	r.byID = scanSystemSlice(r.root)
	r.lastScan = now
	return r.byID[cgroupID]
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

// resolveSystemdUnit — значение поля proc.systemd_unit для события.
func resolveSystemdUnit(cgroupID uint64) string {
	h, _ := cgroupUnitResolver.Load().(cgroupUnitResolverHolder)
	if h.r == nil {
		systemdUnitLookups.WithLabelValues("no_resolver").Inc()
		return ""
	}
	u := h.r.ResolveCgroupUnit(cgroupID)
	if u == "" {
		systemdUnitLookups.WithLabelValues("unresolved").Inc()
		return ""
	}
	systemdUnitLookups.WithLabelValues("resolved").Inc()
	return u
}
