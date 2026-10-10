package correlator

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Долги 8.1, остаток №549 (ночь H4, 10.10.2026 03:17): impact_systemd_service_disabled
// называл stop/disable/mask, а условием было «root исполнил systemctl». Формы
// argv — дословно из алертов ночи (server-logs/collect-8.1-H4).

const h4SystemctlRule = "impact_systemd_service_disabled"

// Чтение состояния и старт юнита — работа таймеров ноды, правило молчит.
func TestW81H5_SystemctlReadOnlySilent(t *testing.T) {
	engine, res := w549EngineFrom(t, w549Rules(t))
	for i, args := range []string{
		"systemctl is-active -q connman.service",
		"systemctl is-active -q NetworkManager.service",
		"systemctl start --no-block apt-news.service esm-cache.service",
		"systemctl show -p MainPID --value auditd",
		"systemctl status stop.service",
		"service auditd status",
	} {
		comm := "systemctl"
		if args[:7] == "service" {
			comm = "service"
		}
		ev := h4Syscall(res, uint32(99500+i), comm, "/usr/bin/"+comm, 59, args, 0, 0)
		assert.Falsef(t, w81Fired(engine.Evaluate(ev))[h4SystemctlRule], "%q не останавливает сервис", args)
	}
}

// Остановка, выключение, маскировка — правило срабатывает; пустой proc.args
// (спуф argv[0] обнуляет аргументы) — тоже, отказ в шум.
func TestW81H5_SystemctlStopFires(t *testing.T) {
	engine, res := w549EngineFrom(t, w549Rules(t))
	for i, args := range []string{
		"systemctl stop auditd",
		"systemctl --now disable falco.service",
		"systemctl mask ebpf-guard",
		"systemctl kill -s KILL auditd",
		"systemctl isolate rescue.target",
		"service auditd stop",
		"",
	} {
		comm := "systemctl"
		if len(args) >= 7 && args[:7] == "service" {
			comm = "service"
		}
		ev := h4Syscall(res, uint32(99600+i), comm, "/usr/bin/"+comm, 59, args, 0, 0)
		assert.Truef(t, w81Fired(engine.Evaluate(ev))[h4SystemctlRule], "%q обязано сработать", args)
	}
	// Не root — правило про root, как и до правки.
	ev := h4Syscall(res, 99700, "systemctl", "/usr/bin/systemctl", 59, "systemctl stop auditd", 0, 1000)
	assert.False(t, w81Fired(engine.Evaluate(ev))[h4SystemctlRule], "uid 1000")
}

// --- proc.systemd_unit: резолвер по cgroup_id и исключения container_escape_init_proc.

// w81UnitResolver — подставной резолвер: cgroup_id → юнит.
type w81UnitResolver map[uint64]string

func (r w81UnitResolver) ResolveCgroupUnit(id uint64) string { return r[id] }

func w81WithUnits(t *testing.T, units w81UnitResolver) {
	t.Helper()
	prev, _ := cgroupUnitResolver.Load().(cgroupUnitResolverHolder)
	SetCgroupUnitResolver(units)
	t.Cleanup(func() { SetCgroupUnitResolver(prev.r) })
}

const (
	h5InitRule   = "container_escape_init_proc"
	h5AptMethod  = "/usr/lib/apt/methods/http"
	h5DetectVirt = "/usr/bin/systemd-detect-virt"
	h5CgEsm      = 5001 // esm-cache.service
	h5CgUser     = 5002 // user.slice: резолвер system.slice его не знает
	h5CgOther    = 5003 // чужой юнит system.slice
)

func h5Units() w81UnitResolver {
	return w81UnitResolver{h5CgEsm: "esm-cache.service", h5CgOther: "cron.service"}
}

func h5File(res w81CommExeResolver, pid uint32, comm, exe, path string, op uint8, flags int32, cg uint64, container string) types.Event {
	e := w549Event(res, pid, comm, exe, path, op, flags, container)
	e.CgroupID = cg
	return e
}

// Формы ночи H4: метод APT читает /proc/1/cgroup, systemd-detect-virt под
// esm-cache.service (образ не разрешён — мс-процесс) читает /proc/1/environ.
func TestW81H5_InitProcNodeTimerSuppressed(t *testing.T) {
	engine, res := w549EngineFrom(t, w549Rules(t))
	w81WithUnits(t, h5Units())
	for i, c := range []struct {
		comm, exe, path, exc string
		cg                   uint64
	}{
		{"http", h5AptMethod, "/proc/1/cgroup", "apt-method-init-cgroup", 0},
		{"https", h5AptMethod, "/proc/1/cgroup", "apt-method-init-cgroup", 0},
		// Гонка readlink (смок w81-h5, фаза A): образ пуст, ось — юнит.
		{"https", "", "/proc/1/cgroup", "apt-method-init-cgroup-unit", h5CgEsm},
		{"systemd-detect-", "", "/proc/1/environ", "node-timer-detect-virt", h5CgEsm},
		{"systemd-detect-", h5DetectVirt, "/proc/1/environ", "node-timer-detect-virt", h5CgEsm},
	} {
		before := w81ExcCount(h5InitRule, c.exc)
		for j, f := range []struct {
			op    uint8
			flags int32
		}{{0, 0}, {0, w549OCloexec}, {w549OpRead, 0}} {
			ev := h5File(res, uint32(99800+10*i+j), c.comm, c.exe, c.path, f.op, f.flags, c.cg, "")
			assert.Falsef(t, w81Fired(engine.Evaluate(ev))[h5InitRule], "%s %s (образ %q)", c.comm, c.path, c.exe)
		}
		assert.Greaterf(t, w81ExcCount(h5InitRule, c.exc), before, "подавление %s обязано считаться", c.exc)
	}
}

// Тот же comm вне таймерного юнита, в user.slice, без юнита, в контейнере,
// на запись, на чужом пути /proc/1/* — правило срабатывает.
func TestW81H5_DetectVirtUnitSpoofFires(t *testing.T) {
	engine, res := w549EngineFrom(t, w549Rules(t))
	w81WithUnits(t, h5Units())
	const oWronly = 1
	for i, c := range []struct {
		path, container, why string
		cg                   uint64
		flags                int32
	}{
		{"/proc/1/environ", "", "чужой юнит system.slice", h5CgOther, 0},
		{"/proc/1/environ", "", "user.slice (systemd-run --user --unit=esm-cache.service)", h5CgUser, 0},
		{"/proc/1/environ", "", "cgroup_id не разрешён", 0, 0},
		{"/proc/1/environ", w549Container, "контейнер", h5CgEsm, 0},
		{"/proc/1/environ", "", "открытие на запись", h5CgEsm, oWronly},
		{"/proc/1/mem", "", "чужой путь /proc/1/mem", h5CgEsm, 0},
		{"/proc/1/root/etc/shadow", "", "побег через /proc/1/root", h5CgEsm, 0},
	} {
		ev := h5File(res, uint32(99900+i), "systemd-detect-", "", c.path, 0, c.flags, c.cg, c.container)
		assert.Truef(t, w81Fired(engine.Evaluate(ev))[h5InitRule], "обязано сработать: %s", c.why)
	}
	// Тот же юнит, другой comm — исключение только для наблюдённого процесса.
	ev := h5File(res, 99950, "python3", "/usr/bin/python3.10", "/proc/1/environ", 0, 0, h5CgEsm, "")
	assert.True(t, w81Fired(engine.Evaluate(ev))[h5InitRule], "python3 под esm-cache читает environ init")
}

// Метод APT: копия образа, пустой образ, чужой путь — срабатывает.
func TestW81H5_AptMethodInitCgroupSpoofFires(t *testing.T) {
	engine, res := w549EngineFrom(t, w549Rules(t))
	w81WithUnits(t, h5Units())
	for i, c := range []struct{ exe, path, container, why string }{
		{"/tmp/http", "/proc/1/cgroup", "", "копия в /tmp"},
		{"", "/proc/1/cgroup", "", "образ не разрешён и юнита нет"},
		{h5AptMethod, "/proc/1/environ", "", "чужой путь"},
		{h5AptMethod, "/proc/1/cgroup", w549Container, "контейнер"},
	} {
		ev := h5File(res, uint32(99960+i), "http", c.exe, c.path, 0, 0, 0, c.container)
		assert.Truef(t, w81Fired(engine.Evaluate(ev))[h5InitRule], "обязано сработать: %s", c.why)
	}
	// Ветка юнита: пустой образ в чужом юните, в user.slice, на чужом пути.
	for i, c := range []struct {
		path, why string
		cg        uint64
	}{
		{"/proc/1/cgroup", "чужой юнит system.slice", h5CgOther},
		{"/proc/1/cgroup", "user.slice", h5CgUser},
		{"/proc/1/environ", "чужой путь в таймерном юните", h5CgEsm},
	} {
		ev := h5File(res, uint32(99990+i), "https", "", c.path, 0, 0, c.cg, "")
		assert.Truef(t, w81Fired(engine.Evaluate(ev))[h5InitRule], "обязано сработать: %s", c.why)
	}
}

// Резолвер: inode каталога под system.slice → имя юнита верхнего уровня;
// user.slice и корень не разрешаются; новый юнит виден после паузы скана.
func TestW81H5_SystemSliceUnitResolver(t *testing.T) {
	root := t.TempDir()
	mk := func(p string) uint64 {
		full := filepath.Join(root, p)
		require.NoError(t, os.MkdirAll(full, 0o755))
		st, err := os.Stat(full)
		require.NoError(t, err)
		return uint64(st.Sys().(*syscall.Stat_t).Ino)
	}
	esm := mk("system.slice/esm-cache.service")
	nested := mk("system.slice/esm-cache.service/payload")
	user := mk("user.slice/user-1000.slice/user@1000.service/app.slice/esm-cache.service")
	slice := mk("system.slice")
	notUnit := mk("system.slice/foo.slice")

	now := time.Unix(1_000_000, 0)
	r := NewSystemSliceUnitResolver(root)
	r.now = func() time.Time { return now }

	assert.Equal(t, "esm-cache.service", r.ResolveCgroupUnit(esm))
	assert.Equal(t, "esm-cache.service", r.ResolveCgroupUnit(nested), "вложенный cgroup — юнит верхнего уровня")
	assert.Empty(t, r.ResolveCgroupUnit(user), "user.slice не признаётся")
	assert.Empty(t, r.ResolveCgroupUnit(slice), "сам system.slice — не юнит")
	assert.Empty(t, r.ResolveCgroupUnit(notUnit), "*.slice — не юнит")
	assert.Empty(t, r.ResolveCgroupUnit(0))
	assert.Empty(t, r.ResolveCgroupUnit(1))

	late := mk("system.slice/apt-news.service")
	assert.Empty(t, r.ResolveCgroupUnit(late), "внутри паузы скана — промах, отказ в шум")
	now = now.Add(cgroupUnitRescanInterval)
	assert.Equal(t, "apt-news.service", r.ResolveCgroupUnit(late), "после паузы — пересканирован")

	require.NoError(t, os.Remove(filepath.Join(root, "system.slice/esm-cache.service/payload")))
	require.NoError(t, os.Remove(filepath.Join(root, "system.slice/esm-cache.service")))
	now = now.Add(cgroupUnitRescanInterval)
	r.ResolveCgroupUnit(12345) // промах → скан
	assert.Empty(t, r.ResolveCgroupUnit(esm), "ушедший юнит выпадает из карты")
}

// Явный legacy-набор op: container_escape_init_proc мутаций не видит, open и
// write видит (память op-in-exception-drops-legacy-flag).
func TestW81H5_InitProcIgnoresMutations(t *testing.T) {
	engine, res := w549EngineFrom(t, w549Rules(t))
	w81WithUnits(t, h5Units())
	for j, op := range w81MutationOps {
		ev := h5File(res, uint32(99970+j), "bash", "/usr/bin/bash", "/proc/1/environ", op, 0, 0, "")
		assert.Falsef(t, w81Fired(engine.Evaluate(ev))[h5InitRule], "%s", fileOpNames[op])
	}
	for j, op := range []uint8{0, 2} { // open, write
		ev := h5File(res, uint32(99980+j), "bash", "/usr/bin/bash", "/proc/1/environ", op, 0, 0, "")
		assert.Truef(t, w81Fired(engine.Evaluate(ev))[h5InitRule], "%s", fileOpNames[op])
	}
}
