package correlator

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// №545 (08.10.2026): container_escape_module_access сужен до двух веток —
// A: процесс контейнера трогает модульную ось; B: посадка модуля (write/rename
// в /lib/modules) кем угодно, кроме dpkg и kmod (depmod) на хосте по образу.
// Формы шума — из сторов ночей H (mkinitramfs) и H2 (fwupd, aa-enabled,
// systemd, systemd-udevd) и входа пакета атак (insmod на modules.softdep).

const w545Rule = "container_escape_module_access"

type w545Proc struct {
	comm, exe, container string
}

func w545Event(t *testing.T, res w81CommExeResolver, pid uint32, p w545Proc, path string, op uint8) types.Event {
	t.Helper()
	res[pid] = p.exe
	e := w81FileEvent(pid, p.comm, path, op)
	if p.container != "" {
		e.Enrichment = &types.EnrichmentInfo{ContainerID: p.container}
	}
	return e
}

func w545Engine(t *testing.T) (*RuleEngine, w81CommExeResolver) {
	t.Helper()
	res := w81CommExeResolver{}
	prev, _ := exeResolver.Load().(exeResolverHolder)
	SetExePathResolver(res)
	t.Cleanup(func() { SetExePathResolver(prev.r) })
	return w81Engine(t), res
}

// Хостовые чтения модульной оси — шум ночей H/H2 и бывший вход пакета атак —
// правило больше не поднимают.
func TestWave8_1_ModuleAccessHostReadsSilent(t *testing.T) {
	engine, res := w545Engine(t)
	forms := []struct {
		p    w545Proc
		path string
	}{
		{w545Proc{"insmod", "/usr/bin/kmod", ""}, "/lib/modules/5.15.0-194-generic/modules.softdep"},
		{w545Proc{"modinfo", "/usr/bin/kmod", ""}, "/lib/modules/5.15.0-194-generic/modules.softdep"},
		{w545Proc{"modprobe", "/usr/bin/kmod", ""}, "/lib/modules/5.15.0-198-generic/kernel/drivers/bcma/bcma.ko"},
		{w545Proc{"cp", "/usr/bin/cp", ""}, "/lib/modules/5.15.0-194-generic/kernel/drivers/bcma/bcma.ko"},
		{w545Proc{"fwupd", "/usr/libexec/fwupd/fwupd", ""}, "/proc/modules"},
		{w545Proc{"aa-enabled", "/usr/sbin/aa-enabled", ""}, "/sys/module/apparmor/parameters/enabled"},
		{w545Proc{"systemd", "/usr/lib/systemd/systemd", ""}, "/sys/module/kernel/parameters/crash_kexec_post_notifiers"},
		{w545Proc{"systemd-udevd", "/usr/lib/systemd/systemd-udevd", ""}, "/lib/modules/5.15.0-194-generic/modules.softdep"},
	}
	for i, f := range forms {
		for _, op := range []uint8{0, 1} { // open, read
			fired := w81Fired(engine.Evaluate(w545Event(t, res, uint32(97000+i), f.p, f.path, op)))
			assert.Falsef(t, fired[w545Rule], "%s на %s %s с хоста", w545Rule, fileOpNames[op], f.path)
		}
	}
}

// Ветка A: тот же доступ из контейнера срабатывает (предмет правила).
func TestWave8_1_ModuleAccessContainerFires(t *testing.T) {
	engine, res := w545Engine(t)
	ctr := w545Proc{"cat", "/usr/bin/cat", "3f2a9c0d1e4b"}
	for i, path := range []string{"/proc/modules", "/proc/kallsyms", "/sys/module/overlay/parameters/x",
		"/lib/modules/5.15.0-194-generic/modules.dep"} {
		fired := w81Fired(engine.Evaluate(w545Event(t, res, uint32(97100+i), ctr, path, 0)))
		assert.Truef(t, fired[w545Rule], "%s из контейнера на open %s", w545Rule, path)
	}
	// Исключение по образу — только хостовое: dpkg внутри контейнера срабатывает.
	dpkgIn := w545Proc{"dpkg", "/usr/bin/dpkg", "3f2a9c0d1e4b"}
	fired := w81Fired(engine.Evaluate(w545Event(t, res, 97110, dpkgIn, "/lib/modules/x/kernel/evil.ko", w81OpRename)))
	assert.True(t, fired[w545Rule], "dpkg в контейнере не получает host-module-tooling")
}

// Ветка B: посадка модуля с хоста срабатывает; штатный инструмент — нет;
// копия инструмента вне его образа — срабатывает (спуф comm).
func TestWave8_1_ModuleAccessPlantBranch(t *testing.T) {
	engine, res := w545Engine(t)
	const opWrite uint8 = 2
	before := w81ExcCount(w545Rule, "host-module-tooling")
	for i, c := range []struct {
		p    w545Proc
		path string
		op   uint8
	}{
		{w545Proc{"dpkg", "/usr/bin/dpkg", ""}, "/lib/modules/5.15.0-198-generic/kernel/foo.ko.dpkg-new", opWrite},
		{w545Proc{"dpkg", "/usr/bin/dpkg", ""}, "/lib/modules/5.15.0-198-generic/kernel/foo.ko", w81OpRename},
		{w545Proc{"depmod", "/usr/bin/kmod", ""}, "/lib/modules/5.15.0-198-generic/modules.dep.bin", w81OpRename},
		{w545Proc{"depmod", "/usr/bin/kmod", ""}, "/lib/modules/5.15.0-198-generic/modules.dep.tmp", opWrite},
	} {
		fired := w81Fired(engine.Evaluate(w545Event(t, res, uint32(97200+i), c.p, c.path, c.op)))
		assert.Falsef(t, fired[w545Rule], "%s от %s на %s %s", w545Rule, c.p.exe, fileOpNames[c.op], c.path)
	}
	assert.Greater(t, w81ExcCount(w545Rule, "host-module-tooling"), before,
		"подавление обязано считаться в rule_exceptions_total{exception_name=host-module-tooling}")

	for i, c := range []struct {
		p   w545Proc
		op  uint8
		why string
	}{
		{w545Proc{"mv", "/usr/bin/mv", ""}, w81OpRename, "mv от root shell"},
		{w545Proc{"cp", "/usr/bin/cp", ""}, opWrite, "cp от root shell"},
		{w545Proc{"dpkg", "/tmp/dpkg", ""}, w81OpRename, "копия /tmp/dpkg (comm=dpkg)"},
		{w545Proc{"depmod", "/tmp/kmod", ""}, w81OpRename, "копия /tmp/kmod (comm=depmod)"},
	} {
		fired := w81Fired(engine.Evaluate(w545Event(t, res, uint32(97300+i), c.p,
			"/lib/modules/5.15.0-198-generic/extra/evil.ko", c.op)))
		assert.Truef(t, fired[w545Rule], "%s обязано сработать: %s", w545Rule, c.why)
	}

	// Удаление в /lib/modules — не посадка: правило молчит, а impact (op
	// называет) срабатывает, как в фазе M смока №543.
	fired := w81Fired(engine.Evaluate(w545Event(t, res, 97400, w545Proc{"rm", "/usr/bin/rm", ""},
		"/lib/modules/5.15.0-198-generic/extra/evil.ko", w81OpUnlink)))
	assert.False(t, fired[w545Rule], "unlink не входит в ветку посадки")
	assert.True(t, fired["impact_mass_file_deletion_critical"], "unlink в /lib/modules видит impact")
}
