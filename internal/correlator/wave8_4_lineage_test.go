package correlator

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/internal/procinfo"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 8.4.1/8.4.2 на таблице процессов ядра (8.5, P1): поля proc.lineage / proc.lineage_exe_paths и
// исключение dpkg-maintainer-script-stop правила impact_systemd_service_disabled.

type lineageFake struct {
	anc []procinfo.Record
	out procinfo.Outcome
	ok  bool
}

func (l *lineageFake) AncestorChain(uint32) ([]procinfo.Record, procinfo.Outcome, bool) {
	return l.anc, l.out, l.ok
}

func withLineage(t *testing.T, anc []procinfo.Record, ok bool) {
	t.Helper()
	prev, _ := lineageResolver.Load().(lineageResolverHolder)
	SetLineageChainResolver(&lineageFake{anc: anc, out: procinfo.OutcomeResolved, ok: ok})
	t.Cleanup(func() { SetLineageChainResolver(prev.r) })
}

// withImages подменяет кэш образов: путь образа по паре (dev, ino), без файловой системы.
func withImages(t *testing.T, paths map[uint64]string) {
	t.Helper()
	prev := lineageImages
	lineageImages = procinfo.NewImageCacheWith(64,
		func(string) (uint32, uint64, bool) { return 0, 0, false },
		func(string) (string, error) { return "", errors.New("no /proc") })
	for ino, p := range paths {
		lineageImages.Put(1, ino, p)
	}
	t.Cleanup(func() { lineageImages = prev })
}

// звено цепочки: образ задаётся через inode карты withImages, exec-filename — явно
func hop(ino uint64, filename string) procinfo.Record {
	return procinfo.Record{PID: uint32(ino), ExeDev: 1, ExeIno: ino, Filename: filename}
}

const (
	inoDpkg = 11
	inoDash = 12
	inoPerl = 13
	inoBash = 14
	inoApt  = 15
)

func stdImages() map[uint64]string {
	return map[uint64]string{inoDpkg: "/usr/bin/dpkg", inoDash: "/usr/bin/dash", inoPerl: "/usr/bin/perl", inoBash: "/usr/bin/bash", inoApt: "/usr/bin/apt-get"}
}

// настоящая цепочка `dpkg -r pkg`: apt-get → dpkg → prerm (dash) → deb-systemd-invoke (perl) → systemctl
func legitChain() []procinfo.Record {
	return []procinfo.Record{
		hop(inoApt, "/usr/bin/apt-get"),
		hop(inoDpkg, "/usr/bin/dpkg"),
		hop(inoDash, "/var/lib/dpkg/info/mypkg.prerm"),
		hop(inoPerl, "/usr/bin/deb-systemd-invoke"),
	}
}

func TestW84_Lineage_FieldFormatAndProjection(t *testing.T) {
	withImages(t, stdImages())
	withLineage(t, legitChain(), true)
	full := resolveLineageField(4242, lineageFieldFull)
	assert.Equal(t, strings.Join([]string{
		"/usr/bin/apt-get\t/usr/bin/apt-get",
		"/usr/bin/dpkg\t/usr/bin/dpkg",
		"/usr/bin/dash\t/var/lib/dpkg/info/mypkg.prerm",
		"/usr/bin/perl\t/usr/bin/deb-systemd-invoke",
	}, "\n"), full, "звено = образ<TAB>exec-filename, от корня к родителю; образ скрипта — интерпретатор")
	assert.Equal(t, "/usr/bin/apt-get\n/usr/bin/dpkg\n/usr/bin/dash\n/usr/bin/perl", resolveLineageField(4242, lineageFieldImages))
}

func TestW84_Lineage_UnresolvedAndNoTable(t *testing.T) {
	withImages(t, nil)
	withLineage(t, []procinfo.Record{{PID: 5, ExeIno: 0}}, true)
	assert.Equal(t, "?\t?", resolveLineageField(1, lineageFieldFull), "нет образа и нет exec-filename — «?»")
	withLineage(t, nil, true)
	assert.Equal(t, "", resolveLineageField(1, lineageFieldFull), "нет предков под init — пусто")
	withLineage(t, nil, false)
	assert.Equal(t, "", resolveLineageField(1, lineageFieldFull), "нет таблицы — пусто")
	SetLineageChainResolver(nil)
	assert.Equal(t, "", resolveLineageField(1, lineageFieldFull), "нет резолвера — пусто")
}

// Имя файла — данные атакующего: «\n» и «\t» в нём не должны выдавать себя за соседнее звено.
func TestW84_Lineage_ControlCharsInFilenameCannotForgeAHop(t *testing.T) {
	withImages(t, stdImages())
	evil := "/tmp/x\n/usr/bin/dpkg\t/var/lib/dpkg/info/a.prerm"
	withLineage(t, []procinfo.Record{hop(inoBash, evil)}, true)
	v := resolveLineageField(1, lineageFieldFull)
	assert.NotContains(t, v, "\n", "перевод строки нейтрализован")
	assert.Equal(t, 1, strings.Count(v, "\t"), "ровно один разделитель образ/filename")
}

// ── исключение 8.4.2 на настоящем наборе правил ──────────────────────────────────────────────

const stopRule = "impact_systemd_service_disabled"

func stopEvent(res w81CommExeResolver, args string) types.Event {
	return h4Syscall(res, 50001, "systemctl", "/usr/bin/systemctl", 59, args, 0, 0)
}

func firesWith(t *testing.T, chain []procinfo.Record, ok bool, args string) bool {
	t.Helper()
	withImages(t, stdImages())
	withLineage(t, chain, ok)
	engine, res := w549EngineFrom(t, w549Rules(t))
	return w81Fired(engine.Evaluate(stopEvent(res, args)))[stopRule]
}

// Позитив: dpkg -r → prerm → deb-systemd-invoke stop. Алерта НЕТ; исключение посчитано.
func TestW84_Exception_LegitDpkgMaintainerStopIsSilent(t *testing.T) {
	before := w81ExcCount(stopRule, "dpkg-maintainer-script-stop")
	assert.False(t, firesWith(t, legitChain(), true, "systemctl stop mypkg.service"))
	assert.Equal(t, before+1, w81ExcCount(stopRule, "dpkg-maintainer-script-stop"))
	for _, a := range []string{
		"systemctl --no-block stop mypkg.service",
		"/bin/systemctl stop mypkg.service mypkg.socket",
		"systemctl -q stop mypkg",
	} {
		assert.Falsef(t, firesWith(t, legitChain(), true, a), "%q", a)
	}
	for _, s := range []string{"prerm", "postrm", "preinst", "postinst"} {
		ch := legitChain()
		ch[2].Filename = "/var/lib/dpkg/info/libc6:amd64." + s
		assert.Falsef(t, firesWith(t, ch, true, "systemctl stop x"), "maintainer-скрипт .%s", s)
	}
}

// СПУФЫ — алерт ЕСТЬ.
func TestW84_Exception_SpoofsStillFire(t *testing.T) {
	// 1. dpkg --pre-invoke='systemctl stop X': dpkg → sh -c → systemctl; скрипта нет
	preInvoke := []procinfo.Record{hop(inoApt, "/usr/bin/apt-get"), hop(inoDpkg, "/usr/bin/dpkg"), hop(inoDash, "/bin/sh")}
	assert.True(t, firesWith(t, preInvoke, true, "systemctl stop auditd"), "--pre-invoke")
	// 2. копия perl-скрипта deb-systemd-invoke вне /usr/bin под dpkg: ни одного звена с maintainer-путём
	copyPerl := []procinfo.Record{hop(inoDpkg, "/usr/bin/dpkg"), hop(inoDash, "/bin/sh"), hop(inoPerl, "/tmp/deb-systemd-invoke")}
	assert.True(t, firesWith(t, copyPerl, true, "systemctl stop auditd"), "копия скрипта вне /usr/bin")
	// 3. скрипт *.prerm вне /var/lib/dpkg/info
	outside := legitChain()
	outside[2].Filename = "/tmp/x.prerm"
	assert.True(t, firesWith(t, outside, true, "systemctl stop auditd"), "скрипт вне /var/lib/dpkg/info")
	outside[2].Filename = "/var/lib/dpkg/info/../../../../tmp/x.prerm" // путь вверх: нет ни /usr/bin/dpkg-родителя... регэксп требует [^/]+
	assert.True(t, firesWith(t, outside, true, "systemctl stop auditd"), "обход через ..")
	outside[2].Filename = "/var/lib/dpkg/info/sub/x.prerm"
	assert.True(t, firesWith(t, outside, true, "systemctl stop auditd"), "подкаталог info")
	outside[2].Filename = "/var/lib/dpkg/info/x.prerm.sh"
	assert.True(t, firesWith(t, outside, true, "systemctl stop auditd"), "суффикс после prerm")
	// 4. exec -a dpkg: процесс назвался dpkg, но образ — bash; comm и argv[0] образа не меняют
	execA := []procinfo.Record{hop(inoBash, "/usr/bin/bash"), hop(inoDash, "/var/lib/dpkg/info/x.prerm"), hop(inoPerl, "/usr/bin/deb-systemd-invoke")}
	assert.True(t, firesWith(t, execA, true, "systemctl stop auditd"), "exec -a dpkg: образ не dpkg")
	// 5. exec -a самому systemctl: argv[0] не сходится с comm — коллектор обнуляет proc.args
	assert.True(t, firesWith(t, legitChain(), true, ""), "пустой proc.args (exec -a systemctl)")
	// 6. порядок: maintainer-скрипт ВЫШЕ dpkg, а не между dpkg и systemctl
	reversed := []procinfo.Record{hop(inoDash, "/var/lib/dpkg/info/x.postinst"), hop(inoDpkg, "/usr/bin/dpkg"), hop(inoPerl, "/usr/bin/perl")}
	assert.True(t, firesWith(t, reversed, true, "systemctl stop auditd"), "скрипт выше dpkg")
	// 7. разрыв цепочки: dpkg выше разрыва поле не отдаёт (в значении остаётся только нижняя часть)
	broken := []procinfo.Record{hop(inoDash, "/var/lib/dpkg/info/x.prerm"), hop(inoPerl, "/usr/bin/deb-systemd-invoke")}
	assert.True(t, firesWith(t, broken, true, "systemctl stop auditd"), "разрыв: dpkg не виден")
	// 8. нет таблицы процессов — исключение не применяется
	assert.True(t, firesWith(t, legitChain(), false, "systemctl stop auditd"), "нет таблицы")
	// 9. не stop: другие глаголы остаются уликой даже под dpkg
	for _, a := range []string{"systemctl disable auditd", "systemctl mask auditd", "systemctl --now disable auditd", "systemctl kill auditd", "systemctl isolate rescue.target"} {
		assert.Truef(t, firesWith(t, legitChain(), true, a), "глагол %q под dpkg", a)
	}
	// 10. подделка звена через перевод строки в имени файла
	forged := []procinfo.Record{hop(inoBash, "/tmp/x\n/usr/bin/dpkg\t/usr/bin/dpkg\n/usr/bin/dash\t/var/lib/dpkg/info/a.prerm")}
	assert.True(t, firesWith(t, forged, true, "systemctl stop auditd"), "подделка звена переводом строки")
	// 11. не systemctl (comm service): исключение — только для systemctl
	withImages(t, stdImages())
	withLineage(t, legitChain(), true)
	engine, res := w549EngineFrom(t, w549Rules(t))
	ev := h4Syscall(res, 50002, "service", "/usr/sbin/service", 59, "systemctl stop auditd", 0, 0)
	assert.True(t, w81Fired(engine.Evaluate(ev))[stopRule], "comm service с argv, похожим на systemctl stop, не покрыт исключением")
}

// Образ предка берётся по inode, а не по тому, как процесс назвался: звено с «поддельным» именем
// образа, которого кэш не знает, не сходит за dpkg.
func TestW84_Exception_UnknownImageIsNotDpkg(t *testing.T) {
	withImages(t, nil) // кэш пуст, stat/readlink недоступны — образ «?»
	withLineage(t, legitChain(), true)
	engine, res := w549EngineFrom(t, w549Rules(t))
	assert.True(t, w81Fired(engine.Evaluate(stopEvent(res, "systemctl stop x")))[stopRule],
		"образы не разрешились — исключение не применяется (отказ в шум, не в тишину)")
}

func TestW84_FieldsAreAcceptedByTheLoaderAndUnknownOnesAreNot(t *testing.T) {
	for _, f := range []string{"proc.lineage", "proc.lineage_exe_paths", "lineage", "lineage_exe_paths"} {
		rules := []Rule{{ID: "t", Name: "t", EventType: types.EventSyscall, Severity: "warning", Action: ActionAlert,
			Condition: RuleCondition{Field: f, Op: OpContains, Values: []string{"x"}}}}
		require.NoErrorf(t, ValidateFull(rules), "поле %s", f)
	}
	rules := []Rule{{ID: "t", Name: "t", EventType: types.EventSyscall, Severity: "warning", Action: ActionAlert,
		Condition: RuleCondition{Field: "proc.lineage_typo", Op: OpContains, Values: []string{"x"}}}}
	require.Error(t, ValidateFull(rules), "неизвестное поле отвергается: поле и бинарь едут вместе")
}
