package correlator

import (
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 8.1, №543 — офлайн-реплей ночи H (server-logs/collect-8.1-H, окно
// 06:41–06:50 UTC 07.10.2026, unattended-upgrades ставил ядро 5.15.0-198 и
// снимал 5.15.0-191). Формы событий взяты из стора ночи (alerts-end.json:
// comm, путь, ветвь process_tree) и из журнала агента (noise-diag:
// example_exe_path). Op в сторе не хранится, поэтому каждая форма подаётся
// ВСЕМИ мутациями, которые этот инструмент делает по своей семантике: dpkg —
// unlink/rename/truncate/rmdir; rm — unlink/rmdir; depmod и ldconfig — rename
// временного файла на место; unattended-upgr (libapt) — unlink/rename дампа;
// cp/modinfo/modprobe/find только читают и пишут — мутаций у них нет, их
// формы здесь ничего не подают (их open-шум — №545, вне 8.1). Подача всех
// четырёх op каждой форме (первая версия теста) поднимала impact на «unlink
// depmod» и integrity_lib_replaced на «rename cp» — действия, которых эти
// инструменты не совершают.
//
// Ожидание — ноль алертов на мутациях по ВСЕМУ поставляемому набору, кроме
// предъявленного остатка w81NightHResidual. Движок молчит до дедупа и
// лимитера, поэтому ноль здесь — ноль на всех трёх слоях.

type w81NightHForm struct {
	comm, parentComm, exe, path string
}

// w81ToolOps — мутации, которые инструмент формы совершает по своей семантике.
func w81ToolOps(comm string) []uint8 {
	switch comm {
	case "dpkg":
		return w81MutationOps
	case "rm":
		return []uint8{w81OpUnlink, w81OpRmdir}
	case "depmod", "ldconfig.real":
		return []uint8{w81OpRename}
	case "unattended-upgr":
		return []uint8{w81OpUnlink, w81OpRename}
	}
	return nil
}

var w81NightHForms = []w81NightHForm{
	// dpkg сам: распаковка и снятие ядра, .dpkg-new/.dpkg-tmp, финальные имена.
	{"dpkg", "unattended-upgr", "/usr/bin/dpkg", "/lib/modules/5.15.0-198-generic/kernel/drivers/net/wireless/intel/iwlwifi/dvm/iwldvm.ko.dpkg-new"},
	{"dpkg", "unattended-upgr", "/usr/bin/dpkg", "/lib/modules/5.15.0-198-generic/kernel/drivers/net/wireless/intel/iwlwifi/dvm/iwldvm.ko"},
	{"dpkg", "unattended-upgr", "/usr/bin/dpkg", "/lib/modules/5.15.0-191-generic/build.dpkg-tmp"},
	{"dpkg", "unattended-upgr", "/usr/bin/dpkg", "/lib/modules/5.15.0-191-generic/kernel/sound/xen/snd_xen_front.ko.dpkg-tmp"},
	{"dpkg", "unattended-upgr", "/usr/bin/dpkg", "/lib/modules/5.15.0-191-generic/kernel/sound/xen"},
	{"dpkg", "unattended-upgr", "/usr/bin/dpkg", "/lib/modules/5.15.0-191-generic/vdso/.build-id/b1/6e02fc0f2fba7f067d6fd07e7fd6f1e74225fa.debug.dpkg-tmp"},
	{"dpkg", "unattended-upgr", "/usr/bin/dpkg", "/lib/modules/5.15.0-198-generic/build.dpkg-new"},
	{"dpkg", "unattended-upgr", "/usr/bin/dpkg", "/boot/System.map-5.15.0-198-generic.dpkg-new"},
	{"dpkg", "unattended-upgr", "/usr/bin/dpkg", "/boot/System.map-5.15.0-198-generic"},
	{"dpkg", "unattended-upgr", "/usr/bin/dpkg", "/boot/vmlinuz-5.15.0-191-generic"},
	{"dpkg", "unattended-upgr", "/usr/bin/dpkg", "/usr/bin/acpidbg.dpkg-new"},
	{"dpkg", "unattended-upgr", "/usr/bin/dpkg", "/usr/bin/acpidbg"},
	{"dpkg", "unattended-upgr", "/usr/bin/dpkg", "/usr/src/linux-headers-5.15.0-191/include/linux"},
	{"dpkg", "unattended-upgr", "/usr/bin/dpkg", "/var/lib/dpkg/info/linux-image-5.15.0-191-generic.list"},
	{"dpkg", "unattended-upgr", "/usr/bin/dpkg", "/etc/kernel/postinst.d/zz-update-grub.dpkg-new"},
	// Потомки: maintainer-скрипты, mkinitramfs, depmod, grub-mkconfig.
	{"rm", "linux-image-5.1", "/usr/bin/rm", "/lib/modules/5.15.0-198-generic/.fresh-install"},
	{"rm", "linux-image-5.1", "/usr/bin/rm", "/lib/modules/5.15.0-191-generic/.fresh-install"},
	{"rm", "grub-mkconfig", "/usr/bin/rm", "/boot/grub/grub.cfg.new"},
	{"rm", "update-initramf", "/usr/bin/rm", "/boot/initrd.img-5.15.0-194-generic.dpkg-bak"},
	{"depmod", "linux-image-5.1", "/usr/bin/kmod", "/lib/modules/5.15.0-198-generic/modules.softdep"},
	{"depmod", "linux-modules-5", "/usr/bin/kmod", "/lib/modules/5.15.0-191-generic/modules.softdep"},
	{"depmod", "linux-modules-e", "/usr/bin/kmod", "/lib/modules/5.15.0-198-generic/modules.dep.bin"},
	{"cp", "mkinitramfs", "/usr/bin/cp", "/lib/modules/5.15.0-194-generic/modules.builtin"},
	{"cp", "mkinitramfs", "/usr/bin/cp", "/var/tmp/mkinitramfs_UqU33d//usr/lib/modules/5.15.0-194-generic/kernel/drivers/bcma/bcma.ko"},
	{"modinfo", "mkinitramfs", "/usr/bin/kmod", "/lib/modules/5.15.0-194-generic/modules.softdep"},
	{"modprobe", "mkinitramfs", "/usr/bin/kmod", "/lib/modules/5.15.0-198-generic/modules.softdep"},
	{"find", "mkinitramfs", "/usr/bin/find", "/lib/modules/5.15.0-194-generic/kernel/drivers/usb/host"},
	{"rm", "mkinitramfs", "/usr/bin/rm", "/var/tmp/mkinitramfs_UqU33d"},
	{"cp", "plymouth", "/usr/bin/cp", "/usr/lib/x86_64-linux-gnu/plymouth/renderers/drm.so"},
	{"ldconfig.real", "libc-bin.postin", "/usr/sbin/ldconfig.real", "/etc/ld.so.cache"},
	// unattended-upgrades (python3.10): дамп планировщика libapt.
	{"unattended-upgr", "unattended-upgr", "/usr/bin/python3.10", "/var/log/apt/eipp.log.xz"},
}

// w81NightHResidual — предъявленный остаток: удаление старого initrd под
// update-initramfs при снятии ядра. Это сам предмет impact_mass_file_deletion
// (система без initrd не загрузится), исключению не подлежит; один алерт на
// снятие ядра. Пусто — значит остаток исчез, и строку надо убрать.
var w81NightHResidual = []w81NightHForm{
	{"rm", "update-initramf", "/usr/bin/rm", "/boot/initrd.img-5.15.0-191-generic"},
}

type w81CommExeResolver map[uint32]string

func (r w81CommExeResolver) ResolveExePath(pid uint32) string { return r[pid] }

func w81ReplayForms(t *testing.T, engine *RuleEngine, forms []w81NightHForm) map[string][]string {
	t.Helper()
	res := w81CommExeResolver{}
	prev, _ := exeResolver.Load().(exeResolverHolder)
	SetExePathResolver(res)
	t.Cleanup(func() { SetExePathResolver(prev.r) })

	fired := map[string][]string{}
	for i, f := range forms {
		pid, ppid := uint32(96000+2*i), uint32(96001+2*i)
		res[pid] = f.exe
		res[ppid] = "/usr/bin/dash" // родитель — скрипт/обёртка; у dpkg — python unattended-upgr
		if f.comm == "dpkg" {
			res[ppid] = "/usr/bin/python3.10"
		}
		for _, op := range w81ToolOps(f.comm) {
			e := w81FileEventPPID(pid, ppid, f.comm, f.path, op)
			copy(e.ParentComm[:], f.parentComm)
			for _, a := range engine.Evaluate(e) {
				fired[a.RuleID] = append(fired[a.RuleID], fileOpNames[op]+" "+f.comm+" "+f.path)
			}
		}
	}
	return fired
}

func TestWave8_1_NightHReplay_MutationsSilent(t *testing.T) {
	engine := w81Engine(t)
	fired := w81ReplayForms(t, engine, w81NightHForms)
	var ids []string
	for id, hits := range fired {
		ids = append(ids, id)
		t.Logf("%s: %d — %s", id, len(hits), strings.Join(hits[:min(3, len(hits))], "; "))
	}
	sort.Strings(ids)
	assert.Empty(t, ids, "мутации дерева обновления ночи H подняли правила")
}

func TestWave8_1_NightHReplay_ResidualPresented(t *testing.T) {
	engine := w81Engine(t)
	fired := w81ReplayForms(t, engine, w81NightHResidual)
	assert.Equal(t, []string{"impact_mass_file_deletion_critical"}, w81SortedKeys(fired),
		"остаток ночи H изменился: обновить w81NightHResidual и plan.md (№543)")
}

// До починки (флаг снят у всех, исключений нет) реплей обязан краснеть —
// иначе формы не воспроизводят ночь H и ноль выше ничего не доказывает.
func TestWave8_1_NightHReplay_ReproducesRegressionWithoutFix(t *testing.T) {
	rules, err := LoadRulesFromDir("../../rules")
	if err != nil {
		t.Fatal(err)
	}
	for i := range rules {
		var keep []RuleException
		for _, x := range rules[i].Exceptions {
			switch x.Name {
			// host-module-tooling — №545: после сужения container_escape_module_access
			// назвал op (ветка посадки модуля), и снятый флаг его больше не
			// раскрывает; ночь H он воспроизводит без этого исключения.
			case "package-manager", "apt-planner-dump", "package-transient-artifact", "host-module-tooling":
				continue
			}
			keep = append(keep, x)
		}
		rules[i].Exceptions = keep
	}
	engine := NewRuleEngine(rules)
	ft := engine.byType[types.EventFileAccess]
	for i := range ft {
		ft[i].legacyOpsOnly = false
	}
	fired := w81ReplayForms(t, engine, w81NightHForms)
	for _, id := range []string{"container_escape_module_access", "impact_mass_file_deletion_critical",
		"evasion_log_clear", "defense_evasion_journald_log_clear", "ransomware_log_wipe"} {
		assert.NotEmptyf(t, fired[id], "%s обязано сработать на формах ночи H без починки", id)
	}
	t.Logf("без починки сработало правил: %d (%v)", len(fired), w81SortedKeys(fired))
}

func w81SortedKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
