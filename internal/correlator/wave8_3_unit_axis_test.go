package correlator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Долги 8.3, п. 8.3.2 и 8.3.3: ось юнита (proc.systemd_unit) для мягких
// правил, на которых образ мёртв (мс-процесс) или родовой.

const (
	w83CgApt   = 6001 // apt-daily.service
	w83CgUser  = 6002 // user.slice — резолвер system.slice не знает
	w83CgOther = 6003 // cron.service
	w83CgEsm   = 6004 // esm-cache.service
	w83Virt    = "systemd-detect-"
	w83HidElf  = "evasion_hidden_elf_in_tmp"
)

func w83Units() w81UnitResolver {
	return w81UnitResolver{w83CgApt: "apt-daily.service", w83CgOther: "cron.service", w83CgEsm: "esm-cache.service"}
}

// 8.3.2: четыре правила, каждое на своих путях detect-virt, под таймерным юнитом.
func TestW83_DetectVirtSoftRulesSuppressedByUnit(t *testing.T) {
	engine, res := w549EngineFrom(t, w549Rules(t))
	w81WithUnits(t, w83Units())
	for i, c := range []struct{ rule, path string }{
		{"mitre_vm_detect_dmi_read", "/sys/class/dmi/id/product_name"},
		{"mitre_vm_detect_dmi_read", "/sys/firmware/dmi/tables/DMI"},
		{"mitre_sandbox_detect_proc_read", "/proc/1/environ"},
		{"mitre_sandbox_detect_proc_read", "/proc/1/cgroup"},
		{"sigma_memory_proc_dump", "/proc/1/environ"},
		{"sigma_cpu_info_access", "/proc/cpuinfo"},
		{"sigma_cpu_info_access", "/proc/sys/kernel/osrelease"},
	} {
		before := w81ExcCount(c.rule, "node-timer-detect-virt")
		// образ пуст (гонка readlink) — ось только юнит
		ev := h5File(res, uint32(97000+i), w83Virt, "", c.path, 0, 0, w83CgApt, "")
		assert.Falsef(t, w81Fired(engine.Evaluate(ev))[c.rule], "%s на %s под apt-daily.service", c.rule, c.path)
		assert.Greaterf(t, w81ExcCount(c.rule, "node-timer-detect-virt"), before, "%s: подавление обязано считаться", c.rule)
	}
}

// Спуф и вне оси: правило срабатывает.
func TestW83_DetectVirtSoftRulesSpoofFires(t *testing.T) {
	engine, res := w549EngineFrom(t, w549Rules(t))
	w81WithUnits(t, w83Units())
	const oWronly = 1
	for i, c := range []struct {
		rule, path, comm, container, why string
		cg                               uint64
		flags                            int32
	}{
		{"mitre_vm_detect_dmi_read", "/sys/class/dmi/id/product_name", w83Virt, "", "чужой юнит", w83CgOther, 0},
		{"mitre_vm_detect_dmi_read", "/sys/class/dmi/id/product_name", w83Virt, "", "user.slice", w83CgUser, 0},
		{"mitre_vm_detect_dmi_read", "/sys/class/dmi/id/product_name", w83Virt, "", "юнит не определён", 0, 0},
		{"mitre_vm_detect_dmi_read", "/sys/class/dmi/id/product_name", w83Virt, w549Container, "контейнер", w83CgApt, 0},
		{"mitre_vm_detect_dmi_read", "/sys/class/dmi/id/product_name", w83Virt, "", "на запись", w83CgApt, oWronly},
		{"mitre_vm_detect_dmi_read", "/sys/class/dmi/id/product_name", "python3", "", "другой comm в том же юните", w83CgApt, 0},
		{"mitre_sandbox_detect_proc_read", "/proc/uptime", w83Virt, "", "чужой путь", w83CgApt, 0},
		{"mitre_sandbox_detect_proc_read", "/proc/1/environ", w83Virt, "", "user.slice", w83CgUser, 0},
		{"sigma_memory_proc_dump", "/proc/1/mem", w83Virt, "", "/proc/1/mem из того же юнита", w83CgApt, 0},
		{"sigma_memory_proc_dump", "/proc/4242/environ", w83Virt, "", "чужой environ", w83CgApt, 0},
		{"sigma_memory_proc_dump", "/proc/1/environ", "python3", "", "другой comm", w83CgApt, 0},
		{"sigma_memory_proc_dump", "/proc/1/environ", w83Virt, "", "чужой юнит", w83CgOther, 0},
		{"sigma_cpu_info_access", "/proc/meminfo", w83Virt, "", "чужой путь", w83CgApt, 0},
		{"sigma_cpu_info_access", "/proc/cpuinfo", w83Virt, "", "user.slice", w83CgUser, 0},
	} {
		ev := h5File(res, uint32(97100+i), c.comm, "", c.path, 0, c.flags, c.cg, c.container)
		assert.Truef(t, w81Fired(engine.Evaluate(ev))[c.rule], "%s обязано сработать: %s", c.rule, c.why)
	}
}

// Правила, получившие op в исключении, мутаций не видят (гард №549).
func TestW83_DetectVirtRulesIgnoreMutations(t *testing.T) {
	engine, res := w549EngineFrom(t, w549Rules(t))
	w81WithUnits(t, w83Units())
	for i, c := range []struct{ rule, path string }{
		{"mitre_sandbox_detect_proc_read", "/proc/1/cgroup"},
		{"sigma_memory_proc_dump", "/proc/1/environ"},
	} {
		for j, op := range w81MutationOps {
			ev := h5File(res, uint32(97300+10*i+j), "python3", "/usr/bin/python3.10", c.path, op, 0, 0, "")
			assert.Falsef(t, w81Fired(engine.Evaluate(ev))[c.rule], "%s на %s", c.rule, fileOpNames[op])
		}
	}
}

// 8.3.3: gpgv с неразрешённым exe и apt-key/cp/touch под apt-daily.
func TestW83_AptTmpVolumeSuppressedByUnit(t *testing.T) {
	engine, res := w549EngineFrom(t, w549Rules(t))
	w81WithUnits(t, w83Units())
	for i, c := range []struct{ exc, comm, path string }{
		{"apt-gpgv-tmp-unit", "gpgv", "/tmp/apt.sig.TS8yGp"},
		{"apt-gpgv-tmp-unit", "gpgv", "/tmp/apt.data.Lycdfa"},
		{"apt-key-gpghome-unit", "apt-key", "/tmp/apt-key-gpghome.Ab3dEf9hIj/pubring.gpg"},
		{"apt-key-gpghome-unit", "cp", "/tmp/apt-key-gpghome.Ab3dEf9hIj/pubring.orig.gpg"},
		{"apt-key-gpghome-unit", "touch", "/tmp/apt-key-gpghome.Ab3dEf9hIj/trustdb.gpg"},
	} {
		before := w81ExcCount(w83HidElf, c.exc)
		ev := h5File(res, uint32(97500+i), c.comm, "", c.path, w549OpWrite, 0, w83CgApt, "")
		assert.Falsef(t, w81Fired(engine.Evaluate(ev))[w83HidElf], "%s %s под apt-daily.service", c.comm, c.path)
		assert.Greaterf(t, w81ExcCount(w83HidElf, c.exc), before, "%s: подавление обязано считаться", c.exc)
	}
}

// Те же формы под esm-cache.service / apt-news.service (хук apt-get update).
func TestW83_AptTmpVolumeSuppressedUnderEsmCache(t *testing.T) {
	engine, res := w549EngineFrom(t, w549Rules(t))
	w81WithUnits(t, w83Units())
	for i, c := range []struct{ comm, path string }{
		{"apt-key", "/tmp/apt-key-gpghome.Ab3dEf9hIj/gpg.1.sh"},
		{"cp", "/tmp/apt-key-gpghome.Ab3dEf9hIj/pubring.orig.gpg"},
		{"gpgv", "/tmp/apt.conf.JEwQyP"},
	} {
		ev := h5File(res, uint32(97550+i), c.comm, "", c.path, w549OpWrite, 0, w83CgEsm, "")
		assert.Falsef(t, w81Fired(engine.Evaluate(ev))[w83HidElf], "%s %s под esm-cache.service", c.comm, c.path)
	}
}

func TestW83_AptTmpVolumeSpoofFires(t *testing.T) {
	engine, res := w549EngineFrom(t, w549Rules(t))
	w81WithUnits(t, w83Units())
	const key = "/tmp/apt-key-gpghome.Ab3dEf9hIj/pubring.gpg"
	for i, c := range []struct {
		comm, path, container, why string
		cg                         uint64
	}{
		{"cp", key, "", "чужой юнит", w83CgOther},
		{"cp", key, "", "user.slice (systemd-run --user --unit=apt-daily.service)", w83CgUser},
		{"cp", key, "", "юнит не определён — обход одним mkdir", 0},
		{"cp", key, w549Container, "контейнер", w83CgApt},
		{"cp", "/tmp/apt-key-gpghome.short/x", "", "каталог не той формы", w83CgApt},
		{"cp", "/tmp/apt-key-gpghome.Ab3dEf9hIj/sub/x", "", "вложенный путь", w83CgApt},
		{"cp", "/tmp/payload", "", "посторонний объект из apt-daily", w83CgApt},
		{"curl", key, "", "посторонний comm в том же юните", w83CgApt},
		{"gpgv", "/tmp/apt.sig.TS8yGp.elf", "", "объект не той формы", w83CgApt},
		{"gpgv", "/tmp/apt.sig.TS8yGp", "", "gpgv без юнита", 0},
	} {
		ev := h5File(res, uint32(97600+i), c.comm, "", c.path, w549OpWrite, 0, c.cg, c.container)
		assert.Truef(t, w81Fired(engine.Evaluate(ev))[w83HidElf], "обязано сработать: %s", c.why)
	}
}

// 8.3.1: исключения по родителю нет — остановка из prerm под dpkg срабатывает
// при любом родителе (в том числе perl и точный путь deb-systemd-invoke).
func TestW83_StopFiresUnderAnyParent(t *testing.T) {
	engine, res := w549EngineFrom(t, w549Rules(t))
	for i, parent := range []string{"/usr/bin/deb-systemd-invoke", "/usr/bin/perl", "/usr/bin/bash", ""} {
		pid, ppid := uint32(98100+2*i), uint32(98101+2*i)
		ev := h4Syscall(res, pid, "systemctl", "/usr/bin/systemctl", 59, "systemctl stop irqbalance.service", 0, 0)
		ev.PPID = ppid
		res[ppid] = parent
		assert.Truef(t, w81Fired(engine.Evaluate(ev))[h4SystemctlRule], "родитель %q", parent)
	}
}
