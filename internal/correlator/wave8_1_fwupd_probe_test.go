package correlator

import (
	"regexp"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// №549 (09.10.2026, решение владельца 08.10 — вариант (б)): аппаратная
// разведка демона fwupd по таймеру fwupd-refresh поднимала attack-инцидент
// (score 56, замер w549-price; класс 23:02 ночи H2). Семь read-only правил
// получили исключение fwupd-hardware-probe: хост, op open/read, флаги open с
// режимом O_RDONLY, точный образ последним. Формы — из стора замера: демон
// fwupd на каждом из семи правил, fwupdmgr только на sigma_kernel_version_read.

const (
	w549Exc       = "fwupd-hardware-probe"
	w549Fwupd     = "/usr/libexec/fwupd/fwupd"
	w549Fwupdmgr  = "/usr/bin/fwupdmgr"
	w549OCloexec  = 0o2000000 // O_CLOEXEC
	w549ORdwr     = 2
	w549OWronly   = 1
	w549OpRead    = 1
	w549OpWrite   = 2
	w549OpChmod   = 3
	w549FlagsRx   = `^([0-9]*[02468][048]|[0-9]*[13579][26]|[048])$`
	w549Container = "3f2a9c0d1e4b"
)

// w549Forms — правило и путь, на котором его поднимал демон fwupd.
var w549Forms = []struct{ rule, path string }{
	{"container_escape_kmem_access", "/dev/mem"},
	{"sigma_dev_mem_access", "/dev/mem"},
	{"rootkit_kcore_access", "/proc/kcore"},
	{"rootkit_proc_modules_read", "/proc/modules"},
	{"mitre_vm_detect_dmi_read", "/sys/class/dmi/id/product_uuid"},
	{"sigma_kernel_version_read", "/proc/version"},
	{"sigma_cpu_info_access", "/proc/cpuinfo"},
}

func w549Event(res w81CommExeResolver, pid uint32, comm, exe, path string, op uint8, flags int32, container string) types.Event {
	res[pid] = exe
	e := w81FileEvent(pid, comm, path, op)
	e.File.Flags = flags
	if container != "" {
		e.Enrichment = &types.EnrichmentInfo{ContainerID: container}
	}
	return e
}

func w549EngineFrom(t *testing.T, rules []Rule) (*RuleEngine, w81CommExeResolver) {
	t.Helper()
	res := w81CommExeResolver{}
	prev, _ := exeResolver.Load().(exeResolverHolder)
	SetExePathResolver(res)
	t.Cleanup(func() { SetExePathResolver(prev.r) })
	return NewRuleEngine(rules), res
}

func w549Rules(t *testing.T) []Rule {
	t.Helper()
	rules, err := LoadRulesFromDir("../../rules")
	require.NoError(t, err)
	return rules
}

// Чтение демона fwupd с хоста подавлено и считается в rule_exceptions_total.
func TestW549_FwupdProbeSuppressed(t *testing.T) {
	engine, res := w549EngineFrom(t, w549Rules(t))
	for i, f := range w549Forms {
		before := w81ExcCount(f.rule, w549Exc)
		for j, c := range []struct {
			op    uint8
			flags int32
		}{{0, 0}, {0, w549OCloexec}, {0, 0o100000 | w549OCloexec}, {w549OpRead, 0}} {
			ev := w549Event(res, uint32(98000+10*i+j), "fwupd", w549Fwupd, f.path, c.op, c.flags, "")
			fired := w81Fired(engine.Evaluate(ev))
			assert.Falsef(t, fired[f.rule], "%s на %s %s (flags %#o) от %s", f.rule, fileOpNames[c.op], f.path, c.flags, w549Fwupd)
		}
		assert.Greaterf(t, w81ExcCount(f.rule, w549Exc), before,
			"подавление %s обязано считаться в rule_exceptions_total{exception_name=%s}", f.rule, w549Exc)
	}
	for i, p := range []string{"/proc/version", "/etc/os-release"} {
		ev := w549Event(res, uint32(98100+i), "fwupdmgr", w549Fwupdmgr, p, 0, w549OCloexec, "")
		assert.Falsef(t, w81Fired(engine.Evaluate(ev))["sigma_kernel_version_read"], "fwupdmgr на %s", p)
	}
}

// Спуф: копия под именем fwupd вне образа срабатывает; fwupdmgr получает
// исключение только там, где замер его показал.
func TestW549_FwupdProbeSpoofFires(t *testing.T) {
	engine, res := w549EngineFrom(t, w549Rules(t))
	for i, f := range w549Forms {
		for j, exe := range []string{"/tmp/fwupd", "/var/tmp/fwupd", "/usr/bin/cat", ""} {
			ev := w549Event(res, uint32(98200+10*i+j), "fwupd", exe, f.path, 0, 0, "")
			assert.Truef(t, w81Fired(engine.Evaluate(ev))[f.rule], "%s обязано сработать: comm=fwupd, образ %q", f.rule, exe)
		}
		if f.rule == "sigma_kernel_version_read" {
			continue
		}
		ev := w549Event(res, uint32(98290+i), "fwupdmgr", w549Fwupdmgr, f.path, 0, 0, "")
		assert.Truef(t, w81Fired(engine.Evaluate(ev))[f.rule], "%s: fwupdmgr исключения не получает", f.rule)
	}
}

// Запись и открытие на запись тем же образом — срабатывают, как и из контейнера.
func TestW549_FwupdProbeWriteAndContainerFire(t *testing.T) {
	engine, res := w549EngineFrom(t, w549Rules(t))
	for i, f := range w549Forms {
		for j, c := range []struct {
			op    uint8
			flags int32
			why   string
		}{
			{0, w549ORdwr | w549OCloexec, "open O_RDWR"},
			{0, w549OWronly, "open O_WRONLY"},
			{w549OpWrite, 0, "write"},
			{w549OpChmod, 0, "chmod"},
		} {
			ev := w549Event(res, uint32(98300+10*i+j), "fwupd", w549Fwupd, f.path, c.op, c.flags, "")
			assert.Truef(t, w81Fired(engine.Evaluate(ev))[f.rule], "%s обязано сработать: %s от %s", f.rule, c.why, w549Fwupd)
		}
		ev := w549Event(res, uint32(98390+i), "fwupd", w549Fwupd, f.path, 0, 0, w549Container)
		assert.Truef(t, w81Fired(engine.Evaluate(ev))[f.rule], "%s: образ fwupd в контейнере исключения не получает", f.rule)
	}
}

// Явный legacy-набор op сохраняет прежнюю семантику: мутаций правила не видят.
func TestW549_FwupdRulesIgnoreMutations(t *testing.T) {
	engine, res := w549EngineFrom(t, w549Rules(t))
	for i, f := range w549Forms {
		for j, op := range w81MutationOps {
			ev := w549Event(res, uint32(98400+10*i+j), "bash", "/usr/bin/bash", f.path, op, 0, "")
			assert.Falsef(t, w81Fired(engine.Evaluate(ev))[f.rule], "%s на %s", f.rule, fileOpNames[op])
		}
	}
}

// Регулярка режима доступа ≡ flags & O_ACCMODE == O_RDONLY.
func TestW549_FlagsRegexIsRdonly(t *testing.T) {
	rx := regexp.MustCompile(w549FlagsRx)
	for _, hi := range []int{0, 0o100000, w549OCloexec, w549OCloexec | 0o100000 | 0o4000, 0o200000} {
		for n := 0; n < 512; n++ {
			v := hi | n
			assert.Equalf(t, v&3 == 0, rx.MatchString(strconv.Itoa(v)), "flags %d (%#o)", v, v)
		}
	}
	assert.False(t, rx.MatchString("-4"), "отрицательные флаги не совпадают — отказ открытый")
	assert.False(t, rx.MatchString(""), "пустые флаги не совпадают")
	// Регулярка в YAML — та же строка, что здесь.
	n := 0
	for _, r := range w549Rules(t) {
		for _, ex := range r.Exceptions {
			if ex.Name != w549Exc || ex.ConditionGroup == nil {
				continue
			}
			n++
			for _, c := range ex.ConditionGroup.Conditions {
				if normaliseFieldName(c.Field) == "flags" {
					assert.Equalf(t, []string{w549FlagsRx}, c.Values, "%s: регулярка флагов", r.ID)
				}
			}
			last := ex.ConditionGroup.Conditions[len(ex.ConditionGroup.Conditions)-1]
			assert.Equalf(t, "proc.exe_path", last.Field, "%s: exe_path обязан стоять последним", r.ID)
			assert.Equalf(t, OpIn, last.Op, "%s: образ — точный путь (op: in)", r.ID)
		}
	}
	assert.Equal(t, len(w549Forms), n, "исключение %s обязано стоять ровно на семи правилах", w549Exc)
	for _, r := range w549Rules(t) {
		for _, ex := range r.Exceptions {
			if ex.Name == "virt-detect-self" {
				c := ex.ConditionGroup.Conditions
				assert.Equal(t, "proc.exe_path", c[len(c)-1].Field, "virt-detect-self: exe_path последним")
			}
		}
	}
}

// Мутация встроена: правила без исключения — формы fwupd срабатывают.
func TestW549_FwupdProbeMutationWithoutException(t *testing.T) {
	rules := w549Rules(t)
	stripped := 0
	for i := range rules {
		keep := rules[i].Exceptions[:0]
		for _, ex := range rules[i].Exceptions {
			if ex.Name == w549Exc {
				stripped++
				continue
			}
			keep = append(keep, ex)
		}
		rules[i].Exceptions = keep
	}
	require.Equal(t, len(w549Forms), stripped)
	engine, res := w549EngineFrom(t, rules)
	for i, f := range w549Forms {
		ev := w549Event(res, uint32(98500+i), "fwupd", w549Fwupd, f.path, 0, 0, "")
		assert.Truef(t, w81Fired(engine.Evaluate(ev))[f.rule], "без исключения %s обязано сработать — иначе подавление держит не %s", f.rule, w549Exc)
	}
}

// №549, пункт 4: systemd-detect-virt на DMI — то же исключение по образу.
func TestW549_DetectVirtSuppressed(t *testing.T) {
	engine, res := w549EngineFrom(t, w549Rules(t))
	const rule, exc = "mitre_vm_detect_dmi_read", "virt-detect-self"
	before := w81ExcCount(rule, exc)
	for i, p := range []string{"/sys/class/dmi/id/sys_vendor", "/sys/class/dmi/id/product_name", "/sys/firmware/dmi/entries/0-0/raw"} {
		ev := w549Event(res, uint32(98600+i), "systemd-detect-", "/usr/bin/systemd-detect-virt", p, 0, w549OCloexec, "")
		assert.Falsef(t, w81Fired(engine.Evaluate(ev))[rule], "%s от systemd-detect-virt на %s", rule, p)
	}
	assert.Greater(t, w81ExcCount(rule, exc), before, "подавление обязано считаться в rule_exceptions_total")
}

func TestW549_DetectVirtSpoofFires(t *testing.T) {
	engine, res := w549EngineFrom(t, w549Rules(t))
	const rule = "mitre_vm_detect_dmi_read"
	for i, c := range []struct {
		exe, container string
		op             uint8
		flags          int32
		why            string
	}{
		{"/tmp/systemd-detect-virt", "", 0, 0, "копия в /tmp"},
		{"/var/tmp/systemd-detect-virt", "", 0, 0, "копия в /var/tmp"},
		{"/usr/bin/systemd-detect-virt", "", 0, w549ORdwr, "open O_RDWR"},
		{"/usr/bin/systemd-detect-virt", "", w549OpWrite, 0, "write"},
		{"/usr/bin/systemd-detect-virt", w549Container, 0, 0, "в контейнере"},
	} {
		ev := w549Event(res, uint32(98700+i), "systemd-detect-", c.exe, "/sys/class/dmi/id/product_uuid", c.op, c.flags, c.container)
		assert.Truef(t, w81Fired(engine.Evaluate(ev))[rule], "%s обязано сработать: %s", rule, c.why)
	}
}

// №549 (в): метод APT gpgv пишет mkstemp-файлы в /tmp при apt-get update.
func TestW549_AptGpgvMethodTmp(t *testing.T) {
	engine, res := w549EngineFrom(t, w549Rules(t))
	const rule, exc, method = "evasion_hidden_elf_in_tmp", "apt-gpgv-method-tmp", "/usr/lib/apt/methods/gpgv"
	before := w81ExcCount(rule, exc)
	for i, p := range []string{"/tmp/apt.conf.30j7x9", "/tmp/apt.sig.TS8yGp", "/tmp/apt.data.Lycdfa"} {
		ev := w549Event(res, uint32(98800+i), "gpgv", method, p, w549OpWrite, 0, "")
		assert.Falsef(t, w81Fired(engine.Evaluate(ev))[rule], "%s от метода apt на %s", rule, p)
	}
	assert.Greater(t, w81ExcCount(rule, exc), before, "подавление обязано считаться в rule_exceptions_total")
	for i, c := range []struct{ exe, path, container, why string }{
		{"/tmp/gpgv", "/tmp/apt.sig.TS8yGp", "", "копия /tmp/gpgv (comm=gpgv)"},
		{"/usr/bin/gpgv", "/tmp/apt.sig.TS8yGp", "", "/usr/bin/gpgv — не метод"},
		{method, "/tmp/apt.sig.TS8yGp.elf", "", "объект не той формы"},
		{method, "/tmp/payload", "", "метод пишет посторонний объект"},
		{method, "/tmp/apt.data.Lycdfa", w549Container, "метод в контейнере"},
		{"/usr/bin/cp", "/tmp/apt-key-gpghome.Ab3dEf9hIj/pubring.orig.gpg", "", "cp под apt-key (долг, ось нет)"},
	} {
		ev := w549Event(res, uint32(98900+i), "gpgv", c.exe, c.path, w549OpWrite, 0, c.container)
		assert.Truef(t, w81Fired(engine.Evaluate(ev))[rule], "%s обязано сработать: %s", rule, c.why)
	}
}
