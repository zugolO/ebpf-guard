package correlator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// №562 / Д16 (14.10.2026): qemu-ga раз в минуту читает /etc/os-release
// (guest-get-osinfo) — 477 из 693 idle-алертов ночи 8.5. Исключение
// qemu-ga-os-release на sigma_kernel_version_read: хост, open/read с режимом
// O_RDONLY, точный образ, только /etc/os-release.

const (
	w86Rule   = "sigma_kernel_version_read"
	w86Exc    = "qemu-ga-os-release"
	w86Qemu   = "/usr/sbin/qemu-ga"
	w86OsRel  = "/etc/os-release"
	w86ProcV  = "/proc/version"
	w86Contnr = "3f2a9c0d1e4b"
)

func TestW86_QemuGaOsReleaseSuppressed(t *testing.T) {
	engine, res := w549EngineFrom(t, w549Rules(t))
	before := w81ExcCount(w86Rule, w86Exc)
	for j, c := range []struct {
		op    uint8
		flags int32
	}{{0, 0}, {0, w549OCloexec}, {0, 0o100000 | w549OCloexec}, {w549OpRead, 0}} {
		ev := w549Event(res, uint32(99000+j), "qemu-ga", w86Qemu, w86OsRel, c.op, c.flags, "")
		assert.Falsef(t, w81Fired(engine.Evaluate(ev))[w86Rule], "qemu-ga на %s (op %d flags %#o)", w86OsRel, c.op, c.flags)
	}
	assert.Greater(t, w81ExcCount(w86Rule, w86Exc), before, "подавление обязано считаться в rule_exceptions_total")
}

func TestW86_QemuGaExceptionDoesNotWiden(t *testing.T) {
	engine, res := w549EngineFrom(t, w549Rules(t))
	for i, c := range []struct {
		comm, exe, path, container string
		op                         uint8
		flags                      int32
		why                        string
	}{
		{"qemu-ga", w86Qemu, w86ProcV, "", 0, 0, "чтение /proc/version тем же образом"},
		{"qemu-ga", w86Qemu, "/etc/lsb-release", "", 0, 0, "другой файл релиза"},
		{"qemu-ga", w86Qemu, w86OsRel, "", 0, w549ORdwr, "open O_RDWR"},
		{"qemu-ga", w86Qemu, w86OsRel, "", 0, w549OWronly, "open O_WRONLY"},
		{"qemu-ga", w86Qemu, w86OsRel, "", w549OpWrite, 0, "write"},
		{"qemu-ga", w86Qemu, w86OsRel, "", w549OpChmod, 0, "chmod"},
		{"qemu-ga", w86Qemu, w86OsRel, w86Contnr, 0, 0, "тот же образ в контейнере"},
		{"qemu-ga", "/tmp/qemu-ga", w86OsRel, "", 0, 0, "спуф: копия под именем qemu-ga"},
		{"qemu-ga", "/usr/bin/cat", w86OsRel, "", 0, 0, "спуф: comm=qemu-ga у другого образа"},
		{"qemu-ga", "", w86OsRel, "", 0, 0, "образ не разрешён"},
		{"cat", "/usr/bin/cat", w86OsRel, "", 0, 0, "другой образ"},
		{"bash", "/usr/bin/bash", w86OsRel, "", 0, 0, "оболочка"},
	} {
		ev := w549Event(res, uint32(99100+i), c.comm, c.exe, c.path, c.op, c.flags, c.container)
		assert.Truef(t, w81Fired(engine.Evaluate(ev))[w86Rule], "%s обязано сработать: %s", w86Rule, c.why)
	}
}

// Мутация встроена: без исключения чтение демона срабатывает — подавляет именно оно.
func TestW86_QemuGaMutationWithoutException(t *testing.T) {
	rules := w549Rules(t)
	stripped := 0
	for i := range rules {
		keep := rules[i].Exceptions[:0]
		for _, ex := range rules[i].Exceptions {
			if ex.Name == w86Exc {
				stripped++
				continue
			}
			keep = append(keep, ex)
		}
		rules[i].Exceptions = keep
	}
	require.Equal(t, 1, stripped, "исключение %s обязано стоять ровно на одном правиле", w86Exc)
	engine, res := w549EngineFrom(t, rules)
	ev := w549Event(res, 99200, "qemu-ga", w86Qemu, w86OsRel, 0, w549OCloexec, "")
	assert.True(t, w81Fired(engine.Evaluate(ev))[w86Rule], "без исключения правило обязано сработать на qemu-ga")
}

// Форма: образ последним, точный путь; регулярка флагов — та же, что у fwupd.
func TestW86_QemuGaExceptionShape(t *testing.T) {
	n := 0
	for _, r := range w549Rules(t) {
		for _, ex := range r.Exceptions {
			if ex.Name != w86Exc {
				continue
			}
			n++
			require.NotNil(t, ex.ConditionGroup)
			cs := ex.ConditionGroup.Conditions
			last := cs[len(cs)-1]
			assert.Equal(t, "proc.exe_path", last.Field)
			assert.Equal(t, OpIn, last.Op)
			assert.Equal(t, []string{w86Qemu}, last.Values)
			for _, c := range cs {
				if normaliseFieldName(c.Field) == "flags" {
					assert.Equal(t, []string{w549FlagsRx}, c.Values)
				}
			}
		}
	}
	assert.Equal(t, 1, n)
}
