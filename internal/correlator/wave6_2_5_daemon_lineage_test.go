package correlator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Волна 6.2.5, находка №261, исход (б): verified-daemon-image проигрывает
// гонку readlink на ежеминутном forked-потомке cron — PAM/NSS lookup читает
// /etc/passwd/shadow ДО execve и потомок умирает за единицы миллисекунд, то
// есть /proc/<pid>/exe уже не существует, когда корреляция доходит до
// readlink. Собственный exe_path такого потомка НЕДОСТИЖИМ не потому, что он
// подделан, а потому, что процесс уже мёртв. verified-daemon-lineage
// разрешает proc.parent_exe_path — образ РОДИТЕЛЯ (сам демон cron, живущий
// часами) — вместо образа мёртвого потомка.
//
// w624DeadPID/w624GenuinePID/w624WithExe — общая инфраструктура волны 6.2.4
// (wave6_2_4_daemon_image_test.go): резолвер отдаёт "" для w624DeadPID и
// системный путь демона для любого другого pid при заданном comm.

// w624LineageCases — из w624Cases() только правила, где verified-daemon-lineage
// заведена (только cron: см. комментарий у самого исключения в YAML — sshd
// форкается на сессию и живёт дольше этой гонки, по архиву 6.2.4 её не
// показывает).
func w624LineageCases(t *testing.T) []w624Case {
	t.Helper()
	var out []w624Case
	for _, c := range w624Cases() {
		if c.comm == "cron" {
			out = append(out, c)
		}
	}
	if len(out) != 2 { // passwd_shadow, sensitive_file_read
		t.Fatalf("ожидались ровно два cron-случая (passwd_shadow, sensitive_file_read), получено %d", len(out))
	}
	return out
}

// (1) Позитивная половина №261: собственный exe_path потомка недостижим (он
// уже умер), но родитель — живой /usr/sbin/cron. Правило обязано МОЛЧАТЬ:
// это и есть весь остаток гейта волны 6 (30 алертов/окно → 0).
func TestWave6_2_5LineageSuppressesShortLivedForkedChild(t *testing.T) {
	for _, c := range w624LineageCases(t) {
		t.Run(c.name, func(t *testing.T) {
			w624WithExe(t, c.comm)
			e := w624Engine(t, c.file, c.twin, c.parent)
			ev := w624FileWithPPID(w624DeadPID, w624GenuinePID, c.comm, c.path, c.op)
			assert.Emptyf(t, w624Fired(e, ev),
				"короткоживущий потомок демона (собственный exe_path недостижим, "+
					"родитель — /usr/sbin/cron) обязан быть снят verified-daemon-lineage, "+
					"а не считаться подделкой: %s", c.twin)
		})
	}
}

// (2) На подделку: атакующая оболочка не является потомком настоящего cron —
// её PPID не резолвится в путь демона. Ни verified-daemon-image (свой образ
// подделан), ни verified-daemon-lineage (родитель — не демон) не применяются,
// правило обязано СРАБОТАТЬ. Без этой половины лёгкая ось выглядела бы как
// немой обход: подставь ЛЮБОГО мёртвого потомка — и молчание гарантировано.
func TestWave6_2_5LineageDoesNotShieldSpoofFromNonDaemonParent(t *testing.T) {
	for _, c := range w624LineageCases(t) {
		t.Run(c.name, func(t *testing.T) {
			w624WithExe(t, c.comm)
			e := w624Engine(t, c.file, c.twin, c.parent)
			// PPID = w624SpoofPID: резолвер отдаёт "/tmp/w624/<comm>" — путь,
			// назначенный подделкой, а не системным демоном.
			ev := w624FileWithPPID(w624DeadPID, w624SpoofPID, c.comm, c.path, c.op)
			fired := w624Fired(e, ev)
			assert.Containsf(t, fired, c.twin,
				"мёртвый потомок НЕ-демона (PPID резолвится не в /usr/sbin/cron) "+
					"обязан поднять %s — lineage не даёт немого обхода", c.twin)
		})
	}
}

// (3) Условие на parent_exe_path — часть контракта короткого замыкания, как
// и exe_path: событие постороннего comm не должно стоить ни одного
// обращения к /proc ни на PID, ни на PPID.
func TestWave6_2_5LineageStaysOffTheHotPath(t *testing.T) {
	for _, c := range w624LineageCases(t) {
		t.Run(c.name, func(t *testing.T) {
			e := w624Engine(t, c.file, c.twin, c.parent)
			cnt := &countingExeResolver{}
			prev, _ := exeResolver.Load().(exeResolverHolder)
			SetExePathResolver(cnt)
			t.Cleanup(func() { SetExePathResolver(prev.r) })

			for i := 0; i < 100; i++ {
				e.Evaluate(w624FileWithPPID(w624GenuinePID, w624GenuinePID, c.stranger, c.path, c.op))
			}
			assert.Zerof(t, cnt.n,
				"события постороннего comm не должны стоить обращения к /proc, "+
					"включая ось parent_exe_path (%s)", c.twin)
		})
	}
}
