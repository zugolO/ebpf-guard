package correlator

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"strings"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// --- Волна 6.2.9.F.1, item 4 (№235/№251/№280 → критерий 6.2.4.6): ось
// systemd-ЮНИТА для корня инцидента.
//
// ЧТО ИЗМЕРЕНО. Прогон 14.09.2026 провалил условие 2 критерия выхода из куста
// РОВНО ОДНИМ инцидентом: корень 50-motd-news, цепочка
// 50-motd-news → 50-motd-news → dpkg, score 57, 17 алертов — дословное
// описание того, что /etc/update-motd.d/50-motd-news делает по расписанию
// (dpkg-query, чтение /proc/version, wget за новостями). Обе половины
// hasQualifyingSignal взведены ЧЕСТНО: недоверенные comm (wget, dpkg, mktemp)
// есть, сетевой сигнал (wget) есть. Лжёт не сигнал — лжёт ярлык
// "confirmed_attack" на штатной периодической работе ноды.
//
// ПОЧЕМУ НЕ ИМЯ. defaultTrustedComms/verifiedDaemonImages знают ИМЕНА демонов.
// 50-motd-news — не демон, а скрипт разовой задачи; заносить его имя в
// allowlist нельзя дважды: имя подделывается (`exec -a 50-motd-news`), и у
// одного и того же процесса оно за его жизнь меняется (№301 — systemd ставит
// форкнутому потомку скобочный comm между fork() и execve()).
//
// ПОЧЕМУ ЮНИТ. cgroup процесса с PPid == 1 пишет systemd, а не сам процесс:
// непривилегированный процесс не может назначить себе чужой юнит
// (память exclusions-key-on-cgroup-not-comm). Это та же ось, которую куст
// выбрал для исключений в правилах, — здесь она применяется к КОРНЮ дерева
// инцидента.
//
// ЧЕГО ОСЬ НЕ ДЕЛАЕТ. Она не гасит алерты: правила срабатывают как прежде,
// объём окна не меняется НИ НА ОДИН алерт, инцидент остаётся и копит счёт со
// статусом "suspicious". Снимается только автоматический ярлык
// "confirmed_attack", и только с МЯГКОГО состава (recon/enum/anomaly) —
// твёрдые улики промотируют как раньше, см. incidentHasHardEvidence.

// UnitResolver возвращает имя systemd-юнита процесса pid, или "" когда юнит не
// определяется (процесс умер, нет procfs, cgroup не systemd'шный). Пустая
// строка — штатный ответ, а не ошибка: вызывающая сторона обязана трактовать
// её как «доверие НЕ применяется», ровно как ExePathResolver.
type UnitResolver interface {
	ResolveUnit(pid uint32) string
}

// ProcCgroupUnitResolver читает /proc/<pid>/cgroup. Формат cgroup v2 —
// одна строка "0::/system.slice/motd-news.service"; у v1 строк несколько, и
// юнит берётся из первой, где он есть. На платформах без procfs (mac, тесты)
// файл не открывается и резолвер возвращает "" — инциденты при этом
// промотируются ровно как до правки, то есть отказ в сторону ШУМА.
type ProcCgroupUnitResolver struct{}

// ResolveUnit implements UnitResolver.
func (ProcCgroupUnitResolver) ResolveUnit(pid uint32) string {
	if pid == 0 {
		return ""
	}
	f, err := os.Open(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if unit := unitFromCgroupLine(sc.Text()); unit != "" {
			return unit
		}
	}
	return ""
}

// unitFromCgroupLine вытаскивает имя юнита из строки /proc/<pid>/cgroup.
//
// Берётся ПОСЛЕДНИЙ сегмент пути, оканчивающийся на .service/.scope/.socket/
// .timer/.mount: у транзиентной задачи путь выглядит как
// /system.slice/motd-news.service, а у юнита с потомками —
// /system.slice/foo.service/bar.scope, и значимо там именно то, что ближе к
// процессу. Сегменты вида "user-1000.slice" юнитом не являются и
// пропускаются.
func unitFromCgroupLine(line string) string {
	parts := strings.SplitN(line, ":", 3)
	if len(parts) != 3 {
		return ""
	}
	p := parts[2]
	if p == "" || p == "/" {
		return ""
	}
	segments := strings.Split(strings.Trim(p, "/"), "/")
	for i := len(segments) - 1; i >= 0; i-- {
		seg := segments[i]
		switch {
		case strings.HasSuffix(seg, ".service"), strings.HasSuffix(seg, ".scope"),
			strings.HasSuffix(seg, ".socket"), strings.HasSuffix(seg, ".timer"),
			strings.HasSuffix(seg, ".mount"):
			return seg
		}
	}
	return ""
}

var unitResolver atomic.Value // unitResolverHolder

type unitResolverHolder struct{ r UnitResolver }

// SetUnitResolver устанавливает источник systemd-юнита. Пока он не установлен,
// ось выключена целиком: unitForPID возвращает "" и ни один инцидент не
// получает доверия по юниту.
func SetUnitResolver(r UnitResolver) {
	unitResolver.Store(unitResolverHolder{r: r})
}

var incidentRootUnitLookups = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "ebpf_guard_incident_root_unit_total",
		Help: "systemd unit resolutions for incident roots, by result (resolved, unresolved, no_resolver).",
	},
	[]string{"result"},
)

func init() {
	// Материализация с нуля: «resolved = 0» обязано отличаться в /metrics от
	// «бинарь про эту ось не знает» — тот же контракт, что у
	// exe_path_lookups_total (№292 и класс drift-stuck).
	for _, result := range []string{"resolved", "unresolved", "no_resolver"} {
		incidentRootUnitLookups.WithLabelValues(result)
	}
}

// unitForPID разрешает юнит один раз, в момент создания инцидента: корень
// разовой задачи (50-motd-news) умирает за секунды, и на промоушене
// /proc/<pid>/cgroup уже пуст. Момент ВЕРДИКТА верен для решения (память
// tree-exclusion-must-be-evaluated-at-verdict-time), но не для ЧТЕНИЯ /proc.
func unitForPID(pid uint32) string {
	h, _ := unitResolver.Load().(unitResolverHolder)
	if h.r == nil {
		incidentRootUnitLookups.WithLabelValues("no_resolver").Inc()
		return ""
	}
	u := h.r.ResolveUnit(pid)
	if u == "" {
		incidentRootUnitLookups.WithLabelValues("unresolved").Inc()
		return ""
	}
	incidentRootUnitLookups.WithLabelValues("resolved").Inc()
	return u
}

// matchUnitPattern сверяет имя юнита с одним образцом списка доверия.
// Поддерживается ровно та форма, которой пользуется systemd сам, — glob
// (apt-daily*.service); регулярных выражений здесь нет намеренно: список
// правит оператор, а не автор правил, и «.» в имени юнита должна означать
// точку.
func matchUnitPattern(pattern, unit string) bool {
	if pattern == "" || unit == "" {
		return false
	}
	if pattern == unit {
		return true
	}
	if !strings.ContainsAny(pattern, "*?[") {
		return false
	}
	ok, err := path.Match(pattern, unit)
	return err == nil && ok
}
