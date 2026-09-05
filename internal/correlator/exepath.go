package correlator

import (
	"fmt"
	"os"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Wave 6.2.1, слой 2 продакшен-решения (№220/№221).
//
// Слой 1 завёл ось идентичности из cgroup (container.id/k8s.pod/k8s.namespace):
// её процесс себе назначить не может, поэтому исключение фона ноды больше не
// является инструкцией по обходу для нагрузки В ПОДЕ. Но у ХОСТОВЫХ процессов
// эта ось пуста у всех сразу — она отвечает «не в контейнере» и не отличает
// k3s-server от чего угодно другого, запущенного на ноте с root-правами. Для
// хостовой половины исключений единственный различающий ключ, который процесс
// себе не выбирает, — образ, из которого он запущен.
//
// /proc/<pid>/exe — символическая ссылка на inode исполняемого файла, её
// проставляет ядро в execve; prctl(PR_SET_NAME) и `exec -a` меняют comm и
// argv[0] и не трогают её. Отсюда позитивный контроль слоя:
//
//	cp /bin/cat /tmp/k3s-server && exec -a k3s-server /tmp/k3s-server /etc/hostname
//
// — comm станет "k3s-server", exe_path останется /tmp/k3s-server, исключение
// не применится, правило обязано сработать.
//
// ПОЧЕМУ USERSPACE, А НЕ BPF. Для proc.args (6.0j/№210) первичным путём стала
// BPF-карта, потому что /proc/<pid>/cmdline проигрывает гонку короткоживущему
// процессу. Здесь так сделать нельзя и не нужно:
//   - нельзя: путь образа в ядре берётся через bpf_d_path(mm->exe_file->f_path),
//     а bpf_d_path разрешён верификатором только на allowlist хуков (LSM и часть
//     tracing), куда tp/sched/sched_process_exec не входит; обходной разбор
//     dentry-цепочки вручную — это цикл по родителям, который упирается в лимит
//     инструкций ровно так же, как уже упёрлась развёртка NUL-замены в
//     trace_sched_process_exec;
//   - не нужно: поле читается ТОЛЬКО в исключениях фона ноды, а фон ноды — это
//     демоны, живущие часами. Проигранная гонка здесь даёт пустую строку, то
//     есть отказ применить исключение, то есть срабатывание правила. Отказ
//     открытый: деградация в сторону шума, который видно, а не тишины.
//
// ПОЧЕМУ БЕЗ КЭША. Кэш по TGID пришлось бы валидировать starttime из
// /proc/<pid>/stat, иначе переиспользованный PID вернул бы чужой образ — то
// есть применил бы исключение к чужому процессу, отказ в сторону ТИШИНЫ. А
// чтение stat — это open+read+close против одного readlinkat, то есть
// валидация кэша дороже самого разрешения. Поэтому разрешение прямое, а
// стоимость удерживается порядком условий (см. ниже), а не памятью.

var exePathLookups = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "ebpf_guard_exe_path_lookups_total",
		Help: "proc.exe_path resolutions attempted by rule conditions, by result (resolved, unresolved)",
	},
	[]string{"result"},
)

func init() {
	// Материализуем оба исхода с нуля: прогон, где ни одно исключение не
	// спрашивало exe_path, должен отличаться в /metrics от бинаря, который
	// счётчика не знает вовсе. Иначе "unresolved = 0" читается как «ключ
	// разрешается всегда», хотя может значить «инструмента нет» — ровно та
	// двусмысленность, которую 6.0j уже закрывал для proc.args.
	exePathLookups.WithLabelValues("resolved")
	exePathLookups.WithLabelValues("unresolved")
}

// ExePathResolver возвращает путь к образу процесса pid, или "" если образ
// не разрешается (процесс уже умер, нет /proc, нет прав). Пустая строка —
// штатный ответ, а не ошибка: вызывающая сторона обязана трактовать её как
// «исключение не применяется».
type ExePathResolver interface {
	ResolveExePath(pid uint32) string
}

// ProcExePathResolver разрешает образ через readlink("/proc/<pid>/exe").
// На платформах без procfs (сборка/тесты на darwin) readlink всегда падает и
// резолвер возвращает "" — правила при этом срабатывают, как если бы
// исключения не было.
type ProcExePathResolver struct{}

// ResolveExePath implements ExePathResolver.
func (ProcExePathResolver) ResolveExePath(pid uint32) string {
	if pid == 0 {
		return ""
	}
	target, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ""
	}
	// Ядро дописывает " (deleted)" к ссылке, когда образ удалён с диска после
	// запуска. Суффикс НЕ срезается: удалённый образ — сам по себе признак
	// (T1070.004, самоудаляющийся дроппер), и срезание суффикса приравняло бы
	// его к живому файлу с тем же путём, то есть отдало бы ему исключение
	// демона. Пусть лучше не совпадёт.
	return target
}

// exeResolver — атомарный держатель резолвера, чтобы горячая перезагрузка
// правил и Evaluate из нескольких горутин не гонялись за полем движка.
// Значение общее на процесс, а не на RuleEngine: перезагрузка правил создаёт
// новый RuleEngine, и потерять резолвер при ней означало бы бесшумно
// выключить весь слой.
var exeResolver atomic.Value // exeResolverHolder

// exeResolverHolder оборачивает интерфейс: atomic.Value паникует на попытке
// сохранить nil-интерфейс, а «резолвера нет» — это штатное состояние (агент
// ещё не стартовал, тест снял свой), которое обязано быть выразимым.
type exeResolverHolder struct{ r ExePathResolver }

// SetExePathResolver устанавливает разрешатель образа процесса, используемый
// полем proc.exe_path. Вызывается один раз при старте агента. Пока он не
// установлен, поле пусто у всех событий и все исключения, которые на него
// опираются, не применяются — то есть слой выключен в сторону шума.
func SetExePathResolver(r ExePathResolver) {
	exeResolver.Store(exeResolverHolder{r: r})
}

// resolveExePath возвращает значение поля proc.exe_path для события.
func resolveExePath(pid uint32) string {
	h, _ := exeResolver.Load().(exeResolverHolder)
	v := h.r
	if v == nil {
		exePathLookups.WithLabelValues("unresolved").Inc()
		return ""
	}
	p := v.ResolveExePath(pid)
	if p == "" {
		exePathLookups.WithLabelValues("unresolved").Inc()
		return ""
	}
	exePathLookups.WithLabelValues("resolved").Inc()
	return p
}
