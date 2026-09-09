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
//   - не нужно: поле читается ТОЛЬКО в исключениях фона ноды. Волна 6.2.4
//     (архив collect-6.2.4, находка №261) измерила, что фон ноды — это НЕ
//     только демоны, живущие часами: это ещё и ежеминутный `fork` cron'а,
//     живущий единицы миллисекунд (PAM/NSS lookup читает /etc/passwd ДО
//     всякого execve и умирает раньше, чем корреляция дойдёт до
//     readlink("/proc/<pid>/exe")). На этом форке прямой readlink на pid
//     проигрывает гонку в 87% случаев (exe_path_lookups_total{unresolved}
//     +348 против {resolved} +6118 за 10-минутное окно) — и это ВЕСЬ
//     остаток гейта волны 6. Проигранная гонка даёт пустую строку, то есть
//     отказ применить исключение, то есть срабатывание правила. Отказ
//     открытый: деградация в сторону шума, который видно, а не тишины. Для
//     процессов, которые не проходят через execve (fork без exec), гонку
//     закрывает вторая ось — proc.parent_exe_path (см. ниже): родитель
//     форка — сам демон, он живёт часами и не проигрывает эту гонку, а
//     родителя себе процесс не выбирает, так что антиспуф сохраняется.
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
		Help: "proc.exe_path resolutions attempted by rule conditions, by result (resolved, unresolved) and field (exe_path, parent_exe_path)",
	},
	[]string{"result", "field"},
)

// exePathLookupFields перечисляет обе оси разрешения образа — волна 6.2.6,
// №277: до этой правки `exe_path` (само событие, execve только что случился)
// и `parent_exe_path` (форкнутый потомок демона без своего execve) шли через
// один и тот же счётчик без лейбла поля, и «unresolved=375» на архиве 6.2.5
// было смесью двух разных гонок с разными причинами и разными починками —
// см. exepath.go выше про readlink-гонку execve vs долгоживущего родителя.
const (
	exePathFieldSelf     = "exe_path"
	exePathFieldParent   = "parent_exe_path"
	exePathFieldAncestor = "ancestor_exe_path"
)

func init() {
	// Материализуем все четыре исхода с нуля: прогон, где ни одно исключение
	// не спрашивало exe_path/parent_exe_path, должен отличаться в /metrics от
	// бинаря, который счётчика не знает вовсе. Иначе "unresolved = 0"
	// читается как «ключ разрешается всегда», хотя может значить «инструмента
	// нет» — ровно та двусмысленность, которую 6.0j уже закрывал для
	// proc.args.
	for _, field := range []string{exePathFieldSelf, exePathFieldParent, exePathFieldAncestor} {
		exePathLookups.WithLabelValues("resolved", field)
		exePathLookups.WithLabelValues("unresolved", field)
	}
	// Та же материализация с нуля для исходов обхода: «ancestor = 0» обязано
	// отличаться в /metrics от «бинарь про обход не знает». Ноль в исходе
	// "ancestor" при ненулевых остальных = обход работает, но НИ РАЗУ не
	// дотянулся дальше родителя, то есть item 5 не даёт того, ради чего сделан.
	for _, outcome := range []string{
		ancestorOutcomeParent, ancestorOutcomeAncestor, ancestorOutcomeNoLineage,
		ancestorOutcomeCommBreak, ancestorOutcomeExhausted,
	} {
		exePathAncestorWalks.WithLabelValues(outcome)
	}
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

// resolveExePath возвращает значение поля proc.exe_path/proc.parent_exe_path
// для события. field — одна из exePathFieldSelf/exePathFieldParent, она идёт
// только в лейбл метрики и не влияет на разрешение: вызывающая сторона уже
// выбрала PID или PPID.
func resolveExePath(pid uint32, field string) string {
	h, _ := exeResolver.Load().(exeResolverHolder)
	v := h.r
	if v == nil {
		exePathLookups.WithLabelValues("unresolved", field).Inc()
		return ""
	}
	p := rawResolveExePath(pid)
	if p == "" {
		exePathLookups.WithLabelValues("unresolved", field).Inc()
		return ""
	}
	exePathLookups.WithLabelValues("resolved", field).Inc()
	return p
}

// rawResolveExePath — разрешение без счётчика. Обход родословной ниже делает
// до maxAncestorExePathHops попыток на ОДНО вычисление поля, и если бы каждая
// попытка инкрементила exePathLookups, доля unresolved по оси
// ancestor_exe_path считала бы хопы, а не поля, — та же подмена величины,
// из-за которой №277 вообще появился (один счётчик на две оси). Поэтому
// exePathLookups{field="ancestor_exe_path"} инкрементится РОВНО ОДИН РАЗ на
// вычисление поля, а внутренняя механика обхода живёт в своём счётчике.
func rawResolveExePath(pid uint32) string {
	h, _ := exeResolver.Load().(exeResolverHolder)
	if h.r == nil {
		return ""
	}
	return h.r.ResolveExePath(pid)
}

// --- Волна 6.2.6, item 5 (№261 → №277 → №285): ось предка ----------------
//
// ЧТО ИЗМЕРЕНО. Живой разбор на ebaka2 09.09.2026 назвал причину утечки
// `sigma_passwd_shadow_read_daemon comm=cron` числом: cron форкает задачу в ДВА
// поколения — cron(667, демон) → 3167143 (джоб-обёртка) → 3167144 (сам процесс
// задачи), — и алертует ВТОРОЕ поколение. У него пуст собственный exe_path
// (гонка readlink, процесс живёт единицы миллисекунд) И пуст parent_exe_path,
// потому что непосредственный родитель — тоже гоночное первое поколение, уже
// мёртвое к моменту разбора правил. Обе оси, заведённые волнами 6.2.1 и 6.2.5,
// структурно не дотягиваются до стабильного демона: между алертующим процессом
// и живым образом ДВА хопа, а обе смотрят на один.
//
// ПОЧЕМУ НЕ BPF-РЕЗОЛВ НА execve (вариант (а) из №285). Он не закрывает ЭТОТ
// случай ни в каком исполнении: ни одно из двух поколений не делает execve —
// это форки cron'а, читающие /etc/passwd через PAM/NSS ДО запуска задачи
// (потому comm у всех троих и равен "cron"). Хук на execve не сработает на них
// ни разу. Работал бы только полный kernel-side pid→exe_path с наследованием
// на fork — новая карта, новый хук, пересборка BPF; и это при том, что нужное
// значение УЖЕ лежит в userspace (см. ниже). Вариант (а) отклонён не по цене,
// а потому что мимо цели.
//
// ПОЧЕМУ ЭТО НЕ РАСШИРЕНИЕ ДОВЕРИЯ. Обход дальше родителя разрешён ТОЛЬКО пока
// comm вдоль цепочки не меняется, и это не эвристика, а тождество: comm
// назначается ядром по имени образа в execve, форк его наследует. Непрерывный
// участок цепочки с ОДНИМ И ТЕМ ЖЕ comm — это набор процессов, ни один из
// которых с момента форка не звал execve, а значит все они делят один и тот же
// mm->exe_file, то есть ОДИН ОБРАЗ. Поэтому ancestor_exe_path не «доверяет
// предку» — он восстанавливает СОБСТВЕННЫЙ exe_path алертующего процесса,
// прочитав его у живого родственника, который делит с ним тот же inode. Цена
// по детекту — ноль: возвращается ровно то значение, которое вернул бы
// exe_path, не проиграй он гонку.
//
// ЧТО С ПОДДЕЛКОЙ. prctl(PR_SET_NAME,"cron") и `exec -a cron` дают comm="cron"
// процессу с чужим образом — но обход на первом же хопе упирается в предка с
// ДРУГИМ comm (bash, sshd) и останавливается, а его exe_path в списке демонов
// не значится. Чтобы обход дошёл до /usr/sbin/cron, подделывающему нужен
// непрерывный форк-участок, укоренённый в живом процессе cron'а, — то есть уже
// исполняться внутри самого демона. Единственный остаточный обход — бинарь,
// НАЗВАННЫЙ ровно "cron" и запущенный из cron-задачи, — существует ровно в том
// же виде и у сегодняшнего parent_exe_path (хоп 1) и волнами 6.2.4/6.2.5 уже
// принят; ось предка не добавляет НОВОГО класса обхода, она удлиняет уже
// принятый на два хопа. См. [[exe-path-is-the-antispoof-axis]].
//
// ОТКУДА БЕРЁТСЯ РОДОСЛОВНАЯ МЁРТВЫХ PID. Не из /proc — там их уже нет; из
// LineageTracker, который CorrelationEngine и так зовёт на КАЖДОМ событии
// (Track), складывая kernel-supplied pid/ppid/parent_comm. Тот самый разбор
// №285 напечатал `chain=[cron,cron,cron]` — то есть трекер восстановил все три
// поколения ТОГДА ЖЕ, когда резолвер возвращал пустую строку. Данные лежали
// рядом и не читались. Отсюда и нулевая цена: новых syscall'ов на событие нет,
// новых карт нет, хопы стоят по одному RLock'у и делаются только для событий,
// у которых имя демона уже совпало (условие на ось обязано стоять ПОСЛЕДНИМ в
// "and" — тот же контракт короткого замыкания, что у exe_path).

// maxAncestorExePathHops ограничивает обход. 4 хопа — это форк-глубина cron'а
// (2) с запасом; предел нужен не столько от цены (цепочка почти всегда
// обрывается раньше по comm), сколько от цикла в родословной, если карта
// трекера окажется несогласованной после переиспользования PID.
const maxAncestorExePathHops = 4

const (
	// ancestorOutcomeParent — разрешилось на хопе 1, ровно то, что умел
	// parent_exe_path до этой правки.
	ancestorOutcomeParent = "parent"
	// ancestorOutcomeAncestor — разрешилось на хопе ≥2. ЭТО и есть величина
	// item 5: ноль здесь означает, что правка задеплоена и не сработала.
	ancestorOutcomeAncestor = "ancestor"
	// ancestorOutcomeNoLineage — трекер не знает pid, обход не начался.
	ancestorOutcomeNoLineage = "no_lineage"
	// ancestorOutcomeCommBreak — обход остановлен расхождением comm (то есть
	// антиспуф-условие сработало и не пустило дальше).
	ancestorOutcomeCommBreak = "comm_break"
	// ancestorOutcomeExhausted — упёрлись в предел хопов или в конец
	// известной цепочки, ничего не разрешив.
	ancestorOutcomeExhausted = "exhausted"
)

var exePathAncestorWalks = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "ebpf_guard_exe_path_ancestor_walk_total",
		Help: "proc.ancestor_exe_path lineage walks by outcome (parent, ancestor, no_lineage, comm_break, exhausted)",
	},
	[]string{"outcome"},
)

// AncestryResolver отдаёт родителя pid и его comm по записям, сделанным на
// предыдущих событиях. Реализуется profiler.LineageTracker; интерфейс — чтобы
// обход тестировался без трекера и чтобы «трекера нет» (lineage выключен
// конфигом) было выразимым состоянием, а не паникой.
type AncestryResolver interface {
	ParentOf(pid uint32) (ppid uint32, parentComm string, ok bool)
}

var ancestryResolver atomic.Value // ancestryResolverHolder

type ancestryResolverHolder struct{ r AncestryResolver }

// SetAncestryResolver устанавливает источник родословной для поля
// proc.ancestor_exe_path. Пока он не установлен, поле деградирует до
// parent_exe_path (хоп 1 не требует родословной) — то есть в сторону шума,
// как и весь остальной слой.
func SetAncestryResolver(r AncestryResolver) {
	ancestryResolver.Store(ancestryResolverHolder{r: r})
}

// resolveAncestorExePath возвращает образ ближайшего предка pid, начиная с
// РОДИТЕЛЯ (хоп 0 — сам процесс — намеренно не входит в обход: иначе ось
// поглотила бы exe_path, и два исключения-двойника, verified-daemon-image и
// verified-daemon-lineage, перестали бы различаться в rule_exceptions_total —
// а сторож волны требует ненулевого счётчика по КАЖДОМУ из них).
//
// Хоп 1 берётся безусловно — это в точности сегодняшняя семантика
// parent_exe_path. Хопы 2..maxAncestorExePathHops — только пока comm вдоль
// цепочки совпадает с comm события. Поэтому значение поля есть строгое
// НАДМНОЖЕСТВО parent_exe_path: там, где старая ось разрешалась, новая
// разрешается в то же значение, и ни одно существующее подавление не может
// от этой правки регрессировать.
// pid/comm — сам алертующий процесс, ppid/parentComm — его родитель (и то и
// другое проставлено ядром прямо в событии). Оба нужны потому, что признак
// непрерывности участка проверяется на КАЖДОМ пройденном звене, включая первое:
// разрешить хоп 2, не убедившись, что звено событие→родитель тоже внутри
// одного comm-участка, значило бы склеить два РАЗНЫХ образа (цепочка
// cron → bash → процесс, переименовавший себя в "cron" через prctl, получила бы
// /usr/sbin/cron — ровно та подделка, от которой ось и строилась).
func resolveAncestorExePath(pid, ppid uint32, comm, parentComm string) string {
	// Хоп 1: родитель события. Родословная для него не нужна — PPID проставлен
	// ядром прямо в событии. Хоп безусловный и БЕЗ предварительной проверки
	// ppid: это должен быть ровно тот же вызов, что делал parent_exe_path, до
	// последней детали. Ранний выход по ppid==0 здесь выглядел бы безобидным
	// (в проде ProcExePathResolver сам отвечает "" на pid 0), но подменил бы
	// поведение для любого другого резолвера — и первым это поймал регресс на
	// фикстурах волны 6.2.4, где «настоящий демон» имеет как раз pid 0.
	if p := rawResolveExePath(ppid); p != "" {
		exePathAncestorWalks.WithLabelValues(ancestorOutcomeParent).Inc()
		exePathLookups.WithLabelValues("resolved", exePathFieldAncestor).Inc()
		return p
	}

	// Дальше хопа 1 — только по непрерывному участку одного comm.
	curComm := parentComm
	if curComm == "" {
		// BPF не заполнил parent_comm: последний шанс — запись трекера о
		// самом событии. Если и её нет, обход не начинается: пустой comm не
		// сравнивается ни с чем, и считать его совпадением значило бы
		// открыть обход именно там, где мы про цепочку ничего не знаем.
		if h, _ := ancestryResolver.Load().(ancestryResolverHolder); h.r != nil {
			if _, pc, ok := h.r.ParentOf(pid); ok {
				curComm = pc
			}
		}
	}

	h, _ := ancestryResolver.Load().(ancestryResolverHolder)
	outcome := ancestorOutcomeExhausted
	switch {
	case h.r == nil || ppid == 0:
		outcome = ancestorOutcomeNoLineage
	case curComm == "" || curComm != comm:
		outcome = ancestorOutcomeCommBreak
	default:
		cur := ppid
		for hop := 2; hop <= maxAncestorExePathHops; hop++ {
			// ParentOf(cur) отдаёт следующего предка и ЕГО comm. Проверяем
			// совпадение ДО перехода: расхождение = где-то между cur и next
			// был execve = образы разные = участок кончился.
			next, nextComm, ok := h.r.ParentOf(cur)
			if !ok {
				// Про cur ничего не записано (TTL трекера, или цепочка
				// упёрлась в pid 1): обход кончается, ничего не разрешив.
				if hop == 2 {
					outcome = ancestorOutcomeNoLineage
				}
				break
			}
			if nextComm != curComm {
				outcome = ancestorOutcomeCommBreak
				break
			}
			if p := rawResolveExePath(next); p != "" {
				exePathAncestorWalks.WithLabelValues(ancestorOutcomeAncestor).Inc()
				exePathLookups.WithLabelValues("resolved", exePathFieldAncestor).Inc()
				return p
			}
			cur, curComm = next, nextComm
		}
	}

	exePathAncestorWalks.WithLabelValues(outcome).Inc()
	exePathLookups.WithLabelValues("unresolved", exePathFieldAncestor).Inc()
	return ""
}
