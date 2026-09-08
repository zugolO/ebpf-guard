package correlator

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 6.2.4, находка №253, исход (г): четыре info-двойника на sshd/cron
// давали 91% величины гейта (122 из 134 алертов за 10-минутное окно прогона
// 6.2.3), и сузить их было нечем — путь, op и comm у всех четырёх уже
// точечные. Вместо удаления правил каждому добавлено именованное исключение
// verified-daemon-image на ОБРАЗ процесса.
//
// Смысл правки не в том, что стало тише, а в том, ЧЕМ она отличается от
// немого обхода. Исключение, построенное на comm, снимает объём и ровно тем же
// движением выдаёт инструкцию по обходу: `exec -a cron` меняет comm и argv[0]
// за один вызов. /proc/<pid>/exe ставит ядро в execve, и подделать её тем же
// приёмом нельзя. Поэтому у каждого правила здесь проверяются ТРИ половины:
//
//	(1) негативная — штатный демон с верным образом молчит;
//	(2) на подделку — тот же comm из чужого образа СРАБАТЫВАЕТ (это и есть
//	    разница между осью-образом и осью-именем; без этой половины правка
//	    неотличима от `comm not_in`, снятого волной 6.2.3 как немой обход);
//	(3) позитивная — родительское правило по-прежнему поднимается на подаче
//	    от постороннего comm, то есть детект не вырезан.
//
// Плюс (4): пустой exe_path (процесс умер, нет procfs, резолвер не поставлен)
// обязан ОТКРЫТЬ отказ — исключение не применяется, правило срабатывает.
// Деградация в сторону шума, который видно, а не тишины.

const (
	// w624GenuinePID — демон, запущенный из своего системного образа.
	w624GenuinePID uint32 = 0
	// w624SpoofPID — `cp /bin/cat /tmp/w624/cron && exec -a cron /tmp/w624/cron`:
	// comm и argv[0] подделаны, образ — нет.
	w624SpoofPID uint32 = 94001
	// w624DeadPID — процесс, не доживший до readlink: резолвер вернёт "".
	w624DeadPID uint32 = 94002
)

// w624ExeResolver отдаёт образ по PID. Для w624GenuinePID образ выбирается по
// имени процесса — так тест описывает «настоящий демон» одним резолвером на
// все четыре правила.
type w624ExeResolver struct{ comm string }

func (r w624ExeResolver) ResolveExePath(pid uint32) string {
	switch pid {
	case w624SpoofPID:
		return "/tmp/w624/" + r.comm
	case w624DeadPID:
		return ""
	}
	switch r.comm {
	case "sshd":
		return "/usr/sbin/sshd"
	case "cron":
		return "/usr/sbin/cron"
	case "rsyslogd":
		return "/usr/sbin/rsyslogd"
	case "systemd-journald", "systemd-journal":
		return "/usr/lib/systemd/systemd-journald"
	}
	return "/usr/bin/" + r.comm
}

func w624WithExe(t *testing.T, comm string) {
	t.Helper()
	prev, _ := exeResolver.Load().(exeResolverHolder)
	SetExePathResolver(w624ExeResolver{comm: comm})
	t.Cleanup(func() { SetExePathResolver(prev.r) })
}

// w624Engine собирает движок из ИМЕНОВАННЫХ правил файла — двойника и его
// родителя вместе, чтобы позитивная половина проверялась тем же движком, что
// и негативная, а не отдельной сборкой.
func w624Engine(t *testing.T, file string, ids ...string) *RuleEngine {
	t.Helper()
	loaded, err := LoadRulesFromFile(file)
	require.NoError(t, err)
	var out []Rule
	for _, id := range ids {
		found := false
		for i := range loaded {
			if loaded[i].ID == id {
				out = append(out, loaded[i])
				found = true
				break
			}
		}
		require.Truef(t, found, "правило %s не найдено в %s", id, file)
	}
	return NewRuleEngine(out)
}

// w624NoLineagePPID — PPID нарочно вне трёх специальных pid'ов резолвера
// (w624GenuinePID/w624SpoofPID/w624DeadPID): резолвер отдаёт для него ветку
// по умолчанию ("/usr/bin/"+comm), которая не совпадает ни с одним путём в
// verified-daemon-lineage (волна 6.2.5, №261/исход (б)). Без этого PID=0 у
// w624GenuinePID и незаданный (нулевой) PPID событий совпали бы, и новая ось
// молча подмешивалась бы в тесты старой оси exe_path.
const w624NoLineagePPID uint32 = 999999

// w624File — файловое событие. op: 0=open, 1=read, 2=write, 3=chmod
// (fileOpNames в rules.go). PPID — генуинный форк (см. w624NoLineagePPID):
// эти тесты проверяют ось exe_path в изоляции, родословная не участвует.
func w624File(pid uint32, comm, path string, op uint8) types.Event {
	return w624FileWithPPID(pid, w624NoLineagePPID, comm, path, op)
}

// w624FileWithPPID — как w624File, но с явным PPID, для тестов оси
// verified-daemon-lineage (волна 6.2.5, №261/исход (б)), где родословная как
// раз и решает, применяется исключение или нет.
func w624FileWithPPID(pid, ppid uint32, comm, path string, op uint8) types.Event {
	e := types.Event{Type: types.EventFileAccess, PID: pid, PPID: ppid, File: &types.FileEvent{Op: op}}
	copy(e.Comm[:], comm)
	copy(e.File.Filename[:], path)
	return e
}

func w624Fired(e *RuleEngine, ev types.Event) []string {
	var ids []string
	for _, a := range e.Evaluate(ev) {
		ids = append(ids, a.RuleID)
	}
	return ids
}

type w624Case struct {
	name   string
	file   string
	twin   string
	parent string
	comm   string // демон, чью работу снимает исключение
	path   string
	op     uint8
	// stranger — comm, ради которого правило существует: подача не от демона.
	stranger string
}

func w624Cases() []w624Case {
	return []w624Case{
		{
			name: "passwd_shadow", file: "../../rules/sigma-linux.yaml",
			twin: "sigma_passwd_shadow_read_daemon", parent: "sigma_passwd_shadow_read",
			comm: "cron", path: "/etc/shadow", op: 0, stranger: "cat",
		},
		{
			name: "sensitive_file_read", file: "../../rules/credential-access.yaml",
			twin: "sensitive_file_read_daemon", parent: "sensitive_file_read",
			comm: "cron", path: "/etc/shadow", op: 0, stranger: "cat",
		},
		{
			name: "log_deletion", file: "../../rules/sigma-linux.yaml",
			twin: "sigma_log_deletion_daemon", parent: "sigma_log_deletion",
			comm: "rsyslogd", path: "/var/log/syslog", op: 2, stranger: "cat",
		},
		{
			name: "utmp_wtmp", file: "../../rules/sigma-linux.yaml",
			twin: "sigma_utmp_wtmp_modified_daemon", parent: "sigma_utmp_wtmp_modified",
			comm: "sshd", path: "/var/log/wtmp", op: 2, stranger: "cat",
		},
	}
}

// (1) Негативная половина: штатный демон, запущенный из своего образа, не даёт
// ни одного алерта. Это и есть 762 совпадения за окно, снятые с формулы гейта.
func TestWave6_2_4GenuineDaemonImageIsSuppressed(t *testing.T) {
	for _, c := range w624Cases() {
		t.Run(c.name, func(t *testing.T) {
			w624WithExe(t, c.comm)
			e := w624Engine(t, c.file, c.twin, c.parent)
			assert.Empty(t, w624Fired(e, w624File(w624GenuinePID, c.comm, c.path, c.op)),
				"штатный %s из системного образа обязан молчать: объём уходит в "+
					"ebpf_guard_rule_exceptions_total, а не в alerts_total", c.comm)
		})
	}
}

// (2) Половина на ПОДДЕЛКУ — то, ради чего ось выбрана образом, а не именем.
// Тот же comm, тот же путь, тот же хостовой контекст; отличается только
// /proc/<pid>/exe. Правило обязано сработать. Ноль здесь означает, что
// исключение сужено по ИМЕНИ, то есть является инструкцией по обходу.
func TestWave6_2_4SpoofedDaemonNameStillAlerts(t *testing.T) {
	for _, c := range w624Cases() {
		t.Run(c.name, func(t *testing.T) {
			w624WithExe(t, c.comm)
			e := w624Engine(t, c.file, c.twin, c.parent)
			// PPID тоже w624SpoofPID: подделка образа целиком, включая
			// родословную — иначе тест доказывал бы только то, что
			// verified-daemon-lineage не сработала бы, а не то, что ни одно
			// исключение не сработало (родитель подделки — не демон, см.
			// verified-daemon-lineage: реальный родитель-cron у атакующей
			// оболочки не появляется).
			fired := w624Fired(e, w624FileWithPPID(w624SpoofPID, w624SpoofPID, c.comm, c.path, c.op))
			assert.Containsf(t, fired, c.twin,
				"`exec -a %s /tmp/w624/%s` подделывает comm, но не образ — %s обязано сработать",
				c.comm, c.comm, c.twin)
		})
	}
}

// (3) Позитивная половина: подача не от демона по-прежнему поднимает
// РОДИТЕЛЬСКОЕ правило. Ноль здесь означает, что правка вырезала детект.
func TestWave6_2_4ParentRuleStillDetectsStranger(t *testing.T) {
	for _, c := range w624Cases() {
		t.Run(c.name, func(t *testing.T) {
			w624WithExe(t, c.comm)
			e := w624Engine(t, c.file, c.twin, c.parent)
			fired := w624Fired(e, w624File(w624GenuinePID, c.stranger, c.path, c.op))
			assert.Containsf(t, fired, c.parent,
				"%s на %s посторонним comm=%s — это то, ради чего правило существует",
				c.parent, c.path, c.stranger)
		})
	}
}

// (4) Отказ разрешения образа ОТКРЫТЫЙ: пустой exe_path не совпадает с точным
// путём, исключение не применяется, правило срабатывает. Если однажды кто-то
// сделает исключение «применяется при пустом образе ради тишины» — упадёт
// здесь. Доля таких событий на живом прогоне видна в
// ebpf_guard_exe_path_lookups_total{result="unresolved"}.
func TestWave6_2_4UnresolvedImageFailsOpen(t *testing.T) {
	for _, c := range w624Cases() {
		t.Run(c.name, func(t *testing.T) {
			w624WithExe(t, c.comm)
			e := w624Engine(t, c.file, c.twin, c.parent)
			// PPID тоже w624DeadPID: резолвер недоступен целиком (нет procfs,
			// оба readlink'а — на pid и на ppid — падают одинаково), а не
			// только для события. Иначе тест проверял бы только гонку
			// verified-daemon-image и не проверял бы, что при полном отказе
			// резолвера lineage-ось тоже не закрывает отказ тишиной.
			assert.Containsf(t, w624Fired(e, w624FileWithPPID(w624DeadPID, w624DeadPID, c.comm, c.path, c.op)), c.twin,
				"неразрешённый образ обязан ОТКРЫТЬ отказ (шум, который видно), а не закрыть его тишиной")
		})
	}
}

// Порядок условий в YAML — часть контракта, а не стиль: proc.exe_path стоит
// последним в группе "and", поэтому живой readlink случается только там, где
// имя демона уже совпало. Событие постороннего comm не должно стоить ни
// одного обращения к /proc. Переставит кто-нибудь условие наверх — тест упадёт.
func TestWave6_2_4ExePathStaysOffTheHotPath(t *testing.T) {
	for _, c := range w624Cases() {
		t.Run(c.name, func(t *testing.T) {
			e := w624Engine(t, c.file, c.twin, c.parent)
			cnt := &countingExeResolver{}
			prev, _ := exeResolver.Load().(exeResolverHolder)
			SetExePathResolver(cnt)
			t.Cleanup(func() { SetExePathResolver(prev.r) })

			for i := 0; i < 100; i++ {
				e.Evaluate(w624File(w624GenuinePID, c.stranger, c.path, c.op))
			}
			assert.Zerof(t, cnt.n,
				"события постороннего comm не должны стоить обращения к /proc (%s)", c.twin)
		})
	}
}

// ---------------------------------------------------------------------------
// Офлайн-сторож величины гейта на архиве прогона 6.2.3.
// ---------------------------------------------------------------------------

// Правка №253 обещает число, и число обязано проверяться на данных, а не на
// арифметике в голове. Сторож читает разбивку РЕАЛЬНОГО прогона
// (server-logs/collect-6.2.3/controls/artifacts/volume-by-rule.txt — величина
// (а) поимённо за окно 15:23:03…15:33:03) и пересчитывает её так, как окно
// выглядело бы с сегодняшним набором правил.
//
// Чего сторож НЕ делает: он не заменяет живой прогон. Архив хранит агрегаты,
// а не события, поэтому пересчёт исходит из того, что весь объём этих шести
// правил на тихом окне поднят демонами со штатным образом — что и утверждает
// разбивка (источники поимённо: sshd/cron у четырёх двойников, k3s-server у
// двух recon-правил). Живой прогон обязан подтвердить это ненулевым
// ebpf_guard_rule_exceptions_total; см. критерий 6.2.4.5.
//
// Зачем он всё-таки нужен: он ловит расхождение между тем, что записано в
// плане как ожидаемая величина, и тем, что следует из архива.
func TestWave6_2_4GateArithmeticOnArchive(t *testing.T) {
	const (
		archive     = "../../server-logs/collect-6.2.3/controls/artifacts/volume-by-rule.txt"
		windowMin   = 10.0
		gatePerHour = 100.0
	)

	// Снимается исходом (г) — четыре info-двойника, 91% величины.
	twins := map[string]bool{
		"sigma_passwd_shadow_read_daemon": true,
		"sensitive_file_read_daemon":      true,
		"sigma_log_deletion_daemon":       true,
		"sigma_utmp_wtmp_modified_daemon": true,
	}
	// Снимается п. 2в — работой на запас, по факту разбивки (оба k3s-server).
	headroom := map[string]bool{
		"sigma_cpu_info_access":    true,
		"mitre_vm_detect_dmi_read": true,
	}

	// Каталог server-logs/ — локальный каталог разбора (в .gitignore), на
	// стенде его нет и быть не может. Сторож офлайн-разбора не вправе красить
	// прогон тестов на стенде в красный: там его вход отсутствует ПО УСТРОЙСТВУ,
	// а не по недосмотру. Отсутствие самого каталога — пропуск с явной причиной;
	// каталог есть, а разбивки нет — по-прежнему жёсткий провал.
	if _, statErr := os.Stat(filepath.Dir(filepath.Dir(filepath.Dir(archive)))); os.IsNotExist(statErr) {
		t.Skip("каталог server-logs/ отсутствует (стенд не хранит архивы офлайн-разбора) — сторож величины гейта неприменим")
	}

	raw, err := os.ReadFile(archive)
	require.NoError(t, err, "архив прогона 6.2.3 — вход этой волны, без него сторож не имеет смысла")

	var total, afterTwins, afterHeadroom int
	residual := map[string]int{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		n, err := strconv.Atoi(f[1])
		require.NoError(t, err, "строка разбивки %q", line)
		total += n
		if twins[f[0]] {
			continue
		}
		afterTwins += n
		if headroom[f[0]] {
			continue
		}
		afterHeadroom += n
		residual[f[0]] = n
	}

	perHour := func(n int) float64 { return float64(n) * 60.0 / windowMin }

	t.Logf("величина (а) на архиве:            %3d/окно = %.0f/ч  (гейт %.0f/ч — ПРОВАЛ 6.2.3.1)",
		total, perHour(total), gatePerHour)
	t.Logf("после исхода (г), четыре двойника: %3d/окно = %.0f/ч", afterTwins, perHour(afterTwins))
	t.Logf("после п. 2в, работа на запас:      %3d/окно = %.0f/ч  (запас %.1fx)",
		afterHeadroom, perHour(afterHeadroom), gatePerHour/perHour(afterHeadroom))
	for id, n := range residual {
		t.Logf("    остаток: %-34s %d", id, n)
	}

	// Числа плана: 804/ч -> 72/ч -> 48/ч. Расхождение означает, что архив и
	// план разошлись, и заметить это надо ДО прогона, а не после.
	assert.Equal(t, 134, total, "величина (а) архива 6.2.3")
	assert.Equal(t, 12, afterTwins, "остаток после снятия четырёх двойников (план: 72/ч)")
	assert.Equal(t, 8, afterHeadroom, "остаток после работы на запас (план: 48/ч)")

	assert.Lessf(t, perHour(afterHeadroom), gatePerHour,
		"гейт волны 6 не берётся даже по арифметике архива — правка недостаточна")

	// Запас, а не просто PASS: одиночное окно на 8 алертах при разрешённых
	// 16,7 не отличает взятый критерий от разброса anomaly_detection (5 из
	// этих 8 — профилировщик, правкой правил он не снимается). Двукратный
	// запас — то, ради чего в волну добавлен п. 2в.
	assert.GreaterOrEqualf(t, gatePerHour/perHour(afterHeadroom), 2.0,
		"запас до гейта меньше двукратного (%.1fx) — PASS окажется в пределах разброса",
		gatePerHour/perHour(afterHeadroom))

	assert.Equal(t, 5, residual["anomaly_detection"],
		"пол волны — профилировщик; если он изменился, п. 2в надо пересчитать")
}

// ---------------------------------------------------------------------------
// №254 — вторая половина №250: ось проверенного образа демона поднята с
// отдельного правила на промоушен ИНЦИДЕНТА. До этой правки IncidentTracker
// доверял comm=cron/sshd/rsyslogd/systemd-journald(-al) БЕЗ проверки образа
// (defaultTrustedComms — чистая карта по имени), то есть ту же подделку,
// которую verified-daemon-image (rules/sigma-linux.yaml,
// rules/credential-access.yaml, №253) ловит на уровне правила, инцидентный
// слой мог погасить одним движением: алерт двойника поднимается верно, но
// HasUntrustedSignal остаётся false, потому что comm="cron" совпадает с
// картой доверия, и score, набранный этим же алертом вместе с остальными,
// никогда не квалифицируется как attack (hasQualifyingSignal ложно).
//
// isImageVerifiedComm (incident.go) закрывает это: для пяти охраняемых comm
// требуется совпадение /proc/<pid>/exe с тем же списком путей, что и
// verified-daemon-image, а неразрешённый образ ОТКАТЫВАЕТСЯ к прежнему
// доверию по имени (а не флипается в недоверие) — иначе выключенный
// резолвер (или любой тест этого пакета, ни один из которых его не ставит)
// массово превратил бы фон cron/sshd в attack. Три половины ниже проверяют
// ровно это: штатный образ остаётся тихим, подделка образа промотируется,
// а отсутствие резолвера ведёт себя как до правки.
func w624AttackBurstComm(tr *IncidentTracker, pid uint32, ns, comm string, start time.Time) {
	for i, id := range []string{"r1", "r2", "r3", "r4", "r5"} {
		tr.Add(makeAlertWithComm(id, pid, ns, types.SeverityCritical, start.Add(time.Duration(i)*time.Second), comm))
	}
}

func TestWave6_2_4GenuineCronBurstStaysGatedBySuspicion(t *testing.T) {
	w624WithExe(t, "cron")
	tr := newIncidentTracker(60*time.Second, nil, scoringRules())
	w624AttackBurstComm(tr, w624GenuinePID, "prod", "cron", time.Now())

	incidents := tr.GetAll("", "", 0)
	require.Len(t, incidents, 1)
	assert.NotEqualf(t, types.VerdictAttack, incidents[0].Verdict,
		"штатный cron (образ /usr/sbin/cron) не должен получать доверенный "+
			"сигнал из своей же природы: пять правил на его счёт не обязаны "+
			"промотировать incident_confirmed_attack (verdict=%v)", incidents[0].Verdict)
}

func TestWave6_2_4SpoofedCronBurstPromotesAttack(t *testing.T) {
	w624WithExe(t, "cron")
	tr := newIncidentTracker(60*time.Second, nil, scoringRules())
	// w624SpoofPID — тот же резолвер отдаёт "/tmp/w624/cron" для этого PID:
	// `cp /bin/cat /tmp/w624/cron && exec -a cron /tmp/w624/cron ...`.
	w624AttackBurstComm(tr, w624SpoofPID, "prod", "cron", time.Now())

	incidents := tr.GetAll("", "", 0)
	require.Len(t, incidents, 1)
	assert.Equalf(t, types.VerdictAttack, incidents[0].Verdict,
		"comm=cron из /tmp/w624/cron — подделка имени, а не демон; инцидент "+
			"обязан промотироваться, иначе правку rule-уровня (№253) отменяет "+
			"собственный трастовый шлюз инцидентного слоя (verdict=%v)", incidents[0].Verdict)
}

func TestWave6_2_4UnresolvedCronBurstStaysGatedBySuspicion(t *testing.T) {
	// Резолвер НЕ установлен — ровно то состояние, в котором находится любой
	// другой тест этого пакета (incident_bgcoalesce_test.go и соседи) и
	// сборка без procfs (darwin). Поведение обязано остаться ДОРЕФОРМЕННЫМ:
	// откат к доверию по имени, а не к недоверию.
	tr := newIncidentTracker(60*time.Second, nil, scoringRules())
	w624AttackBurstComm(tr, 4242, "prod", "cron", time.Now())

	incidents := tr.GetAll("", "", 0)
	require.Len(t, incidents, 1)
	assert.NotEqualf(t, types.VerdictAttack, incidents[0].Verdict,
		"неразрешённый образ обязан откатиться к доверию по имени — иначе "+
			"выключенный резолвер массово превращает фон cron/sshd в attack "+
			"(verdict=%v)", incidents[0].Verdict)
}
