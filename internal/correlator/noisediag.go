package correlator

import (
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/zugolO/ebpf-guard/internal/util"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// ДИАГНОСТИКА ШУМА (волна 6.3.9, item 1). Выключена по умолчанию.
//
// ЗАЧЕМ. Объём тихого окна состоит из двух половин, и вторую не видит никто:
// за окно прогона #4 напечатано 38 алертов, а лимитер срезал ещё 18, и весь
// срез принадлежит `anomaly_detection`. Срезанный алерт в стор не попадает —
// ни его вклада (какое поведение сочтено аномальным), ни его осей (exe_path,
// parent_comm) в архиве нет вовсе. Разбор архива может говорить только о
// выживших, а решать точечно надо по тем, кого больше.
//
// ПОЧЕМУ АГРЕГАЦИЯ, А НЕ СТРОКА НА АЛЕРТ. Первая версия печатала строку на
// каждый алерт с потолком на окно. Смок на стенде 18.09.2026 назвал цену этой
// формы числом: 1944 строки напечатано, 33 996 НЕ напечатано по потолку. Через
// воронки подавления проходит ~36 тысяч алертов за прогон (почти всё — дедуп),
// и построчная печать такого объёма не проходит ни через потолок, ни через
// собственный rate-limit journald. Хуже усечения — его ХАРАКТЕР: потолок
// выбирается в первые секунды каждого окна, то есть выборка смещена к началу
// минуты, а не случайна; такие разбивки нельзя читать даже нижними оценками.
//
// Поэтому считается ВСЁ, а печатается СВОДКА. Ни один алерт не выпадает из
// учёта: ключей больше потолка — лишние сворачиваются в бакет переполнения, но
// остаются посчитанными. Это прямо следует из ограничения владельца «ни один
// алерт не потерян и не затёрт»: прибор не вправе терять их даже из счёта.
//
// ЧТО В СВОДКЕ И ПОЧЕМУ ИМЕННО ЭТО:
//
//   - `outcome` — слой, на котором алерт умер (`dedup`, `rate_limit`) или
//     прошёл (`emitted`). Это и есть разрез по слоям подавления: понижение и
//     дедуп переименовывают объём, а не снимают его, и без разреза «стало
//     меньше» неотличимо от «переехало в другой ярус».
//   - `message` — вклад аномалии (`formatAnomalyDescription` складывает туда
//     `field=value` каждой contribution): ответ на «за что именно». Именно
//     этим разрезом по сторовым алертам найдена №364.
//   - гистограммы `samples_*` и `age_*` — состояние профиля НА МОМЕНТ
//     СКОРИНГА. Гипотеза №363 (нет поюкладного разогрева) проверяется тем,
//     какая доля аномалий вынесена против базы с единицами наблюдений.
//   - `exe_resolved`/`exe_unresolved` при явном `exe_sampled` — ось, на
//     которой волна собирается сужать. `exe_path` проигрывает гонку readlink у
//     процессов, живущих миллисекунды, а шум узла — как раз они, поэтому доля
//     неразрешённых и есть ответ, применима ли ось вообще. Знаменатель
//     печатается рядом: readlink делается не на каждый алерт (36 тысяч
//     syscall'ов на горячем пути), а на первые несколько в каждом ключе, и
//     доля без своего знаменателя была бы величиной ни о чём.
//
// ЧЕГО ДИАГНОСТИКА НЕ ДЕЛАЕТ. Не меняет ни одного вердикта, ни одного счётчика
// подавления и ни одного алерта: только счёт и печать.
const (
	noiseDiagOutcomeEmitted   = "emitted"
	noiseDiagOutcomeDedup     = "dedup"
	noiseDiagOutcomeRateLimit = "rate_limit"

	// noiseDiagMaxKeys — потолок РАЗЛИЧИМЫХ ключей сводки. Ключ несёт message,
	// а тот содержит значения полей (порт, каталог), то есть кардинальность в
	// пределе не ограничена ничем. Сверх потолка ключи сворачиваются в один
	// бакет переполнения — посчитанный, но неатрибутированный.
	noiseDiagMaxKeys = 512

	// noiseDiagExeSamplesPerKey — сколько readlink'ов на ключ за окно. Доля
	// разрешённых считается по этой выборке, и её знаменатель печатается.
	noiseDiagExeSamplesPerKey = 8

	noiseDiagOverflowKey = "__overflow__"
)

// noiseDiagExtra несёт то, что знает ТОЛЬКО точка синтеза алерта и что не
// восстановить из самого алерта.
type noiseDiagExtra struct {
	hasProfile     bool
	profileAgeMs   int64
	profileSamples uint64
}

type noiseAggKey struct {
	rule    string
	outcome string
	message string
}

type noiseAggVal struct {
	n uint64

	exeSampled    uint64
	exeResolved   uint64
	exeUnresolved uint64

	// Гистограмма наблюдений в профиле на момент скоринга — ею и проверяется
	// гипотеза №363.
	samplesLE1   uint64
	samples2To5  uint64
	samples6To50 uint64
	samplesGT50  uint64

	ageLT10s uint64
	ageLT5m  uint64
	ageGE5m  uint64

	exComm       string
	exPID        uint32
	exParentComm string
	exExePath    string
}

// NoiseDiagnostics считает все алерты и периодически печатает сводку.
type NoiseDiagnostics struct {
	enabled bool
	window  time.Duration
	maxKeys int
	log     *slog.Logger

	mu          sync.Mutex
	windowStart time.Time
	agg         map[noiseAggKey]*noiseAggVal

	accounted prometheus.Counter
	overflow  prometheus.Counter
	lines     *prometheus.CounterVec
}

// NewNoiseDiagnostics возвращает выключенную диагностику, если enabled=false:
// такой объект не берёт мьютекса и ничего не считает.
//
// maxKeys оставлен параметром конфига (историческое имя max_lines_per_window):
// смысл сменился со «строк за окно» на «ключей сводки», и потолок по-прежнему
// нужен — но теперь он ограничивает АТРИБУЦИЮ, а не учёт.
func NewNoiseDiagnostics(enabled bool, maxKeys int, window time.Duration, log *slog.Logger) *NoiseDiagnostics {
	if window <= 0 {
		window = time.Minute
	}
	if maxKeys <= 0 {
		maxKeys = noiseDiagMaxKeys
	}
	if log == nil {
		log = slog.Default()
	}
	return &NoiseDiagnostics{
		enabled: enabled,
		window:  window,
		maxKeys: maxKeys,
		log:     log,
		agg:     make(map[noiseAggKey]*noiseAggVal),
		lines: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ebpf_guard_noise_diag_lines_total",
			Help: "Alerts accounted by the noise diagnostics, by the suppression layer they reached (emitted, dedup, rate_limit). Wave 6.3.9: an alert cut by the rate limiter never reaches the store, so this is the only record that it fired at all.",
		}, []string{"outcome"}),
		accounted: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ebpf_guard_noise_diag_emitted_total",
			Help: "Alerts accounted by the noise diagnostics. Zero while the feature is enabled means the accounting path was never reached — not that there was no noise.",
		}),
		overflow: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ebpf_guard_noise_diag_omitted_total",
			Help: "Alerts counted but NOT attributed: their summary key did not fit the per-window key cap and was folded into the overflow bucket. They are never lost from the count, only from the breakdown.",
		}),
	}
}

// Register публикует счётчики диагностики. Они регистрируются ДАЖЕ когда
// диагностика выключена: их отсутствие в /metrics должно означать «бинарь без
// правки», а не «правка выключена» — иначе преflight деплоя не отличит одно от
// другого ([[rule-fields-and-binary-ship-together]]).
func (nd *NoiseDiagnostics) Register(reg prometheus.Registerer) error {
	if nd == nil || reg == nil {
		return nil
	}
	for _, c := range []prometheus.Collector{nd.lines, nd.accounted, nd.overflow} {
		if err := reg.Register(c); err != nil {
			return err
		}
	}
	return nil
}

// Enabled сообщает, считает ли диагностика.
func (nd *NoiseDiagnostics) Enabled() bool {
	return nd != nil && nd.enabled
}

// Emit учитывает один алерт. Безопасна на выключенной диагностике и на
// nil-получателе.
func (nd *NoiseDiagnostics) Emit(a *types.Alert, outcome string, extra noiseDiagExtra) {
	if !nd.Enabled() || a == nil {
		return
	}
	now := time.Now()

	nd.mu.Lock()
	if nd.windowStart.IsZero() {
		nd.windowStart = now
	}
	if now.Sub(nd.windowStart) >= nd.window {
		due := nd.takeLocked(now)
		nd.mu.Unlock()
		nd.flush(due)
		nd.mu.Lock()
	}

	key := noiseAggKey{rule: a.RuleID, outcome: outcome, message: a.Message}
	v, ok := nd.agg[key]
	if !ok {
		if len(nd.agg) >= nd.maxKeys {
			// Ключ не поместился — алерт всё равно ПОСЧИТАН, просто не
			// атрибутирован. Терять его из счёта нельзя.
			key = noiseAggKey{rule: noiseDiagOverflowKey, outcome: outcome, message: noiseDiagOverflowKey}
			v, ok = nd.agg[key]
			if !ok {
				v = &noiseAggVal{}
				nd.agg[key] = v
			}
			nd.overflow.Inc()
		} else {
			v = &noiseAggVal{}
			nd.agg[key] = v
		}
	}
	v.n++

	if extra.hasProfile {
		switch {
		case extra.profileSamples <= 1:
			v.samplesLE1++
		case extra.profileSamples <= 5:
			v.samples2To5++
		case extra.profileSamples <= 50:
			v.samples6To50++
		default:
			v.samplesGT50++
		}
		switch {
		case extra.profileAgeMs < 10_000:
			v.ageLT10s++
		case extra.profileAgeMs < 300_000:
			v.ageLT5m++
		default:
			v.ageGE5m++
		}
	}

	if v.exComm == "" {
		v.exComm = a.Comm
		v.exPID = a.PID
		if a.Event.Type != 0 {
			v.exParentComm = util.InternBytes(a.Event.ParentComm[:])
		}
	}
	needExe := v.exeSampled < noiseDiagExeSamplesPerKey
	pid := a.PID
	nd.mu.Unlock()

	if !needExe {
		return
	}
	// readlink делается ВНЕ мьютекса и только на выборку: 36 тысяч syscall'ов
	// на горячем пути — цена, которой измерение не стоит. exe_path берётся БЕЗ
	// счётчика (rawResolveExePath): exePathLookups есть измеряемая величина
	// доли unresolved, и диагностика, инкрементящая её, сдвинула бы чужой
	// замер ([[one-resolver-two-fields-one-counter]]).
	exe := rawResolveExePath(pid)

	nd.mu.Lock()
	// Ключ мог уехать в новое окно, пока шёл readlink: берём его заново, и
	// если окно сменилось — выборка просто не засчитывается, а не пишется в
	// чужой бакет.
	if cur, ok := nd.agg[key]; ok && cur == v && v.exeSampled < noiseDiagExeSamplesPerKey {
		v.exeSampled++
		if exe == "" {
			v.exeUnresolved++
		} else {
			v.exeResolved++
			if v.exExePath == "" {
				v.exExePath = exe
			}
		}
	}
	nd.mu.Unlock()
}

// takeLocked забирает накопленное и начинает новое окно. Вызывается под
// мьютексом.
func (nd *NoiseDiagnostics) takeLocked(now time.Time) map[noiseAggKey]*noiseAggVal {
	due := nd.agg
	nd.agg = make(map[noiseAggKey]*noiseAggVal, len(due))
	nd.windowStart = now
	return due
}

// Flush печатает накопленное немедленно. Зовётся при остановке движка, иначе
// последнее неполное окно осталось бы ненапечатанным — а это ровно окно
// замера, ради которого всё и заводилось.
func (nd *NoiseDiagnostics) Flush() {
	if !nd.Enabled() {
		return
	}
	nd.mu.Lock()
	due := nd.takeLocked(time.Now())
	nd.mu.Unlock()
	nd.flush(due)
}

func (nd *NoiseDiagnostics) flush(due map[noiseAggKey]*noiseAggVal) {
	for k, v := range due {
		nd.accounted.Add(float64(v.n))
		nd.lines.WithLabelValues(k.outcome).Add(float64(v.n))
		nd.log.Info("noise-diag: bucket",
			slog.String("outcome", k.outcome),
			slog.String("rule_id", k.rule),
			slog.Uint64("count", v.n),
			slog.String("message", k.message),
			slog.Uint64("exe_sampled", v.exeSampled),
			slog.Uint64("exe_resolved", v.exeResolved),
			slog.Uint64("exe_unresolved", v.exeUnresolved),
			slog.Uint64("samples_le1", v.samplesLE1),
			slog.Uint64("samples_2_5", v.samples2To5),
			slog.Uint64("samples_6_50", v.samples6To50),
			slog.Uint64("samples_gt50", v.samplesGT50),
			slog.Uint64("age_lt10s", v.ageLT10s),
			slog.Uint64("age_lt5m", v.ageLT5m),
			slog.Uint64("age_ge5m", v.ageGE5m),
			slog.String("example_comm", v.exComm),
			slog.Uint64("example_pid", uint64(v.exPID)),
			slog.String("example_parent_comm", v.exParentComm),
			slog.String("example_exe_path", v.exExePath),
		)
	}
}
