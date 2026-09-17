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
// ЗАЧЕМ. Объём тихого окна прогонов 6.3 состоит из двух половин, и вторую не
// видит НИКТО: за окно #4 напечатано 38 алертов, а лимитер срезал ещё 18, и
// весь срез принадлежит `anomaly_detection`. Срезанный алерт в стор не
// попадает, то есть ни его вклада (какое поведение сочтено аномальным), ни его
// осей (exe_path, parent_comm) в архиве нет вовсе. Разбор архива может
// говорить только о выживших — а решать точечно надо по тем, кого больше.
//
// Офлайн-разбор выживших уже назвал вершину: 38 из 53 anomaly-алертов
// прогона #4 несут вклад динамического загрузчика (`/etc/ld.so.cache`,
// `glibc-hwcaps/*.so.2`, `*.so.N`). Диагностика обязана ответить, верно ли
// это и для срезанных — если да, точечная правка адресует почти весь шум, а
// если нет, срез держит что-то другое, и правка промахнётся.
//
// ЧТО ИМЕННО ПЕЧАТАЕТСЯ И ПОЧЕМУ ЭТИ ПОЛЯ:
//
//   - `outcome` — слой, на котором алерт умер (`dedup`, `rate_limit`) или
//     прошёл (`emitted`). Это и есть разрез по слоям подавления: понижение и
//     дедуп переименовывают объём, а не снимают его, и без разреза «стало
//     меньше» неотличимо от «переехало в другой ярус».
//   - `message` — несёт вклад аномалии (`formatAnomalyDescription` уже
//     складывает туда field=value каждой contribution), то есть ответ на
//     «за что именно».
//   - `profile_age_ms` / `profile_samples` — состояние профиля НА МОМЕНТ
//     СКОРИНГА. Гипотеза №363 (у anomaly-слоя нет поюкладного разогрева, в
//     отличие от drift-слоя) проверяется ровно этими двумя числами: профиль
//     возрастом секунды с базой из одного наблюдения — это она, а профиль
//     часовой давности с сотнями наблюдений — это не она, и правка разогрева
//     шум не уберёт.
//   - `exe_path` / `parent_comm` — те самые оси, на которых item 4 волны
//     собирается сужать. Печатаются ВКЛЮЧАЯ пустое значение: exe_path
//     проигрывает гонку readlink у процессов, живущих миллисекунды, а шум
//     этого узла — как раз короткоживущие родовые имена. Доля пустых и есть
//     ответ на вопрос, применима ли ось вообще, и его надо получить ДО того,
//     как на ней построят сужение.
//
// ЧЕГО ДИАГНОСТИКА НЕ ДЕЛАЕТ. Не меняет ни одного вердикта, ни одного
// счётчика подавления и ни одного алерта: это только печать. И она не вправе
// сама стать шумом — потолок строк на окно обязателен, а число НЕнапечатанных
// строк публикуется счётчиком, потому что усечённая печать, о усечении
// которой не сказано, читается как полная картина.
const (
	noiseDiagOutcomeEmitted   = "emitted"
	noiseDiagOutcomeDedup     = "dedup"
	noiseDiagOutcomeRateLimit = "rate_limit"
)

// noiseDiagExtra несёт то, что знает ТОЛЬКО точка синтеза алерта и что не
// восстановить из самого алерта. Нулевое значение допустимо: для алертов слоя
// правил профиля нет, и поля не печатаются вовсе, а не печатаются нулями
// (ноль возраста профиля — осмысленная величина, «нет профиля» — нет).
type noiseDiagExtra struct {
	hasProfile     bool
	profileAgeMs   int64
	profileSamples uint64
}

// NoiseDiagnostics печатает по одной структурной строке на алерт.
type NoiseDiagnostics struct {
	enabled      bool
	maxPerWindow int
	window       time.Duration
	log          *slog.Logger

	mu          sync.Mutex
	windowStart time.Time
	inWindow    int

	emitted prometheus.Counter
	omitted prometheus.Counter
	lines   *prometheus.CounterVec
}

// NewNoiseDiagnostics возвращает выключенную диагностику, если enabled=false:
// такой объект не читает часов, не берёт мьютекса и не форматирует строк.
func NewNoiseDiagnostics(enabled bool, maxPerWindow int, window time.Duration, log *slog.Logger) *NoiseDiagnostics {
	if window <= 0 {
		window = time.Minute
	}
	if maxPerWindow <= 0 {
		maxPerWindow = 500
	}
	if log == nil {
		log = slog.Default()
	}
	return &NoiseDiagnostics{
		enabled:      enabled,
		maxPerWindow: maxPerWindow,
		window:       window,
		log:          log,
		lines: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ebpf_guard_noise_diag_lines_total",
			Help: "Noise-diagnostic lines written, by the suppression layer the alert reached (emitted, dedup, rate_limit). Wave 6.3.9: the value of a noisy rule is the limiter's reading, and a rate_limit line is the only record of an alert that never reached the store.",
		}, []string{"outcome"}),
		emitted: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ebpf_guard_noise_diag_emitted_total",
			Help: "Noise-diagnostic lines actually written. Zero while the feature is enabled means the accounting path was never reached — not that there was no noise.",
		}),
		omitted: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ebpf_guard_noise_diag_omitted_total",
			Help: "Noise-diagnostic lines NOT written because the per-window cap was hit. A truncated print whose truncation is not stated reads as the whole picture, so this counter is mandatory beside the log.",
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
	for _, c := range []prometheus.Collector{nd.lines, nd.emitted, nd.omitted} {
		if err := reg.Register(c); err != nil {
			return err
		}
	}
	return nil
}

// Enabled сообщает, печатает ли диагностика. Нужен вызывающей стороне, чтобы
// не считать extra-поля (возраст профиля и число наблюдений) на горячем пути
// при выключенной диагностике.
func (nd *NoiseDiagnostics) Enabled() bool {
	return nd != nil && nd.enabled
}

// allow берёт одну строку из потолка окна. Возвращает false, когда потолок
// исчерпан, и считает пропуск.
func (nd *NoiseDiagnostics) allow(now time.Time) bool {
	nd.mu.Lock()
	defer nd.mu.Unlock()
	if nd.windowStart.IsZero() || now.Sub(nd.windowStart) >= nd.window {
		nd.windowStart = now
		nd.inWindow = 0
	}
	if nd.inWindow >= nd.maxPerWindow {
		return false
	}
	nd.inWindow++
	return true
}

// Emit печатает одну строку про один алерт. Безопасна на выключенной
// диагностике и на nil-получателе.
func (nd *NoiseDiagnostics) Emit(a *types.Alert, outcome string, extra noiseDiagExtra) {
	if !nd.Enabled() || a == nil {
		return
	}
	if !nd.allow(time.Now()) {
		nd.omitted.Inc()
		return
	}
	nd.emitted.Inc()
	nd.lines.WithLabelValues(outcome).Inc()

	// exe_path берётся БЕЗ счётчика (rawResolveExePath): exePathLookups —
	// измеряемая величина доли unresolved, и диагностика, инкрементящая её,
	// сдвинула бы чужой замер ([[one-resolver-two-fields-one-counter]]).
	exePath := rawResolveExePath(a.PID)

	attrs := []any{
		slog.String("outcome", outcome),
		slog.String("rule_id", a.RuleID),
		slog.String("severity", string(a.Severity)),
		slog.String("comm", a.Comm),
		slog.Uint64("pid", uint64(a.PID)),
		slog.String("exe_path", exePath),
		slog.String("exe_path_state", nonEmptyState(exePath)),
		slog.String("message", a.Message),
	}
	// Alert.Event — ЗНАЧЕНИЕ, а не указатель (и `json:"-"`, поэтому в сторе его
	// нет вовсе — №327). Признак заполненности — тип события: нуля среди
	// types.Event* нет, отсчёт идёт с EventSyscall = 1.
	if a.Event.Type != 0 {
		attrs = append(attrs,
			slog.Uint64("ppid", uint64(a.Event.PPID)),
			slog.String("parent_comm", util.InternBytes(a.Event.ParentComm[:])),
			slog.String("event_type", eventTypeLabel[a.Event.Type]),
		)
	}
	if extra.hasProfile {
		attrs = append(attrs,
			slog.Int64("profile_age_ms", extra.profileAgeMs),
			slog.Uint64("profile_samples", extra.profileSamples),
		)
	}
	nd.log.Info("noise-diag: alert accounted", attrs...)
}

// nonEmptyState называет класс пустоты словом, а не оставляет пустую строку:
// грепу по архиву нужен признак, а не отсутствие значения.
func nonEmptyState(v string) string {
	if v == "" {
		return "unresolved"
	}
	return "resolved"
}
