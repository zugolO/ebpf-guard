package correlator

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 6.3.9. Диагностика шума заводится ради ОДНОГО вопроса, на который
// архивы четырёх прогонов 6.3 ответить не могут: за что именно срабатывают
// алерты, срезанные лимитером. Их 18…42 за тихое окно против 38 напечатанных,
// все — `anomaly_detection`, и в стор они не попадают, поэтому ни вклада, ни
// осей у них нет нигде.
//
// Форма — СВОДКА, а не строка на алерт: смок на стенде 18.09.2026 показал
// 1944 напечатанных строки против 33 996 не напечатанных по потолку, причём
// усечение смещено к началу каждого окна. Тесты ниже держат главное свойство
// новой формы: НИ ОДИН алерт не выпадает из счёта, даже когда его ключ не
// поместился в потолок атрибуции.

func newTestDiag(t *testing.T, enabled bool, cap int) (*NoiseDiagnostics, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	nd := NewNoiseDiagnostics(enabled, cap, time.Minute, log)
	require.NoError(t, nd.Register(prometheus.NewRegistry()))
	return nd, &buf
}

func diagCounterValue(t *testing.T, c prometheus.Collector) float64 {
	t.Helper()
	ch := make(chan prometheus.Metric, 8)
	c.Collect(ch)
	close(ch)
	var sum float64
	for m := range ch {
		var pb dto.Metric
		require.NoError(t, m.Write(&pb))
		sum += pb.GetCounter().GetValue()
	}
	return sum
}

func diagAlert(rule, comm string) *types.Alert {
	a := &types.Alert{
		RuleID:   rule,
		Comm:     comm,
		PID:      4242,
		Severity: types.SeverityWarning,
		Message:  "Anomalous behavior detected: directory=/etc/, extension=.cache",
	}
	a.Event.Type = types.EventFileAccess
	a.Event.PPID = 4000
	copy(a.Event.ParentComm[:], "bash")
	return a
}

// Главная половина: срезанный алерт обязан попасть в сводку СО СВОИМ слоем и
// нести то, чего нет в сторе — вклад, оси и состояние профиля.
func TestWave6_3_9_NoiseDiagSummarisesSuppressedAlertsWithTheirLayer(t *testing.T) {
	nd, buf := newTestDiag(t, true, 100)

	for i := 0; i < 3; i++ {
		nd.Emit(diagAlert("anomaly_detection", "mktemp"), noiseDiagOutcomeRateLimit,
			noiseDiagExtra{hasProfile: true, profileAgeMs: 1200, profileSamples: 1})
	}
	nd.Emit(diagAlert("anomaly_detection", "mktemp"), noiseDiagOutcomeEmitted,
		noiseDiagExtra{hasProfile: true, profileAgeMs: 900000, profileSamples: 120})
	nd.Flush()

	byOutcome := map[string]map[string]any{}
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var line map[string]any
		require.NoError(t, json.Unmarshal([]byte(l), &line))
		byOutcome[line["outcome"].(string)] = line
	}

	cut := byOutcome["rate_limit"]
	require.NotNil(t, cut, "срезанные лимитером обязаны иметь свой бакет — ради них прибор и заведён")
	require.EqualValues(t, 3, cut["count"], "счёт точный, а не выборочный")
	require.Equal(t, "anomaly_detection", cut["rule_id"])
	require.Contains(t, cut["message"], "extension=.cache",
		"вклад аномалии — единственный ответ на «за что именно»")
	require.Equal(t, "mktemp", cut["example_comm"])
	require.Equal(t, "bash", cut["example_parent_comm"])

	// Гипотеза №363 читается этой гистограммой: три аномалии вынесены против
	// базы из одного наблюдения.
	require.EqualValues(t, 3, cut["samples_le1"])
	require.EqualValues(t, 3, cut["age_lt10s"])

	// Прошедший алерт лежит в СВОЁМ бакете и в гистограмме зрелого профиля —
	// иначе «стало меньше» было бы неотличимо от «переехало в другой ярус».
	passed := byOutcome["emitted"]
	require.NotNil(t, passed)
	require.EqualValues(t, 1, passed["count"])
	require.EqualValues(t, 1, passed["samples_gt50"])
	require.EqualValues(t, 1, passed["age_ge5m"])

	require.EqualValues(t, 4, diagCounterValue(t, nd.accounted))
	require.EqualValues(t, 0, diagCounterValue(t, nd.overflow))
}

// Знаменатель доли разрешённых осей печатается рядом с ней: readlink делается
// на выборку, и доля без своего знаменателя была бы величиной ни о чём.
func TestWave6_3_9_NoiseDiagPrintsExeSampleDenominator(t *testing.T) {
	nd, buf := newTestDiag(t, true, 100)

	for i := 0; i < 20; i++ {
		nd.Emit(diagAlert("recon_system_info", "uname"), noiseDiagOutcomeEmitted, noiseDiagExtra{})
	}
	nd.Flush()

	var line map[string]any
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &line))
	require.EqualValues(t, 20, line["count"])
	require.EqualValues(t, noiseDiagExeSamplesPerKey, line["exe_sampled"],
		"выборка осей ограничена и её размер напечатан")
	require.EqualValues(t, line["exe_sampled"],
		line["exe_resolved"].(float64)+line["exe_unresolved"].(float64),
		"разрешённые и неразрешённые обязаны складываться в знаменатель")
}

// Алерт слоя правил профиля не имеет — гистограммы профиля остаются нулевыми,
// а не выдумывают нагрузке возраст.
func TestWave6_3_9_NoiseDiagProfileHistogramsStayZeroWithoutProfile(t *testing.T) {
	nd, buf := newTestDiag(t, true, 100)

	nd.Emit(diagAlert("recon_system_info", "uname"), noiseDiagOutcomeEmitted, noiseDiagExtra{})
	nd.Flush()

	var line map[string]any
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &line))
	require.EqualValues(t, 1, line["count"])
	for _, k := range []string{"samples_le1", "samples_2_5", "samples_6_50", "samples_gt50",
		"age_lt10s", "age_lt5m", "age_ge5m"} {
		require.EqualValues(t, 0, line[k], "поле %s не должно заполняться без профиля", k)
	}
}

// ГЛАВНОЕ СВОЙСТВО ФОРМЫ: потолок ограничивает АТРИБУЦИЮ, а не учёт. Алерт,
// чей ключ не поместился, обязан остаться посчитанным — это прямое следствие
// ограничения «ни один алерт не потерян». Прежняя форма теряла 95% строк по
// потолку и не говорила о них ничего, кроме их числа.
func TestWave6_3_9_NoiseDiagKeyCapLosesAttributionNeverTheCount(t *testing.T) {
	nd, buf := newTestDiag(t, true, 2)

	nd.Emit(diagAlert("rule_a", "a"), noiseDiagOutcomeEmitted, noiseDiagExtra{})
	nd.Emit(diagAlert("rule_b", "b"), noiseDiagOutcomeEmitted, noiseDiagExtra{})
	for i := 0; i < 7; i++ {
		nd.Emit(diagAlert("rule_c", "c"), noiseDiagOutcomeEmitted, noiseDiagExtra{})
	}
	nd.Flush()

	total := 0.0
	overflowSeen := false
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var line map[string]any
		require.NoError(t, json.Unmarshal([]byte(l), &line))
		total += line["count"].(float64)
		if line["rule_id"] == noiseDiagOverflowKey {
			overflowSeen = true
			require.EqualValues(t, 7, line["count"])
		}
	}
	require.EqualValues(t, 9, total, "сумма по бакетам обязана равняться числу учтённых алертов")
	require.True(t, overflowSeen, "непоместившиеся ключи обязаны иметь свой названный бакет")
	require.EqualValues(t, 9, diagCounterValue(t, nd.accounted))
	require.EqualValues(t, 7, diagCounterValue(t, nd.overflow),
		"неатрибутированные обязаны быть предъявлены числом")
}

// Окно сводки закрывается временем: накопленное печатается и счёт начинается
// заново, а не растёт до конца прогона одной строкой.
func TestWave6_3_9_NoiseDiagFlushesOnWindowRollover(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	nd := NewNoiseDiagnostics(true, 100, time.Millisecond, log)
	require.NoError(t, nd.Register(prometheus.NewRegistry()))

	nd.Emit(diagAlert("anomaly_detection", "cp"), noiseDiagOutcomeEmitted, noiseDiagExtra{})
	time.Sleep(3 * time.Millisecond)
	nd.Emit(diagAlert("anomaly_detection", "mv"), noiseDiagOutcomeEmitted, noiseDiagExtra{})
	nd.Flush()

	require.Equal(t, 2, strings.Count(strings.TrimSpace(buf.String()), "\n")+1,
		"два окна — две сводки")
	require.EqualValues(t, 2, diagCounterValue(t, nd.accounted))
}

// ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ: выключенная диагностика не печатает ничего и не
// двигает ни одного счётчика — но её серии в /metrics ЕСТЬ (см. ниже), чтобы
// преflight деплоя отличал «бинарь без правки» от «правка выключена».
func TestWave6_3_9_NoiseDiagDisabledPrintsNothing(t *testing.T) {
	nd, buf := newTestDiag(t, false, 100)

	nd.Emit(diagAlert("anomaly_detection", "mktemp"), noiseDiagOutcomeRateLimit,
		noiseDiagExtra{hasProfile: true, profileAgeMs: 5, profileSamples: 1})
	nd.Flush()

	require.Empty(t, strings.TrimSpace(buf.String()))
	require.EqualValues(t, 0, diagCounterValue(t, nd.accounted))
	require.EqualValues(t, 0, diagCounterValue(t, nd.overflow))
}

func TestWave6_3_9_NoiseDiagCountersRegisterEvenWhenDisabled(t *testing.T) {
	reg := prometheus.NewRegistry()
	nd := NewNoiseDiagnostics(false, 0, 0, slog.Default())
	require.NoError(t, nd.Register(reg))

	families, err := reg.Gather()
	require.NoError(t, err)
	names := make(map[string]bool, len(families))
	for _, f := range families {
		names[f.GetName()] = true
	}
	// Ноль значения при наличии серии означает «правка есть, шума нет»;
	// отсутствие серии — «бинарь до правки». Разные вещи, и преflight стенда
	// обязан их различать ([[rule-fields-and-binary-ship-together]]).
	require.True(t, names["ebpf_guard_noise_diag_emitted_total"])
	require.True(t, names["ebpf_guard_noise_diag_omitted_total"])
}

// nil-получатель безопасен: движок, собранный без диагностики, зовёт те же
// воронки подавления и тот же Flush на остановке.
func TestWave6_3_9_NoiseDiagNilReceiverIsSafe(t *testing.T) {
	var nd *NoiseDiagnostics
	require.False(t, nd.Enabled())
	require.NotPanics(t, func() {
		nd.Emit(diagAlert("x", "y"), noiseDiagOutcomeEmitted, noiseDiagExtra{})
		nd.Flush()
	})
	require.NoError(t, nd.Register(prometheus.NewRegistry()))
}

// СКВОЗНОЙ КОНТРОЛЬ ПРОВОДКИ. Тесты выше проверяют сам эмиттер; они ничего не
// говорят о том, зовут ли его воронки подавления. А ценность диагностики
// ровно в срезанных алертах: если воронка лимитера эмиттер не вызывает, на
// стенде получится полный журнал ПРОШЕДШИХ алертов и ни одной строки про тех,
// кого больше, — приборный ноль, читаемый как «лимитер ничего не резал».
func TestWave6_3_9_EngineEmitsDiagFromTheSuppressionFunnels(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	defer slog.SetDefault(prev)

	comm := func(s string) [16]byte {
		var b [16]byte
		copy(b[:], s)
		return b
	}
	noisy := Rule{
		ID:        "noisediag_probe",
		EventType: types.EventTCPConnect,
		Condition: RuleCondition{Field: "dport", Op: OpEquals, Values: []string{"443"}},
		Severity:  types.SeverityWarning,
		Action:    ActionAlert,
	}

	cfg := DefaultCorrelationEngineConfig()
	cfg.Rules = []Rule{noisy}
	cfg.EnableRateLimit = true
	cfg.RateLimitWindow = time.Minute
	cfg.MaxAlertsPerWindow = 2
	cfg.EnableAnomaly = false
	cfg.EnableDedup = false
	cfg.NoiseDiagEnabled = true
	cfg.NoiseDiagMaxLinesPerWindow = 100
	cfg.NoiseDiagWindow = time.Minute

	engine := NewCorrelationEngineWithConfig(cfg)

	ctx := context.Background()
	for pid := uint32(100); pid < 105; pid++ {
		engine.Ingest(ctx, types.Event{
			Type:    types.EventTCPConnect,
			PID:     pid,
			Comm:    comm("nginx"),
			Network: &types.NetworkEvent{Dport: 443},
		})
	}
	// Close печатает последнее неполное окно: без этого сводка замера
	// осталась бы в памяти агента, а прогон — без своих чисел.
	engine.Close()

	var emitted, limited float64
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if !strings.Contains(l, "noise-diag") {
			continue
		}
		var line map[string]any
		require.NoError(t, json.Unmarshal([]byte(l), &line))
		if line["rule_id"] != noisy.ID {
			continue
		}
		switch line["outcome"] {
		case noiseDiagOutcomeEmitted:
			emitted += line["count"].(float64)
		case noiseDiagOutcomeRateLimit:
			limited += line["count"].(float64)
		}
	}

	require.EqualValues(t, 2, emitted, "два прошедших алерта обязаны быть учтены")
	require.EqualValues(t, 3, limited,
		"ТРИ срезанных лимитером обязаны быть учтены — ради них диагностика и заведена; "+
			"их нет ни в сторе, ни где-либо ещё")
}

// Интервал бакета печатается ЕГО СОБСТВЕННЫМИ числами, а не выводится
// читателем из шага. Смок 18.09.2026 дважды дал «0 сводок в окне замера» при
// сотнях за прогон: флаш событийный, и на тихом узле бакет покрывает не шаг, а
// всё время с прошлого флаша. Срез по окну строится на этих полях, поэтому
// они обязаны быть и обязаны расти монотонно от бакета к бакету.
func TestWave6_3_9_BucketCarriesItsOwnInterval(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	nd := NewNoiseDiagnostics(true, 100, 20*time.Millisecond, log)
	require.NoError(t, nd.Register(prometheus.NewRegistry()))

	nd.Emit(diagAlert("anomaly_detection", "cp"), noiseDiagOutcomeEmitted, noiseDiagExtra{})
	time.Sleep(40 * time.Millisecond)
	nd.Emit(diagAlert("anomaly_detection", "mv"), noiseDiagOutcomeEmitted, noiseDiagExtra{})
	nd.Flush()

	var prevTo float64
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.Len(t, lines, 2, "два окна — две сводки")
	for i, l := range lines {
		var line map[string]any
		require.NoError(t, json.Unmarshal([]byte(l), &line))
		from, okF := line["window_from_ms"].(float64)
		to, okT := line["window_to_ms"].(float64)
		require.True(t, okF && okT, "бакет обязан нести свой интервал")
		require.LessOrEqual(t, from, to, "интервал не может идти вспять")
		if i > 0 {
			require.GreaterOrEqual(t, from, prevTo,
				"интервалы соседних сводок не перекрываются: иначе срез по окну посчитал бы покрытие дважды")
		}
		prevTo = to
	}
}

// Флаш ПО ТАЙМЕРУ, а не на следующем алерте. Боевой прогон 18.09.2026 показал
// цену событийного флаша прямо: за тихое окно 600с не закрылся НИ ОДИН бакет,
// единственный охватил промежуток от пролога до контролей, и срез по окну дал
// покрытие 0с из 600с — окно замера не измерялось вовсе.
func TestWave6_3_9_TimerFlushClosesBucketsWithoutTraffic(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	nd := NewNoiseDiagnostics(true, 100, 30*time.Millisecond, log)
	require.NoError(t, nd.Register(prometheus.NewRegistry()))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	nd.Start(ctx)

	nd.Emit(diagAlert("anomaly_detection", "cp"), noiseDiagOutcomeEmitted, noiseDiagExtra{})
	// Тишина: ни одного Emit. Событийный флаш здесь не закрыл бы ничего.
	time.Sleep(120 * time.Millisecond)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.GreaterOrEqual(t, len(lines), 2,
		"таймер обязан закрывать бакеты и без трафика — иначе тихое окно остаётся неизмеренным")

	var silence, withCount int
	for _, l := range lines {
		var line map[string]any
		require.NoError(t, json.Unmarshal([]byte(l), &line))
		require.Contains(t, line, "window_from_ms")
		if line["rule_id"] == "__none__" {
			silence++
			require.EqualValues(t, 0, line["count"])
		} else {
			withCount++
		}
	}
	require.GreaterOrEqual(t, silence, 1,
		"интервал без алертов обязан быть ЗАПИСАН: иначе он неотличим от интервала, в котором прибор не работал")
	require.Equal(t, 1, withCount, "единственный алерт учтён ровно один раз")
}
