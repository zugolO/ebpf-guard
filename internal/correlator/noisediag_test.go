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

// Главная половина: срезанный алерт обязан быть напечатан со СВОИМ слоем и
// нести то, чего нет в сторе — вклад, оси и состояние профиля.
func TestWave6_3_9_NoiseDiagPrintsSuppressedAlertWithItsLayer(t *testing.T) {
	nd, buf := newTestDiag(t, true, 100)

	nd.Emit(diagAlert("anomaly_detection", "mktemp"), noiseDiagOutcomeRateLimit,
		noiseDiagExtra{hasProfile: true, profileAgeMs: 1200, profileSamples: 1})

	var line map[string]any
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &line))

	require.Equal(t, "rate_limit", line["outcome"],
		"слой подавления обязан стоять в строке: без него «стало меньше» неотличимо от «переехало в другой ярус»")
	require.Equal(t, "anomaly_detection", line["rule_id"])
	require.Equal(t, "mktemp", line["comm"])
	require.Equal(t, "bash", line["parent_comm"])
	require.Equal(t, "file", line["event_type"])
	require.Contains(t, line["message"], "extension=.cache",
		"вклад аномалии — единственный ответ на «за что именно», и он живёт в message")

	// Гипотеза №363 проверяется ровно этой парой чисел.
	require.EqualValues(t, 1200, line["profile_age_ms"])
	require.EqualValues(t, 1, line["profile_samples"])

	// Ось сужения печатается ВКЛЮЧАЯ пустое значение, названное словом:
	// доля unresolved и есть ответ, применима ли ось к этому шуму вообще.
	require.Contains(t, []any{"resolved", "unresolved"}, line["exe_path_state"])

	require.EqualValues(t, 1, diagCounterValue(t, nd.emitted))
	require.EqualValues(t, 0, diagCounterValue(t, nd.omitted))
}

// Алерт слоя правил профиля не имеет, и поля профиля не печатаются ВОВСЕ, а не
// печатаются нулями: ноль возраста — осмысленная величина, «нет профиля» — нет.
func TestWave6_3_9_NoiseDiagOmitsProfileFieldsWhenThereIsNoProfile(t *testing.T) {
	nd, buf := newTestDiag(t, true, 100)

	nd.Emit(diagAlert("recon_system_info", "uname"), noiseDiagOutcomeEmitted, noiseDiagExtra{})

	var line map[string]any
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &line))
	require.NotContains(t, line, "profile_age_ms")
	require.NotContains(t, line, "profile_samples")
	require.Equal(t, "emitted", line["outcome"])
}

// Диагностика не вправе сама стать шумом — и обязана СКАЗАТЬ, что усечена.
// Усечённая печать, о усечении которой не сказано, читается как полная
// картина, и это тот же класс, что пустой снимок метрик, молча ставший нулями.
func TestWave6_3_9_NoiseDiagCapIsCountedNotSilent(t *testing.T) {
	nd, buf := newTestDiag(t, true, 2)

	for i := 0; i < 5; i++ {
		nd.Emit(diagAlert("anomaly_detection", "sed"), noiseDiagOutcomeDedup, noiseDiagExtra{})
	}

	require.Equal(t, 2, strings.Count(strings.TrimSpace(buf.String()), "\n")+1,
		"строк напечатано ровно по потолку")
	require.EqualValues(t, 2, diagCounterValue(t, nd.emitted))
	require.EqualValues(t, 3, diagCounterValue(t, nd.omitted),
		"три ненапечатанные строки обязаны быть предъявлены числом, а не пропасть")
}

// Окно потолка сдвигается, а не исчерпывается навсегда.
func TestWave6_3_9_NoiseDiagCapResetsWithTheWindow(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	nd := NewNoiseDiagnostics(true, 1, time.Millisecond, log)
	require.NoError(t, nd.Register(prometheus.NewRegistry()))

	nd.Emit(diagAlert("anomaly_detection", "cp"), noiseDiagOutcomeEmitted, noiseDiagExtra{})
	time.Sleep(3 * time.Millisecond)
	nd.Emit(diagAlert("anomaly_detection", "mv"), noiseDiagOutcomeEmitted, noiseDiagExtra{})

	require.EqualValues(t, 2, diagCounterValue(t, nd.emitted))
	require.EqualValues(t, 0, diagCounterValue(t, nd.omitted))
}

// ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ: выключенная диагностика не печатает ничего и не
// двигает ни одного счётчика — но её серии в /metrics ЕСТЬ (см. ниже), чтобы
// преflight деплоя отличал «бинарь без правки» от «правка выключена».
func TestWave6_3_9_NoiseDiagDisabledPrintsNothing(t *testing.T) {
	nd, buf := newTestDiag(t, false, 100)

	nd.Emit(diagAlert("anomaly_detection", "mktemp"), noiseDiagOutcomeRateLimit,
		noiseDiagExtra{hasProfile: true, profileAgeMs: 5, profileSamples: 1})

	require.Empty(t, strings.TrimSpace(buf.String()))
	require.EqualValues(t, 0, diagCounterValue(t, nd.emitted))
	require.EqualValues(t, 0, diagCounterValue(t, nd.omitted))
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
	// отсутствие серии — «бинарь до правки». Разные вещи, и преflight
	// стенда обязан их различать ([[rule-fields-and-binary-ship-together]]).
	require.True(t, names["ebpf_guard_noise_diag_emitted_total"])
	require.True(t, names["ebpf_guard_noise_diag_omitted_total"])
}

// nil-получатель безопасен: движок, собранный без диагностики, зовёт те же
// воронки подавления.
func TestWave6_3_9_NoiseDiagNilReceiverIsSafe(t *testing.T) {
	var nd *NoiseDiagnostics
	require.False(t, nd.Enabled())
	require.NotPanics(t, func() {
		nd.Emit(diagAlert("x", "y"), noiseDiagOutcomeEmitted, noiseDiagExtra{})
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
	defer engine.Close()

	ctx := context.Background()
	for pid := uint32(100); pid < 105; pid++ {
		engine.Ingest(ctx, types.Event{
			Type:    types.EventTCPConnect,
			PID:     pid,
			Comm:    comm("nginx"),
			Network: &types.NetworkEvent{Dport: 443},
		})
	}

	var emitted, limited int
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
			emitted++
		case noiseDiagOutcomeRateLimit:
			limited++
		}
	}

	require.Equal(t, 2, emitted, "два прошедших алерта обязаны быть напечатаны")
	require.Equal(t, 3, limited,
		"ТРИ срезанных лимитером обязаны быть напечатаны — ради них диагностика и заведена; "+
			"их нет ни в сторе, ни где-либо ещё")
}
