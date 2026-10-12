package main

import (
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	internalbpf "github.com/zugolO/ebpf-guard/internal/bpf"
	"github.com/zugolO/ebpf-guard/internal/config"
	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/internal/profiler"
	"github.com/zugolO/ebpf-guard/pkg/types"

	"github.com/zugolO/ebpf-guard/internal/exporter"
)

type fakeProgrammer struct {
	hasMap  bool
	preds   []internalbpf.SyscallPredicate
	calls   int
	failOn  int // номер вызова (с 1), на котором вернуть ошибку; 0 — никогда
	history [][]uint32
}

func (f *fakeProgrammer) HasPredicateMap() bool { return f.hasMap }
func (f *fakeProgrammer) SetSyscallPredicates(p []internalbpf.SyscallPredicate) error {
	f.calls++
	if f.failOn != 0 && f.calls == f.failOn {
		return errors.New("map update failed")
	}
	f.preds = p
	f.history = append(f.history, predNrs(p))
	return nil
}

type fakeRules struct {
	re      *correlator.RuleEngine
	anomaly bool
	ingest  [][]profiler.SyscallCount
}

func (f *fakeRules) DeriveKernelPredicates(c []uint32) correlator.KernelPredDerivation {
	return f.re.DeriveKernelPredicates(c)
}
func (f *fakeRules) AnomalyEnabled() bool { return f.anomaly }
func (f *fakeRules) IngestSyscallCounts(b []profiler.SyscallCount, _ func(*types.Event)) (uint64, uint64) {
	f.ingest = append(f.ingest, b)
	var n uint64
	for _, c := range b {
		n += c.N
	}
	return n, 0
}

type fakePoller struct {
	d []internalbpf.SyscallCountDelta
}

func (f *fakePoller) Poll() ([]internalbpf.SyscallCountDelta, error) {
	d := f.d
	f.d = nil
	return d, nil
}

func w85Rules(t *testing.T) []correlator.Rule {
	t.Helper()
	rules, err := correlator.LoadRulesFromDir("../../rules")
	if err != nil {
		t.Fatal(err)
	}
	return rules
}

func w85Cfg(enabled bool) *config.Config {
	cfg := &config.Config{}
	cfg.BPF.KernelFilter.ArgPredicates = config.ArgPredicatesConfig{Enabled: enabled, Nrs: []int{9, 10, 158}}
	return cfg
}

func TestKernelPredController_StatesFollowTheReasonOrder(t *testing.T) {
	rules := w85Rules(t)
	re := correlator.NewRuleEngine(rules)

	cases := []struct {
		name     string
		mutate   func(*config.Config)
		hasMap   bool
		anomaly  bool
		counts   kernelCountPoller
		want     string
		wantNrs  []uint32
		wantCall bool // ожидаем запись в карту (в том числе пустую)
	}{
		{name: "выключено конфигом", mutate: func(c *config.Config) { c.BPF.KernelFilter.ArgPredicates.Enabled = false }, hasMap: true, counts: &fakePoller{}, want: kpStateOffConfig, wantCall: true}, // выключено — карта всё равно очищается
		{name: "нет карты предикатов", hasMap: false, counts: &fakePoller{}, want: kpStateOffNoMap},
		{name: "deny-unknown allowlist учится на потоке", mutate: func(c *config.Config) {
			c.Profiler.Enabled = true
			c.Profiler.SyscallAllowlist.Enabled = true
		}, hasMap: true, counts: &fakePoller{}, want: kpStateOffTraining, wantCall: true},
		{name: "детектор дрейфа контейнера включён", mutate: func(c *config.Config) { c.Drift.Enabled = true }, hasMap: true, counts: &fakePoller{}, want: kpStateOffTraining, wantCall: true},
		{name: "allowlist объявлен, но профайлер выключен", mutate: func(c *config.Config) { c.Profiler.SyscallAllowlist.Enabled = true }, hasMap: true, counts: &fakePoller{}, want: kpStateActive, wantNrs: []uint32{9, 10, 158}, wantCall: true},
		{name: "anomaly есть, счётчиков нет", hasMap: true, anomaly: true, counts: nil, want: kpStateOffNoCounters, wantCall: true},
		{name: "anomaly выключен — счётчики не нужны", hasMap: true, anomaly: false, counts: nil, want: kpStateActive, wantNrs: []uint32{9, 10, 158}, wantCall: true},
		{name: "всё есть", hasMap: true, anomaly: true, counts: &fakePoller{}, want: kpStateActive, wantNrs: []uint32{9, 10, 158}, wantCall: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := w85Cfg(true)
			if c.mutate != nil {
				c.mutate(cfg)
			}
			fr := &fakeRules{re: re, anomaly: c.anomaly}
			fp := &fakeProgrammer{hasMap: c.hasMap}
			ctl := newKernelPredController(cfg, fr)
			ctl.attach(fp, c.counts)
			if got := ctl.State(); got != c.want {
				t.Fatalf("состояние=%s, ожидалось %s", got, c.want)
			}
			if c.wantCall != (fp.calls > 0) {
				t.Fatalf("записей в карту=%d, ожидалась запись=%v", fp.calls, c.wantCall)
			}
			got := predNrs(fp.preds)
			if len(got) != len(c.wantNrs) {
				t.Fatalf("предикаты %v, ожидались %v", got, c.wantNrs)
			}
			for i := range got {
				if got[i] != c.wantNrs[i] {
					t.Fatalf("предикаты %v, ожидались %v", got, c.wantNrs)
				}
			}
			if v := testutil.ToFloat64(exporter.KernelPredicateState.WithLabelValues(c.want)); v != 1 {
				t.Fatalf("метрика state=%s равна %v, ожидалась 1", c.want, v)
			}
		})
	}
}

// Перезагрузка правил: новое правило без условия на nr снимает предикат с mmap
// без правки C; возврат прежнего набора — возвращает его.
func TestKernelPredController_ReloadReshapesPredicates(t *testing.T) {
	rules := w85Rules(t)
	fr := &fakeRules{re: correlator.NewRuleEngine(rules), anomaly: true}
	fp := &fakeProgrammer{hasMap: true}
	ctl := newKernelPredController(w85Cfg(true), fr)
	ctl.attach(fp, &fakePoller{})
	if len(fp.preds) != 3 {
		t.Fatalf("после старта предикатов %d, ожидалось 3", len(fp.preds))
	}

	wide := append(append([]correlator.Rule{}, rules...), correlator.Rule{
		ID: "mut_any_nr", EventType: types.EventSyscall,
		Condition: correlator.RuleCondition{Field: "comm", Op: correlator.OpEquals, Values: []string{"x"}},
		Severity:  types.SeverityWarning, Action: "alert",
	})
	// То же, что делает engine.UpdateRules: вывод из НОВОГО набора, до подмены.
	ctl.Apply(correlator.NewRuleEngine(wide).DeriveKernelPredicates)
	fr.re = correlator.NewRuleEngine(wide)
	if got := ctl.State(); got != kpStateOffNoRules || len(fp.preds) != 0 {
		t.Fatalf("после правила без nr: state=%s предикатов=%d (ожидалось off_no_rules и 0)", got, len(fp.preds))
	}

	ctl.Apply(correlator.NewRuleEngine(rules).DeriveKernelPredicates)
	fr.re = correlator.NewRuleEngine(rules)
	if got := ctl.State(); got != kpStateActive || len(fp.preds) != 3 {
		t.Fatalf("после возврата правил: state=%s предикатов=%d", got, len(fp.preds))
	}
}

// Сбой записи в карту не оставляет предикатов: честное состояние off_no_map.
func TestKernelPredController_ProgrammingFailureClearsTheMap(t *testing.T) {
	fr := &fakeRules{re: correlator.NewRuleEngine(w85Rules(t))}
	fp := &fakeProgrammer{hasMap: true, failOn: 1}
	ctl := newKernelPredController(w85Cfg(true), fr)
	ctl.attach(fp, &fakePoller{})
	if got := ctl.State(); got != kpStateOffNoMap || len(fp.preds) != 0 {
		t.Fatalf("state=%s предикатов=%d, ожидалось off_no_map и 0", got, len(fp.preds))
	}
}

func TestKernelPredController_FlushCounters(t *testing.T) {
	exporter.SetSyscallNRAxis([]int{9, 10})
	fr := &fakeRules{re: correlator.NewRuleEngine(nil), anomaly: true}
	ctl := newKernelPredController(w85Cfg(true), fr)
	before := testutil.ToFloat64(exporter.SyscallEventsKernelFiltered.WithLabelValues(exporter.SyscallNRLabel(9)))
	p := &fakePoller{d: []internalbpf.SyscallCountDelta{{PID: 10, Nr: 9, N: 40}, {PID: 11, Nr: 10, N: 2}}}

	ctl.flushCounters(p, nil)
	if len(fr.ingest) != 1 || len(fr.ingest[0]) != 2 || fr.ingest[0][0].N != 40 || fr.ingest[0][0].Nr != 9 {
		t.Fatalf("в профиль ушло %+v", fr.ingest)
	}
	if got := testutil.ToFloat64(exporter.SyscallEventsKernelFiltered.WithLabelValues(exporter.SyscallNRLabel(9))); got-before != 40 {
		t.Fatalf("метрика отброшенного выросла на %v, ожидалось 40", got-before)
	}

	// anomaly выключен: метрика считается, профилям отдавать нечего.
	fr.anomaly = false
	fr.ingest = nil
	ctl.flushCounters(&fakePoller{d: []internalbpf.SyscallCountDelta{{PID: 10, Nr: 9, N: 5}}}, nil)
	if len(fr.ingest) != 0 {
		t.Fatalf("при выключенном anomaly счётчики ушли в профиль: %+v", fr.ingest)
	}
	if got := testutil.ToFloat64(exporter.SyscallEventsKernelFiltered.WithLabelValues(exporter.SyscallNRLabel(9))); got-before != 45 {
		t.Fatalf("метрика отброшенного = +%v, ожидалось +45", got-before)
	}
}

// Переключатель для пары A/B: включение и выключение на ходу применяются к
// ядру сразу, причины «off_*» им не отменяются.
func TestKernelPredController_RuntimeSwitch(t *testing.T) {
	fr := &fakeRules{re: correlator.NewRuleEngine(w85Rules(t))}
	fp := &fakeProgrammer{hasMap: true}
	ctl := newKernelPredController(w85Cfg(false), fr)
	ctl.attach(fp, &fakePoller{})
	if ctl.Enabled() || ctl.State() != kpStateOffConfig || len(fp.preds) != 0 {
		t.Fatalf("старт: enabled=%v state=%s предикатов=%d", ctl.Enabled(), ctl.State(), len(fp.preds))
	}
	ctl.SetEnabled(true)
	if !ctl.Enabled() || ctl.State() != kpStateActive || len(fp.preds) != 3 {
		t.Fatalf("после включения: enabled=%v state=%s предикатов=%d", ctl.Enabled(), ctl.State(), len(fp.preds))
	}
	ctl.SetEnabled(false)
	if ctl.State() != kpStateOffConfig || len(fp.preds) != 0 {
		t.Fatalf("после выключения: state=%s предикатов=%d", ctl.State(), len(fp.preds))
	}

	// Обучающий потребитель сильнее переключателя.
	cfg := w85Cfg(false)
	cfg.Drift.Enabled = true
	ctl2 := newKernelPredController(cfg, fr)
	fp2 := &fakeProgrammer{hasMap: true}
	ctl2.attach(fp2, &fakePoller{})
	ctl2.SetEnabled(true)
	if ctl2.State() != kpStateOffTraining || len(fp2.preds) != 0 {
		t.Fatalf("включение при drift.enabled: state=%s предикатов=%d", ctl2.State(), len(fp2.preds))
	}
}

type occPoller struct {
	fakePoller
	live, max uint32
}

func (o *occPoller) Occupancy() (uint32, uint32) { return o.live, o.max }

// Прибор вытеснений: заполненность печатается и на сливе без приращений.
func TestKernelPredController_FlushPublishesMapOccupancy(t *testing.T) {
	ctl := &kernelPredController{rules: &fakeRules{}}
	ctl.flushCounters(&occPoller{live: 6144, max: 8192}, nil)
	if got := testutil.ToFloat64(exporter.SyscallCountsMapFill); got != 0.75 {
		t.Fatalf("fill_ratio = %v, want 0.75", got)
	}
	if got := testutil.ToFloat64(exporter.SyscallCountsMapLive); got != 6144 {
		t.Fatalf("live_entries = %v, want 6144", got)
	}
}
