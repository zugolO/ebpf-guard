package main

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	internalbpf "github.com/zugolO/ebpf-guard/internal/bpf"
	"github.com/zugolO/ebpf-guard/internal/config"
	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/internal/exporter"
	"github.com/zugolO/ebpf-guard/internal/profiler"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 8.5, F1/F2: предикаты аргументов syscall в ядре и счётчики отброшенного.
//
// Контроллер связывает три вещи, которые по отдельности небезопасны:
//   - вывод предикатов из ЗАГРУЖЕННЫХ правил (correlator.DeriveKernelPredicates);
//   - запись их в карту ядра (bpf.KernelFilterController.SetSyscallPredicates);
//   - слив счётчиков отброшенного в профиль нагрузки (F2).
//
// Правило 3 волны: предикаты не включаются раньше, чем у отброшенного есть
// получатель. Поэтому состояние выбирается строго по порядку причин в Apply, и
// любое «нет» оставляет карту пустой — номера идут целиком, как до F1.

// Состояния предикатов (значения label state метрики ebpf_guard_kernel_predicate_state).
const (
	kpStateActive           = "active"
	kpStateOffConfig        = "off_config"
	kpStateOffTraining      = "off_training_consumer"
	kpStateOffNoCounters    = "off_no_counters"
	kpStateOffNoMap         = "off_no_map"
	kpStateOffNoRules       = "off_no_rules"
	defaultKernelPredPeriod = 5 * time.Second
)

// kernelPredProgrammer — то, чем контроллер пишет в ядро (*bpf.KernelFilterController).
type kernelPredProgrammer interface {
	HasPredicateMap() bool
	SetSyscallPredicates(preds []internalbpf.SyscallPredicate) error
}

// kernelPredRules — то, откуда контроллер берёт правила и получателя счётчиков
// (*correlator.CorrelationEngine).
type kernelPredRules interface {
	DeriveKernelPredicates(candidates []uint32) correlator.KernelPredDerivation
	AnomalyEnabled() bool
	IngestSyscallCounts(batch []profiler.SyscallCount, enrich func(*types.Event)) (applied, skipped uint64)
}

type kernelCountPoller interface {
	Poll() ([]internalbpf.SyscallCountDelta, error)
}

type kernelPredController struct {
	cfg        config.ArgPredicatesConfig
	candidates []uint32
	// trainingConsumers — какие потребители, учащиеся на ПОШТУЧНОМ потоке номеров,
	// включены (deny-unknown allowlist, детектор дрейфа контейнера). Не пуст — F1 выключен.
	trainingConsumers []string
	rules             kernelPredRules

	// enabled — рабочее состояние переключателя: начальное значение из конфига,
	// дальше его переворачивает POST /api/v1/tuning/kernel-predicates (пара A/B
	// на смежных окнах: рестарт между окнами измерил бы рестарт).
	enabled atomic.Bool

	// flushMu сериализует слив: читатель карты не потокобезопасен, а слить
	// могут и периодический цикл, и остановка агента.
	flushMu sync.Mutex
	enrich  func(*types.Event)
	stopped bool

	mu     sync.Mutex
	kf     kernelPredProgrammer
	counts kernelCountPoller
	state  string
}

func newKernelPredController(cfg *config.Config, rules kernelPredRules) *kernelPredController {
	ap := cfg.BPF.KernelFilter.ArgPredicates
	nrs := ap.Nrs
	if len(nrs) == 0 {
		nrs = []int{9, 10, 158}
	}
	c := &kernelPredController{cfg: ap, rules: rules}
	c.enabled.Store(ap.Enabled)
	for _, nr := range nrs {
		if nr >= 0 && nr < 512 {
			c.candidates = append(c.candidates, uint32(nr))
		}
	}
	// Потребители, читающие номер вызова из поштучного потока и УЧАЩИЕСЯ на нём:
	// пропуск номера в ядре во время обучения даст ложное нарушение на первом же
	// пропущенном вызове (inventory F0, решение (3)).
	if cfg.Profiler.Enabled && cfg.Profiler.SyscallAllowlist.Enabled {
		c.trainingConsumers = append(c.trainingConsumers, "profiler.syscall_allowlist")
	}
	if cfg.Drift.Enabled {
		c.trainingConsumers = append(c.trainingConsumers, "drift")
	}
	// Метрики заводятся нулями сразу: отсутствие серии — «бинарь старше волны».
	exporter.SetKernelPredicateState(kpStateOffConfig)
	exporter.SetKernelPredicateNrs(c.candidates, nil)
	c.state = kpStateOffConfig
	return c
}

// attach подключает ядро: контроллер фильтра (с картой предикатов) и читателя
// счётчиков. Вызывается из отчёта syscall-коллектора после загрузки объекта.
// Сразу применяет предикаты по текущим правилам.
func (c *kernelPredController) attach(kf kernelPredProgrammer, counts kernelCountPoller) {
	c.mu.Lock()
	c.kf = kf
	c.counts = counts
	c.mu.Unlock()
	c.Apply(nil)
}

// Enabled — состояние переключателя предикатов.
func (c *kernelPredController) Enabled() bool { return c.enabled.Load() }

// SetEnabled переворачивает переключатель и сразу применяет его к ядру.
// Не отменяет причин, по которым предикаты не включаются (обучающий
// потребитель, нет счётчиков, нет правил): они видны в state.
func (c *kernelPredController) SetEnabled(on bool) {
	c.enabled.Store(on)
	c.Apply(nil)
}

// State возвращает текущее состояние (для логов и тестов).
func (c *kernelPredController) State() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

// Apply выводит предикаты из правил и программирует их, либо снимает — по
// первой подходящей причине. derive — вывод из НОВОГО набора правил (движок
// зовёт перед подменой, см. SetKernelPredicateUpdater); nil — из текущих
// правил движка (подключение ядра).
func (c *kernelPredController) Apply(derive func([]uint32) correlator.KernelPredDerivation) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if derive == nil {
		derive = c.rules.DeriveKernelPredicates
	}
	state, preds, blockers := c.decide(derive)
	var err error
	if c.kf != nil && c.kf.HasPredicateMap() {
		// В любом «off» карта должна быть пуста: после перезагрузки правил
		// состояние могло перейти active → off_no_rules.
		err = c.kf.SetSyscallPredicates(preds)
		if err != nil {
			// Не удалось записать — не знаем, что в карте. Честное состояние —
			// «карты нет в рабочем виде»; следующая перезагрузка правил попробует снова.
			slog.Error("kernel_pred: programming the syscall predicate map failed, forwarding every number whole",
				slog.Any("error", err))
			_ = c.kf.SetSyscallPredicates(nil)
			state, preds = kpStateOffNoMap, nil
		}
	}

	active := make(map[uint32]bool, len(preds))
	for _, p := range preds {
		active[p.Nr] = true
	}
	exporter.SetKernelPredicateState(state)
	exporter.SetKernelPredicateNrs(c.candidates, active)

	if state != c.state {
		slog.Info("kernel_pred: state changed",
			slog.String("from", c.state), slog.String("to", state),
			slog.Any("predicate_nrs", predNrs(preds)),
			slog.Any("training_consumers", c.trainingConsumers))
	}
	for nr, ids := range blockers {
		slog.Info("kernel_pred: syscall number forwarded whole, rules without a checkable argument",
			slog.Uint64("nr", uint64(nr)), slog.Int("rules", len(ids)), slog.Any("rule_ids", firstN(ids, 10)))
	}
	c.state = state
}

// decide выбирает состояние и набор предикатов; без побочных эффектов.
func (c *kernelPredController) decide(derive func([]uint32) correlator.KernelPredDerivation) (state string, preds []internalbpf.SyscallPredicate, blockers map[uint32][]string) {
	switch {
	case !c.enabled.Load():
		return kpStateOffConfig, nil, nil
	case c.kf == nil || !c.kf.HasPredicateMap():
		return kpStateOffNoMap, nil, nil
	case len(c.trainingConsumers) > 0:
		return kpStateOffTraining, nil, nil
	case c.rules.AnomalyEnabled() && c.counts == nil:
		// У отброшенного был бы получатель — слой anomaly, — но счётчиков нет.
		return kpStateOffNoCounters, nil, nil
	}
	d := derive(c.candidates)
	for _, p := range d.Predicates {
		bp := internalbpf.SyscallPredicate{Nr: p.Nr}
		for _, t := range p.Terms {
			bp.Terms = append(bp.Terms, internalbpf.SyscallPredTerm{Arg: t.Arg, Values: t.Values})
		}
		preds = append(preds, bp)
	}
	if len(preds) == 0 {
		return kpStateOffNoRules, nil, d.Blockers
	}
	return kpStateActive, preds, d.Blockers
}

// runCounters раз в интервал сливает приращения счётчиков ядра: в метрику
// «отброшено ядром» и (если слой anomaly включён) в профили нагрузок.
// enrich — тот же набор энричеров, что у поштучных событий.
func (c *kernelPredController) runCounters(ctx context.Context, enrich func(*types.Event)) {
	interval := c.cfg.CountersInterval
	if interval <= 0 {
		interval = defaultKernelPredPeriod
	}
	c.flushMu.Lock()
	c.enrich = enrich
	c.flushMu.Unlock()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// Читатель подключается из отчёта коллектора уже после старта цикла.
			c.mu.Lock()
			poller := c.counts
			c.mu.Unlock()
			if poller != nil {
				c.flushCounters(poller, enrich)
			}
		}
	}
}

// FinalFlush — последний слив при штатной остановке: до закрытия объектов BPF.
// После него периодический цикл больше не читает карту. Идемпотентен.
func (c *kernelPredController) FinalFlush() {
	c.mu.Lock()
	poller := c.counts
	c.mu.Unlock()
	c.flushMu.Lock()
	defer c.flushMu.Unlock()
	if c.stopped {
		return
	}
	c.stopped = true
	if poller == nil {
		return
	}
	slog.Info("kernel_pred: final drain of syscall counters before BPF objects close")
	c.drain(poller, c.enrich)
}

func (c *kernelPredController) flushCounters(poller kernelCountPoller, enrich func(*types.Event)) {
	c.flushMu.Lock()
	defer c.flushMu.Unlock()
	if c.stopped {
		return // финальный слив уже прошёл, карта может быть закрыта
	}
	c.drain(poller, enrich)
}

// drain читает приращения и складывает их; вызывающий держит flushMu.
func (c *kernelPredController) drain(poller kernelCountPoller, enrich func(*types.Event)) {
	deltas, err := poller.Poll()
	if err != nil {
		slog.Warn("kernel_pred: reading syscall counters failed", slog.Any("error", err))
		return
	}
	if se, ok := poller.(interface{ SelfExcludedDelta() uint64 }); ok {
		if n := se.SelfExcludedDelta(); n > 0 {
			exporter.RecordSyscallSelfExcluded(n)
		}
	}
	if occ, ok := poller.(interface{ Occupancy() (live, max uint32) }); ok {
		exporter.SetSyscallCountsOccupancy(occ.Occupancy())
	}
	if len(deltas) == 0 {
		return
	}
	batch := make([]profiler.SyscallCount, 0, len(deltas))
	for _, d := range deltas {
		exporter.RecordSyscallKernelFiltered(int64(d.Nr), d.N)
		batch = append(batch, profiler.SyscallCount{
			PID: d.PID, Nr: int64(d.Nr), CgroupID: d.CgroupID, Comm: d.Comm, N: d.N,
		})
	}
	if !c.rules.AnomalyEnabled() {
		return
	}
	applied, skipped := c.rules.IngestSyscallCounts(batch, enrich)
	exporter.SyscallCountsFolded.WithLabelValues("applied").Add(float64(applied))
	exporter.SyscallCountsFolded.WithLabelValues("skipped").Add(float64(skipped))
}

func predNrs(preds []internalbpf.SyscallPredicate) []uint32 {
	out := make([]uint32, 0, len(preds))
	for _, p := range preds {
		out = append(out, p.Nr)
	}
	return out
}

func firstN(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
