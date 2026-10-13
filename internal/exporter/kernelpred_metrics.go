package exporter

import (
	"strconv"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Волна 8.5, F1/F2: приборы отбора syscall-событий в ядре.
//
// ebpf_guard_syscall_events_by_nr_total считает ПОСЛЕ кольца: после F1 он
// показывает уже отобранный поток. Чтобы база «до отбора» не терялась (вопрос 3
// этапа 0), ядро считает отброшенное предикатом, а userspace сводит счётчик в
// эту серию: сумма by_nr + kernel_filtered по номеру — число событий, которое
// доехало бы без F1 (enter и exit — отдельными событиями, как и в by_nr).
var (
	// SyscallEventsKernelFiltered — события номера, отброшенные предикатом ядра.
	// Ось nr — та же ограниченная декларацией, что у SyscallEventsByNR.
	SyscallEventsKernelFiltered = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_guard_syscall_events_kernel_filtered_total",
			Help: "Syscall events dropped by the in-kernel argument predicate (wave 8.5 F1), by syscall number on the same bounded axis as ebpf_guard_syscall_events_by_nr_total. events_by_nr + kernel_filtered = the stream as it was before the predicate.",
		},
		[]string{"nr"},
	)

	// SyscallCountsFolded — события, учтённые профайлером из счётчиков ядра.
	// outcome=applied: сложены в профиль нагрузки; skipped: нагрузка не
	// определена (предэкзековый comm без разрешения), как у поштучных событий.
	SyscallCountsFolded = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_guard_syscall_counts_folded_total",
			Help: "Kernel-counted (predicate-dropped) syscall events folded into the anomaly profile (wave 8.5 F2), by outcome (applied, skipped).",
		},
		[]string{"outcome"},
	)

	// SyscallCountsMapFill — заполненность карты счётчиков ядра при сливе:
	// живых записей / max_entries. Прибор вытеснений (LRU): у потолка пары
	// вытесняются и счёт пересоздаётся с единицы.
	SyscallCountsMapFill = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ebpf_guard_syscall_counts_map_fill_ratio",
		Help: "Live entries / max_entries of the kernel syscall_counts LRU map at the last drain (wave 8.5 F2). Near 1 means LRU evictions undercount the dropped events.",
	})

	// SyscallCountsMapLive — живых записей карты счётчиков на последнем сливе.
	SyscallCountsMapLive = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ebpf_guard_syscall_counts_map_live_entries",
		Help: "Live entries of the kernel syscall_counts map at the last drain (wave 8.5 F2).",
	})

	// SyscallSelfExcluded — события, которые ядро не отправило в кольцо из-за
	// самоисключения служебных bpf() агента (F3). Единица — события (enter и exit
	// по отдельности), как у by_nr; серия nr="321" заведена нулём сразу.
	SyscallSelfExcluded = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_guard_syscall_self_excluded_total",
			Help: "Syscall events the kernel did not forward because they were the agent's own service bpf() calls (lookup/update/get_next_key/batch), wave 8.5 F3. Destructive commands from the agent are not excluded.",
		},
		[]string{"nr"},
	)

	// KernelPredicateState — состояние предикатов ядра. Ровно одна серия
	// state=<причина> равна 1: active — предикаты запрограммированы; off_* —
	// карта пуста, номера идут целиком, как до F1. Отсутствие серии в /metrics
	// означает бинарь старше волны 8.5, а не «выключено».
	KernelPredicateState = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ebpf_guard_kernel_predicate_state",
			Help: "State of the in-kernel syscall argument predicates (wave 8.5 F1): exactly one state label is 1. active, off_config, off_training_consumer, off_no_counters, off_no_map, off_no_rules.",
		},
		[]string{"state"},
	)

	// KernelPredicateNr — у каких номеров сейчас есть предикат (1) и нет (0).
	KernelPredicateNr = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ebpf_guard_kernel_predicate_nr",
			Help: "1 when the syscall number currently has an in-kernel argument predicate, 0 when it is forwarded whole (wave 8.5 F1).",
		},
		[]string{"nr"},
	)
)

// KernelPredicateStates — полный перечень значений state; серии заводятся
// нулями, чтобы переход был виден как смена 1→0, а не как появление серии.
var KernelPredicateStates = []string{
	"active", "off_config", "off_training_consumer", "off_no_counters", "off_no_map", "off_no_rules",
}

// SetKernelPredicateState выставляет единственное активное состояние.
func SetKernelPredicateState(state string) {
	for _, s := range KernelPredicateStates {
		v := 0.0
		if s == state {
			v = 1
		}
		KernelPredicateState.WithLabelValues(s).Set(v)
	}
}

// SetKernelPredicateNrs выставляет gauge по номерам-кандидатам.
func SetKernelPredicateNrs(candidates []uint32, active map[uint32]bool) {
	for _, nr := range candidates {
		v := 0.0
		if active[nr] {
			v = 1
		}
		KernelPredicateNr.WithLabelValues(strconv.FormatUint(uint64(nr), 10)).Set(v)
	}
}

// RecordSyscallKernelFiltered добавляет n отброшенных ядром событий номера nr.
func RecordSyscallKernelFiltered(nr int64, n uint64) {
	SyscallEventsKernelFiltered.WithLabelValues(SyscallNRLabel(nr)).Add(float64(n))
}

func init() { SyscallSelfExcluded.WithLabelValues("321") }

// RecordSyscallSelfExcluded добавляет n исключённых событий bpf() агента.
func RecordSyscallSelfExcluded(n uint64) {
	SyscallSelfExcluded.WithLabelValues("321").Add(float64(n))
}

// SetSyscallCountsOccupancy выставляет заполненность карты счётчиков.
func SetSyscallCountsOccupancy(live, max uint32) {
	SyscallCountsMapLive.Set(float64(live))
	if max > 0 {
		SyscallCountsMapFill.Set(float64(live) / float64(max))
	}
}

// RulesLoadErrors — файлы каталога правил, пропущенные загрузчиком (плохой
// YAML, провал валидации, дубль id). Растёт на каждой попытке загрузки — старте
// и каждой горячей перезагрузке; ось file ограничена числом файлов каталога.
var RulesLoadErrors = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "ebpf_guard_rules_load_errors_total",
		Help: "Rule files skipped by the tolerant loader at startup or hot reload (unreadable, invalid or duplicate rule IDs); the remaining files still load.",
	},
	[]string{"file"},
)

// RulesFileStale — 1, пока для файла каталога правил держится ПОСЛЕДНЯЯ УДАЧНАЯ
// версия, потому что текущее содержимое не загрузилось (№557): правила файла
// живы, но не из того, что лежит на диске. 0 — файл вновь загружается нормально
// (или исчез из каталога). Ось file ограничена файлами, которые когда-либо стали плохими.
var RulesFileStale = promauto.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "ebpf_guard_rules_file_stale",
		Help: "1 while the hot reload holds the last good version of a rule file because its current content failed to load; 0 once it loads again.",
	},
	[]string{"file"},
)

var (
	staleMu       sync.Mutex
	staleReported = map[string]bool{}
)

// SetRulesFileStale выставляет gauge по результату очередной загрузки каталога:
// files — файлы, которые держатся старой версией СЕЙЧАС. Ранее отмеченные и
// больше не державшиеся сбрасываются в 0.
func SetRulesFileStale(files []string) {
	staleMu.Lock()
	defer staleMu.Unlock()
	now := make(map[string]bool, len(files))
	for _, f := range files {
		now[f] = true
		RulesFileStale.WithLabelValues(f).Set(1)
	}
	for f := range staleReported {
		if !now[f] {
			RulesFileStale.WithLabelValues(f).Set(0)
		}
	}
	staleReported = now
}
