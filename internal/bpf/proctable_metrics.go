package bpf

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Состояния таблицы процессов (метка state серии ebpf_guard_proc_table_state).
const (
	ProcTableActive        = "active"
	ProcTableOffConfig     = "off_config"      // выключена конфигом (bpf.proc_table.enabled)
	ProcTableOffDryRun     = "off_dry_run"     // --dry-run: ядра нет
	ProcTableOffLoadFailed = "off_load_failed" // объект не загрузился / хуки не привязались (верификатор, нет BTF)
	ProcTableOffNoLineage  = "off_no_lineage"  // трекер родословной выключен профайлером
)

var procTableStates = []string{ProcTableActive, ProcTableOffConfig, ProcTableOffDryRun, ProcTableOffLoadFailed, ProcTableOffNoLineage}

var procTableState = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Name: "ebpf_guard_proc_table_state",
	Help: "In-kernel process table (wave 8.5, P1): 1 on the current state. off_* means the LineageTracker stays on its Go maps and /proc.",
}, []string{"state"})

func init() {
	for _, s := range procTableStates {
		procTableState.WithLabelValues(s)
	}
}

// ProcTableStateGauge — серия состояния (для тестов и проверки).
func ProcTableStateGauge(state string) prometheus.Gauge { return procTableState.WithLabelValues(state) }

// SetProcTableState выставляет единственное активное состояние.
func SetProcTableState(state string) {
	for _, s := range procTableStates {
		v := 0.0
		if s == state {
			v = 1
		}
		procTableState.WithLabelValues(s).Set(v)
	}
}

// ProcTableStats — то, что собирает коллектор метрик (ProcTable его выполняет).
type ProcTableStats interface {
	Counters() (map[string]uint64, error)
	LookupErrors() uint64
	Capacity() (live, exited uint32)
}

// procTableCollector читает счётчики ядра на скрейпе (ничего не опрашивает по таймеру).
type procTableCollector struct {
	t      ProcTableStats
	events *prometheus.Desc
	errs   *prometheus.Desc
	cap    *prometheus.Desc
}

// RegisterProcTableMetrics регистрирует серии таблицы процессов: исходы хуков в ядре
// (ebpf_guard_proc_table_events_total{event}), сбои чтения и ёмкости карт.
func RegisterProcTableMetrics(reg prometheus.Registerer, t ProcTableStats) error {
	c := &procTableCollector{
		t:      t,
		events: prometheus.NewDesc("ebpf_guard_proc_table_events_total", "Outcomes of the in-kernel process-table hooks (fork_ok, fork_live_full, exec_updated, exec_created, exec_live_full, exit_moved, exit_no_record, exited_inserts). fork_live_full/exec_live_full are records lost to a full proc_live; exited_inserts above the proc_exited capacity within the TTL means the LRU is evicting records the TTL would still keep.", []string{"event"}, nil),
		errs:   prometheus.NewDesc("ebpf_guard_proc_table_lookup_errors_total", "Failed (not 'absent') reads of the process-table maps.", nil, nil),
		cap:    prometheus.NewDesc("ebpf_guard_proc_table_capacity", "Capacity of the process-table maps in entries (live, exited).", []string{"map"}, nil),
	}
	return reg.Register(c)
}

func (c *procTableCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.events
	ch <- c.errs
	ch <- c.cap
}

func (c *procTableCollector) Collect(ch chan<- prometheus.Metric) {
	if cs, err := c.t.Counters(); err == nil {
		for _, name := range procTableCounterNames {
			ch <- prometheus.MustNewConstMetric(c.events, prometheus.CounterValue, float64(cs[name]), name)
		}
	}
	ch <- prometheus.MustNewConstMetric(c.errs, prometheus.CounterValue, float64(c.t.LookupErrors()))
	live, exited := c.t.Capacity()
	ch <- prometheus.MustNewConstMetric(c.cap, prometheus.GaugeValue, float64(live), "live")
	ch <- prometheus.MustNewConstMetric(c.cap, prometheus.GaugeValue, float64(exited), "exited")
}
