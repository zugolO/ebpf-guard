package exporter

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Волна 8.6, заход C: флаги РАНТАЙМА для входного сторожа ночи. Конфиг говорит,
// что просили; эти серии говорят, что включено в процессе (память
// entry-guard-must-read-runtime-not-config): ночь с включённым дампом событий
// или метками правил измеряла бы не продукт.
var (
	// RuntimeFlag — булевы флаги измерительных режимов и вкладов в цену.
	// flag ∈ event_dump, pprof_event_labels, pprof_rule_labels, enable_pprof,
	// arg_predicates_config.
	RuntimeFlag = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ebpf_guard_runtime_flag",
			Help: "Runtime state of measurement/cost flags in this process (1 = on). Wave 8.6.",
		},
		[]string{"flag"},
	)
	// RuntimeCountersInterval — интервал слива счётчиков ядра F2, секунды.
	RuntimeCountersInterval = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ebpf_guard_runtime_counters_interval_seconds",
		Help: "Effective interval of the kernel syscall counters drain (wave 8.5 F2), seconds (configured value, or the default when unset). Wave 8.6.",
	})
	// RuntimeBlockBackend — единственная серия backend=<значение> равна 1.
	RuntimeBlockBackend = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ebpf_guard_runtime_block_backend",
			Help: "Effective enforcer block backend of this process (exactly one backend label is 1). Wave 8.6.",
		},
		[]string{"backend"},
	)
)

// SetRuntimeFlag выставляет булев флаг рантайма.
func SetRuntimeFlag(flag string, on bool) {
	v := 0.0
	if on {
		v = 1
	}
	RuntimeFlag.WithLabelValues(flag).Set(v)
}
