package exporter

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Волна 8.7, Д19 (№565): правила, которые в этом запуске не могут сработать.
// Живое покрытие = загружено − мёртвое; серии пересоздаются на старте и каждой
// горячей перезагрузке правил.
var (
	RulesLoadedGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ebpf_guard_rules_loaded",
		Help: "Rules loaded into the engine, including rules that cannot fire in this run.",
	})
	RulesLiveGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ebpf_guard_rules_live",
		Help: "Loaded rules that can fire in this run: loaded minus ebpf_guard_rule_unreachable. Coverage reports count these.",
	})
	RuleUnreachable = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ebpf_guard_rule_unreachable",
		Help: "1 per loaded rule that cannot fire in this run; axis is event_type (no producer in the build or config), nr (outside the kernel syscall allowlist), file_op or proto (no hook produces the value).",
	}, []string{"rule_id", "axis", "event_type"})
	RulesUnreachableByAxis = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ebpf_guard_rules_unreachable",
		Help: "Number of loaded rules that cannot fire in this run, by axis.",
	}, []string{"axis"})
)

// DeadRuleSeries — одна мёртвая запись для метрики.
type DeadRuleSeries struct{ RuleID, Axis, EventType string }

var deadRulesMu sync.Mutex

// DeadRulesAxes — оси, для которых серия заводится нулём всегда: отсутствие
// серии читалось бы как «бинарь старше Д19», а не как «мёртвых нет».
var DeadRulesAxes = []string{"event_type", "nr", "file_op", "proto"}

// SetDeadRules заменяет серии мёртвых правил (старт и горячая перезагрузка).
func SetDeadRules(loaded, live int, dead []DeadRuleSeries) {
	deadRulesMu.Lock()
	defer deadRulesMu.Unlock()
	RulesLoadedGauge.Set(float64(loaded))
	RulesLiveGauge.Set(float64(live))
	RuleUnreachable.Reset()
	counts := map[string]int{}
	for _, d := range dead {
		RuleUnreachable.WithLabelValues(d.RuleID, d.Axis, d.EventType).Set(1)
		counts[d.Axis]++
	}
	for _, a := range DeadRulesAxes {
		RulesUnreachableByAxis.WithLabelValues(a).Set(float64(counts[a]))
	}
}
