package correlator

import (
	"context"
	"runtime/pprof"
	"sync/atomic"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 8.6, G0(а): метки pprof на проходе RuleEngine.EvaluateInto, чтобы CPU
// движка раскладывался по типу события (и, отдельно, по файлу правил и id
// правила) средствами `go tool pprof -tagfocus/-tagroot`, без догадок по
// именам функций.
//
// Цена на горячем пути: выключено — одна атомарная загрузка на событие;
// event_type — две установки меток на событие (контексты построены заранее);
// rule_file/rule_id — установка на КАЖДОЕ правило, это измерительный режим
// (server.pprof_rule_labels), на боевом агенте он не включается.
var (
	profileEventLabels atomic.Bool
	profileRuleLabels  atomic.Bool
	// profileTypeCtx[t] — контекст с меткой event_type для типа t. Заполняется
	// при включении (до публикации движка); без меток — nil.
	profileTypeCtx [byTypeSize]atomic.Pointer[context.Context]
)

// SetProfileLabels включает метки pprof. eventType — метка event_type на проходе
// по событию; rule — дополнительно rule_file и rule_id на проходе по правилу.
// Вызывать до создания движка: метки правил строятся в buildTypeIndex.
func SetProfileLabels(eventType, rule bool) {
	if eventType || rule {
		for t := 1; t < byTypeSize; t++ {
			ctx := pprof.WithLabels(context.Background(), pprof.Labels("stage", "rules", "event_type", types.EventType(t).String()))
			profileTypeCtx[t].Store(&ctx)
		}
	}
	profileEventLabels.Store(eventType || rule)
	profileRuleLabels.Store(rule)
}

// ProfileLabelsState — РАНТАЙМ-состояние меток (а не конфиг): метки типа события
// и метки правил. Читается экспортёром флагов рантайма (ночь 8.6 сверяет по нему).
func ProfileLabelsState() (eventLabels, ruleLabels bool) {
	return profileEventLabels.Load(), profileRuleLabels.Load()
}

// ruleProfileCtx строит контекст меток правила: event_type + rule_file + rule_id.
func ruleProfileCtx(r *Rule) *context.Context {
	file := r.sourceFile
	if file == "" {
		file = "unknown"
	}
	ctx := pprof.WithLabels(context.Background(), pprof.Labels(
		"stage", "rules", "event_type", r.EventType.String(), "rule_file", file, "rule_id", r.ID))
	return &ctx
}

// profileEnter ставит метки типа события и возвращает true, если их надо снять.
func profileEnter(t int) bool {
	if !profileEventLabels.Load() {
		return false
	}
	if p := profileTypeCtx[t].Load(); p != nil {
		pprof.SetGoroutineLabels(*p)
		return true
	}
	return false
}

func profileLeave() { pprof.SetGoroutineLabels(context.Background()) }
