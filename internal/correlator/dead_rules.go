package correlator

import (
	"sort"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 8.7, Д19 (№565): единый список правил, которые в ЭТОМ запуске не могут
// сработать. До Д19 агент называл при старте только четыре оси по отдельности
// (nr, file.op, proto, cgroup_esc) — 8 правил из 57; 49 правил на типах без
// продюсера (cloud_audit, gpu, io_uring, http_plaintext) молчали, и отчёты
// покрытия считали их живыми (завышение ≈ 9%).
//
// «Нет продюсера» бывает двух видов: в сборке (unproducibleEventTypes) и по
// конфигу (коллектор выключен) — второй вид передаёт вызывающий.

// Оси мёртвых правил (значения label axis).
const (
	DeadAxisEventType = "event_type"
	DeadAxisNr        = "nr"
	DeadAxisFileOp    = "file_op"
	DeadAxisProto     = "proto"
)

// DeadRule — одно правило, которое не может сработать, и почему.
type DeadRule struct {
	RuleID    string
	Axis      string
	EventType string
	Action    string
	Reason    string
}

// DeadRulesReport — загруженные, живые и мёртвые правила набора.
type DeadRulesReport struct {
	Loaded int
	Live   int
	Dead   []DeadRule     // по возрастанию RuleID
	ByAxis map[string]int // ось → число правил
}

// DeadIDs — множество id мёртвых правил.
func (r DeadRulesReport) DeadIDs() map[string]DeadRule {
	m := make(map[string]DeadRule, len(r.Dead))
	for _, d := range r.Dead {
		m[d.RuleID] = d
	}
	return m
}

// DeadRules собирает мёртвые правила по четырём осям. nrAllowlist == nil
// пропускает ось nr (фильтр ядра выключен). notProduced — типы событий, у
// которых по конфигу нет продюсера (тип → причина); типы без продюсера в сборке
// добавляются сами. Правило попадает в список один раз: по первой оси.
func (re *RuleEngine) DeadRules(nrAllowlist []int, notProduced map[types.EventType]string) DeadRulesReport {
	re.mu.RLock()
	loaded := len(re.rules)
	byID := make(map[string]*Rule, loaded)
	for i := range re.rules {
		byID[re.rules[i].ID] = &re.rules[i]
	}
	re.mu.RUnlock()

	rep := DeadRulesReport{Loaded: loaded, ByAxis: map[string]int{}}
	seen := map[string]bool{}
	add := func(id, axis, reason string) {
		if seen[id] {
			return
		}
		seen[id] = true
		d := DeadRule{RuleID: id, Axis: axis, Reason: reason}
		if r := byID[id]; r != nil {
			d.EventType = r.EventType.String()
			d.Action = string(r.Action)
		}
		rep.Dead = append(rep.Dead, d)
		rep.ByAxis[axis]++
	}

	for _, r := range re.UnproducibleEventTypeRules() {
		add(r.RuleID, DeadAxisEventType, r.Reason)
	}
	if len(notProduced) > 0 {
		re.mu.RLock()
		for i := range re.rules {
			if reason, ok := notProduced[re.rules[i].EventType]; ok {
				add(re.rules[i].ID, DeadAxisEventType, reason)
			}
		}
		re.mu.RUnlock()
	}
	if nrAllowlist != nil {
		for _, id := range re.UnreachableSyscallRules(nrAllowlist) {
			add(id, DeadAxisNr, "every numeric nr the rule names is outside the in-kernel syscall allowlist")
		}
	}
	for _, id := range re.UnreachableFileOpRules() {
		add(id, DeadAxisFileOp, "the rule's op condition names no file operation any hook produces")
	}
	for _, id := range re.UnreachableProtoRules() {
		add(id, DeadAxisProto, "the rule's proto condition names no protocol any hook produces")
	}

	sort.Slice(rep.Dead, func(i, j int) bool { return rep.Dead[i].RuleID < rep.Dead[j].RuleID })
	rep.Live = loaded - len(rep.Dead)
	return rep
}

// LiveRules возвращает правила набора без мёртвых — вход отчётов покрытия.
func LiveRules(rules []Rule, rep DeadRulesReport) []Rule {
	dead := rep.DeadIDs()
	out := make([]Rule, 0, len(rules))
	for _, r := range rules {
		if _, ok := dead[r.ID]; !ok {
			out = append(out, r)
		}
	}
	return out
}
