package correlator

import "sort"

// Волна 8.6, заход B, шаг 2: порядок условий в группе — дешёвые раньше дорогих.
//
// evaluateConditionGroup идёт по условиям слева направо с коротким замыканием
// (and — до первого false, or — до первого true). Результат группы от порядка
// чистых условий не зависит, зависит цена: regex по пути, поставленный раньше
// сравнения eq/in/prefix по comm или op, гонится на каждом событии впустую.
// Загрузка переставляет условия по классу цены (стабильно) и меняет порядок
// только там, где он реально был «дорогое раньше дешёвого».
//
// Что НЕ переставляется — условия с побочным эффектом (readlink без кэша,
// счётчик exe_path_lookups_total, скан system.slice): exe_path, parent_exe_path,
// ancestor_exe_path, lineage, systemd_unit. Они — барьеры: условия сортируются
// только внутри отрезка между барьерами, поэтому множество чистых условий перед
// каждым барьером остаётся прежним, а значит, остаётся прежним и то, до какого
// барьера доходит вычисление. Контракт «exe_path последним» (память
// exe-path-is-the-antispoof-axis) не нарушается ни в какую сторону.

// reorderConditions — выключатель для сравнения «до/после» (бенч, мутационный
// тест). Читается при компиляции правил, не на горячем пути.
var reorderConditions = true

const (
	costCheap   = iota // eq/neq/in/not_in/prefix/suffix/gt/lt…: сравнение строк
	costMedium         // contains, CIDR
	costRegex          // regex
	costUnknown        // неизвестный оператор: как есть, после всего чистого
	costBarrier = -1
)

func isBarrierField(field string) bool {
	switch normaliseFieldName(field) {
	case "exe_path", "parent_exe_path", "ancestor_exe_path", "lineage", "lineage_exe_paths", "systemd_unit":
		return true
	}
	return false
}

func condCostClass(c *RuleCondition) int {
	if isBarrierField(c.Field) {
		return costBarrier
	}
	switch c.opCode {
	case condOpIn, condOpNotIn, condOpEquals, condOpNotEquals, condOpPrefix, condOpNotPrefix,
		condOpSuffix, condOpNotSuffix, condOpGT, condOpLT, condOpGTE, condOpLTE:
		return costCheap
	case condOpContains, condOpInCIDR, condOpNotInCIDR, condOpCapsGained, condOpCapsDropped:
		return costMedium
	case condOpRegex:
		return costRegex
	}
	return costUnknown
}

// orderGroupConditions переставляет Conditions одной группы (подгруппы
// обрабатывает compileGroupPatterns). Группа не пишется, если порядок не менялся.
func orderGroupConditions(g *RuleConditionGroup) {
	if !reorderConditions || len(g.Conditions) < 2 {
		return
	}
	perm := make([]int, 0, len(g.Conditions))
	changed := false
	start := 0
	flush := func(end int) {
		seg := make([]int, 0, end-start)
		for i := start; i < end; i++ {
			seg = append(seg, i)
		}
		sort.SliceStable(seg, func(a, b int) bool {
			return condCostClass(&g.Conditions[seg[a]]) < condCostClass(&g.Conditions[seg[b]])
		})
		for k, i := range seg {
			if i != start+k {
				changed = true
			}
		}
		perm = append(perm, seg...)
	}
	for i := range g.Conditions {
		if condCostClass(&g.Conditions[i]) == costBarrier {
			flush(i)
			perm = append(perm, i)
			start = i + 1
		}
	}
	flush(len(g.Conditions))
	if !changed {
		return
	}
	out := make([]RuleCondition, len(perm))
	for k, i := range perm {
		out[k] = g.Conditions[i]
	}
	g.Conditions = out
}
