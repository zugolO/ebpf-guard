package correlator

import (
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 8.5, F0(а): инвентарь правил на номерах, которые F1 хочет отбирать в
// ядре предикатом по аргументу. Номер получает предикат, только если КАЖДОЕ
// syscall-правило, способное совпасть с этим номером, требует конъюнктивно
// один и тот же argN из конечного набора (op eq/in). Правило без условия на nr
// (или с nr not_in/neq) способно совпасть с ЛЮБЫМ номером — оно снимает
// предикат со всех.

// nrReach — множество номеров, с которыми условие может совпасть; any=true —
// ограничения нет.
type nrReach struct {
	any bool
	set map[int64]struct{}
}

func reachAny() nrReach { return nrReach{any: true} }

func (a nrReach) and(b nrReach) nrReach {
	switch {
	case a.any:
		return b
	case b.any:
		return a
	}
	out := nrReach{set: map[int64]struct{}{}}
	for n := range a.set {
		if _, ok := b.set[n]; ok {
			out.set[n] = struct{}{}
		}
	}
	return out
}

func (a nrReach) or(b nrReach) nrReach {
	if a.any || b.any {
		return reachAny()
	}
	out := nrReach{set: map[int64]struct{}{}}
	for n := range a.set {
		out.set[n] = struct{}{}
	}
	for n := range b.set {
		out.set[n] = struct{}{}
	}
	return out
}

func (a nrReach) has(n int64) bool {
	if a.any {
		return true
	}
	_, ok := a.set[n]
	return ok
}

func condNrReach(c RuleCondition) nrReach {
	if !namesLiteralValues(c, "nr") {
		return reachAny()
	}
	out := nrReach{set: map[int64]struct{}{}}
	for _, v := range c.Values {
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil {
			return reachAny()
		}
		out.set[n] = struct{}{}
	}
	return out
}

func groupNrReach(g *RuleConditionGroup) nrReach {
	isOr := strings.EqualFold(g.Operator, "or")
	var acc nrReach
	first := true
	add := func(r nrReach) {
		if first {
			acc, first = r, false
			return
		}
		if isOr {
			acc = acc.or(r)
		} else {
			acc = acc.and(r)
		}
	}
	for _, c := range g.Conditions {
		add(condNrReach(c))
	}
	for i := range g.SubGroups {
		add(groupNrReach(&g.SubGroups[i]))
	}
	if first {
		return reachAny()
	}
	return acc
}

func ruleNrReach(r Rule) nrReach {
	if r.ConditionGroup != nil {
		return groupNrReach(r.ConditionGroup)
	}
	return condNrReach(r.Condition)
}

// argNeed — какие argN условие требует конъюнктивно (argN → допустимые
// значения). Пусто — не требует ничего, что можно проверить в ядре.
type argNeed map[string]map[string]struct{}

func condArgNeed(c RuleCondition) argNeed {
	f := normaliseFieldName(c.Field)
	if !strings.HasPrefix(f, "arg") || len(f) != 4 || !namesLiteralValues(c, f) {
		return nil
	}
	vals := map[string]struct{}{}
	for _, v := range c.Values {
		vals[strings.TrimSpace(v)] = struct{}{}
	}
	return argNeed{f: vals}
}

func groupArgNeed(g *RuleConditionGroup) argNeed {
	var parts []argNeed
	for _, c := range g.Conditions {
		parts = append(parts, condArgNeed(c))
	}
	for i := range g.SubGroups {
		parts = append(parts, groupArgNeed(&g.SubGroups[i]))
	}
	if strings.EqualFold(g.Operator, "or") {
		// Ветвь без требования к аргументу снимает требование со всей группы;
		// иначе остаётся только тот argN, который требует каждая ветвь.
		var out argNeed
		for i, p := range parts {
			if len(p) == 0 {
				return nil
			}
			if i == 0 {
				out = argNeed{}
				for k, v := range p {
					out[k] = copySet(v)
				}
				continue
			}
			for k := range out {
				pv, ok := p[k]
				if !ok {
					delete(out, k)
					continue
				}
				for v := range pv {
					out[k][v] = struct{}{}
				}
			}
		}
		return out
	}
	out := argNeed{}
	for _, p := range parts {
		for k, v := range p {
			if cur, ok := out[k]; ok {
				for x := range cur {
					if _, keep := v[x]; !keep {
						delete(cur, x)
					}
				}
				continue
			}
			out[k] = copySet(v)
		}
	}
	return out
}

func copySet(s map[string]struct{}) map[string]struct{} {
	out := make(map[string]struct{}, len(s))
	for k := range s {
		out[k] = struct{}{}
	}
	return out
}

func ruleArgNeed(r Rule) argNeed {
	if r.ConditionGroup != nil {
		return groupArgNeed(r.ConditionGroup)
	}
	return condArgNeed(r.Condition)
}

func sortedKeys(s map[string]struct{}) []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestW85_F0_RuleInventoryOnHotNrs печатает, какие правила боевого набора
// способны совпасть с mmap/mprotect/bpf/arch_prctl и что они требуют от
// аргументов, и судит предпосылку F1: у номера есть общий конъюнктивный argN.
func TestW85_F0_RuleInventoryOnHotNrs(t *testing.T) {
	rules, err := LoadRulesFromDir("../../rules")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	hot := []struct {
		nr   int64
		name string
	}{{9, "mmap"}, {10, "mprotect"}, {321, "bpf"}, {158, "arch_prctl"}}

	var anyNr []string
	for _, r := range rules {
		if r.EventType == types.EventSyscall && ruleNrReach(r).any {
			anyNr = append(anyNr, r.ID)
		}
	}
	sort.Strings(anyNr)
	t.Logf("syscall-правил всего с любым nr (снимают предикат со всех номеров): %d %v", len(anyNr), anyNr)

	for _, h := range hot {
		var lines []string
		common := map[string]map[string]struct{}(nil)
		blocked := false
		for _, r := range rules {
			if r.EventType != types.EventSyscall || !ruleNrReach(r).has(h.nr) {
				continue
			}
			need := ruleArgNeed(r)
			var desc []string
			for _, k := range sortedKeyList(need) {
				desc = append(desc, k+"∈{"+strings.Join(sortedKeys(need[k]), ",")+"}")
			}
			if len(need) == 0 {
				desc = []string{"— (аргумент не требуется)"}
				blocked = true
			}
			lines = append(lines, "    "+r.ID+": "+strings.Join(desc, " ∧ "))
			if common == nil {
				common = argNeed{}
				for k, v := range need {
					common[k] = copySet(v)
				}
				continue
			}
			for k := range common {
				v, ok := need[k]
				if !ok {
					delete(common, k)
					continue
				}
				for x := range v {
					common[k][x] = struct{}{}
				}
			}
		}
		sort.Strings(lines)
		verdict := "предикат возможен по " + strings.Join(sortedKeyList(common), "/")
		if blocked || len(common) == 0 {
			verdict = "ПРЕДИКАТ НЕВОЗМОЖЕН"
		}
		t.Logf("nr %d (%s): правил %d — %s\n%s", h.nr, h.name, len(lines), verdict, strings.Join(lines, "\n"))
	}
}

func sortedKeyList(m argNeed) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
