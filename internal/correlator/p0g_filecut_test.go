package correlator

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 8.7, П0(г): доля file-событий, которые НИ ОДНО file-правило не может
// совпасть по пути и op. Оценка сверху для «может совпасть»: условия на полях
// пути/операции вычисляются движком, условие на любом другом поле (comm,
// proc.args, exe_path, …) считается истинным. Группы только and/or (монотонны),
// поэтому ослабленное правило совпадает не реже настоящего: событие, не
// прошедшее ни одно ослабленное правило, не совпадёт ни с одним настоящим.
// Исключения только подавляют и в оценку не входят. Порог решения П1 — 50%.
//
//	W87_DUMP=server-logs/w86-b/events.jsonl go test ./internal/correlator -run TestP0gFileCut -v
var pathFields = map[string]bool{
	"filename": true, "fd.name": true, "fd.name_truncated": true, "flags": true,
	"mode": true, "op": true, "directory": true, "extension": true,
}

func (re *RuleEngine) mayMatchPath(e *types.Event, r *Rule, cache *eventFieldCache) bool {
	if r.legacyOpsOnly && e.File != nil && e.File.Op >= fileOpFirstMutation {
		return false
	}
	var leaf func(c *RuleCondition) bool
	leaf = func(c *RuleCondition) bool {
		f := c.fieldNorm
		if f == "" {
			f = normaliseFieldName(c.Field)
		}
		if !pathFields[f] {
			return true
		}
		return re.evaluateCondition(e, c, nil, cache)
	}
	var grp func(g *RuleConditionGroup) bool
	grp = func(g *RuleConditionGroup) bool {
		if len(g.Conditions) == 0 && len(g.SubGroups) == 0 {
			return true
		}
		if g.Operator == "or" {
			for i := range g.Conditions {
				if leaf(&g.Conditions[i]) {
					return true
				}
			}
			for i := range g.SubGroups {
				if grp(&g.SubGroups[i]) {
					return true
				}
			}
			return false
		}
		for i := range g.Conditions {
			if !leaf(&g.Conditions[i]) {
				return false
			}
		}
		for i := range g.SubGroups {
			if !grp(&g.SubGroups[i]) {
				return false
			}
		}
		return true
	}
	if r.ConditionGroup != nil {
		return grp(r.ConditionGroup)
	}
	return leaf(&r.Condition)
}

func pathClass(p string) string {
	if p == "" {
		return "(пусто)"
	}
	parts := strings.SplitN(strings.TrimPrefix(p, "/"), "/", 4)
	n := 2
	if len(parts) > 0 && (parts[0] == "proc" || parts[0] == "sys") {
		n = 2
	}
	if len(parts) < n {
		n = len(parts)
	}
	return "/" + strings.Join(parts[:n], "/")
}

func TestP0gFileCut(t *testing.T) {
	p := os.Getenv("W87_DUMP")
	if p == "" {
		t.Skip()
	}
	evs, err := LoadEventDump(p)
	require.NoError(t, err)
	rules, err := LoadRulesFromDir("../../rules")
	require.NoError(t, err)
	re := NewRuleEngine(rules)
	frs := re.byType[types.EventFileAccess]
	type k struct {
		class string
		op    uint8
	}
	type st struct {
		n, kept int
		rules   map[string]int
	}
	m := map[k]*st{}
	total, kept := 0, 0
	byOp := map[uint8][2]int{}
	for i := range evs {
		e := &evs[i]
		if e.Type != types.EventFileAccess || e.File == nil {
			continue
		}
		cache := &eventFieldCache{}
		key := k{pathClass(eventFilename(e, cache)), e.File.Op}
		s := m[key]
		if s == nil {
			s = &st{rules: map[string]int{}}
			m[key] = s
		}
		s.n++
		total++
		any := false
		for j := range frs {
			if re.mayMatchPath(e, &frs[j], cache) {
				any = true
				s.rules[frs[j].ID]++
			}
		}
		o := byOp[e.File.Op]
		o[0]++
		if any {
			s.kept++
			kept++
			o[1]++
		}
		byOp[e.File.Op] = o
	}
	fmt.Printf("P0G| file-правил=%d file-событий=%d могут совпасть=%d (%.1f%%) НЕ могут=%d (%.1f%%)\n",
		len(frs), total, kept, 100*float64(kept)/float64(total), total-kept, 100*float64(total-kept)/float64(total))
	for op, v := range byOp {
		fmt.Printf("P0G| op=%d: %d, не могут %d (%.1f%%)\n", op, v[0], v[0]-v[1], 100*float64(v[0]-v[1])/float64(v[0]))
	}
	var ks []k
	for kk := range m {
		ks = append(ks, kk)
	}
	sort.Slice(ks, func(i, j int) bool { return m[ks[i]].n > m[ks[j]].n })
	for _, kk := range ks[:min(len(ks), 40)] {
		s := m[kk]
		type rc struct {
			id string
			n  int
		}
		var rs []rc
		for id, n := range s.rules {
			rs = append(rs, rc{id, n})
		}
		sort.Slice(rs, func(a, b int) bool { return rs[a].n > rs[b].n })
		top := ""
		for _, r := range rs[:min(len(rs), 3)] {
			top += fmt.Sprintf(" %s×%d", r.id, r.n)
		}
		fmt.Printf("P0G| %-34s op=%d  n=%-7d не могут=%5.1f%%  кандидаты(%d):%s\n", kk.class, kk.op, s.n,
			100*float64(s.n-s.kept)/float64(s.n), len(s.rules), top)
	}
}

// ── П1: что из «не может совпасть» выразимо в ядре префиксами ─────────────────
//
// Верхняя оценка отсечения в ядре, если смотреть ТОЛЬКО на правила (профайлер не
// учитывается): множество префиксов пути и множество op выводятся из условий
// правил; условие, не сводимое к префиксу/имени/op (regex без якоря, contains,
// suffix, любое другое поле), открывает правило целиком (ANY).
type kPred struct {
	any    bool // путь не ограничен
	prefix []string
}

func kUnion(a, b kPred) kPred {
	if a.any || b.any {
		return kPred{any: true}
	}
	return kPred{prefix: append(append([]string{}, a.prefix...), b.prefix...)}
}

func kAnd(a, b kPred) kPred {
	switch {
	case a.any:
		return b
	case b.any:
		return a
	case len(a.prefix) <= len(b.prefix):
		return a
	default:
		return b
	}
}

func kLeaf(c *RuleCondition) kPred {
	f := c.fieldNorm
	if f == "" {
		f = normaliseFieldName(c.Field)
	}
	if f != "filename" && f != "fd.name" {
		return kPred{any: true}
	}
	switch c.opCode {
	case condOpPrefix, condOpIn, condOpEquals:
		return kPred{prefix: c.Values}
	case condOpRegex:
		var ps []string
		for _, v := range c.Values {
			lit := ""
			if strings.HasPrefix(v, "^/") {
				for _, r := range v[1:] {
					if strings.ContainsRune(`\.[](){}*+?|^$`, r) {
						break
					}
					lit += string(r)
				}
			}
			if len(lit) < 2 {
				return kPred{any: true}
			}
			ps = append(ps, lit)
		}
		return kPred{prefix: ps}
	}
	return kPred{any: true}
}

func kGroup(g *RuleConditionGroup) kPred {
	if len(g.Conditions) == 0 && len(g.SubGroups) == 0 {
		return kPred{any: true}
	}
	var parts []kPred
	for i := range g.Conditions {
		parts = append(parts, kLeaf(&g.Conditions[i]))
	}
	for i := range g.SubGroups {
		parts = append(parts, kGroup(&g.SubGroups[i]))
	}
	acc := parts[0]
	for _, p := range parts[1:] {
		if g.Operator == "or" {
			acc = kUnion(acc, p)
		} else {
			acc = kAnd(acc, p)
		}
	}
	return acc
}

func TestP1KernelExpressibleCut(t *testing.T) {
	p := os.Getenv("W87_DUMP")
	if p == "" {
		t.Skip()
	}
	evs, err := LoadEventDump(p)
	require.NoError(t, err)
	rules, err := LoadRulesFromDir("../../rules")
	require.NoError(t, err)
	re := NewRuleEngine(rules)
	frs := re.byType[types.EventFileAccess]
	var union kPred
	anyRules := 0
	for i := range frs {
		var kp kPred
		if frs[i].ConditionGroup != nil {
			kp = kGroup(frs[i].ConditionGroup)
		} else {
			kp = kLeaf(&frs[i].Condition)
		}
		if kp.any {
			anyRules++
		}
		if i == 0 {
			union = kp
		} else {
			union = kUnion(union, kp)
		}
	}
	total, kept := 0, 0
	for i := range evs {
		e := &evs[i]
		if e.Type != types.EventFileAccess || e.File == nil {
			continue
		}
		total++
		if union.any {
			kept++
			continue
		}
		fn := e.File.Path()
		if fn == "" {
			fn = e.File.Filename
		}
		for _, pre := range union.prefix {
			if strings.HasPrefix(fn, pre) {
				kept++
				break
			}
		}
	}
	fmt.Printf("P1| file-правил=%d, из них не сводимых к префиксу пути (ANY)=%d; объединение открыто=%v префиксов=%d\n", len(frs), anyRules, union.any, len(union.prefix))
	fmt.Printf("P1| событий %d, прошло бы префиксный отбор %d (%.1f%%), отсечено бы %d (%.1f%%) — БЕЗ учёта профайлера/drift/anomaly\n",
		total, kept, 100*float64(kept)/float64(total), total-kept, 100*float64(total-kept)/float64(total))
}

// Какие file-правила не сводятся к префиксу и чем (для вопроса владельцу по П1).
func TestP1WhyAny(t *testing.T) {
	if os.Getenv("W87_DUMP") == "" {
		t.Skip()
	}
	rules, err := LoadRulesFromDir("../../rules")
	require.NoError(t, err)
	re := NewRuleEngine(rules)
	frs := re.byType[types.EventFileAccess]
	why := map[string]int{}
	for i := range frs {
		var kp kPred
		if frs[i].ConditionGroup != nil {
			kp = kGroup(frs[i].ConditionGroup)
		} else {
			kp = kLeaf(&frs[i].Condition)
		}
		if !kp.any {
			continue
		}
		var fields []string
		var walk func(g *RuleConditionGroup)
		walk = func(g *RuleConditionGroup) {
			for j := range g.Conditions {
				c := &g.Conditions[j]
				fields = append(fields, normaliseFieldName(c.Field)+"/"+string(c.Op))
			}
			for j := range g.SubGroups {
				walk(&g.SubGroups[j])
			}
		}
		if frs[i].ConditionGroup != nil {
			walk(frs[i].ConditionGroup)
		} else {
			fields = append(fields, normaliseFieldName(frs[i].Condition.Field)+"/"+string(frs[i].Condition.Op))
		}
		sort.Strings(fields)
		why[strings.Join(fields, " ")]++
	}
	var ks []string
	for k := range why {
		ks = append(ks, k)
	}
	sort.Slice(ks, func(i, j int) bool { return why[ks[i]] > why[ks[j]] })
	for _, k := range ks[:min(len(ks), 12)] {
		fmt.Printf("P1WHY| %3d  %s\n", why[k], k)
	}
}
