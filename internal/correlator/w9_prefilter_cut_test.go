package correlator

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Офлайн-замер к волне предфильтра (после 8.8, до волны 9): какую долю потока,
// дошедшего до движка, отсёк бы КОРРЕКТНЫЙ предфильтр в ядре, выведенный из
// правил. Корректный — необходимое условие: лист условия, который ядро проверить
// не может, заменяется истиной (И теряет конъюнкт, ИЛИ с таким листом — истина),
// исключения, порог и сэмплер правила отбрасываются. Ослабленное правило
// совпадает со всем, с чем совпадает исходное, — это проверяет сторож тождества
// ниже на каждом событии дампа.
//
// Уровни (что ядро умеет проверить):
//
// На всех уровнях непустой proc.args у syscall-правила замещается выводом F1
// (nr ∈ ProcArgsSyscallNrs, сторож TestW85_F1_ProcArgsNrsMatchCollector).
//
//	L1 — хеш/LPM по статическим картам: тип, op, flags, mode, uid, nr, argN, ret,
//	     порты/proto/family/адреса, comm, parent_comm; путь — eq/in/prefix;
//	     exe_path — eq/in (набор dev/ino из таблицы процессов). Отрицания по этим
//	     полям — тот же промах хеша, точны.
//	L2 — плюс suffix/contains/directory/extension по пути и comm, prefix по
//	     exe_path, «в контейнере» (container.id eq/neq "") — карта cgroup id.
//	L2L — реалистичный предел: плюс regex по пути, замещённый своими
//	     обязательными литералами (КНФ-наборы G1, requiredLiteralSets): «в пути
//	     есть хоть один литерал каждого набора» — поиск подстрок в BPF.
//	     Непригодный набор (usableLiteralSet) выбрасывается — это расширение.
//	L3 — потолок: плюс regex по строкам, видимым в ядре (путь, comm, exe_path).
//	     В BPF regex не исполнить — это верхняя граница любой схемы на этих осях.
//
// Вход — дамп движка (server-logs/w86-b/events.jsonl, 36 мин idle k3s-ноды,
// event_dump_every 1, file_rate 1): поток ПОСЛЕ уже действующих фильтров ядра
// (предикаты nr F1, path_denylist), то есть замер — прибавка сверх них.
// Профайлер, дрейф и lineage читают поток помимо правил: их цена отсечения
// здесь не считается.
//
//	W86_DUMP=../../server-logs/w86-b/events.jsonl go test ./internal/correlator \
//	  -run TestW9PrefilterCut -v -timeout 30m
func TestW9PrefilterCut(t *testing.T) {
	p := os.Getenv("W86_DUMP")
	if p == "" {
		t.Skip("W86_DUMP не задан")
	}
	evs, err := LoadEventDump(p)
	require.NoError(t, err)
	rules, err := LoadRulesFromDir("../../rules")
	require.NoError(t, err)
	base := NewRuleEngine(rules)

	levels := []struct {
		name  string
		lvl   int
		lits  bool
		short bool     // L2L1: однобайтовые наборы (пробел, скобка) тоже ищутся
		skip  []string // правила, выключенные в варианте
	}{{"L1", 1, false, false, nil}, {"L2", 2, false, false, nil}, {"L2L", 2, true, false, nil},
		{"L2L1", 2, true, true, nil},
		{"L3", 3, false, false, nil}}

	byType := map[types.EventType]int{}
	for i := range evs {
		byType[evs[i].Type]++
	}

	// Исходные совпадения по событию: правило → есть алерт.
	baseHit := make([]map[string]struct{}, len(evs))
	for i := range evs {
		base.EvaluateInto(evs[i], func(a types.Alert) {
			if baseHit[i] == nil {
				baseHit[i] = map[string]struct{}{}
			}
			baseHit[i][a.RuleID] = struct{}{}
		})
	}

	baseNs := engineNsOver(base, evs, nil)
	t.Logf("поток: %d событий; по типам %v; движок целиком %.0f мс", len(evs), byType, baseNs/1e6)

	for _, lv := range levels {
		relaxed, openers := relaxRules(rules, prefilterTransform(lv.lvl, lv.lits, lv.short))
		if len(lv.skip) > 0 {
			kept := relaxed[:0]
			for _, r := range relaxed {
				if !contains(lv.skip, r.ID) {
					kept = append(kept, r)
				}
			}
			relaxed = kept
		}
		re := NewRuleEngine(relaxed)
		pass := make([]bool, len(evs))
		passByType := map[types.EventType]int{}
		perRule := map[string]int{}
		// единственный пропускающий: событие ушло бы в userspace только из-за него
		soleRule := map[string]int{}
		violations := 0
		var violSample []string
		for i := range evs {
			hit := map[string]struct{}{}
			re.EvaluateInto(evs[i], func(a types.Alert) { hit[a.RuleID] = struct{}{} })
			if len(hit) > 0 {
				pass[i] = true
				passByType[evs[i].Type]++
				for id := range hit {
					perRule[id]++
					if len(hit) == 1 {
						soleRule[id]++
					}
				}
			}
			for id := range baseHit[i] {
				if contains(lv.skip, id) {
					continue
				}
				if _, ok := hit[id]; !ok {
					violations++
					if len(violSample) < 5 {
						violSample = append(violSample, fmt.Sprintf("%s на событии %d", id, i))
					}
				}
			}
		}
		require.Zerof(t, violations, "%s: ослабленный набор потерял совпадения: %v", lv.name, violSample)

		cutNs := engineNsOver(base, evs, pass)
		passed := 0
		for _, v := range pass {
			if v {
				passed++
			}
		}
		t.Logf("=== %s: пропущено %d из %d (%.1f%%), отсечено %.1f%%; CPU движка на пропущенных %.1f%% от целого",
			lv.name, passed, len(evs), pct(passed, len(evs)), 100-pct(passed, len(evs)), 100*cutNs/baseNs)
		for _, ty := range sortedTypes(byType) {
			t.Logf("  тип %-3d: %7d → %7d (отсечено %.1f%%)", ty, byType[ty], passByType[ty], 100-pct(passByType[ty], byType[ty]))
		}
		for _, ty := range sortedTypes(byType) {
			if ids := openers[ty]; len(ids) > 0 {
				t.Logf("  открывают тип %d целиком (%d правил): %s", ty, len(ids), strings.Join(firstN(ids, 12), ", "))
			}
		}
		t.Logf("  топ правил по пропущенным событиям: %s", topRules(perRule, 12))
		t.Logf("  топ единственных пропускающих: %s", topRules(soleRule, 12))
		if lv.lits {
			t.Logf("  литералов для поиска в ядре: %s", literalBudget(rules))
		}
		t.Logf("  остаток file по op: %s", fileOpMix(evs, pass))
	}
}

// prefilterKeeps — может ли ядро проверить лист на уровне lvl точно.
func prefilterKeeps(c RuleCondition, lvl int) bool {
	f := normaliseFieldName(c.Field)
	op := string(c.Op)
	exact := map[string]bool{"in": true, "not_in": true, "eq": true, "equals": true, "neq": true, "not_equals": true}
	num := map[string]bool{"gt": true, "lt": true, "gte": true, "lte": true}
	switch f {
	case "op", "flags", "mode", "uid", "nr", "arg0", "arg1", "arg2", "arg3", "arg4", "arg5", "ret",
		"dport", "sport", "proto", "family", "pid", "ppid":
		return exact[op] || num[op]
	case "daddr", "saddr":
		return exact[op] || op == "in_cidr" || op == "not_in_cidr"
	case "caps":
		return op == "caps_gained" || op == "caps_dropped"
	case "comm", "parent_comm", "filename", "fd.name":
		switch {
		case exact[op] || op == "prefix" || op == "not_prefix":
			return true
		case op == "suffix" || op == "not_suffix" || op == "contains":
			return lvl >= 2
		case op == "regex":
			return lvl >= 3
		}
	case "directory", "extension":
		return lvl >= 2 && (exact[op] || op == "prefix" || op == "suffix")
	case "exe_path":
		switch {
		case exact[op]:
			return true
		case op == "prefix" || op == "not_prefix" || op == "suffix" || op == "contains":
			return lvl >= 2
		case op == "regex":
			return lvl >= 3
		}
	case "container_id":
		if lvl >= 2 && (op == "eq" || op == "equals" || op == "neq" || op == "not_equals") &&
			len(c.Values) == 1 && c.Values[0] == "" {
			return true
		}
	}
	return false
}

// relaxRules строит ослабленный набор и для каждого типа — правила, ставшие
// истиной (открывают тип целиком, кроме ворот legacyOpsOnly).
func relaxRules(rules []Rule, tr condTransform) ([]Rule, map[types.EventType][]string) {
	out := make([]Rule, 0, len(rules))
	openers := map[types.EventType][]string{}
	for _, r := range rules {
		if r.Synthetic || r.Action == ActionDrop {
			continue
		}
		var g RuleConditionGroup
		var isTrue bool
		if r.ConditionGroup != nil {
			g, isTrue = relaxGroup(*r.ConditionGroup, r.EventType, tr)
		} else {
			g, isTrue = relaxGroup(RuleConditionGroup{Operator: "and", Conditions: []RuleCondition{r.Condition}}, r.EventType, tr)
		}
		if isTrue {
			g = RuleConditionGroup{Operator: "and"}
			openers[r.EventType] = append(openers[r.EventType], r.ID)
		}
		n := Rule{
			ID: r.ID, Name: r.Name, EventType: r.EventType, Severity: r.Severity,
			Action: ActionAlert, ConditionGroup: &g,
		}
		// Ворота legacyOpsOnly считаются по ИСХОДНОМУ правилу: ослабление не
		// должно ни открыть мутации правилу без op, ни закрыть их правилу с op.
		if r.EventType == types.EventFileAccess && ruleNamesFileOp(&r) && !ruleNamesFileOpGroup(&g) {
			n.ConditionGroup = &RuleConditionGroup{Operator: "and", SubGroups: []RuleConditionGroup{g},
				Conditions: []RuleCondition{{Field: "op", Op: OpNotIn, Values: []string{"__w9_none__"}}}}
		}
		out = append(out, n)
	}
	for ty := range openers {
		sort.Strings(openers[ty])
	}
	return out, openers
}

func ruleNamesFileOpGroup(g *RuleConditionGroup) bool {
	r := Rule{EventType: types.EventFileAccess, ConditionGroup: g}
	return ruleNamesFileOp(&r)
}

// condTransform — чем ядро заменяет лист: подгруппой (проверяемое необходимое
// условие) или истиной (isTrue).
type condTransform func(c RuleCondition, ty types.EventType) (g RuleConditionGroup, isTrue bool)

func prefilterTransform(lvl int, lits, short bool) condTransform {
	return func(c RuleCondition, ty types.EventType) (RuleConditionGroup, bool) {
		plain := RuleCondition{Field: c.Field, Op: c.Op, Values: c.Values}
		if prefilterKeeps(c, lvl) {
			return RuleConditionGroup{Operator: "and", Conditions: []RuleCondition{plain}}, false
		}
		f := normaliseFieldName(c.Field)
		if f == "proc.args" && ty == types.EventSyscall && condRejectsEmptyProcArgs(c) {
			vals := make([]string, 0, len(ProcArgsSyscallNrs))
			for _, n := range ProcArgsSyscallNrs {
				vals = append(vals, fmt.Sprint(n))
			}
			return RuleConditionGroup{Operator: "and", Conditions: []RuleCondition{{Field: "nr", Op: OpIn, Values: vals}}}, false
		}
		if lits && c.Op == OpRegex && (f == "filename" || f == "fd.name") && len(c.Values) > 0 {
			// Значения regex — ИЛИ шаблонов; шаблон — И своих наборов.
			or := RuleConditionGroup{Operator: "or"}
			for _, pat := range c.Values {
				and := RuleConditionGroup{Operator: "and"}
				for _, set := range requiredLiteralSets(pat) {
					if usableLiteralSet(set) || (short && kernelShortSet(set)) {
						and.Conditions = append(and.Conditions, RuleCondition{Field: c.Field, Op: OpContains, Values: set})
					}
				}
				if len(and.Conditions) == 0 {
					return RuleConditionGroup{}, true
				}
				or.SubGroups = append(or.SubGroups, and)
			}
			return or, false
		}
		return RuleConditionGroup{}, true
	}
}

func relaxGroup(g RuleConditionGroup, ty types.EventType, tr condTransform) (RuleConditionGroup, bool) {
	isOr := strings.EqualFold(g.Operator, "or")
	out := RuleConditionGroup{Operator: g.Operator}
	for _, c := range g.Conditions {
		rg, t := tr(c, ty)
		if t {
			if isOr {
				return RuleConditionGroup{}, true
			}
			continue
		}
		if len(rg.SubGroups) == 0 && len(rg.Conditions) == 1 {
			out.Conditions = append(out.Conditions, rg.Conditions[0])
		} else {
			out.SubGroups = append(out.SubGroups, rg)
		}
	}
	for _, sg := range g.SubGroups {
		rg, t := relaxGroup(sg, ty, tr)
		if t {
			if isOr {
				return RuleConditionGroup{}, true
			}
			continue
		}
		out.SubGroups = append(out.SubGroups, rg)
	}
	if len(out.Conditions) == 0 && len(out.SubGroups) == 0 {
		return RuleConditionGroup{}, true
	}
	return out, false
}

// engineNsOver — время исходного движка на событиях (mask == nil — на всех),
// минимум из трёх проходов.
func engineNsOver(re *RuleEngine, evs []types.Event, mask []bool) float64 {
	sink := func(types.Alert) {}
	best := 0.0
	for k := 0; k < 3; k++ {
		st := time.Now()
		for i := range evs {
			if mask == nil || mask[i] {
				re.EvaluateInto(evs[i], sink)
			}
		}
		d := float64(time.Since(st).Nanoseconds())
		if k == 0 || d < best {
			best = d
		}
	}
	return best
}

func pct(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return 100 * float64(a) / float64(b)
}

func sortedTypes(m map[types.EventType]int) []types.EventType {
	out := make([]types.EventType, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func firstN(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(append([]string{}, s[:n]...), fmt.Sprintf("… ещё %d", len(s)-n))
}

func topRules(m map[string]int, n int) string {
	type kv struct {
		k string
		v int
	}
	var s []kv
	for k, v := range m {
		s = append(s, kv{k, v})
	}
	sort.Slice(s, func(i, j int) bool { return s[i].v > s[j].v || (s[i].v == s[j].v && s[i].k < s[j].k) })
	var parts []string
	for i := 0; i < len(s) && i < n; i++ {
		parts = append(parts, fmt.Sprintf("%s=%d", s[i].k, s[i].v))
	}
	return strings.Join(parts, " ")
}

func fileOpMix(evs []types.Event, pass []bool) string {
	all, kept := map[uint8]int{}, map[uint8]int{}
	for i := range evs {
		if evs[i].File == nil {
			continue
		}
		all[evs[i].File.Op]++
		if pass[i] {
			kept[evs[i].File.Op]++
		}
	}
	var ops []int
	for op := range all {
		ops = append(ops, int(op))
	}
	sort.Ints(ops)
	var parts []string
	for _, op := range ops {
		parts = append(parts, fmt.Sprintf("op%d %d→%d", op, all[uint8(op)], kept[uint8(op)]))
	}
	return strings.Join(parts, " ")
}

// literalBudget — сколько литералов и наборов пришлось бы искать в пути в ядре
// на уровне L2L (по всем file-правилам с regex по пути).
func literalBudget(rules []Rule) string {
	lits := map[string]struct{}{}
	sets, pats, bare := 0, 0, 0
	maxLen := 0
	for i := range rules {
		r := &rules[i]
		if r.EventType != types.EventFileAccess || r.Synthetic || r.Action == ActionDrop {
			continue
		}
		for _, c := range extractAllRuleConditions(r) {
			f := normaliseFieldName(c.Field)
			if c.Op != OpRegex || (f != "filename" && f != "fd.name") {
				continue
			}
			for _, pat := range c.Values {
				pats++
				got := false
				for _, set := range requiredLiteralSets(pat) {
					if !usableLiteralSet(set) {
						continue
					}
					got = true
					sets++
					for _, l := range set {
						lits[l] = struct{}{}
						if len(l) > maxLen {
							maxLen = len(l)
						}
					}
				}
				if !got {
					bare++
				}
			}
		}
	}
	return fmt.Sprintf("шаблонов %d (без пригодного набора %d), наборов %d, различных литералов %d, длиннейший %d байт",
		pats, bare, sets, len(lits), maxLen)
}

// kernelShortSet — набор, который G1 отвергает за короткие литералы, но ядру
// дёшев: все члены непустые, без U+FFFD, не шире prefilterMaxAlternatives.
// Поиск байта в пути — один проход, без автомата.
func kernelShortSet(set []string) bool {
	if len(set) == 0 || len(set) > prefilterMaxAlternatives {
		return false
	}
	for _, l := range set {
		if l == "" || strings.ContainsRune(l, utf8.RuneError) {
			return false
		}
	}
	return true
}
