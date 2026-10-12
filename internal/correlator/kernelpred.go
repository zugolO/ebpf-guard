package correlator

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 8.5, F1: предикаты аргументов в ядре, ГЕНЕРИРУЕМЫЕ из загруженных
// правил. Правила — единственный источник истины: ручных списков номеров и
// значений в C нет, а правка правила, расширившая условие, снимает предикат
// без правки C (см. DeriveKernelPredicates и мутационный тест).
//
// Предикат — НЕОБХОДИМОЕ условие совпадения: событие номера nr уходит в
// userspace, только если хоть одно syscall-правило, способное совпасть с nr,
// может совпасть с таким значением аргумента. Меньше события — не результат
// (правило волны 1): предикат обязан не терять совпадения, и это проверяет
// тест тождества на случайных событиях.

// KernelPredMaxTerms — сколько конъюнктов (argN ∈ набор) ядро проверяет на
// номер. Должно совпадать с EG_PRED_TERMS в bpf/common.h.
const KernelPredMaxTerms = 2

// KernelPredMaxValues — размер набора значений одного конъюнкта. Должно
// совпадать с EG_PRED_VALUES в bpf/common.h.
const KernelPredMaxValues = 8

// ProcArgsSyscallNrs — номера, на которых коллектор заполняет proc.args
// (internal/collector/syscall.go: execve и execveat). Правило, которое
// конъюнктивно требует НЕПУСТОЙ proc.args, не может совпасть ни с каким другим
// номером; на этом выводе держится возможность предиката вообще — без него 68
// exec-правил без условия на nr снимали бы предикат со всех номеров. Сторож
// TestW85_F1_ProcArgsNrsMatchCollector держит константу равной коллектору:
// если proc.args начнёт заполняться на других номерах, вывод ломается молча.
var ProcArgsSyscallNrs = []int64{59, 322}

// KernelPredTerm — один конъюнкт предиката: arg[Arg] ∈ Values.
type KernelPredTerm struct {
	Arg    uint8
	Values []uint64
}

// KernelPredicate — предикат номера Nr: событие нужно userspace, только если
// выполнены ВСЕ Terms. Пустой Terms для номера не бывает: номер без
// предиката не попадает в результат.
type KernelPredicate struct {
	Nr    uint32
	Terms []KernelPredTerm
}

// Matches — эталонная проверка предиката в Go (зеркало ядерной), на ней
// стоит тест тождества. args — как в types.SyscallEvent.Args.
func (p KernelPredicate) Matches(args [6]uint64) bool {
	for _, t := range p.Terms {
		ok := false
		for _, v := range t.Values {
			if args[t.Arg] == v {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// KernelPredDerivation — результат вывода: предикаты и причины, по которым
// номер-кандидат предиката не получил.
type KernelPredDerivation struct {
	Predicates []KernelPredicate
	// Blockers: кандидат → правила, способные совпасть с ним и не
	// требующие от аргументов ничего проверяемого в ядре (или требующие
	// несовместимое с другими правилами номера). Номер из Blockers идёт в
	// userspace целиком, как до F1.
	Blockers map[uint32][]string
}

// nrReach — множество номеров, с которыми условие может совпасть: либо
// конечное (cofinite=false, set — сами номера), либо дополнение конечного
// (cofinite=true, set — исключённые). Пересечение и объединение замкнуты.
type nrReach struct {
	cofinite bool
	set      map[int64]struct{}
}

func reachAll() nrReach { return nrReach{cofinite: true, set: map[int64]struct{}{}} }

func reachOf(nrs []int64) nrReach {
	s := make(map[int64]struct{}, len(nrs))
	for _, n := range nrs {
		s[n] = struct{}{}
	}
	return nrReach{set: s}
}

func (a nrReach) has(n int64) bool {
	_, in := a.set[n]
	return in != a.cofinite
}

func (a nrReach) and(b nrReach) nrReach {
	switch {
	case !a.cofinite && !b.cofinite:
		out := map[int64]struct{}{}
		for n := range a.set {
			if _, ok := b.set[n]; ok {
				out[n] = struct{}{}
			}
		}
		return nrReach{set: out}
	case !a.cofinite && b.cofinite:
		out := map[int64]struct{}{}
		for n := range a.set {
			if _, ex := b.set[n]; !ex {
				out[n] = struct{}{}
			}
		}
		return nrReach{set: out}
	case a.cofinite && !b.cofinite:
		return b.and(a)
	}
	out := map[int64]struct{}{}
	for n := range a.set {
		out[n] = struct{}{}
	}
	for n := range b.set {
		out[n] = struct{}{}
	}
	return nrReach{cofinite: true, set: out}
}

func (a nrReach) or(b nrReach) nrReach {
	switch {
	case !a.cofinite && !b.cofinite:
		out := map[int64]struct{}{}
		for n := range a.set {
			out[n] = struct{}{}
		}
		for n := range b.set {
			out[n] = struct{}{}
		}
		return nrReach{set: out}
	case !a.cofinite && b.cofinite:
		// (B-комплемент) ∪ A: исключения B, которых нет в A.
		out := map[int64]struct{}{}
		for n := range b.set {
			if _, ok := a.set[n]; !ok {
				out[n] = struct{}{}
			}
		}
		return nrReach{cofinite: true, set: out}
	case a.cofinite && !b.cofinite:
		return b.or(a)
	}
	out := map[int64]struct{}{}
	for n := range a.set {
		if _, ok := b.set[n]; ok {
			out[n] = struct{}{}
		}
	}
	return nrReach{cofinite: true, set: out}
}

// condRejectsEmptyProcArgs: условие по proc.args, которое НЕ принимает пустую
// строку. Только такие операции дают право вывести «правило требует
// заполненный proc.args». Остальное (not_prefix, not_in, неизвестные
// операции) — консервативно «может принять пустую».
func condRejectsEmptyProcArgs(c RuleCondition) bool {
	if len(c.Values) == 0 {
		return false
	}
	switch c.Op {
	case OpRegex:
		for _, v := range c.Values {
			re, err := regexp.Compile(v)
			if err != nil || re.MatchString("") {
				return false
			}
		}
		return true
	case OpPrefix, OpSuffix, OpContains:
		for _, v := range c.Values {
			if v == "" {
				return false
			}
		}
		return true
	case OpIn, OpEquals, "eq":
		for _, v := range c.Values {
			if v == "" {
				return false
			}
		}
		return true
	}
	return false
}

func condNrReach(c RuleCondition) nrReach {
	switch normaliseFieldName(c.Field) {
	case "nr":
		switch c.Op {
		case OpIn, OpEquals, "eq", OpNotIn, OpNotEquals, "neq":
			nrs := make([]int64, 0, len(c.Values))
			for _, v := range c.Values {
				n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
				if err != nil {
					// Непонятное значение: считать, что условие может
					// совпасть с чем угодно, — безопасная сторона.
					return reachAll()
				}
				nrs = append(nrs, n)
			}
			r := reachOf(nrs)
			if c.Op == OpNotIn || c.Op == OpNotEquals || c.Op == "neq" {
				r.cofinite = true
			}
			return r
		}
	case "proc.args":
		if condRejectsEmptyProcArgs(c) {
			return reachOf(ProcArgsSyscallNrs)
		}
	}
	return reachAll()
}

func groupNrReach(g *RuleConditionGroup) nrReach {
	isOr := strings.EqualFold(g.Operator, "or")
	acc, first := reachAll(), true
	add := func(r nrReach) {
		switch {
		case first:
			acc, first = r, false
		case isOr:
			acc = acc.or(r)
		default:
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
		return reachAll()
	}
	return acc
}

func ruleNrReach(r *Rule) nrReach {
	if r.ConditionGroup != nil {
		return groupNrReach(r.ConditionGroup)
	}
	return condNrReach(r.Condition)
}

// argNeed — какие argN условие требует конъюнктивно: argN → допустимые
// значения. nil/пусто — не требует ничего, проверяемого в ядре.
type argNeed map[uint8]map[uint64]struct{}

func cloneNeed(n argNeed) argNeed {
	out := make(argNeed, len(n))
	for k, v := range n {
		c := make(map[uint64]struct{}, len(v))
		for x := range v {
			c[x] = struct{}{}
		}
		out[k] = c
	}
	return out
}

// argIndex возвращает N из имени argN (с учётом syscall.argN) или -1.
func argIndex(field string) int {
	f := normaliseFieldName(field)
	if len(f) != 4 || !strings.HasPrefix(f, "arg") || f[3] < '0' || f[3] > '5' {
		return -1
	}
	return int(f[3] - '0')
}

func condArgNeed(c RuleCondition) argNeed {
	idx := argIndex(c.Field)
	if idx < 0 || !(c.Op == OpIn || c.Op == OpEquals || c.Op == "eq") || len(c.Values) == 0 {
		return nil
	}
	vals := make(map[uint64]struct{}, len(c.Values))
	for _, v := range c.Values {
		u, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
		if err != nil {
			// Значение, которое не разобрать числом, строкой аргумента
			// (FormatUint) никогда не совпадёт, но «никогда» здесь —
			// вывод о правиле; консервативно не требуем ничего.
			return nil
		}
		vals[u] = struct{}{}
	}
	return argNeed{uint8(idx): vals}
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
		// Требование ветки-ИЛИ — только то, что требует КАЖДАЯ ветка: по
		// общим argN объединение значений.
		var out argNeed
		for i, p := range parts {
			if len(p) == 0 {
				return nil
			}
			if i == 0 {
				out = cloneNeed(p)
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
			cur, ok := out[k]
			if !ok {
				out[k] = cloneNeed(argNeed{k: v})[k]
				continue
			}
			// И-конъюнкция двух требований к одному argN — пересечение.
			for x := range cur {
				if _, keep := v[x]; !keep {
					delete(cur, x)
				}
			}
		}
	}
	return out
}

func ruleArgNeed(r *Rule) argNeed {
	if r.ConditionGroup != nil {
		return groupArgNeed(r.ConditionGroup)
	}
	return condArgNeed(r.Condition)
}

// DeriveKernelPredicates выводит предикаты ядра для номеров-кандидатов.
//
// Номер получает предикат, только если КАЖДОЕ syscall-правило, способное
// совпасть с ним, конъюнктивно требует хоть один общий argN из конечного
// набора (op in/eq). Для общего argN берётся объединение значений по всем
// правилам номера. Выбираются до KernelPredMaxTerms самых узких конъюнктов
// (набор ≤ KernelPredMaxValues значений); остальное дочищает userspace —
// предикат лишь необходимое условие. Ни одного пригодного конъюнкта (или
// правило без требований к аргументам) — номер в Blockers и идёт целиком,
// как до F1.
//
// Правило с пустым набором значений после пересечения (условие, которое не
// совпадёт ни с чем) не требует ничего: безопасная сторона.
func (re *RuleEngine) DeriveKernelPredicates(candidates []uint32) KernelPredDerivation {
	out := KernelPredDerivation{Blockers: map[uint32][]string{}}
	rules := re.byType[int(types.EventSyscall)]

	type perRule struct {
		id    string
		reach nrReach
		need  argNeed
	}
	rs := make([]perRule, 0, len(rules))
	for i := range rules {
		r := &rules[i]
		rs = append(rs, perRule{id: r.ID, reach: ruleNrReach(r), need: ruleArgNeed(r)})
	}

	for _, nr := range candidates {
		var common argNeed
		var blockers []string
		matched := 0
		for _, r := range rs {
			if !r.reach.has(int64(nr)) {
				continue
			}
			matched++
			if len(r.need) == 0 {
				blockers = append(blockers, r.id)
				continue
			}
			if common == nil {
				common = cloneNeed(r.need)
				continue
			}
			for k := range common {
				pv, ok := r.need[k]
				if !ok {
					delete(common, k)
					continue
				}
				for v := range pv {
					common[k][v] = struct{}{}
				}
			}
		}
		if len(blockers) > 0 {
			sort.Strings(blockers)
			out.Blockers[nr] = blockers
			continue
		}
		if matched == 0 {
			// Ни одно правило не совпадёт с номером вовсе: предикат
			// «ничего» — не наше решение (номер может быть в allowlist
			// по другой причине), оставляем без предиката.
			continue
		}
		var terms []KernelPredTerm
		for arg, vals := range common {
			if len(vals) == 0 || len(vals) > KernelPredMaxValues {
				continue
			}
			vs := make([]uint64, 0, len(vals))
			for v := range vals {
				vs = append(vs, v)
			}
			sort.Slice(vs, func(i, j int) bool { return vs[i] < vs[j] })
			terms = append(terms, KernelPredTerm{Arg: arg, Values: vs})
		}
		if len(terms) == 0 {
			out.Blockers[nr] = []string{"(нет общего argN с набором ≤ " + strconv.Itoa(KernelPredMaxValues) + " значений)"}
			continue
		}
		sort.Slice(terms, func(i, j int) bool {
			if len(terms[i].Values) != len(terms[j].Values) {
				return len(terms[i].Values) < len(terms[j].Values)
			}
			return terms[i].Arg < terms[j].Arg
		})
		if len(terms) > KernelPredMaxTerms {
			terms = terms[:KernelPredMaxTerms]
		}
		out.Predicates = append(out.Predicates, KernelPredicate{Nr: nr, Terms: terms})
	}
	sort.Slice(out.Predicates, func(i, j int) bool { return out.Predicates[i].Nr < out.Predicates[j].Nr })
	return out
}
