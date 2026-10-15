package correlator

import (
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 8.6 C0 (G3): индекс правил по nr/op и предвычисленные коды полей.

func withDispatch(on bool, f func()) {
	prev := dispatchEnabled
	dispatchEnabled = on
	defer func() { dispatchEnabled = prev }()
	f()
}

// orderedAlerts — алерты по событиям В ПОРЯДКЕ выдачи (индекс не должен менять и порядок).
func orderedAlerts(re *RuleEngine, evs []types.Event) []string {
	globalBurstTracker = NewBurstTracker()
	var out []string
	for i := range evs {
		re.EvaluateInto(evs[i], func(a types.Alert) { out = append(out, fmt.Sprintf("%d:%s", i, a.RuleID)) })
	}
	return out
}

// dispatchCorpus — файловые события корпуса cond_order (или дамп) + syscall-события
// по ВСЕМ номерам таблицы и за её краями, nil-Syscall, неизвестные операции файла.
func dispatchCorpus(t *testing.T, rules []Rule) []types.Event {
	evs := orderIdentityCorpus(t, rules)
	if os.Getenv("W86_DUMP") != "" {
		return evs
	}
	rng := rand.New(rand.NewSource(8603))
	comms := []string{"nginx", "bash", "python3", "sshd", "curl", "runc", "nc", "xmrig", "systemd"}
	for nr := int64(-2); nr < 600; nr++ {
		for k := 0; k < 4; k++ {
			e := types.Event{Type: types.EventSyscall, PID: uint32(200 + rng.Intn(40)), UID: uint32(rng.Intn(2) * 1000),
				Syscall: &types.SyscallEvent{Nr: nr, Ret: int64(rng.Intn(3) - 1)}}
			for a := range e.Syscall.Args {
				e.Syscall.Args[a] = uint64(rng.Intn(40))
			}
			copy(e.Comm[:], comms[rng.Intn(len(comms))])
			evs = append(evs, e)
		}
	}
	evs = append(evs, types.Event{Type: types.EventSyscall, PID: 7}) // Syscall == nil
	for op := 0; op < 12; op++ {
		e := types.Event{Type: types.EventFileAccess, PID: 9, File: &types.FileEvent{Op: uint8(op), Filename: "/etc/shadow"}}
		copy(e.Comm[:], "cat")
		evs = append(evs, e)
	}
	evs = append(evs, types.Event{Type: types.EventFileAccess, PID: 9}) // File == nil
	return evs
}

func loadShipped(t *testing.T, dispatch bool) (*RuleEngine, []Rule) {
	var re *RuleEngine
	var rules []Rule
	withDispatch(dispatch, func() {
		var err error
		rules, err = LoadRulesFromDir("../../rules")
		require.NoError(t, err)
		re = NewRuleEngine(rules)
	})
	return re, rules
}

// firstDiff — первое расхождение двух выдач (пусто — выдачи совпали).
func firstDiff(a, b []string) string {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return fmt.Sprintf("позиция %d: %q против %q", i, a[i], b[i])
		}
	}
	if len(a) != len(b) {
		return fmt.Sprintf("длины %d против %d", len(a), len(b))
	}
	return ""
}

// Боевые правила: те же алерты в том же порядке с индексом и без — на корпусе
// (все nr таблицы и за её краями, op вне таблицы, nil-структуры) и на дампе (W86_DUMP).
func TestDispatch_ShippedRulesetSameAlerts(t *testing.T) {
	reOff, rules := loadShipped(t, false)
	reOn, _ := loadShipped(t, true)
	require.Nil(t, reOff.dispatch)
	require.NotNil(t, reOn.dispatch, "индекс обязан строиться из загруженных правил")
	evs := dispatchCorpus(t, rules)
	a, b := orderedAlerts(reOff, evs), orderedAlerts(reOn, evs)
	require.NotEmpty(t, a, "корпус обязан поднимать алерты, иначе тождество пусто")
	require.Empty(t, firstDiff(a, b), "выдачи разошлись")
	// и Evaluate (отдельный цикл), и единичная проверка matches на каждом правиле
	globalBurstTracker = NewBurstTracker()
	n := 0
	for i := range evs[:min(len(evs), 4000)] {
		x, y := reOff.Evaluate(evs[i]), reOn.Evaluate(evs[i])
		require.Equal(t, len(x), len(y), "Evaluate: событие %d", i)
		for j := range x {
			require.Equal(t, x[j].RuleID, y[j].RuleID)
		}
		n += len(x)
	}
	t.Logf("событий %d, алертов %d; syscall-правил ограничено %d из %d, file — %d из %d",
		len(evs), len(a), reOn.dispatch.sysConstrained, reOn.dispatch.sysTotal, reOn.dispatch.fileConstrained, reOn.dispatch.fileTotal)
}

// Индекс ПРИМЕНЯЕТСЯ: на конкретном nr кандидатов меньше, чем правил типа.
// Мутация «индекс не применяется» (dispatchEnabled=false) краснит этот тест.
func TestDispatch_IndexIsApplied(t *testing.T) {
	re, _ := loadShipped(t, true)
	total := len(re.byType[types.EventSyscall])
	require.Greater(t, re.dispatch.sysConstrained, total/3, "треть и более syscall-правил называет nr")
	e := types.Event{Type: types.EventSyscall, Syscall: &types.SyscallEvent{Nr: 1}}
	cand, ok := re.candidateRules(&e)
	require.True(t, ok)
	require.Less(t, len(cand), total*7/10, "на nr=1 кандидатов должно быть заметно меньше, чем правил (%d)", total)
	fe := types.Event{Type: types.EventFileAccess, File: &types.FileEvent{Op: 1}}
	fc, ok := re.candidateRules(&fe)
	require.True(t, ok)
	require.Less(t, len(fc), len(re.byType[types.EventFileAccess]), "на op=read файловых кандидатов меньше, чем правил")

	off, _ := loadShipped(t, false)
	_, ok = off.candidateRules(&e)
	require.False(t, ok, "выключатель возвращает перебор всех")
}

// Поле предвычислено у КАЖДОГО условия загруженного набора (правил и исключений).
// Мутация «поле не предвычислено» краснит этот тест.
func TestDispatch_FieldsPrecomputedOnEveryCondition(t *testing.T) {
	re, _ := loadShipped(t, true)
	n := 0
	var walk func(c *RuleCondition)
	walk = func(c *RuleCondition) {
		n++
		require.Equal(t, normaliseFieldName(c.Field), c.fieldNorm, "поле %q", c.Field)
		require.Equal(t, fieldIDOf(c.fieldNorm), c.fieldID)
	}
	var walkG func(g *RuleConditionGroup)
	walkG = func(g *RuleConditionGroup) {
		for i := range g.Conditions {
			walk(&g.Conditions[i])
		}
		for i := range g.SubGroups {
			walkG(&g.SubGroups[i])
		}
	}
	for i := range re.rules {
		r := &re.rules[i]
		walk(&r.Condition)
		if r.ConditionGroup != nil {
			walkG(r.ConditionGroup)
		}
		for j := range r.Exceptions {
			if g := r.Exceptions[j].ConditionGroup; g != nil {
				walkG(g)
			} else {
				walk(&r.Exceptions[j].Condition)
			}
		}
	}
	require.Greater(t, n, 500)
}

func mkSys(id string, g *RuleConditionGroup, c RuleCondition) Rule {
	return Rule{ID: id, Name: id, EventType: types.EventSyscall, Severity: "warning", Action: ActionAlert, Condition: c, ConditionGroup: g}
}

func sysEv(nr int64, comm string) types.Event {
	e := types.Event{Type: types.EventSyscall, PID: 11, Syscall: &types.SyscallEvent{Nr: nr}}
	copy(e.Comm[:], comm)
	return e
}

// Границы ограничения: что индекс обязан ограничивать, а что нет.
func TestDispatch_ConstraintBoundaries(t *testing.T) {
	nr := func(op RuleConditionOperator, v ...string) RuleCondition {
		return RuleCondition{Field: "syscall.nr", Op: op, Values: v}
	}
	comm := RuleCondition{Field: "comm", Op: OpIn, Values: []string{"nc"}}
	rules := []Rule{
		mkSys("single_in", nil, nr(OpIn, "59", "322")),
		mkSys("and_direct", &RuleConditionGroup{Operator: "and", Conditions: []RuleCondition{comm, nr(OpEquals, "41")}}, RuleCondition{}),
		mkSys("or_group", &RuleConditionGroup{Operator: "or", Conditions: []RuleCondition{nr(OpEquals, "59"), comm}}, RuleCondition{}),
		mkSys("nested_only", &RuleConditionGroup{Operator: "and", Conditions: []RuleCondition{comm},
			SubGroups: []RuleConditionGroup{{Operator: "and", Conditions: []RuleCondition{nr(OpEquals, "59")}}}}, RuleCondition{}),
		mkSys("noncanonical", nil, nr(OpIn, "059")),
		mkSys("negative", nil, nr(OpEquals, "-1")),
		mkSys("out_of_table", nil, nr(OpIn, "9999")),
		mkSys("eq_first_only", nil, nr(OpEquals, "7", "8")),
		mkSys("not_in", nil, nr(OpNotIn, "59")),
		mkSys("no_nr", nil, comm),
	}
	re := NewRuleEngine(rules)
	require.NoError(t, re.CompileErrors())
	off := func() *RuleEngine {
		var r *RuleEngine
		withDispatch(false, func() { r = NewRuleEngine(rules) })
		return r
	}()
	cands := func(n int64) map[string]bool {
		e := sysEv(n, "nc")
		c, ok := re.candidateRules(&e)
		require.True(t, ok)
		m := map[string]bool{}
		for _, p := range c {
			m[re.byType[types.EventSyscall][p].ID] = true
		}
		return m
	}
	c59 := cands(59)
	require.True(t, c59["single_in"] && c59["or_group"] && c59["nested_only"] && c59["noncanonical"] && c59["negative"] &&
		c59["out_of_table"] && c59["not_in"] && c59["no_nr"], "неограниченные видят любой nr: %v", c59)
	require.False(t, c59["and_direct"] || c59["eq_first_only"], "ограниченные по другому nr не кандидаты: %v", c59)
	require.True(t, cands(41)["and_direct"])
	require.True(t, cands(7)["eq_first_only"])
	require.False(t, cands(8)["eq_first_only"], "eq смотрит только первое значение")
	require.False(t, cands(1)["single_in"])
	require.True(t, cands(322)["single_in"])
	// те же алерты на каждом nr вокруг таблицы
	var evs []types.Event
	for n := int64(-3); n < 600; n++ {
		evs = append(evs, sysEv(n, "nc"), sysEv(n, "bash"))
	}
	evs = append(evs, types.Event{Type: types.EventSyscall, PID: 1})
	require.Empty(t, firstDiff(orderedAlerts(off, evs), orderedAlerts(re, evs)))
}

// Сэмплер: правило со статической ставкой не ограничено, а пока у сэмплера есть
// записи (статические или адаптивные), индекс не применяется вовсе.
func TestDispatch_SamplerDisablesIndex(t *testing.T) {
	plain := mkSys("plain", nil, RuleCondition{Field: "nr", Op: OpIn, Values: []string{"59"}})
	re := NewRuleEngine([]Rule{plain})
	e := sysEv(1, "bash")
	c, ok := re.candidateRules(&e)
	require.True(t, ok)
	require.Empty(t, c)
	re.sampler.setAdaptiveRate("plain", 0.5)
	_, ok = re.candidateRules(&e)
	require.False(t, ok, "с адаптивным переопределением индекс не применяется")

	sampled := mkSys("sampled", nil, RuleCondition{Field: "nr", Op: OpIn, Values: []string{"59"}})
	sampled.SampleRate = 0.5
	re2 := NewRuleEngine([]Rule{sampled})
	_, ok = re2.candidateRules(&e)
	require.False(t, ok, "со статической ставкой индекс не применяется")
	_, constrained := requiredKey(&re2.byType[types.EventSyscall][0], fidNr)
	require.False(t, constrained, "правило с сэмплером не ограничено")
}

// Правка правила меняет кандидатов без правки кода.
func TestDispatch_RuleEditChangesCandidates(t *testing.T) {
	mk := func(n string) *RuleEngine {
		return NewRuleEngine([]Rule{mkSys("r", nil, RuleCondition{Field: "nr", Op: OpIn, Values: []string{n}})})
	}
	a, b := mk("59"), mk("60")
	require.Len(t, a.Evaluate(sysEv(59, "x")), 1)
	require.Empty(t, a.Evaluate(sysEv(60, "x")))
	require.Len(t, b.Evaluate(sysEv(60, "x")), 1)
	require.Empty(t, b.Evaluate(sysEv(59, "x")))
}

// Мутация индекса: из списка кандидатов выброшено правило — тождество краснеет.
func TestDispatch_CorruptedIndexBreaksIdentity(t *testing.T) {
	reOff, rules := loadShipped(t, false)
	reOn, _ := loadShipped(t, true)
	evs := dispatchCorpus(t, rules)
	want := orderedAlerts(reOff, evs)
	require.Empty(t, firstDiff(want, orderedAlerts(reOn, evs)))
	d := reOn.dispatch
	for s := range d.sysLists {
		d.sysLists[s] = nil // «правило потеряно из индекса»
	}
	require.NotEmpty(t, firstDiff(want, orderedAlerts(reOn, evs)), "порча индекса обязана быть видна тождеству")
}

// Свойство: случайные правила × случайные события — индекс не меняет результат.
func TestDispatch_PropertyResultUnchanged(t *testing.T) {
	rng := rand.New(rand.NewSource(8604))
	pick := func() RuleCondition {
		switch rng.Intn(5) {
		case 0:
			return RuleCondition{Field: "syscall.nr", Op: OpIn, Values: []string{strconv.Itoa(rng.Intn(8)), strconv.Itoa(rng.Intn(8))}}
		case 1:
			return RuleCondition{Field: "nr", Op: OpEquals, Values: []string{strconv.Itoa(rng.Intn(8))}}
		case 2:
			return RuleCondition{Field: "comm", Op: OpIn, Values: []string{"a", "b"}}
		case 3:
			return RuleCondition{Field: "nr", Op: OpNotIn, Values: []string{strconv.Itoa(rng.Intn(8))}}
		}
		return RuleCondition{Field: "ret", Op: OpEquals, Values: []string{"0"}}
	}
	for round := 0; round < 60; round++ {
		var rules []Rule
		for i := 0; i < 12; i++ {
			var g *RuleConditionGroup
			var c RuleCondition
			switch rng.Intn(3) {
			case 0:
				c = pick()
			case 1:
				g = &RuleConditionGroup{Operator: "and", Conditions: []RuleCondition{pick(), pick()}}
			default:
				g = &RuleConditionGroup{Operator: "or", Conditions: []RuleCondition{pick()},
					SubGroups: []RuleConditionGroup{{Operator: "and", Conditions: []RuleCondition{pick(), pick()}}}}
			}
			rules = append(rules, mkSys(fmt.Sprintf("r%d", i), g, c))
		}
		var on, off *RuleEngine
		withDispatch(true, func() { on = NewRuleEngine(cloneRules(rules)) })
		withDispatch(false, func() { off = NewRuleEngine(cloneRules(rules)) })
		var evs []types.Event
		for k := 0; k < 120; k++ {
			evs = append(evs, sysEv(int64(rng.Intn(10)-1), []string{"a", "b", "c"}[rng.Intn(3)]))
		}
		require.Empty(t, firstDiff(orderedAlerts(off, evs), orderedAlerts(on, evs)), "раунд %d", round)
	}
}

func cloneRules(rs []Rule) []Rule {
	out := make([]Rule, len(rs))
	for i, r := range rs {
		out[i] = r
		if r.ConditionGroup != nil {
			g := cloneGroup(r.ConditionGroup)
			out[i].ConditionGroup = &g
		}
	}
	return out
}

// Файловые операции: op вне таблицы и nil-File видят только неограниченные.
func TestDispatch_FileOpBoundaries(t *testing.T) {
	mkF := func(id string, c RuleCondition) Rule {
		return Rule{ID: id, Name: id, EventType: types.EventFileAccess, Severity: "warning", Action: ActionAlert, Condition: c}
	}
	rules := []Rule{
		mkF("w", RuleCondition{Field: "file.op", Op: OpIn, Values: []string{"write", "open"}}),
		mkF("badname", RuleCondition{Field: "op", Op: OpEquals, Values: []string{"nonsense"}}),
		mkF("num", RuleCondition{Field: "op", Op: OpEquals, Values: []string{"9"}}),
		mkF("path", RuleCondition{Field: "filename", Op: OpPrefix, Values: []string{"/etc"}}),
	}
	re := NewRuleEngine(rules)
	var off *RuleEngine
	withDispatch(false, func() { off = NewRuleEngine(rules) })
	var evs []types.Event
	for op := 0; op < 14; op++ {
		evs = append(evs, types.Event{Type: types.EventFileAccess, PID: 1, File: &types.FileEvent{Op: uint8(op), Filename: "/etc/x"}})
	}
	evs = append(evs, types.Event{Type: types.EventFileAccess, PID: 1})
	require.Empty(t, firstDiff(orderedAlerts(off, evs), orderedAlerts(re, evs)))
	// op=9 совпадает по числовой записи: правило «num» не ограничено и сработало
	got := orderedAlerts(re, evs[9:10])
	require.Contains(t, got, "0:num")
}

func BenchmarkDispatchShipped(b *testing.B) {
	p := os.Getenv("W86_DUMP")
	if p == "" {
		b.Skip("W86_DUMP не задан")
	}
	evs, err := LoadEventDump(p)
	require.NoError(b, err)
	for _, on := range []bool{false, true} {
		name := "dispatch=off"
		if on {
			name = "dispatch=on"
		}
		b.Run(name, func(b *testing.B) {
			var re *RuleEngine
			withDispatch(on, func() {
				rules, err := LoadRulesFromDir("../../rules")
				require.NoError(b, err)
				re = NewRuleEngine(rules)
			})
			sink := func(types.Alert) {}
			for i := range evs[:min(len(evs), 20000)] {
				re.EvaluateInto(evs[i], sink)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				re.EvaluateInto(evs[i%len(evs)], sink)
			}
		})
	}
}
