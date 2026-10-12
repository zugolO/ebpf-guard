package correlator

import (
	"math/rand"
	"os"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/internal/profiler"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 8.5, F1: предикат ядра — необходимое условие совпадения правила.
// Правило 1 волны: отбор в ядре судится тождеством детекта, не объёмом.

func w85CommBytes(s string) [16]byte {
	var b [16]byte
	copy(b[:], s)
	return b
}

func w85LoadBattleRules(t testing.TB) []Rule {
	t.Helper()
	rules, err := LoadRulesFromDir("../../rules")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	return rules
}

var w85ArgPool = []uint64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 33, 0x20, 0x22, 4097, 4098, 4113, 4114, 4115,
	^uint64(0), ^uint64(0) - 1, 1 << 32, 1 << 63, 12345}

var w85CommPool = []string{"kubectl", "helm", "xmrig", "minerd", "[kworker/0:1]", "[kthreadd]", "bash", "sh",
	"python3", "nginx", "curl", "iptables", "vssadmin", "ebpf-guard", "systemd", ""}

func w85RandomEvent(rng *rand.Rand, nr int64) types.Event {
	e := types.Event{Type: types.EventSyscall, PID: 100 + uint32(rng.Intn(50)), Syscall: &types.SyscallEvent{Nr: nr}}
	for i := range e.Syscall.Args {
		// Половина значений — из пула интересных, остальное — случайные.
		if rng.Intn(2) == 0 {
			e.Syscall.Args[i] = w85ArgPool[rng.Intn(len(w85ArgPool))]
		} else {
			e.Syscall.Args[i] = rng.Uint64()
		}
	}
	e.Comm = w85CommBytes(w85CommPool[rng.Intn(len(w85CommPool))])
	e.ParentComm = w85CommBytes(w85CommPool[rng.Intn(len(w85CommPool))])
	// proc.args заполняет коллектор только на execve/execveat.
	if nr == 59 || nr == 322 {
		e.ProcArgs = []string{"", "/tmp/x", "bash -c id", "/usr/bin/curl http://a"}[rng.Intn(4)]
	}
	return e
}

func w85Matches(re *RuleEngine, e types.Event) []string {
	var ids []string
	re.EvaluateInto(e, func(a types.Alert) { ids = append(ids, a.RuleID) })
	return ids
}

// Тождество: если хоть одно правило совпало с событием номера, у которого есть
// предикат, предикат обязан пропустить это событие. Прогон на всех номерах
// 0..511 с учётом правил, не имеющих предиката вовсе (они идут целиком).
func TestW85_F1_PredicateNeverDropsARuleMatch(t *testing.T) {
	rules := w85LoadBattleRules(t)
	re := NewRuleEngine(rules)
	cands := []uint32{9, 10, 158, 321}
	d := re.DeriveKernelPredicates(cands)
	preds := map[int64]KernelPredicate{}
	for _, p := range d.Predicates {
		preds[int64(p.Nr)] = p
	}
	if len(preds) != 3 {
		t.Fatalf("ожидались предикаты на 9/10/158, получено %d: %+v", len(preds), d.Predicates)
	}

	rng := rand.New(rand.NewSource(85))
	matchedByNr := map[int64]int{}
	for _, nr := range []int64{9, 10, 158} {
		for i := 0; i < 60000; i++ {
			e := w85RandomEvent(rng, nr)
			if ids := w85Matches(re, e); len(ids) > 0 {
				matchedByNr[nr]++
				if !preds[nr].Matches(e.Syscall.Args) {
					t.Fatalf("nr %d: правило %v совпало, а предикат %+v отбросил бы событие args=%v comm=%q",
						nr, ids, preds[nr], e.Syscall.Args, e.Comm)
				}
			}
		}
	}
	// Тест не вакуумен: на каждом номере совпадения случались.
	for _, nr := range []int64{9, 10, 158} {
		if matchedByNr[nr] == 0 {
			t.Errorf("nr %d: ни одного совпадения правил на 60000 событиях — тест ничего не проверяет", nr)
		}
		t.Logf("nr %d: совпадений правил %d, все прошли предикат", nr, matchedByNr[nr])
	}
}

// Положительный контроль построчно: каждое из трёх правил совпадает с
// эталонным событием, и предикат его пропускает; событие того же номера без
// признака (обычный mmap библиотеки) предикат отбрасывает.
func TestW85_F1_PositiveControlPerNr(t *testing.T) {
	re := NewRuleEngine(w85LoadBattleRules(t))
	d := re.DeriveKernelPredicates([]uint32{9, 10, 158})
	preds := map[int64]KernelPredicate{}
	for _, p := range d.Predicates {
		preds[int64(p.Nr)] = p
	}
	cases := []struct {
		nr     int64
		rule   string
		attack [6]uint64
		benign [6]uint64
	}{
		{9, "rootkit_anonymous_exec_memory", [6]uint64{0, 4096, 7, 0x22, ^uint64(0), 0}, [6]uint64{0, 4096, 5, 0x802, 3, 0}},
		{10, "sigma_mprotect_exec_heap", [6]uint64{0x1000, 4096, 7}, [6]uint64{0x1000, 4096, 1}},
		{158, "mitre_sandbox_detect_cpuid", [6]uint64{4113}, [6]uint64{0x1002}},
	}
	for _, c := range cases {
		e := types.Event{Type: types.EventSyscall, PID: 4242, Syscall: &types.SyscallEvent{Nr: c.nr, Args: c.attack}}
		e.Comm = w85CommBytes("evil")
		found := false
		for _, id := range w85Matches(re, e) {
			found = found || id == c.rule
		}
		if !found {
			t.Errorf("nr %d: эталон атаки не совпал с %s — контроль не контролирует", c.nr, c.rule)
		}
		if !preds[c.nr].Matches(c.attack) {
			t.Errorf("nr %d: предикат отбросил эталон атаки", c.nr)
		}
		if preds[c.nr].Matches(c.benign) {
			t.Errorf("nr %d: предикат пропустил заведомо обычный вызов %v — отбор не отбирает", c.nr, c.benign)
		}
	}
}

func w85WithExtraRule(rules []Rule, r Rule) []Rule {
	out := append([]Rule{}, rules...)
	return append(out, r)
}

// Мутации (правило 2 волны): правка правил снимает или расширяет предикат без
// правки C.
func TestW85_F1_MutationsReshapePredicate(t *testing.T) {
	base := w85LoadBattleRules(t)

	derive := func(rules []Rule, nr uint32) (KernelPredicate, bool, []string) {
		d := NewRuleEngine(rules).DeriveKernelPredicates([]uint32{nr})
		for _, p := range d.Predicates {
			if p.Nr == nr {
				return p, true, nil
			}
		}
		return KernelPredicate{}, false, d.Blockers[nr]
	}

	// 1. Новое правило по comm без условия на nr — снимает предикат с mmap.
	m1 := w85WithExtraRule(base, Rule{
		ID: "mut_comm_any_nr", EventType: types.EventSyscall,
		Condition: RuleCondition{Field: "comm", Op: OpEquals, Values: []string{"evilcomm"}},
		Severity:  types.SeverityWarning, Action: "alert",
	})
	if _, ok, bl := derive(m1, 9); ok || len(bl) == 0 || bl[0] != "mut_comm_any_nr" {
		t.Errorf("мутация 1: предикат mmap должен сняться правилом mut_comm_any_nr, ok=%v blockers=%v", ok, bl)
	}

	// 2. То же правило, но с nr not_in [9,10,158] — предикат остаётся.
	m2 := w85WithExtraRule(base, Rule{
		ID: "mut_comm_narrowed", EventType: types.EventSyscall,
		ConditionGroup: &RuleConditionGroup{Operator: "and", Conditions: []RuleCondition{
			{Field: "nr", Op: OpNotIn, Values: []string{"9", "10", "158"}},
			{Field: "comm", Op: OpEquals, Values: []string{"evilcomm"}},
		}},
		Severity: types.SeverityWarning, Action: "alert",
	})
	if _, ok, bl := derive(m2, 9); !ok {
		t.Errorf("мутация 2: сужение nr not_in не должно снимать предикат, blockers=%v", bl)
	}

	// 3. Новое правило на mprotect с другим набором prot — значения объединяются.
	m3 := w85WithExtraRule(base, Rule{
		ID: "mut_mprotect_prot1", EventType: types.EventSyscall,
		ConditionGroup: &RuleConditionGroup{Operator: "and", Conditions: []RuleCondition{
			{Field: "nr", Op: OpEquals, Values: []string{"10"}},
			{Field: "arg2", Op: OpEquals, Values: []string{"1"}},
		}},
		Severity: types.SeverityWarning, Action: "alert",
	})
	p, ok, bl := derive(m3, 10)
	if !ok || !p.Matches([6]uint64{0, 0, 1}) || !p.Matches([6]uint64{0, 0, 7}) || p.Matches([6]uint64{0, 0, 2}) {
		t.Errorf("мутация 3: предикат mprotect должен быть arg2∈{1,4,5,6,7}, получено %+v blockers=%v", p, bl)
	}

	// 4. Новое правило на mmap по ДРУГОМУ аргументу — общего argN уже нет → снят.
	m4 := w85WithExtraRule(base, Rule{
		ID: "mut_mmap_arg1", EventType: types.EventSyscall,
		ConditionGroup: &RuleConditionGroup{Operator: "and", Conditions: []RuleCondition{
			{Field: "nr", Op: OpEquals, Values: []string{"9"}},
			{Field: "arg1", Op: OpEquals, Values: []string{"4096"}},
		}},
		Severity: types.SeverityWarning, Action: "alert",
	})
	if p, ok, bl := derive(m4, 9); ok {
		t.Errorf("мутация 4: общего argN нет, предикат должен сняться: %+v", p)
	} else if len(bl) == 0 {
		t.Errorf("мутация 4: нет причины в Blockers")
	}

	// 5. Правка условия: правило mmap без требования к arg4 — остаётся один конъюнкт.
	var m5 []Rule
	for _, r := range base {
		if r.ID == "rootkit_anonymous_exec_memory" {
			g := *r.ConditionGroup
			g.Conditions = nil
			for _, c := range r.ConditionGroup.Conditions {
				if c.Field != "arg4" {
					g.Conditions = append(g.Conditions, c)
				}
			}
			r.ConditionGroup = &g
		}
		m5 = append(m5, r)
	}
	if p, ok, _ := derive(m5, 9); !ok || len(p.Terms) != 1 || p.Terms[0].Arg != 2 {
		t.Errorf("мутация 5: без arg4 должен остаться один конъюнкт arg2, получено %+v ok=%v", p, ok)
	}

	// 6. ИЛИ-ветка без требования к аргументу снимает требование.
	m6 := w85WithExtraRule(base, Rule{
		ID: "mut_mmap_or", EventType: types.EventSyscall,
		ConditionGroup: &RuleConditionGroup{Operator: "and", Conditions: []RuleCondition{
			{Field: "nr", Op: OpEquals, Values: []string{"9"}},
		}, SubGroups: []RuleConditionGroup{{Operator: "or", Conditions: []RuleCondition{
			{Field: "arg2", Op: OpEquals, Values: []string{"7"}},
			{Field: "comm", Op: OpEquals, Values: []string{"x"}},
		}}}},
		Severity: types.SeverityWarning, Action: "alert",
	})
	if _, ok, _ := derive(m6, 9); ok {
		t.Errorf("мутация 6: ветка ИЛИ без аргумента должна снять предикат")
	}
}

// Сторож вывода «proc.args ⇒ {59,322}»: константа обязана совпасть с
// условием коллектора. Правка коллектора без правки константы — красный тест,
// а не молчаливо ложный вывод.
func TestW85_F1_ProcArgsNrsMatchCollector(t *testing.T) {
	src, err := os.ReadFile("../collector/syscall.go")
	if err != nil {
		t.Fatalf("read collector: %v", err)
	}
	re := regexp.MustCompile(`if nr == (\d+) \|\| nr == (\d+) \{`)
	m := re.FindAllStringSubmatch(string(src), -1)
	if len(m) != 1 {
		t.Fatalf("в collector/syscall.go ожидалось ровно одно условие `nr == A || nr == B` для proc.args, найдено %d — перечитать вывод F1", len(m))
	}
	a, _ := strconv.ParseInt(m[0][1], 10, 64)
	b, _ := strconv.ParseInt(m[0][2], 10, 64)
	if len(ProcArgsSyscallNrs) != 2 || ProcArgsSyscallNrs[0] != a || ProcArgsSyscallNrs[1] != b {
		t.Fatalf("ProcArgsSyscallNrs=%v, коллектор заполняет proc.args на {%d,%d}", ProcArgsSyscallNrs, a, b)
	}
}

// Q1 этапа 0 (читает ли правило на 9/10/158 поле ret): нет. Тест держит ответ:
// появится правило с ret на предикатном номере — выход ядра по exit-событиям
// придётся пересматривать.
func TestW85_F1_NoRuleReadsRetOnPredicateNrs(t *testing.T) {
	rules := w85LoadBattleRules(t)
	for i := range rules {
		r := &rules[i]
		if r.EventType != types.EventSyscall {
			continue
		}
		reach := ruleNrReach(r)
		for _, c := range collectRuleConditions(r) {
			if normaliseFieldName(c.Field) != "ret" {
				continue
			}
			for _, nr := range []int64{9, 10, 158} {
				if reach.has(nr) {
					t.Errorf("правило %s читает ret и способно совпасть с nr %d", r.ID, nr)
				}
			}
		}
	}
}

func collectRuleConditions(r *Rule) []RuleCondition {
	conds := []RuleCondition{}
	if r.ConditionGroup != nil {
		conds = append(conds, collectConditions(r.ConditionGroup)...)
	} else {
		conds = append(conds, r.Condition)
	}
	for _, ex := range r.Exceptions {
		if ex.ConditionGroup != nil {
			conds = append(conds, collectConditions(ex.ConditionGroup)...)
		} else {
			conds = append(conds, ex.Condition)
		}
	}
	return conds
}

// Решение (1) 12.10: пять comm-правил сужены условием nr not_in [9,10,158].
// Детект процесса по имени не теряется: вне горячих номеров правило ведёт
// себя как до сужения (сравнение с копией без этого условия на всех 512
// номерах), на горячих — молчит.
func TestW85_F1_NarrowedCommRulesKeepDetectionOutsideHotNrs(t *testing.T) {
	ids := map[string]bool{
		"cis_5_1_1_cluster_admin_usage": true, "cryptominer_binary_name": true,
		"sigma_masquerade_kernel_thread": true, "sigma_web_server_shell_spawn": true,
		"ransomware_shadow_delete": true,
	}
	var narrowed, original []Rule
	for _, r := range w85LoadBattleRules(t) {
		if !ids[r.ID] {
			continue
		}
		g := r.ConditionGroup
		if g == nil {
			t.Fatalf("%s: ожидался condition_group после сужения", r.ID)
		}
		if g.Conditions[0].Field != "nr" || g.Conditions[0].Op != OpNotIn {
			t.Fatalf("%s: первое условие должно быть nr not_in", r.ID)
		}
		delete(ids, r.ID)
		narrowed = append(narrowed, r)
		o := r
		og := *g
		og.Conditions = append([]RuleCondition{}, g.Conditions[1:]...)
		o.ConditionGroup = &og
		original = append(original, o)
	}
	if len(ids) != 0 {
		t.Fatalf("правила не найдены в боевом наборе: %v", ids)
	}
	reN, reO := NewRuleEngine(narrowed), NewRuleEngine(original)
	rng := rand.New(rand.NewSource(12))
	hits := 0
	for i := 0; i < 80000; i++ {
		nr := int64(rng.Intn(512))
		e := w85RandomEvent(rng, nr)
		// Гарантируем, что имена из правил попадают в выборку.
		if rng.Intn(3) == 0 {
			e.ParentComm = w85CommBytes([]string{"nginx", "apache2", "node"}[rng.Intn(3)])
			e.Comm = w85CommBytes([]string{"bash", "sh", "xmrig", "kubectl", "[kworker/1]"}[rng.Intn(5)])
		}
		got, want := w85Matches(reN, e), w85Matches(reO, e)
		hot := nr == 9 || nr == 10 || nr == 158
		if hot {
			if len(got) != 0 {
				t.Fatalf("nr %d: суженное правило не должно совпасть: %v", nr, got)
			}
			continue
		}
		if len(got) != len(want) {
			t.Fatalf("nr %d: суженное %v ≠ исходное %v", nr, got, want)
		}
		hits += len(want)
	}
	if hits == 0 {
		t.Fatal("ни одного совпадения вне горячих номеров — сравнение вакуумно")
	}
}

// F2 на уровне движка: счётчик попадает в профиль того воркера, который
// получил бы поштучные события этого pid (pid & ingestMask).
func TestW85_F2_EngineRoutesCountsToTheOwningWorker(t *testing.T) {
	cfg := DefaultCorrelationEngineConfig()
	cfg.Rules = nil
	cfg.EnableAnomaly = true
	cfg.LearningPeriod = time.Hour
	cfg.IngestWorkerCount = 4
	ce := NewCorrelationEngineWithConfig(cfg)
	defer ce.Close()

	if !ce.AnomalyEnabled() {
		t.Fatal("anomaly должен быть включён")
	}
	var comm [16]byte
	copy(comm[:], "iptables")
	// pid 4 и 5 попадают в разные воркеры при маске 3.
	batch := []profiler.SyscallCount{
		{PID: 4, Nr: 9, Comm: comm, N: 10},
		{PID: 5, Nr: 10, Comm: comm, N: 7},
	}
	applied, skipped := ce.IngestSyscallCounts(batch, nil)
	if applied != 17 || skipped != 0 {
		t.Fatalf("applied=%d skipped=%d, ожидалось 17/0", applied, skipped)
	}
	key := profiler.WorkloadKey{Comm: "iptables"}
	for i, wantNr := range map[uint32]int64{4 & ce.ingestMask: 9, 5 & ce.ingestMask: 10} {
		prof := ce.ingestPool[i].ad.GetProfileManager().GetByKey(key)
		if prof == nil || prof.SyscallProfile.Syscalls[wantNr] == nil {
			t.Fatalf("воркер %d: профиль iptables без номера %d", i, wantNr)
		}
	}
	// Чужой воркер этого номера не получил.
	if prof := ce.ingestPool[4&ce.ingestMask].ad.GetProfileManager().GetByKey(key); prof != nil && prof.SyscallProfile.Syscalls[10] != nil {
		t.Fatal("счётчик pid 5 попал в воркер pid 4")
	}

	// Без anomaly счётчикам некуда идти: не паника, ноль.
	cfg2 := DefaultCorrelationEngineConfig()
	cfg2.Rules = nil
	cfg2.EnableAnomaly = false
	ce2 := NewCorrelationEngineWithConfig(cfg2)
	defer ce2.Close()
	if a, s := ce2.IngestSyscallCounts(batch, nil); a != 0 || s != 0 {
		t.Fatalf("без anomaly applied=%d skipped=%d", a, s)
	}
}

// Перезагрузка правил: хук предикатов получает вывод из НОВОГО набора и
// вызывается ДО подмены движка — расширенное правило открывает ядро раньше,
// чем начинает требовать события.
func TestW85_F1_ReloadHookRunsBeforeSwapWithNewRules(t *testing.T) {
	rules := w85LoadBattleRules(t)
	cfg := DefaultCorrelationEngineConfig()
	cfg.Rules = rules
	ce := NewCorrelationEngineWithConfig(cfg)
	defer ce.Close()

	var calls int
	var gotPreds []KernelPredicate
	var oldWhenCalled *RuleEngine
	ce.SetKernelPredicateUpdater(func(derive func([]uint32) KernelPredDerivation) {
		calls++
		oldWhenCalled = ce.ruleEngine.Load()
		gotPreds = derive([]uint32{10}).Predicates
	})

	// Новое правило расширяет mprotect до prot=1.
	wide := append(append([]Rule{}, rules...), Rule{
		ID: "mut_mprotect_prot1", EventType: types.EventSyscall,
		ConditionGroup: &RuleConditionGroup{Operator: "and", Conditions: []RuleCondition{
			{Field: "nr", Op: OpEquals, Values: []string{"10"}},
			{Field: "arg2", Op: OpEquals, Values: []string{"1"}},
		}},
		Severity: types.SeverityWarning, Action: "alert",
	})
	before := ce.ruleEngine.Load()
	ce.UpdateRules(wide)
	if calls != 1 {
		t.Fatalf("хук вызван %d раз, ожидалось 1", calls)
	}
	if oldWhenCalled != before {
		t.Fatal("хук вызван ПОСЛЕ подмены движка: расширенное правило сначала начало требовать событий, а ядро их ещё отбрасывало")
	}
	if len(gotPreds) != 1 || !gotPreds[0].Matches([6]uint64{0, 0, 1}) {
		t.Fatalf("вывод хука не из нового набора: %+v", gotPreds)
	}
	if ce.ruleEngine.Load() == before {
		t.Fatal("движок не подменён")
	}
}
