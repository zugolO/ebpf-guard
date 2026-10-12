package correlator

import (
	"sort"
	"strings"
	"testing"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 8.5, F0(а) → F1: инвентарь правил боевого набора на номерах, которые
// F1 хочет отбирать в ядре предикатом по аргументу. До F1 здесь жили свои копии
// вывода достижимости номера; теперь тест судит ПРОДУКТОВЫЙ вывод
// (DeriveKernelPredicates) и печатает правила, мешающие номеру.

// TestW85_F0_RuleInventoryOnHotNrs печатает, какие правила боевого набора
// способны совпасть с mmap/mprotect/bpf/arch_prctl, и судит предпосылку F1:
// у трёх номеров после сужения пяти comm-правил (решение (1), 12.10) есть
// предикат; у bpf его нет (решение (2): drift_dangerous_syscall на все cmd).
func TestW85_F0_RuleInventoryOnHotNrs(t *testing.T) {
	rules, err := LoadRulesFromDir("../../rules")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	re := NewRuleEngine(rules)
	d := re.DeriveKernelPredicates([]uint32{9, 10, 158, 321})

	var anyNr []string
	for i := range rules {
		r := &rules[i]
		if r.EventType == types.EventSyscall && ruleNrReach(r).cofinite && len(ruleNrReach(r).set) == 0 {
			anyNr = append(anyNr, r.ID)
		}
	}
	sort.Strings(anyNr)
	t.Logf("syscall-правил, достижимых с ЛЮБЫМ nr после вывода proc.args⇒{59,322}: %d %v", len(anyNr), anyNr)

	got := map[uint32]KernelPredicate{}
	for _, p := range d.Predicates {
		got[p.Nr] = p
		var terms []string
		for _, tm := range p.Terms {
			terms = append(terms, "arg"+string(rune('0'+tm.Arg)))
		}
		t.Logf("nr %d: предикат по %s %v", p.Nr, strings.Join(terms, " ∧ "), p.Terms)
	}
	for nr, ids := range d.Blockers {
		t.Logf("nr %d: БЕЗ предиката, мешают %d: %v", nr, len(ids), ids)
	}

	for _, nr := range []uint32{9, 10, 158} {
		if _, ok := got[nr]; !ok {
			t.Errorf("nr %d: ожидался предикат, блокеры: %v", nr, d.Blockers[nr])
		}
	}
	if _, ok := got[321]; ok {
		t.Errorf("nr 321 (bpf): предиката быть не должно (решение (2)): drift_dangerous_syscall смотрит все cmd")
	}
	if len(d.Blockers[321]) == 0 {
		t.Errorf("nr 321 должен быть в блокерах (drift_dangerous_syscall)")
	}
}
