package correlator

import (
	"strings"
	"testing"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 8.5, O1 (замер, не включение): что F1 выведет для socket(41) и clone(56) из боевого набора.
func TestW85_O1_DeriveForRejectedNrs(t *testing.T) {
	rules, err := LoadRulesFromDir("../../rules")
	if err != nil {
		t.Fatal(err)
	}
	re := NewRuleEngine(rules)
	d := re.DeriveKernelPredicates([]uint32{41, 56, 57, 435})
	for _, p := range d.Predicates {
		var terms []string
		for _, tm := range p.Terms {
			terms = append(terms, "arg"+string(rune('0'+tm.Arg)))
		}
		t.Logf("nr %d: предикат по %s %v", p.Nr, strings.Join(terms, " ∧ "), p.Terms)
	}
	for nr, ids := range d.Blockers {
		t.Logf("nr %d: БЕЗ предиката, мешают %d: %v", nr, len(ids), ids)
	}
	for _, nr := range []int64{41, 56} {
		var ids []string
		for i := range rules {
			r := &rules[i]
			if r.EventType == types.EventSyscall && ruleNrReach(r).has(nr) && !(ruleNrReach(r).cofinite && len(ruleNrReach(r).set) == 0) {
				ids = append(ids, r.ID)
			}
		}
		t.Logf("nr %d: правила, достижимые именно с этим номером: %v", nr, ids)
	}
}
