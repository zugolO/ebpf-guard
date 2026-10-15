package correlator

import (
	"fmt"
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Разрез G0(в) ПОСЛЕ G1 на дампе событий (заход B): какие шаблоны ещё доходят до
// regexp и сколько раз («литерал прошёл» по КНФ-наборам). Печатает таблицу; не
// утверждение. Запуск: W86_DUMP=… go test ./internal/correlator -run TestG0CutAfterG1 -v
func TestG0CutAfterG1(t *testing.T) {
	p := os.Getenv("W86_DUMP")
	if p == "" {
		t.Skip()
	}
	evs, err := LoadEventDump(p)
	require.NoError(t, err)
	rules, _ := LoadRulesFromDir("../../rules")
	re := NewRuleEngine(rules)
	own := g0Owners(re)
	type k struct{ rule, pat string }
	type st struct{ calls, match, viaRegex int }
	m := map[k]*st{}
	regexProbe = func(c *RuleCondition, i int, lit, matched bool) {
		if !lit {
			return
		}
		kk := k{own[c], c.Values[i]}
		s := m[kk]
		if s == nil {
			s = &st{}
			m[kk] = s
		}
		s.calls++
		if matched {
			s.match++
		}
		s.viaRegex++
	}
	defer func() { regexProbe = nil }()
	for i := range evs {
		re.EvaluateInto(evs[i], func(types.Alert) {})
	}
	var ks []k
	tot, totRegex := 0, 0
	for kk, s := range m {
		ks = append(ks, kk)
		tot += s.calls
		totRegex += s.viaRegex
	}
	sort.Slice(ks, func(i, j int) bool { return m[ks[i]].viaRegex > m[ks[j]].viaRegex })
	fmt.Printf("G0CUT| events=%d pattern evaluations after prefilter=%d via regexp=%d\n", len(evs), tot, totRegex)
	for _, kk := range ks[:25] {
		s := m[kk]
		fmt.Printf("G0CUT| %-45s via_regexp=%-8d matched=%-6d %q\n", kk.rule, s.viaRegex, s.match, kk.pat)
	}
}
