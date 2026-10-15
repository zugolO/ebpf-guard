package correlator

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

func withLiteralIndex(on bool, f func()) {
	prev := literalIndexEnabled
	literalIndexEnabled = on
	defer func() { literalIndexEnabled = prev }()
	f()
}

// Автомат отвечает так же, как strings.Contains по каждому литералу: на случайных
// наборах с общими префиксами, вложенными и перекрывающимися литералами.
func TestLiteralIndex_MatchesStringsContains(t *testing.T) {
	rng := rand.New(rand.NewSource(8603))
	alpha := "ab/_.x"
	rs := func(n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = alpha[rng.Intn(len(alpha))]
		}
		return string(b)
	}
	for it := 0; it < 300; it++ {
		seen := map[string]bool{}
		var lits []string
		for i, n := 0, 1+rng.Intn(40); i < n; i++ {
			l := rs(2 + rng.Intn(5))
			if !seen[l] {
				seen[l] = true
				lits = append(lits, l)
			}
		}
		idx := buildLiteralIndex(lits)
		require.NotNil(t, idx)
		for k := 0; k < 40; k++ {
			s := rs(rng.Intn(60))
			if rng.Intn(3) == 0 {
				s += "\xff\x00é" + rs(5) // байты вне алфавита
			}
			hits := make([]uint64, idx.nWords)
			idx.scan(s, hits)
			for id, l := range lits {
				want := strings.Contains(s, l)
				got := hits[id>>6]&(1<<(uint(id)&63)) != 0
				if want != got {
					t.Fatalf("литерал %q в %q: автомат=%v, Contains=%v (набор %q)", l, s, got, want, lits)
				}
			}
		}
	}
}

// Шипнутые правила: те же алерты с автоматом и без него — на корпусе, пакете
// синтетических путей и (если задан W86_DUMP) дампе событий движка.
func TestLiteralIndex_ShippedRulesetSameAlerts(t *testing.T) {
	load := func(on bool) (*RuleEngine, []Rule) {
		var re *RuleEngine
		var rules []Rule
		withLiteralIndex(on, func() {
			var err error
			rules, err = LoadRulesFromDir("../../rules")
			require.NoError(t, err)
			re = NewRuleEngine(rules)
		})
		return re, rules
	}
	reOff, rulesOff := load(false)
	reOn, _ := load(true)
	require.Nil(t, reOff.fileLits)
	require.NotNil(t, reOn.fileLits, "автомат обязан быть построен из загруженных правил")
	evs := orderIdentityCorpus(t, rulesOff)
	a, b := alertMultiset(reOff, evs), alertMultiset(reOn, evs)
	require.NotEmpty(t, a)
	require.Equal(t, a, b)
}

// Источник истины — правила: правка правила, добавляющая литерал, расширяет
// автомат без правки кода (мутационный тест на расширение условия).
func TestLiteralIndex_RuleEditExtendsCandidates(t *testing.T) {
	mk := func(lit string) *RuleEngine {
		rules := []Rule{{ID: "r1", Name: "n", EventType: types.EventFileAccess, Severity: "warning", Action: ActionAlert,
			Condition: RuleCondition{Field: "filename", Op: OpRegex, Values: []string{lit + "[0-9]+"}}}}
		return NewRuleEngine(rules)
	}
	ev := func(path string) types.Event {
		return types.Event{Type: types.EventFileAccess, PID: 1, File: &types.FileEvent{Op: 0, Filename: path}}
	}
	re := mk("secretfile")
	require.NotNil(t, re.fileLits)
	require.Len(t, re.Evaluate(ev("/x/secretfile42")), 1)
	require.Empty(t, re.Evaluate(ev("/x/otherfile42")))
	re2 := mk("otherfile") // «правка правила»: другой литерал, код тот же
	require.Len(t, re2.Evaluate(ev("/x/otherfile42")), 1)
	require.Empty(t, re2.Evaluate(ev("/x/secretfile42")))
}

// Условия общие у нескольких движков: чужой автомат отбрасывается по указателю,
// движок, построенный раньше, продолжает отвечать верно.
func TestLiteralIndex_SharedRulesBetweenEnginesStayCorrect(t *testing.T) {
	rules, err := LoadRulesFromDir("../../rules")
	require.NoError(t, err)
	var a, b *RuleEngine
	withLiteralIndex(true, func() { a = NewRuleEngine(rules) })
	withLiteralIndex(true, func() { b = NewRuleEngine(rules) }) // перезаписывает litIDs общих условий
	require.NotSame(t, a.fileLits, b.fileLits)
	var off *RuleEngine
	withLiteralIndex(false, func() { off = NewRuleEngine(rules) })
	evs := orderIdentityCorpus(t, rules)[:3000]
	want := alertMultiset(off, evs)
	require.Equal(t, want, alertMultiset(a, evs))
	require.Equal(t, want, alertMultiset(b, evs))
}

func BenchmarkLiteralIndexScan(b *testing.B) {
	rules, _ := LoadRulesFromDir("../../rules")
	re := NewRuleEngine(rules)
	hits := make([]uint64, re.fileLits.nWords)
	p := "/usr/lib/python3/dist-packages/apt/cache.py"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for j := range hits {
			hits[j] = 0
		}
		re.fileLits.scan(p, hits)
	}
}

// КНФ-наборы: шаблон требует литерал из КАЖДОГО набора.
func TestRequiredLiteralSets_Fixtures(t *testing.T) {
	has := func(sets [][]string, want string) bool {
		for _, s := range sets {
			for _, l := range s {
				if l == want {
					return true
				}
			}
		}
		return false
	}
	sets := requiredLiteralSets(`(union.*select|or\s+1\s*=\s*1|drop\s+table).*.*(\.\.|%2e|%2f|%5c)`)
	require.True(t, has(sets, ".."), "второй обязательный набор — обход пути: %v", sets)
	require.True(t, has(sets, "select"), "первый набор — по одной из веток: %v", sets)
	require.GreaterOrEqual(t, len(sets), 2, "КНФ: хотя бы два обязательных набора: %v", sets)
	sets = requiredLiteralSets(`[Ii][Nn][Ss][Ee][Rr][Tt]\s+[Ii][Nn][Tt][Oo]`)
	require.True(t, has(sets, " "), "\\s даёт набор пробельных символов: %v", sets)
	sets = requiredLiteralSets(`/proc/[0-9]+/maps`)
	require.True(t, has(sets, "/proc/") && has(sets, "/maps"), "%v", sets)
	require.Empty(t, requiredLiteralSets(`.*`), "без обязательного текста наборов нет")
	require.Empty(t, requiredLiteralSets(`a|b`), "однобайтовые литералы набором не берутся")
}

// Соундность: если regexp совпал, КНФ-префильтр обязан пропустить. На всех
// regex-шаблонах по filename боевых правил и на строках корпуса/дампа.
func TestLiteralSets_NeverSkipAMatch(t *testing.T) {
	rules, err := LoadRulesFromDir("../../rules")
	require.NoError(t, err)
	re := NewRuleEngine(rules)
	require.NotNil(t, re.fileLits)
	evs := orderIdentityCorpus(t, rules)
	seen := map[string]bool{}
	var names []string
	for _, e := range evs {
		if e.File != nil && !seen[e.File.Filename] {
			seen[e.File.Filename] = true
			names = append(names, e.File.Filename)
		}
	}
	// плюс прицельные строки: пробелы, SQL, обход, /proc
	names = append(names, "/tmp/a union select b/../x", "/tmp/x or 1=1 ..", "/tmp/INSERT   INTO t", "/tmp/drop\ttable ../x",
		"/proc/123/maps", "/proc/9/task/9/environ", "/x/%2e%2e/%2f drop table", "/var/log/a.log", "/tmp/k.PEM", "/etc/shadow")
	checked, matched := 0, 0
	for i := range re.rules {
		r := &re.rules[i]
		if r.EventType.String() != "file" {
			continue
		}
		for _, c := range collectConditionsOf(r) {
			cc := c
			if !isFilenameRegexCond(&cc) {
				continue
			}
			for pi, pat := range cc.Values {
				sets := requiredLiteralSets(pat)
				if len(sets) == 0 {
					continue
				}
				rx := cc.regexes[pi]
				for _, s := range names {
					checked++
					if !rx.MatchString(s) {
						continue
					}
					matched++
					for _, set := range sets {
						found := false
						for _, l := range set {
							if strings.Contains(s, l) {
								found = true
								break
							}
						}
						require.Truef(t, found, "шаблон %q (%s) совпал с %q, а набор %q не найден", pat, r.ID, s, set)
					}
				}
			}
		}
	}
	require.Greater(t, matched, 50, "корпус обязан содержать совпадения, иначе соундность не проверена")
	t.Logf("проверено пар %d, совпадений %d", checked, matched)
}

// «Правило без литерала проверяется всегда»: шаблон без обязательного текста не
// получает ворот и срабатывает так же, как без автомата; рядом шаблон с литералом.
func TestLiteralIndex_PatternWithoutLiteralIsAlwaysChecked(t *testing.T) {
	rules := []Rule{
		{ID: "no_lit", Name: "n", EventType: types.EventFileAccess, Severity: "warning", Action: ActionAlert,
			Condition: RuleCondition{Field: "filename", Op: OpRegex, Values: []string{`^/[a-z]{3}/[0-9]+$`}}},
		{ID: "mixed", Name: "n", EventType: types.EventFileAccess, Severity: "warning", Action: ActionAlert,
			Condition: RuleCondition{Field: "filename", Op: OpRegex, Values: []string{`^/[a-z]{3}/[0-9]+$`, `secretfile[0-9]`}}},
		{ID: "with_lit", Name: "n", EventType: types.EventFileAccess, Severity: "warning", Action: ActionAlert,
			Condition: RuleCondition{Field: "filename", Op: OpRegex, Values: []string{`secretfile[0-9]`}}},
	}
	re := NewRuleEngine(rules)
	require.NotNil(t, re.fileLits)
	ids := func(p string) []string {
		var out []string
		for _, a := range re.Evaluate(types.Event{Type: types.EventFileAccess, PID: 1, File: &types.FileEvent{Filename: p}}) {
			out = append(out, a.RuleID)
		}
		return out
	}
	require.ElementsMatch(t, []string{"no_lit", "mixed"}, ids("/abc/123"), "шаблон без литерала обязан проверяться на каждом пути")
	require.ElementsMatch(t, []string{"mixed", "with_lit"}, ids("/x/secretfile7"))
	require.Empty(t, ids("/x/other"))
	for _, r := range re.rules {
		if r.ID == "no_lit" || r.ID == "mixed" {
			require.Nil(t, r.litGate, "%s: у правила есть шаблон без литерала — ворота запрещены", r.ID)
		}
		if r.ID == "with_lit" {
			require.NotNil(t, r.litGate)
		}
	}
}
