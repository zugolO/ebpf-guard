package correlator

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Заход B: бенч движка на настоящем входе — дамп событий (W86_DUMP). ns/op =
// ns на событие (одна итерация — одно событие). Бенч — сравнение до/после на
// ОДНОМ потоке; секунды ночи он не предсказывает.
//
//	W86_DUMP=server-logs/w86-b/events.jsonl go test ./internal/correlator \
//	  -run xxx -bench BenchmarkG0Dump -benchtime=2000000x -count=5
func BenchmarkG0Dump(b *testing.B) {
	p := os.Getenv("W86_DUMP")
	if p == "" {
		b.Skip("W86_DUMP не задан")
	}
	evs, err := LoadEventDump(p)
	require.NoError(b, err)
	for _, mode := range []struct {
		name    string
		reorder bool
		lit     bool
	}{{"s1", false, false}, {"s1+s2", true, false}, {"s1+s2+G1", true, true}} {
		b.Run(mode.name, func(b *testing.B) {
			var re *RuleEngine
			withReorder(mode.reorder, func() {
				withLiteralIndex(mode.lit, func() {
					rules, err := LoadRulesFromDir("../../rules")
					require.NoError(b, err)
					re = NewRuleEngine(rules)
				})
			})
			sink := func(types.Alert) {}
			for i := range evs[:min(len(evs), 20000)] { // прогрев
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
