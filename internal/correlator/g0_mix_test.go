package correlator

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 8.6, G0(б, в): офлайн-стенд движка правил на миксе событий idle-часа.
//
// Поток событий ночи 8.5 в архиве НЕ хранится (там только срезы метрик,
// алерты, журнал и 9 профилей CPU по 30 с), поэтому поток собирается из
// распределений: типы и операции — счётчики ночи 8.5 (events_total,
// file_events_by_op_total, syscall_events_by_nr_total), пары comm+путь —
// гистограмма openat с самого стенда (bpftrace, G0_PATHS, TSV
// «comm<TAB>path<TAB>count»). Не подгонка: сводка печатает доли узлов рядом с
// ночью, расхождение называется расхождением.
//
// Запуск (не входит в обычный прогон — нужен файл гистограммы):
//
//	G0_PATHS=/path/openat.tsv G0_OUT=/path/out G0_SECONDS=40 \
//	  go test ./internal/correlator -run TestG0MixProfile -count=1 -v
//
// G0_OUT получает: cpu-plain.pprof (без меток), cpu-labels.pprof (метки
// event_type/rule_file/rule_id), regex-probe.tsv (вердикт G0(в) по правилу),
// summary.txt.

// Счётчики ночи 8.5 (idle/metrics-end.txt, хост, 28 800 с).
var g0TypeWeights = []struct {
	t types.EventType
	w float64
}{
	{types.EventFileAccess, 7403851},
	{types.EventSyscall, 385066},
	{types.EventTCPConnect, 34737},
	{types.EventDNS, 477},
}

var g0FileOps = []struct {
	op uint8
	w  float64
}{
	{0, 3784732 + 7624}, {1, 3567846 + 12201}, {2, 34930 + 6}, {3, 1056},
	{4, 1321}, {5, 2148}, {6, 500 + 196}, {7, 157},
}

var g0SyscallNR = []struct {
	nr int64
	w  float64
}{
	{41, 318943}, {157, 51943}, {59, 40776}, {105, 6506}, {62, 5532}, {161, 5532},
	{9, 4912}, {321, 3180}, {82, 1962}, {10, 1380}, {126, 1002}, {165, 322},
	{158, 200}, {317, 156}, {298, 92}, {258, 72}, {166, 70}, {280, 32}, {272, 8}, {319, 4},
}

var g0Denylist = []string{"/sys/devices/system/", "/sys/block/", "/usr/share/zoneinfo/"}

type g0Pair struct {
	comm, path string
	w          float64
}

func g0LoadPairs(t *testing.T, file string) []g0Pair {
	f, err := os.Open(file)
	require.NoError(t, err)
	defer f.Close()
	var out []g0Pair
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		p := strings.Split(sc.Text(), "\t")
		if len(p) != 3 || p[1] == "" {
			continue
		}
		n, err := strconv.ParseFloat(p[2], 64)
		if err != nil || n <= 0 {
			continue
		}
		deny := false
		for _, d := range g0Denylist {
			if strings.HasPrefix(p[1], d) {
				deny = true
			}
		}
		if !deny {
			out = append(out, g0Pair{p[0], p[1], n})
		}
	}
	require.NoError(t, sc.Err())
	require.NotEmpty(t, out)
	return out
}

func g0Pick[T any](rng *rand.Rand, items []T, weight func(T) float64, total float64) T {
	x := rng.Float64() * total
	for _, it := range items {
		x -= weight(it)
		if x <= 0 {
			return it
		}
	}
	return items[len(items)-1]
}

func g0BuildStream(t *testing.T, pairs []g0Pair, n int) []types.Event {
	rng := rand.New(rand.NewSource(8605))
	var totPair, totType, totOp, totNR float64
	for _, p := range pairs {
		totPair += p.w
	}
	for _, x := range g0TypeWeights {
		totType += x.w
	}
	for _, x := range g0FileOps {
		totOp += x.w
	}
	for _, x := range g0SyscallNR {
		totNR += x.w
	}
	comm16 := func(s string) (c [16]byte) { copy(c[:], s); return }
	out := make([]types.Event, 0, n)
	for i := 0; i < n; i++ {
		ty := g0Pick(rng, g0TypeWeights, func(x struct {
			t types.EventType
			w float64
		}) float64 {
			return x.w
		}, totType).t
		pr := g0Pick(rng, pairs, func(p g0Pair) float64 { return p.w }, totPair)
		ev := types.Event{Type: ty, PID: uint32(1000 + rng.Intn(3000)), Comm: comm16(pr.comm)}
		switch ty {
		case types.EventFileAccess:
			op := g0Pick(rng, g0FileOps, func(x struct {
				op uint8
				w  float64
			}) float64 {
				return x.w
			}, totOp).op
			fe := &types.FileEvent{Op: op, Filename: pr.path}
			switch op {
			case 0:
				fe.Flags = 0o2000000 // O_RDONLY|O_CLOEXEC
			case 1, 2:
				fe.FDPath, fe.Filename = pr.path, ""
			}
			ev.File = fe
		case types.EventSyscall:
			nr := g0Pick(rng, g0SyscallNR, func(x struct {
				nr int64
				w  float64
			}) float64 {
				return x.w
			}, totNR).nr
			ev.Syscall = &types.SyscallEvent{Nr: nr}
		case types.EventTCPConnect:
			ne := &types.NetworkEvent{Dport: []uint16{443, 80, 53, 8080}[rng.Intn(4)], Proto: 6, Family: types.AFInet}
			ne.Daddr[0], ne.Daddr[1], ne.Daddr[2], ne.Daddr[3] = byte(1+rng.Intn(200)), byte(rng.Intn(256)), byte(rng.Intn(256)), byte(1+rng.Intn(250))
			ev.Network = ne
		case types.EventDNS:
			ev.DNS = &types.DNSEvent{QName: "example.com"}
		}
		out = append(out, ev)
	}
	return out
}

// g0Owners — владелец (id правила) каждого условия движка, по указателю.
func g0Owners(re *RuleEngine) map[*RuleCondition]string {
	own := map[*RuleCondition]string{}
	var walk func(g *RuleConditionGroup, id string)
	walk = func(g *RuleConditionGroup, id string) {
		if g == nil {
			return
		}
		for i := range g.Conditions {
			own[&g.Conditions[i]] = id
		}
		for i := range g.SubGroups {
			walk(&g.SubGroups[i], id)
		}
	}
	for t := range re.byType {
		for i := range re.byType[t] {
			r := &re.byType[t][i]
			own[&r.Condition] = r.ID
			walk(r.ConditionGroup, r.ID)
			for j := range r.Exceptions {
				ex := &r.Exceptions[j]
				own[&ex.Condition] = r.ID
				walk(ex.ConditionGroup, r.ID)
			}
		}
	}
	return own
}

func g0Run(re *RuleEngine, stream []types.Event, dur time.Duration) (evals int, elapsed time.Duration, perType map[types.EventType][2]int64) {
	perType = map[types.EventType][2]int64{}
	sink := func(types.Alert) {}
	start := time.Now()
	for time.Since(start) < dur {
		for i := range stream {
			re.EvaluateInto(stream[i], sink)
		}
		evals += len(stream)
	}
	return evals, time.Since(start), perType
}

func TestG0MixProfile(t *testing.T) {
	pathsFile := os.Getenv("G0_PATHS")
	dumpFile := os.Getenv("G0_DUMP")
	if pathsFile == "" && dumpFile == "" {
		t.Skip("ни G0_DUMP (дамп событий движка, заход B), ни G0_PATHS (гистограмма со стенда) не заданы")
	}
	out := os.Getenv("G0_OUT")
	require.NotEmpty(t, out, "G0_OUT обязателен")
	require.NoError(t, os.MkdirAll(out, 0o755))
	secs := 40
	if s := os.Getenv("G0_SECONDS"); s != "" {
		secs, _ = strconv.Atoi(s)
	}
	dur := time.Duration(secs) * time.Second

	var pairs []g0Pair
	var stream []types.Event
	if dumpFile != "" {
		// Заход B: настоящий вход — дамп событий движка (server.event_dump_path).
		var err error
		stream, err = LoadEventDump(dumpFile)
		require.NoError(t, err)
	} else {
		pairs = g0LoadPairs(t, pathsFile)
		stream = g0BuildStream(t, pairs, 200000)
	}
	rules, err := LoadRulesFromDir("../../rules")
	require.NoError(t, err)

	var sum strings.Builder
	counts := map[types.EventType]int{}
	for i := range stream {
		counts[stream[i].Type]++
	}
	fmt.Fprintf(&sum, "rules=%d pairs=%d stream=%d types=%v\n", len(rules), len(pairs), len(stream), counts)

	profile := func(name string, labels bool) {
		SetProfileLabels(labels, labels)
		re := NewRuleEngine(rules)
		g0Run(re, stream[:20000], 2*time.Second) // прогрев
		f, err := os.Create(filepath.Join(out, name))
		require.NoError(t, err)
		require.NoError(t, pprof.StartCPUProfile(f))
		n, el, _ := g0Run(re, stream, dur)
		pprof.StopCPUProfile()
		f.Close()
		fmt.Fprintf(&sum, "%s: events=%d elapsed=%.1fs ns/event=%.0f\n", name, n, el.Seconds(), float64(el.Nanoseconds())/float64(n))
	}
	profile("cpu-plain.pprof", false)
	profile("cpu-labels.pprof", true)
	SetProfileLabels(false, false)

	// G0(в): исход префильтра и regex по правилу, один полный проход потока
	// (без автомата литералов и ворот правил — «вызовов шаблона» считаются все).
	var re *RuleEngine
	withLiteralIndex(false, func() { re = NewRuleEngine(rules) })
	own := g0Owners(re)
	type st struct{ calls, lit, match int }
	stats := map[string]*st{}
	regexProbe = func(c *RuleCondition, _ int, lit, m bool) {
		id := own[c]
		if id == "" {
			id = "?"
		}
		s := stats[id]
		if s == nil {
			s = &st{}
			stats[id] = s
		}
		s.calls++
		if lit {
			s.lit++
		}
		if m {
			s.match++
		}
	}
	for i := range stream {
		re.EvaluateInto(stream[i], func(types.Alert) {})
	}
	regexProbe = nil
	ids := make([]string, 0, len(stats))
	for id := range stats {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		return stats[ids[i]].lit-stats[ids[i]].match > stats[ids[j]].lit-stats[ids[j]].match
	})
	pf, err := os.Create(filepath.Join(out, "regex-probe.tsv"))
	require.NoError(t, err)
	fmt.Fprintln(pf, "rule_id\tpattern_calls\tliteral_passed\tregex_matched\twasted_regex")
	for _, id := range ids {
		s := stats[id]
		fmt.Fprintf(pf, "%s\t%d\t%d\t%d\t%d\n", id, s.calls, s.lit, s.match, s.lit-s.match)
	}
	pf.Close()
	require.NoError(t, os.WriteFile(filepath.Join(out, "summary.txt"), []byte(sum.String()), 0o644))
	t.Log("\n" + sum.String())
}

// G0(в): крючок regexProbe различает «литерал не прошёл», «литерал прошёл, regex
// не совпал» (трата) и «совпал» — по правилу, с владельцем по указателю условия.
func TestRegexProbe_CountsLiteralPassAndMatch(t *testing.T) {
	rule := Rule{
		ID: "g0_probe", Name: "g0 probe", EventType: types.EventFileAccess,
		Condition: RuleCondition{Field: "filename", Op: OpRegex, Values: []string{`secret.*key`}},
		Severity:  types.SeverityWarning, Action: ActionAlert,
	}
	// G1 (ворота правила) отсекает правило до вызова шаблона и «calls» не посчитает:
	// счёт G0(в) снимается без автомата; lit/match при автомате те же (проверка ниже).
	var re *RuleEngine
	withLiteralIndex(false, func() { re = NewRuleEngine([]Rule{rule}) })
	own := g0Owners(re)
	type st struct{ calls, lit, match int }
	got := map[string]*st{}
	regexProbe = func(c *RuleCondition, _ int, lit, m bool) {
		id := own[c]
		if got[id] == nil {
			got[id] = &st{}
		}
		got[id].calls++
		if lit {
			got[id].lit++
		}
		if m {
			got[id].match++
		}
	}
	defer func() { regexProbe = nil }()
	for _, p := range []string{"/a/other", "/a/secret_x", "/a/secret_key"} {
		re.EvaluateInto(w81FileEvent(1, "cat", p, 0), func(types.Alert) {})
	}
	require.NotNil(t, got["g0_probe"], "владелец условия должен находиться по указателю")
	require.Equal(t, st{calls: 3, lit: 2, match: 1}, *got["g0_probe"])

	// С автоматом: ворота правила и КНФ-наборы («secret» И «key») снимают шаблон до
	// вызова; доходит только «/a/secret_key», и он совпадает.
	reG1 := NewRuleEngine([]Rule{rule})
	ownG1 := g0Owners(reG1)
	got1 := map[string]*st{}
	regexProbe = func(c *RuleCondition, _ int, lit, m bool) {
		id := ownG1[c]
		if got1[id] == nil {
			got1[id] = &st{}
		}
		got1[id].calls++
		if lit {
			got1[id].lit++
		}
		if m {
			got1[id].match++
		}
	}
	for _, p := range []string{"/a/other", "/a/secret_x", "/a/secret_key"} {
		reG1.EvaluateInto(w81FileEvent(1, "cat", p, 0), func(types.Alert) {})
	}
	require.Equal(t, st{calls: 1, lit: 1, match: 1}, *got1["g0_probe"])
}
