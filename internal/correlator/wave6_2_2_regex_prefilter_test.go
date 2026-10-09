package correlator

import (
	"fmt"
	"math/rand"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Wave 6.2.2, finding №244 / open question 19.
//
// The first pprof profile of the agent put 44.88% of its CPU in regex
// backtracking inside the rule engine — not in enrichment, as the wave
// statement assumed. This file holds the offline instruments that (a) prove
// the load-time normalization and the required-literal prefilter cannot change
// what any rule matches, and (b) attribute the remaining cost per rule, which
// is what open question 19 asked for and what `go tool pprof` cannot answer
// (samples group by engine function, not by rule).

// TestWave6_2_2_RegexPrefilterEquivalence is the safety net for the whole
// optimization: for every regex pattern in every shipped rule, the pattern as
// written and the pattern as the engine now evaluates it (normalized, guarded
// by a required literal) must agree on every string of a large corpus —
// including strings built to hit the pattern's own literals, so the corpus
// contains matches and not only misses.
func TestWave6_2_2_RegexPrefilterEquivalence(t *testing.T) {
	rules, err := LoadRulesFromDir("../../rules")
	require.NoError(t, err)
	require.NotEmpty(t, rules)

	patterns := allRegexPatterns(rules)
	require.NotEmpty(t, patterns, "the shipped ruleset must contain regex conditions")
	t.Logf("checking %d distinct regex patterns from %d rules", len(patterns), len(rules))

	rng := rand.New(rand.NewSource(6222)) //nolint:gosec // deterministic corpus, not crypto
	for _, pattern := range patterns {
		original := regexp.MustCompile(pattern)
		normalized, err := regexp.Compile(normalizeRegexPattern(pattern))
		require.NoErrorf(t, err, "normalized form of %q must compile", pattern)
		literals := requiredLiterals(pattern)

		for _, s := range equivalenceCorpus(pattern, rng) {
			want := original.MatchString(s)
			got := normalized.MatchString(s)
			require.Equalf(t, want, got,
				"normalization changed the language of %q on input %q", pattern, s)
			if len(literals) > 0 && !containsAny(s, literals) {
				require.Falsef(t, want,
					"required literal set %v is not required by %q: it matched %q without containing any member",
					literals, pattern, s)
			}
		}
	}
}

// TestWave6_2_2_RegexPrefilterCoversHotRules pins the patterns that the first
// profile showed to dominate: each must end up with a usable required literal,
// so a regression that loses the prefilter for them is caught here rather than
// on the next node run.
func TestWave6_2_2_RegexPrefilterCoversHotRules(t *testing.T) {
	rules, err := LoadRulesFromDir("../../rules")
	require.NoError(t, err)
	byID := map[string]Rule{}
	for _, r := range rules {
		byID[r.ID] = r
	}

	// The five most expensive file rules from the offline attribution below,
	// together ~35% of all per-event rule cost before this change.
	for _, id := range []string{
		"webshell_common_filename",
		"web_path_traversal_process",
		"supply_chain_lockfile_recon",
		"mitre_ngrok_tunnel",
		"appexploit_xmrig_download",
	} {
		rule, ok := byID[id]
		require.Truef(t, ok, "rule %s is missing from the ruleset", id)
		engine := NewRuleEngine([]Rule{rule})
		for _, cond := range collectRegexConditions(&engine.rules[0]) {
			for i, pattern := range cond.Values {
				assert.NotEmptyf(t, cond.regexLiterals[i],
					"rule %s pattern %q lost its prefilter literal", id, pattern)
			}
		}
	}
}

// TestWave6_2_2_RegexPrefilterAttribution is the answer to open question 19,
// which pprof could not give: which rules the regex cost actually belongs to.
// It evaluates each file rule alone over a realistic idle-node event mix and
// prints ns/event, so the next profile has a per-rule baseline to compare
// against. It asserts only a loose ceiling — the number is machine-dependent
// and the point is the ranking, not a threshold.
func TestWave6_2_2_RegexPrefilterAttribution(t *testing.T) {
	if testing.Short() {
		t.Skip("timing measurement; skipped under -short")
	}
	rules, err := LoadRulesFromDir("../../rules")
	require.NoError(t, err)

	events := idleNodeFileEvents()
	type row struct {
		id string
		ns int64
	}
	var rows []row
	var total int64
	for i := range rules {
		if rules[i].EventType != types.EventFileAccess {
			continue
		}
		engine := NewRuleEngine([]Rule{rules[i]})
		start := time.Now()
		const reps = 50
		for r := 0; r < reps; r++ {
			for j := range events {
				engine.matchesTyped(&events[j], &engine.rules[0])
			}
		}
		ns := time.Since(start).Nanoseconds() / int64(reps*len(events))
		rows = append(rows, row{rules[i].ID, ns})
		total += ns
	}
	sort.Slice(rows, func(a, b int) bool { return rows[a].ns > rows[b].ns })

	var b strings.Builder
	fmt.Fprintf(&b, "per-rule cost over %d file rules, %d ns/event in total\n", len(rows), total)
	for i, r := range rows {
		if i >= 10 {
			break
		}
		fmt.Fprintf(&b, "  %6d ns  %4.1f%%  %s\n", r.ns, 100*float64(r.ns)/float64(total), r.id)
	}
	t.Log("\n" + b.String())

	// The ceiling is for the plain build; under -race it scales by the
	// detector's own cost (race_enabled_test.go), not by loosening the check.
	ceiling := int64(200_000)
	if raceEnabled {
		ceiling *= raceCostFactor
	}
	assert.Lessf(t, total, ceiling,
		"total per-event cost of all file rules regressed sharply (was ~5 µs after the wave 6.2.2 prefilter, ~49 µs before; race=%v)", raceEnabled)
}

// TestWave8_1_RegexRuleAttribution answers item 15 (б) of wave 8.1 offline:
// which `op: regex` conditions the regexp-engine CPU actually belongs to.
// pprof groups samples by engine function (`regexp.tryBacktrack`), not by rule,
// so the split has to be measured per rule. It reuses the idle-node file-event
// mix of the 6.2.2 attribution — the same mix the night profile is dominated
// by — and times the engine's own regex entry point (matchesRegex, i.e. the
// required-literal prefilter plus the compiled pattern) on the field value each
// event produces. The result is ns/event per rule and per pattern, plus how
// many event×pattern pairs get past the prefilter and actually reach the
// regexp engine. This is an upper bound on each rule's live share: a condition
// that sits behind an earlier false `and` term is timed here but never reached
// in production. No stand is involved.
func TestWave8_1_RegexRuleAttribution(t *testing.T) {
	if testing.Short() {
		t.Skip("timing measurement; skipped under -short")
	}
	rules, err := LoadRulesFromDir("../../rules")
	require.NoError(t, err)

	events := idleNodeFileEvents()

	type row struct {
		id       string
		regexNs  int64
		totalNs  int64
		patterns int
		reached  int // event×pattern pairs the prefilter let through to MatchString
	}
	var rows []row
	for i := range rules {
		if rules[i].EventType != types.EventFileAccess {
			continue
		}
		// Single-rule engine, like the 6.2.2 attribution: this is what makes the
		// conditions carry their compiled regexes and prefilter literals.
		engine := NewRuleEngine([]Rule{rules[i]})
		conds := collectRegexConditions(&engine.rules[0])
		if len(conds) == 0 {
			continue
		}

		// Total rule cost over the mix (reachability included).
		start := time.Now()
		const reps = 50
		for r := 0; r < reps; r++ {
			for j := range events {
				engine.matchesTyped(&events[j], &engine.rules[0])
			}
		}
		totalNs := time.Since(start).Nanoseconds() / int64(reps*len(events))

		var regexNs int64
		patterns, reached := 0, 0
		for _, cond := range conds {
			values := make([]string, len(events))
			for j := range events {
				values[j] = engine.getFieldValue(&events[j], cond.Field, nil)
			}
			patterns += len(cond.Values)
			// Mirror matchesRegex exactly, including its OR early-out: patterns
			// after the first match are never tried.
			for _, v := range values {
				for k, compiled := range cond.regexes {
					if !containsAny(v, cond.regexLiterals[k]) {
						continue
					}
					reached++
					if compiled.MatchString(v) {
						break
					}
				}
			}
			start := time.Now()
			const regexReps = 200
			for r := 0; r < regexReps; r++ {
				for _, v := range values {
					_ = engine.matchesRegex(cond, v)
				}
			}
			regexNs += time.Since(start).Nanoseconds() / int64(regexReps*len(events))
		}
		rows = append(rows, row{rules[i].ID, regexNs, totalNs, patterns, reached})
	}
	require.NotEmpty(t, rows, "the shipped ruleset must contain file rules with regex conditions")

	sort.Slice(rows, func(a, b int) bool { return rows[a].regexNs > rows[b].regexNs })

	var regexTotal int64
	totalPatterns := 0
	for _, r := range rows {
		regexTotal += r.regexNs
		totalPatterns += r.patterns
	}
	var b strings.Builder
	fmt.Fprintf(&b, "regex cost attributable to %d file rules (%d patterns) over %d events, %d ns/event in total\n",
		len(rows), totalPatterns, len(events), regexTotal)
	for i, r := range rows {
		if i >= 15 {
			break
		}
		// regexNs is measured on every event and is an upper bound: a condition
		// behind an earlier false `and` term is timed here but not reached in
		// production. totalNs is shown for scale only; the two come from
		// independent timing runs, so no reachability is inferred from them.
		fmt.Fprintf(&b, "  %6d ns regex  %4.1f%% of regex  %6d ns rule  %d pat  %d prefilter-pass  %s\n",
			r.regexNs, 100*float64(r.regexNs)/float64(regexTotal), r.totalNs, r.patterns, r.reached, r.id)
	}
	t.Log("\n" + b.String())
}

// BenchmarkWave6_2_2_FileRuleset measures the whole file-rule set against the
// same idle-node event mix — the closest offline stand-in for the 98.7% of
// node events that are file events.
func BenchmarkWave6_2_2_FileRuleset(b *testing.B) {
	rules, err := LoadRulesFromDir("../../rules")
	if err != nil {
		b.Fatal(err)
	}
	engine := NewRuleEngine(rules)
	events := idleNodeFileEvents()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.EvaluateInto(events[i%len(events)], func(types.Alert) {})
	}
}

func allRegexPatterns(rules []Rule) []string {
	seen := map[string]bool{}
	var out []string
	add := func(cond *RuleCondition) {
		if cond.Op != OpRegex {
			return
		}
		for _, p := range cond.Values {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	for i := range rules {
		for _, c := range conditionPtrs(&rules[i]) {
			add(c)
		}
	}
	sort.Strings(out)
	return out
}

func collectRegexConditions(rule *Rule) []*RuleCondition {
	var out []*RuleCondition
	for _, c := range conditionPtrs(rule) {
		if c.Op == OpRegex {
			out = append(out, c)
		}
	}
	return out
}

// conditionPtrs returns pointers to every condition of a rule — the base
// condition, every condition of its group tree, and those of its exceptions.
// Pointers, not copies, because the fields under test (regexes,
// regexLiterals) are filled in place by compileCondPtr.
func conditionPtrs(rule *Rule) []*RuleCondition {
	out := []*RuleCondition{&rule.Condition}
	var walk func(g *RuleConditionGroup)
	walk = func(g *RuleConditionGroup) {
		if g == nil {
			return
		}
		for i := range g.Conditions {
			out = append(out, &g.Conditions[i])
		}
		for i := range g.SubGroups {
			walk(&g.SubGroups[i])
		}
	}
	walk(rule.ConditionGroup)
	for i := range rule.Exceptions {
		out = append(out, &rule.Exceptions[i].Condition)
		walk(rule.Exceptions[i].ConditionGroup)
	}
	return out
}

// equivalenceCorpus builds strings likely to exercise the pattern: the literal
// fragments the pattern itself contains, realistic node paths, and random
// strings over an alphabet drawn from the pattern.
func equivalenceCorpus(pattern string, rng *rand.Rand) []string {
	corpus := append([]string{}, idleNodePaths...)
	corpus = append(corpus, "", "/", "a", strings.Repeat("a/", 60))

	// Literal runs from the pattern, alone and embedded in a path — these are
	// what makes the corpus contain actual matches and not just misses.
	var run strings.Builder
	flush := func() {
		if run.Len() > 0 {
			frag := run.String()
			corpus = append(corpus, frag, "/var/www/html/"+frag, frag+"/x", "/tmp/"+frag+".bak", frag+frag)
			run.Reset()
		}
	}
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch {
		case c == '\\' && i+1 < len(pattern):
			i++
			run.WriteByte(pattern[i])
		case strings.IndexByte(`.*+?()[]{}|^$`, c) >= 0:
			flush()
		default:
			run.WriteByte(c)
		}
	}
	flush()

	alphabet := []rune("/.-_%\n" + pattern)
	for i := 0; i < 400; i++ {
		n := rng.Intn(40)
		var s strings.Builder
		for j := 0; j < n; j++ {
			s.WriteRune(alphabet[rng.Intn(len(alphabet))])
		}
		corpus = append(corpus, s.String())
	}
	return corpus
}

// idleNodePaths is the file-path mix an idle k3s node actually produces, taken
// from the store snapshots and drift baselines of server-logs/collect-6.2.1.
var idleNodePaths = []string{
	"/var/lib/rancher/k3s/agent/containerd/io.containerd.content.v1.content/blobs/sha256/8d4f1c2b",
	"/proc/1234/status", "/proc/self/mountinfo", "/sys/fs/cgroup/memory.stat",
	"/var/log/pods/kube-system_coredns-abc/coredns/0.log",
	"/var/log/containers/coredns-abc_kube-system_coredns.log",
	"/usr/lib/x86_64-linux-gnu/libc.so.6", "/etc/hosts", "/etc/resolv.conf",
	"/run/systemd/journal/socket",
	"/var/lib/kubelet/pods/x/volumes/kubernetes.io~projected/token",
	"/tmp/tmp.XXXX/work", "/home/user/.cache/go-build/ab/abcdef",
	"/var/lib/rancher/k3s/server/db/state.db-wal",
	"/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq",
	"/usr/bin/containerd-shim-runc-v2", "/opt/ebpf-guard/rules/sigma-linux.yaml",
	"/var/www/html/index.php", "/var/www/uploads/shell.php",
}

var idleNodeComms = []string{
	"k3s-server", "containerd", "kubelet", "coredns", "systemd",
	"bash", "runc:[2:INIT]", "flannel",
}

func idleNodeFileEvents() []types.Event {
	out := make([]types.Event, 0, len(idleNodePaths)*len(idleNodeComms))
	now := uint64(time.Now().UnixNano())
	for i, path := range idleNodePaths {
		for j, comm := range idleNodeComms {
			fe := &types.FileEvent{Op: uint8((i + j) % 3), FDPath: path}
			copy(fe.Filename[:], path)
			e := types.Event{
				Type:      types.EventFileAccess,
				Timestamp: now,
				PID:       uint32(1000 + i*len(idleNodeComms) + j),
				File:      fe,
				ProcArgs:  "/usr/local/bin/k3s server --flannel-backend=vxlan --disable=traefik",
			}
			copy(e.Comm[:], comm)
			out = append(out, e)
		}
	}
	return out
}
