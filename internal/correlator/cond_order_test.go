package correlator

import (
	"fmt"
	"math/rand"
	"net"
	"os"
	"regexp"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

func withReorder(on bool, f func()) {
	prev := reorderConditions
	reorderConditions = on
	defer func() { reorderConditions = prev }()
	f()
}

func condSig(g *RuleConditionGroup) []string {
	var out []string
	for _, c := range g.Conditions {
		out = append(out, fmt.Sprintf("%s/%s", c.Field, c.Op))
	}
	return out
}

func compileGroup(t *testing.T, g *RuleConditionGroup) {
	t.Helper()
	re := &RuleEngine{regexCache: map[string]*regexp.Regexp{}, cidrCache: map[string]*net.IPNet{}, valueSetCache: map[string]map[string]struct{}{}}
	require.NoError(t, re.compileGroupPatterns(g))
}

func TestCondOrder_CheapBeforeRegex_BarriersStay(t *testing.T) {
	mk := func() *RuleConditionGroup {
		return &RuleConditionGroup{Operator: "and", Conditions: []RuleCondition{
			{Field: "filename", Op: OpRegex, Values: []string{"/etc/.*shadow"}},
			{Field: "proc.comm", Op: OpIn, Values: []string{"cat"}},
			{Field: "filename", Op: OpContains, Values: []string{"sh"}},
			{Field: "proc.exe_path", Op: OpIn, Values: []string{"/usr/bin/cat"}},
			{Field: "filename", Op: OpRegex, Values: []string{"x[0-9]"}},
			{Field: "file.op", Op: OpIn, Values: []string{"open"}},
			{Field: "proc.systemd_unit", Op: OpEquals, Values: []string{"u.service"}},
			{Field: "file.flags", Op: OpRegex, Values: []string{"^0$"}},
		}}
	}
	g := mk()
	withReorder(true, func() { compileGroup(t, g) })
	require.Equal(t, []string{
		"proc.comm/in", "filename/contains", "filename/regex", // отрезок до exe_path
		"proc.exe_path/in",
		"file.op/in", "filename/regex", // между барьерами
		"proc.systemd_unit/equals",
		"file.flags/regex",
	}, condSig(g))

	// Мутация «порядок не применяется»: исходный порядок, дорогое раньше дешёвого.
	g0 := mk()
	withReorder(false, func() { compileGroup(t, g0) })
	require.Equal(t, "filename/regex", condSig(g0)[0])
	require.NotEqual(t, condSig(g0), condSig(g))
}

func TestCondOrder_StableAndIdempotent(t *testing.T) {
	g := &RuleConditionGroup{Operator: "and", Conditions: []RuleCondition{
		{Field: "comm", Op: OpIn, Values: []string{"a"}},
		{Field: "op", Op: OpIn, Values: []string{"open"}},
		{Field: "filename", Op: OpPrefix, Values: []string{"/etc"}},
	}}
	before := condSig(g)
	compileGroup(t, g)
	require.Equal(t, before, condSig(g), "уже упорядоченную группу не трогаем")
	compileGroup(t, g)
	require.Equal(t, before, condSig(g))
}

// Свойство: результат группы не зависит от порядка чистых условий — на случайных
// вложенных группах и случайных файловых событиях.
func TestCondOrder_PropertyResultUnchanged(t *testing.T) {
	rng := rand.New(rand.NewSource(86))
	comms := []string{"nginx", "cat", "bash", "python3", "sshd", ""}
	paths := []string{"/etc/shadow", "/etc/passwd", "/tmp/x1", "/var/www/../x", "/usr/lib/a.so", "/proc/1/mem", ""}
	randCond := func() RuleCondition {
		switch rng.Intn(7) {
		case 0:
			return RuleCondition{Field: "filename", Op: OpRegex, Values: []string{[]string{"shadow|mem$", "x[0-9]", "\\.\\./"}[rng.Intn(3)]}}
		case 1:
			return RuleCondition{Field: "proc.comm", Op: OpIn, Values: []string{comms[rng.Intn(5)]}}
		case 2:
			return RuleCondition{Field: "proc.comm", Op: OpNotIn, Values: []string{comms[rng.Intn(5)]}}
		case 3:
			return RuleCondition{Field: "filename", Op: OpPrefix, Values: []string{[]string{"/etc", "/tmp", "/proc"}[rng.Intn(3)]}}
		case 4:
			return RuleCondition{Field: "filename", Op: OpContains, Values: []string{[]string{"sh", "x", "lib"}[rng.Intn(3)]}}
		case 5:
			return RuleCondition{Field: "file.op", Op: OpIn, Values: []string{[]string{"open", "read", "write"}[rng.Intn(3)]}}
		default:
			return RuleCondition{Field: "filename", Op: OpSuffix, Values: []string{[]string{".so", "mem", "1"}[rng.Intn(3)]}}
		}
	}
	var randGroup func(depth int) RuleConditionGroup
	randGroup = func(depth int) RuleConditionGroup {
		g := RuleConditionGroup{Operator: []string{"and", "or"}[rng.Intn(2)]}
		for i, n := 0, 1+rng.Intn(5); i < n; i++ {
			g.Conditions = append(g.Conditions, randCond())
		}
		if depth < 2 {
			for i, n := 0, rng.Intn(3); i < n; i++ {
				g.SubGroups = append(g.SubGroups, randGroup(depth+1))
			}
		}
		return g
	}
	re := &RuleEngine{}
	checked := 0
	for it := 0; it < 400; it++ {
		g1, g2 := randGroup(0), RuleConditionGroup{}
		g2 = cloneGroup(&g1)
		withReorder(false, func() { compileGroup(t, &g1) })
		withReorder(true, func() { compileGroup(t, &g2) })
		for k := 0; k < 25; k++ {
			e := types.Event{Type: types.EventFileAccess, PID: 7, File: &types.FileEvent{Op: uint8(rng.Intn(3)), Filename: paths[rng.Intn(len(paths))]}}
			copy(e.Comm[:], comms[rng.Intn(len(comms))])
			a := re.evaluateConditionGroup(&e, &g1, nil, &eventFieldCache{})
			b := re.evaluateConditionGroup(&e, &g2, nil, &eventFieldCache{})
			require.Equalf(t, a, b, "группа %d событие %d", it, k)
			checked++
		}
	}
	require.Equal(t, 400*25, checked)
}

func cloneGroup(g *RuleConditionGroup) RuleConditionGroup {
	out := RuleConditionGroup{Operator: g.Operator}
	for _, c := range g.Conditions {
		out.Conditions = append(out.Conditions, RuleCondition{Field: c.Field, Op: c.Op, Values: append([]string(nil), c.Values...)})
	}
	for i := range g.SubGroups {
		out.SubGroups = append(out.SubGroups, cloneGroup(&g.SubGroups[i]))
	}
	return out
}

// corpus для тождества на боевом наборе: события дампа (CORPUS_DUMP) либо
// синтетика из значений самих правил.
func orderIdentityCorpus(t *testing.T, rules []Rule) []types.Event {
	if p := os.Getenv("W86_DUMP"); p != "" {
		evs, err := LoadEventDump(p)
		require.NoError(t, err)
		return evs
	}
	rng := rand.New(rand.NewSource(8602))
	var tokens []string
	for i := range rules {
		for _, c := range collectConditionsOf(&rules[i]) {
			tokens = append(tokens, c.Values...)
		}
	}
	sort.Strings(tokens)
	comms := []string{"nginx", "cat", "bash", "python3", "sshd", "tee", "runc", "systemd", "curl", "php-fpm"}
	paths := []string{"/etc/shadow", "/etc/passwd", "/tmp/x1", "/var/www/html/../../etc/passwd", "/usr/lib/python3/a.so", "/proc/1/mem",
		"/sys/fs/cgroup/rdma/release_agent", "/tmp/cgrp/release_agent", "/root/.ssh/authorized_keys", "/dev/shm/a.so", "/etc/cron.d/x"}
	var evs []types.Event
	for i := 0; i < 6000; i++ {
		p := paths[rng.Intn(len(paths))]
		if rng.Intn(3) == 0 && len(tokens) > 0 {
			p = tokens[rng.Intn(len(tokens))]
		}
		e := types.Event{Type: types.EventFileAccess, PID: uint32(100 + rng.Intn(50)), UID: uint32(rng.Intn(2) * 1000),
			File: &types.FileEvent{Op: uint8(rng.Intn(8)), Flags: int32(rng.Intn(3000)), Filename: p}}
		copy(e.Comm[:], comms[rng.Intn(len(comms))])
		evs = append(evs, e)
	}
	return evs
}

func collectConditionsOf(r *Rule) []RuleCondition {
	if r.ConditionGroup != nil {
		return collectConditions(r.ConditionGroup)
	}
	return []RuleCondition{r.Condition}
}

func alertMultiset(re *RuleEngine, evs []types.Event) map[string]int {
	// Пороговые правила считают в package-level трекере: без сброса второй
	// прогон видит счётчики первого.
	globalBurstTracker = NewBurstTracker()
	m := map[string]int{}
	for i := range evs {
		re.EvaluateInto(evs[i], func(a types.Alert) { m[fmt.Sprintf("%s|%d", a.RuleID, i)]++ })
	}
	return m
}

// «Тот же набор алертов» на боевых правилах: порядок включён и выключен.
func TestCondOrder_ShippedRulesetSameAlerts(t *testing.T) {
	load := func(on bool) (*RuleEngine, []Rule) {
		var re *RuleEngine
		var rules []Rule
		withReorder(on, func() {
			var err error
			rules, err = LoadRulesFromDir("../../rules")
			require.NoError(t, err)
			re = NewRuleEngine(rules)
		})
		return re, rules
	}
	reOff, rulesOff := load(false)
	reOn, _ := load(true)
	evs := orderIdentityCorpus(t, rulesOff)
	a, b := alertMultiset(reOff, evs), alertMultiset(reOn, evs)
	require.NotEmpty(t, a, "корпус обязан поднимать алерты, иначе тождество пусто")
	var diff []string
	for k, v := range a {
		if b[k] != v {
			diff = append(diff, fmt.Sprintf("off-only %s (%d vs %d)", k, v, b[k]))
		}
	}
	for k, v := range b {
		if a[k] != v {
			diff = append(diff, fmt.Sprintf("on-only %s (%d vs %d)", k, a[k], v))
		}
	}
	sort.Strings(diff)
	if len(diff) > 20 {
		diff = diff[:20]
	}
	require.Empty(t, diff, "наборы алертов разошлись")
	t.Logf("событий %d, алертов %d", len(evs), len(a))
}
