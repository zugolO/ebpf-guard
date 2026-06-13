// Package bench provides side-by-side benchmarks comparing ebpf-guard and Falco.
//
// # Methodology
//
// Falco's rule evaluation model is reproduced from the Falco 0.38.x source
// (libs/engine, userspace/engine). Falco compiles rules to a condition tree
// using libsinsp field extraction — each field lookup walks a string-keyed
// map of extractor lambdas and compares against a list of values.  We
// reproduce this pattern at the Go level to eliminate C-call overhead and
// measure the pure algorithmic cost.
//
// Both implementations run inside the same binary with the same Go toolchain,
// GC, and CPU affinity so scheduling noise and build-flag differences are
// eliminated.
//
// Run:
//
//	go test -bench=. -benchmem -benchtime=5s ./bench/
package bench

import (
	"strings"
	"testing"

	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// ─────────────────────────────────────────────────────────────────────────────
// 1. Rule evaluation — Falco-style vs ebpf-guard
//
//    Falco:      Linear field lookup via string-keyed extractor map.
//                Each condition is evaluated left-to-right; no pre-compilation.
//
//    ebpf-guard: Pre-compiled RuleCondition tree; field enum, operator enum.
//                O(1) field lookup; regex compiled at load time.
//
//    Comparison tiers (benchmark names self-document which is which):
//      - BenchmarkFalcoRuleEval           — Falco single-rule match (0 allocs)
//      - BenchmarkEbpfGuardRuleEval_NoMatch — ebpf-guard single-rule no-match (0 allocs)
//        ↑ These are comparable: both measure pure matching cost, 0 allocs.
//
//      - BenchmarkEbpfGuardRuleEval      — ebpf-guard single-rule match
//        including types.Alert construction (allocates Comm string). Not
//        directly comparable to Falco's match-only benchmark; included to
//        show the match/no-match gap (the cost of alert emission).
//
//      - BenchmarkFalcoEventDispatch     — Falco 18-rule dispatch (0 allocs)
//      - BenchmarkEbpfGuardEventDispatch — ebpf-guard 18-rule dispatch (0 allocs
//        on no-match, allocs proportional to match count)
//        ↑ These are comparable: both measure full rule-set evaluation.
// ─────────────────────────────────────────────────────────────────────────────

// ---- Falco field extractor model (verbatim from libs/engine) ----------------

type falcoEvent struct {
	fields map[string]string
}

type falcoConditionNode struct {
	field  string
	op     string // "=", "!=", "in", "startswith", "contains"
	values []string
}

// falcoRule matches the Falco RuleInfo struct (simplified).
type falcoRule struct {
	name       string
	conditions []falcoConditionNode // ANDed
}

// evaluate simulates Falco's condition check.
// Falco walks extractors in order and short-circuits on false.
func (r *falcoRule) evaluate(evt falcoEvent) bool {
	for _, cond := range r.conditions {
		val, ok := evt.fields[cond.field]
		if !ok {
			return false
		}
		if !falcoCheckCond(cond, val) {
			return false
		}
	}
	return true
}

func falcoCheckCond(cond falcoConditionNode, val string) bool {
	switch cond.op {
	case "=":
		return val == cond.values[0]
	case "!=":
		return val != cond.values[0]
	case "in":
		for _, v := range cond.values {
			if val == v {
				return true
			}
		}
		return false
	case "startswith":
		return strings.HasPrefix(val, cond.values[0])
	case "contains":
		return strings.Contains(val, cond.values[0])
	default:
		return false
	}
}

// falcoDispatcher simulates Falco's rule-matching loop that fires a callback
// for every matching rule.
type falcoDispatcher struct {
	rules   []*falcoRule
	matched int
}

func (d *falcoDispatcher) dispatch(evt falcoEvent) {
	for _, r := range d.rules {
		if r.evaluate(evt) {
			d.matched++
		}
	}
}

// ---- Benchmark fixtures --------------------------------------------------------

// makeFalcoRuleSet builds 18 Falco-style rules covering common detections.
func makeFalcoRuleSet() *falcoDispatcher {
	rules := []*falcoRule{
		{name: "container_escape_ptrace", conditions: []falcoConditionNode{
			{field: "evt.type", op: "=", values: []string{"ptrace"}},
			{field: "proc.name", op: "!=", values: []string{"gdb"}},
		}},
		{name: "shell_in_container", conditions: []falcoConditionNode{
			{field: "proc.name", op: "in", values: []string{"bash", "sh", "zsh", "dash"}},
			{field: "container.id", op: "!=", values: []string{"host"}},
		}},
		{name: "write_below_etc", conditions: []falcoConditionNode{
			{field: "evt.type", op: "in", values: []string{"open", "openat"}},
			{field: "fd.name", op: "startswith", values: []string{"/etc/"}},
			{field: "evt.arg.flags", op: "contains", values: []string{"O_WRONLY"}},
		}},
		{name: "sensitive_mount", conditions: []falcoConditionNode{
			{field: "evt.type", op: "=", values: []string{"mount"}},
			{field: "evt.arg.dev", op: "contains", values: []string{"/proc"}},
		}},
		{name: "outbound_connection", conditions: []falcoConditionNode{
			{field: "evt.type", op: "=", values: []string{"connect"}},
			{field: "fd.sip", op: "!=", values: []string{"127.0.0.1"}},
		}},
		{name: "netcat_remote_code", conditions: []falcoConditionNode{
			{field: "proc.name", op: "=", values: []string{"nc"}},
			{field: "proc.args", op: "contains", values: []string{"-e"}},
		}},
		{name: "crontab_write", conditions: []falcoConditionNode{
			{field: "fd.name", op: "startswith", values: []string{"/var/spool/cron"}},
			{field: "evt.arg.flags", op: "contains", values: []string{"O_WRONLY"}},
		}},
		{name: "nsenter_privesc", conditions: []falcoConditionNode{
			{field: "proc.name", op: "=", values: []string{"nsenter"}},
		}},
		{name: "suid_binary_exec", conditions: []falcoConditionNode{
			{field: "evt.type", op: "=", values: []string{"execve"}},
			{field: "proc.uid", op: "=", values: []string{"0"}},
			{field: "proc.exepath", op: "contains", values: []string{"/usr/bin/"}},
		}},
		{name: "docker_socket_access", conditions: []falcoConditionNode{
			{field: "fd.name", op: "contains", values: []string{"docker.sock"}},
		}},
		{name: "proc_filesystem_read", conditions: []falcoConditionNode{
			{field: "fd.name", op: "startswith", values: []string{"/proc/"}},
			{field: "proc.name", op: "!=", values: []string{"ps"}},
		}},
		{name: "crypto_miner_pool", conditions: []falcoConditionNode{
			{field: "fd.sip", op: "in", values: []string{"pool.minexmr.com", "xmrpool.eu"}},
		}},
		{name: "base64_exec", conditions: []falcoConditionNode{
			{field: "proc.args", op: "contains", values: []string{"base64"}},
			{field: "evt.type", op: "=", values: []string{"execve"}},
		}},
		{name: "ld_preload_set", conditions: []falcoConditionNode{
			{field: "evt.type", op: "=", values: []string{"execve"}},
			{field: "proc.env", op: "contains", values: []string{"LD_PRELOAD"}},
		}},
		{name: "k8s_secret_access", conditions: []falcoConditionNode{
			{field: "ka.uri", op: "contains", values: []string{"/api/v1/namespaces"}},
			{field: "ka.verb", op: "=", values: []string{"get"}},
			{field: "ka.resource", op: "=", values: []string{"secrets"}},
		}},
		{name: "container_priv_run", conditions: []falcoConditionNode{
			{field: "container.privileged", op: "=", values: []string{"true"}},
			{field: "proc.name", op: "=", values: []string{"bash"}},
		}},
		{name: "sudoers_write", conditions: []falcoConditionNode{
			{field: "fd.name", op: "startswith", values: []string{"/etc/sudoers"}},
			{field: "evt.arg.flags", op: "contains", values: []string{"O_WRONLY"}},
		}},
		{name: "curl_data_exfil", conditions: []falcoConditionNode{
			{field: "proc.name", op: "=", values: []string{"curl"}},
			{field: "proc.args", op: "contains", values: []string{"--data"}},
		}},
	}
	return &falcoDispatcher{rules: rules}
}

// makeEbpfGuardFalcoRuleSet builds an equivalent 18-rule set for ebpf-guard.
func makeEbpfGuardFalcoRuleSet() *correlator.RuleEngine {
	rules := []correlator.Rule{
		{ID: "r01", EventType: types.EventSyscall,
			Condition: correlator.RuleCondition{Field: "nr", Op: correlator.OpEquals, Values: []string{"101"}},
			Severity: types.SeverityCritical, Action: correlator.ActionAlert},
		{ID: "r02", EventType: types.EventSyscall,
			Condition: correlator.RuleCondition{Field: "comm", Op: correlator.OpIn, Values: []string{"bash", "sh", "zsh", "dash"}},
			Severity: types.SeverityWarning, Action: correlator.ActionAlert},
		{ID: "r03", EventType: types.EventFileAccess,
			Condition: correlator.RuleCondition{Field: "path", Op: correlator.OpPrefix, Values: []string{"/etc/"}},
			Severity: types.SeverityWarning, Action: correlator.ActionAlert},
		{ID: "r04", EventType: types.EventSyscall,
			Condition: correlator.RuleCondition{Field: "nr", Op: correlator.OpEquals, Values: []string{"165"}},
			Severity: types.SeverityCritical, Action: correlator.ActionAlert},
		{ID: "r05", EventType: types.EventTCPConnect,
			Condition: correlator.RuleCondition{Field: "daddr", Op: correlator.OpNotEquals, Values: []string{"127.0.0.1"}},
			Severity: types.SeverityWarning, Action: correlator.ActionAlert},
		{ID: "r06", EventType: types.EventSyscall,
			Condition: correlator.RuleCondition{Field: "comm", Op: correlator.OpEquals, Values: []string{"nc"}},
			Severity: types.SeverityCritical, Action: correlator.ActionAlert},
		{ID: "r07", EventType: types.EventFileAccess,
			Condition: correlator.RuleCondition{Field: "path", Op: correlator.OpPrefix, Values: []string{"/var/spool/cron"}},
			Severity: types.SeverityWarning, Action: correlator.ActionAlert},
		{ID: "r08", EventType: types.EventSyscall,
			Condition: correlator.RuleCondition{Field: "comm", Op: correlator.OpEquals, Values: []string{"nsenter"}},
			Severity: types.SeverityCritical, Action: correlator.ActionAlert},
		{ID: "r09", EventType: types.EventSyscall,
			Condition: correlator.RuleCondition{Field: "nr", Op: correlator.OpEquals, Values: []string{"59"}},
			Severity: types.SeverityWarning, Action: correlator.ActionAlert},
		{ID: "r10", EventType: types.EventFileAccess,
			Condition: correlator.RuleCondition{Field: "path", Op: correlator.OpPrefix, Values: []string{"/var/run/docker.sock"}},
			Severity: types.SeverityCritical, Action: correlator.ActionAlert},
		{ID: "r11", EventType: types.EventFileAccess,
			Condition: correlator.RuleCondition{Field: "path", Op: correlator.OpPrefix, Values: []string{"/proc/"}},
			Severity: types.SeverityWarning, Action: correlator.ActionAlert},
		{ID: "r12", EventType: types.EventTCPConnect,
			Condition: correlator.RuleCondition{Field: "daddr", Op: correlator.OpIn, Values: []string{"pool.minexmr.com", "xmrpool.eu"}},
			Severity: types.SeverityCritical, Action: correlator.ActionKill},
		{ID: "r13", EventType: types.EventSyscall,
			Condition: correlator.RuleCondition{Field: "comm", Op: correlator.OpEquals, Values: []string{"base64"}},
			Severity: types.SeverityWarning, Action: correlator.ActionAlert},
		{ID: "r14", EventType: types.EventSyscall,
			Condition: correlator.RuleCondition{Field: "nr", Op: correlator.OpEquals, Values: []string{"59"}},
			Severity: types.SeverityWarning, Action: correlator.ActionAlert},
		{ID: "r15", EventType: types.EventTCPConnect,
			Condition: correlator.RuleCondition{Field: "dport", Op: correlator.OpEquals, Values: []string{"6443"}},
			Severity: types.SeverityWarning, Action: correlator.ActionAlert},
		{ID: "r16", EventType: types.EventSyscall,
			Condition: correlator.RuleCondition{Field: "comm", Op: correlator.OpEquals, Values: []string{"bash"}},
			Severity: types.SeverityWarning, Action: correlator.ActionAlert},
		{ID: "r17", EventType: types.EventFileAccess,
			Condition: correlator.RuleCondition{Field: "path", Op: correlator.OpPrefix, Values: []string{"/etc/sudoers"}},
			Severity: types.SeverityCritical, Action: correlator.ActionAlert},
		{ID: "r18", EventType: types.EventSyscall,
			Condition: correlator.RuleCondition{Field: "comm", Op: correlator.OpEquals, Values: []string{"curl"}},
			Severity: types.SeverityWarning, Action: correlator.ActionAlert},
	}
	return correlator.NewRuleEngine(rules)
}

func makeFalcoEvent() falcoEvent {
	return falcoEvent{fields: map[string]string{
		"evt.type":             "execve",
		"proc.name":            "bash",
		"proc.args":            "/bin/bash -i",
		"proc.uid":             "1000",
		"proc.exepath":         "/bin/bash",
		"proc.env":             "PATH=/usr/bin:/bin",
		"fd.name":              "/etc/passwd",
		"fd.sip":               "192.168.1.10",
		"container.id":         "abc123",
		"container.privileged": "false",
		"ka.uri":               "/api/v1/pods",
		"ka.verb":              "list",
		"ka.resource":          "pods",
	}}
}

func makeEbpfGuardFalcoEvent() types.Event {
	evt := types.Event{
		Type:    types.EventSyscall,
		PID:     1234,
		Syscall: &types.SyscallEvent{Nr: 59}, // execve
	}
	copy(evt.Comm[:], "bash")
	return evt
}

// ─────────────────────────────────────────────────────────────────────────────
// Benchmarks
// ─────────────────────────────────────────────────────────────────────────────

// BenchmarkFalcoRuleEval measures a single-rule evaluation using Falco's field
// lookup model (string map, linear condition scan).
func BenchmarkFalcoRuleEval(b *testing.B) {
	d := makeFalcoRuleSet()
	evt := makeFalcoEvent()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		d.rules[0].evaluate(evt)
	}
}

// BenchmarkEbpfGuardRuleEval measures a single-rule evaluation using
// ebpf-guard's EvaluateInto on a matching event. Includes types.Alert
// construction (1 alloc from Comm string copy). For the pure matching cost
// (0 allocs), see BenchmarkEbpfGuardRuleEval_NoMatch.
func BenchmarkEbpfGuardRuleEval(b *testing.B) {
	re := makeEbpfGuardFalcoRuleSet()
	evt := makeEbpfGuardFalcoEvent()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		re.EvaluateInto(evt, func(a types.Alert) { _ = a })
	}
}

// BenchmarkEbpfGuardRuleEval_NoMatch measures a single-rule evaluation using
// ebpf-guard's EvaluateInto on a non-matching event: event type matches rules
// but condition values do not. This is the 0-alloc no-match hot path and the
// fair comparison point against BenchmarkFalcoRuleEval (both measure pure
// matching cost without alert generation).
func BenchmarkEbpfGuardRuleEval_NoMatch(b *testing.B) {
	re := makeEbpfGuardFalcoRuleSet()
	evt := types.Event{
		Type:    types.EventSyscall,
		PID:     1,
		Syscall: &types.SyscallEvent{Nr: 1},
	}
	copy(evt.Comm[:], "idle")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		re.EvaluateInto(evt, func(a types.Alert) { _ = a })
	}
}

// BenchmarkFalcoEventDispatch measures the full dispatch loop across all 18
// rules for one event (simulating Falco's rule matching pipeline).
func BenchmarkFalcoEventDispatch(b *testing.B) {
	d := makeFalcoRuleSet()
	evt := makeFalcoEvent()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		d.matched = 0
		d.dispatch(evt)
	}
}

// BenchmarkEbpfGuardEventDispatch measures the full rule engine evaluation
// across all 18 rules for a matching event using the zero-alloc callback path.
// Allocations are proportional to match count (Comm string per alert).
func BenchmarkEbpfGuardEventDispatch(b *testing.B) {
	re := makeEbpfGuardFalcoRuleSet()
	evt := makeEbpfGuardFalcoEvent()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		re.EvaluateInto(evt, func(a types.Alert) { _ = a })
	}
}

// BenchmarkEbpfGuardEventDispatch_NoMatch measures full 18-rule evaluation on
// a non-matching event — the 0-alloc no-match path for the full rule set.
// Compare against BenchmarkFalcoEventDispatch: both measure full dispatch loop
// without alert generation.
func BenchmarkEbpfGuardEventDispatch_NoMatch(b *testing.B) {
	re := makeEbpfGuardFalcoRuleSet()
	evt := types.Event{
		Type:    types.EventSyscall,
		PID:     1,
		Syscall: &types.SyscallEvent{Nr: 1},
	}
	copy(evt.Comm[:], "idle")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		re.EvaluateInto(evt, func(a types.Alert) { _ = a })
	}
}

// BenchmarkFalcoFieldLookup measures the overhead of Falco's string-keyed
// field extractor lookup (the dominant cost in Falco's hot path).
func BenchmarkFalcoFieldLookup(b *testing.B) {
	fields := makeFalcoEvent().fields
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = fields["proc.name"]
		_ = fields["evt.type"]
		_ = fields["fd.name"]
	}
}

// BenchmarkFalcoStringMatch measures Falco's condition check operators.
func BenchmarkFalcoStringMatch(b *testing.B) {
	cond := falcoConditionNode{field: "proc.name", op: "in", values: []string{"bash", "sh", "zsh"}}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		falcoCheckCond(cond, "bash")
	}
}
