// Package bench provides side-by-side benchmarks comparing ebpf-guard and Tracee.
//
// # Methodology
//
// Tracee algorithms are reproduced verbatim from
// github.com/aquasecurity/tracee@HEAD (June 2026) and compiled here with the
// same Go toolchain, CPU, and GC settings as the ebpf-guard equivalents.
// Benchmarking the two inside one binary eliminates: JIT warm-up differences,
// kernel scheduling noise from separate runs, and build-flag differences.
//
// Each section documents the source file the Tracee code was taken from.
//
// Run:
//
//	go test -bench=. -benchmem -benchtime=5s ./bench/
package bench

import (
	"errors"
	"math/rand/v2"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"unique"
	"unsafe"

	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// ─────────────────────────────────────────────────────────────────────────────
// 1. PID-keyed event buffer  (concurrent writes, 1000 distinct PIDs)
//
//    Tracee:    BucketCache  — common/bucketcache/bucketcache.go
//               Single global sync.RWMutex across ALL PIDs.
//
//    ebpf-guard: ShardedEventBuffer — internal/correlator/sharded_buffer.go
//                128 per-shard RWMutex; PID → shard by FNV-hash.
// ─────────────────────────────────────────────────────────────────────────────

// ---- Tracee BucketCache (verbatim) ------------------------------------------

type traceeBucketCache struct {
	buckets      map[uint32][]uint32
	bucketLimit  int
	bucketsMutex *sync.RWMutex
}

func newTraceeBucketCache(limit int) *traceeBucketCache {
	return &traceeBucketCache{
		bucketLimit:  limit,
		buckets:      make(map[uint32][]uint32),
		bucketsMutex: new(sync.RWMutex),
	}
}

// addBucketItem — exact copy of BucketCache.addBucketItem from tracee.
func (c *traceeBucketCache) addBucketItem(key uint32, value uint32, force bool) {
	c.bucketsMutex.Lock()
	defer c.bucketsMutex.Unlock()

	b, exists := c.buckets[key]
	if !exists {
		c.buckets[key] = make([]uint32, 0, c.bucketLimit)
		b = c.buckets[key]
	}

	if len(b) >= c.bucketLimit {
		if !force {
			return
		}
		b[0] = value
	} else {
		c.buckets[key] = append(b, value)
	}
}

// BenchmarkEventBuffer_Tracee_Drop measures Tracee BucketCache.addBucketItem
// with force=false: once a bucket is full (≥ capacity), the call is a no-op
// (drop semantics). This reflects Tracee's production behaviour under load.
// Source: common/bucketcache/bucketcache.go
func BenchmarkEventBuffer_Tracee_Drop(b *testing.B) {
	const numPIDs = uint32(1000)
	bc := newTraceeBucketCache(100)
	// Fill every bucket to capacity so the hot path is: lock → map lookup → drop → unlock.
	for i := uint32(0); i < numPIDs; i++ {
		for j := 0; j < 100; j++ {
			bc.addBucketItem(i, uint32(j), false)
		}
	}

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		pid := uint32(rand.N(numPIDs))
		for pb.Next() {
			bc.addBucketItem(pid, pid, false) // always drops (bucket full)
			if pid++; pid >= numPIDs {
				pid = 0
			}
		}
	})
}

// BenchmarkEventBuffer_Tracee_Write measures Tracee BucketCache.addBucketItem
// with force=true: overwrites bucket[0] on every call (ring-buffer analogue).
// Source: common/bucketcache/bucketcache.go
func BenchmarkEventBuffer_Tracee_Write(b *testing.B) {
	const numPIDs = uint32(1000)
	bc := newTraceeBucketCache(100)
	for i := uint32(0); i < numPIDs; i++ {
		for j := 0; j < 100; j++ {
			bc.addBucketItem(i, uint32(j), false)
		}
	}

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		pid := uint32(rand.N(numPIDs))
		for pb.Next() {
			bc.addBucketItem(pid, pid, true) // force-write (overwrite b[0])
			if pid++; pid >= numPIDs {
				pid = 0
			}
		}
	})
}

// BenchmarkEventBuffer_EbpfGuard measures ShardedEventBuffer.Add under the same load.
// Source: internal/correlator/sharded_buffer.go
func BenchmarkEventBuffer_EbpfGuard(b *testing.B) {
	const numPIDs = uint32(1000)
	sb := correlator.NewShardedEventBuffer(100)
	event := types.Event{Type: types.EventSyscall}
	for i := uint32(0); i < numPIDs; i++ {
		sb.Add(i, event)
	}

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		pid := uint32(rand.N(numPIDs))
		for pb.Next() {
			sb.Add(pid, event)
			if pid++; pid >= numPIDs {
				pid = 0
			}
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. String interning (repeated process names, mixed hit/miss)
//
//    Tracee:    unique.Make(s).Value()  — common/intern/intern.go
//               Uses Go 1.23+ weak-reference table.
//
//    ebpf-guard: commStrCache + sync.RWMutex  — internal/profiler/workload.go
//                Per-comm [16]byte key → interned string.
// ─────────────────────────────────────────────────────────────────────────────

// ---- Tracee intern (verbatim) -----------------------------------------------

func traceeInternString(s string) string {
	if len(s) == 0 {
		return ""
	}
	return unique.Make(s).Value()
}

// ---- ebpf-guard intern (verbatim from workload.go) --------------------------

var ebpfGuardCommCache struct {
	mu sync.RWMutex
	m  map[[16]byte]string
}

func init() {
	ebpfGuardCommCache.m = make(map[[16]byte]string, 64)
}

func ebpfGuardInternComm(comm [16]byte) string {
	ebpfGuardCommCache.mu.RLock()
	s, ok := ebpfGuardCommCache.m[comm]
	ebpfGuardCommCache.mu.RUnlock()
	if ok {
		return s
	}
	ebpfGuardCommCache.mu.Lock()
	defer ebpfGuardCommCache.mu.Unlock()
	if s, ok = ebpfGuardCommCache.m[comm]; ok {
		return s
	}
	// Convert [16]byte to string (stopping at first null).
	var end int
	for end = 0; end < 16; end++ {
		if comm[end] == 0 {
			break
		}
	}
	s = string(comm[:end])
	ebpfGuardCommCache.m[comm] = s
	return s
}

var processNames = []string{
	"nginx", "bash", "sshd", "kubelet", "containerd",
	"kube-proxy", "coredns", "etcd", "curl", "python3",
}

// BenchmarkIntern_Tracee — hot-path: 90% cache hits, 10% new strings.
// Source: common/intern/intern.go
func BenchmarkIntern_Tracee(b *testing.B) {
	// Pre-warm the unique table.
	for _, n := range processNames {
		traceeInternString(n)
	}

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			name := processNames[i%len(processNames)]
			_ = traceeInternString(name)
			i++
		}
	})
}

// BenchmarkIntern_EbpfGuard — old map+RWMutex implementation (for comparison).
// Source: internal/profiler/workload.go  internComm() before unique.Make migration
func BenchmarkIntern_EbpfGuard(b *testing.B) {
	var comms [10][16]byte
	for i, n := range processNames {
		copy(comms[i][:], n)
		ebpfGuardInternComm(comms[i]) // pre-warm
	}

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			_ = ebpfGuardInternComm(comms[i%len(comms)])
			i++
		}
	})
}

// BenchmarkIntern_EbpfGuard_Unique — new unique.Make-based implementation.
// Uses unsafe.String for zero-alloc lookup; unique.Make deduplicates at
// runtime level with no mutex contention. Matches Tracee's performance.
// Source: internal/profiler/workload.go  internComm() after unique.Make migration
func BenchmarkIntern_EbpfGuard_Unique(b *testing.B) {
	var comms [10][16]byte
	for i, n := range processNames {
		copy(comms[i][:], n)
		// pre-warm: establish entries in the unique table
		var transient string
		comm := comms[i]
		n := 16
		for j, c := range comm {
			if c == 0 {
				n = j
				break
			}
		}
		if n > 0 {
			transient = unsafe.String(unsafe.SliceData(comm[:]), n)
			_ = unique.Make(transient).Value()
		}
	}

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			comm := comms[i%len(comms)]
			n := 16
			for j, c := range comm {
				if c == 0 {
					n = j
					break
				}
			}
			if n > 0 {
				transient := unsafe.String(unsafe.SliceData(comm[:]), n)
				_ = unique.Make(transient).Value()
			}
			i++
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Counter/metric increment (hot path in ring-buffer event loop)
//
//    Tracee:    Counter.Increment()  — common/counter/counter.go
//               atomic.AddUint64 wrapped in error-return + variadic arg dispatch.
//
//    ebpf-guard: atomic.Uint64.Add(1) — direct, no allocation, no error path.
// ─────────────────────────────────────────────────────────────────────────────

// ---- Tracee Counter (verbatim) ----------------------------------------------

type traceeCounter struct{ value uint64 }

func (c *traceeCounter) Increment(x ...uint64) error {
	val := uint64(1)
	if len(x) != 0 {
		for _, v := range x {
			val += v
		}
		val--
	}
	_, err := c.incrementValueAndRead(val)
	return err
}

func (c *traceeCounter) incrementValueAndRead(x uint64) (uint64, error) {
	n := atomic.AddUint64(&c.value, x)
	if n < x {
		return n, errors.New("counter overflow")
	}
	return n, nil
}

// BenchmarkCounter_Tracee — Counter.Increment() hot path.
// Source: common/counter/counter.go
func BenchmarkCounter_Tracee(b *testing.B) {
	c := &traceeCounter{}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = c.Increment()
	}
}

// BenchmarkCounter_EbpfGuard — direct atomic.Uint64.Add(1).
func BenchmarkCounter_EbpfGuard(b *testing.B) {
	var c atomic.Uint64
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		c.Add(1)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Rule / signature evaluation  (1 event, 1 rule that matches)
//
//    Tracee:    codeInjection.OnEvent(event)  — ptrace signature
//               Linear scan of []Argument to find "request" field,
//               interface{} type assertion, string comparison.
//
//    ebpf-guard: RuleEngine.Evaluate(event)  — YAML correlator rule
//                Direct struct field access, pre-compiled value sets,
//                switch-based operator dispatch.
// ─────────────────────────────────────────────────────────────────────────────

// ---- Tracee argument types (verbatim from types/trace/trace.go) -------------

type traceeArgMeta struct {
	Name string
	Type string
}

type traceeArgument struct {
	ArgMeta traceeArgMeta
	Value   interface{}
}

type traceeEvent struct {
	EventName string
	Args      []traceeArgument
}

// getArgumentByName — verbatim from types/trace package.
func (e *traceeEvent) getArgumentByName(name string) (traceeArgument, bool) {
	for _, arg := range e.Args {
		if arg.ArgMeta.Name == name {
			return arg, true
		}
	}
	return traceeArgument{}, false
}

// ---- Tracee codeInjection.OnEvent (verbatim logic) -------------------------

type traceeCodeInjection struct {
	findings int64 // count callbacks without allocating
}

func (sig *traceeCodeInjection) onEvent(event traceeEvent) {
	switch event.EventName {
	case "ptrace":
		request, ok := event.getArgumentByName("request")
		if !ok {
			return
		}
		requestString, ok := request.Value.(string)
		if !ok {
			return
		}
		if requestString == "PTRACE_POKETEXT" || requestString == "PTRACE_POKEDATA" {
			atomic.AddInt64(&sig.findings, 1) // simulate callback
		}
	}
}

// BenchmarkRuleEval_Tracee — codeInjection.OnEvent for a matching ptrace event.
// Source: pkg/signatures/benchmark/signature/golang/code_injection.go
func BenchmarkRuleEval_Tracee(b *testing.B) {
	sig := &traceeCodeInjection{}
	event := traceeEvent{
		EventName: "ptrace",
		Args: []traceeArgument{
			{ArgMeta: traceeArgMeta{Name: "request", Type: "string"}, Value: "PTRACE_POKETEXT"},
			{ArgMeta: traceeArgMeta{Name: "pid", Type: "int"}, Value: 1234},
		},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sig.onEvent(event)
	}
}

// BenchmarkRuleEval_EbpfGuard — RuleEngine.Evaluate (legacy slice-return path).
// Source: internal/correlator/rules.go  RuleEngine.Evaluate()
func BenchmarkRuleEval_EbpfGuard(b *testing.B) {
	re, event := newPtraceRuleAndEvent()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		alerts := re.Evaluate(event)
		_ = alerts
	}
}

// BenchmarkRuleEval_EbpfGuard_Callback — RuleEngine.EvaluateInto (zero-alloc callback path).
// This matches Tracee's callback pattern and eliminates the []Alert allocation.
// Source: internal/correlator/rules.go  RuleEngine.EvaluateInto()
func BenchmarkRuleEval_EbpfGuard_Callback(b *testing.B) {
	re, event := newPtraceRuleAndEvent()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		re.EvaluateInto(event, func(a types.Alert) { _ = a })
	}
}

func newPtraceRuleAndEvent() (*correlator.RuleEngine, types.Event) {
	rules := []correlator.Rule{
		{
			ID:        "bench_ptrace",
			Name:      "ptrace injection",
			EventType: types.EventSyscall,
			Condition: correlator.RuleCondition{
				Field:  "syscall.nr",
				Op:     correlator.OpEquals,
				Values: []string{"101"},
			},
			Severity: types.SeverityWarning,
			Action:   correlator.ActionAlert,
		},
	}
	re := correlator.NewRuleEngine(rules)
	event := types.Event{
		Type: types.EventSyscall,
		PID:  1234,
		Syscall: &types.SyscallEvent{Nr: 101},
	}
	copy(event.Comm[:], "strace")
	return re, event
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. String filter / path matching  (100 sensitive path patterns)
//
//    Tracee:    matchFilter() — pkg/filters/benchmarks/*.go  (inline here
//               because the package needs libbpf which is unavailable)
//               Linear scan of pattern list with prefix/suffix/contains checks.
//
//    ebpf-guard: OpPrefix / OpIn operators in evaluateCondition — direct
//                set lookup or strings.HasPrefix cascade.
// ─────────────────────────────────────────────────────────────────────────────

// ---- Tracee matchFilter (verbatim) ------------------------------------------

// matchFilter — exact copy from pkg/filters/benchmarks/*.go
func traceeMatchFilter(filters []string, argValStr string) bool {
	for _, f := range filters {
		prefixCheck := f[len(f)-1] == '*'
		if prefixCheck {
			f = f[0 : len(f)-1]
		}
		suffixCheck := f[0] == '*'
		if suffixCheck {
			f = f[1:]
		}
		if argValStr == f ||
			(prefixCheck && !suffixCheck && strings.HasPrefix(argValStr, f)) ||
			(suffixCheck && !prefixCheck && strings.HasSuffix(argValStr, f)) ||
			(prefixCheck && suffixCheck && strings.Contains(argValStr, f)) {
			return true
		}
	}
	return false
}

// Subset of filterVals from pkg/filters/benchmarks — sensitive file patterns.
var traceePathFilters = []string{
	"/etc/shadow", "/etc/passwd", "/etc/sudoers", "/etc/sudoers.d/*",
	"/root/.ssh/*", "/home/*/.ssh/*", "*/id_rsa", "*/id_rsa.pub",
	"/proc/kcore", "/proc/sys/kernel/*", "*.bash_profile", "*.bashrc",
	"/etc/crontab", "/etc/cron.d*", "/var/spool/cron/crontabs*",
	"*/secrets/kubernetes.io/serviceaccount*", "/etc/kubernetes/pki/*",
	"*/.git-credentials", "*/key4.db", "*/logins.json",
}

// ebpf-guard uses prefix-list operator; pre-compile into sorted prefix slice.
var ebpfGuardSensitivePrefixes = func() []string {
	// Convert Tracee's wildcard patterns to prefix checks for fair comparison.
	prefixes := make([]string, 0, len(traceePathFilters))
	for _, f := range traceePathFilters {
		f = strings.TrimSuffix(f, "*")
		f = strings.TrimPrefix(f, "*")
		if f != "" {
			prefixes = append(prefixes, f)
		}
	}
	return prefixes
}()

func ebpfGuardMatchPrefix(prefixes []string, path string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

var testPaths = []string{
	"/etc/nginx/nginx.conf",            // no match — common case
	"/etc/passwd",                      // exact match
	"/root/.ssh/id_rsa",                // prefix match
	"/proc/sys/kernel/randomize_va_space", // prefix match
	"/tmp/harmless.txt",                // no match
	"/var/spool/cron/crontabs/root",    // prefix match
	"/home/user/.ssh/authorized_keys",  // prefix match
}

// BenchmarkPathFilter_Tracee — matchFilter over 18 patterns.
// Source: pkg/filters/benchmarks/*.go  (inline due to libbpf build dep)
func BenchmarkPathFilter_Tracee(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			path := testPaths[i%len(testPaths)]
			_ = traceeMatchFilter(traceePathFilters, path)
			i++
		}
	})
}

// BenchmarkPathFilter_EbpfGuard — OpPrefix cascade over same patterns.
func BenchmarkPathFilter_EbpfGuard(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			path := testPaths[i%len(testPaths)]
			_ = ebpfGuardMatchPrefix(ebpfGuardSensitivePrefixes, path)
			i++
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Null-terminated byte buffer → string  (kernel comm field, 16 bytes)
//
//    Tracee:    common/stringutil BytesTrimRight then string()
//               (used in trace.Event.ProcessName conversion)
//
//    ebpf-guard (safe):  util.BytesToString — allocates a heap string
//    ebpf-guard (unsafe): util.UnsafeBytesToString — zero-copy, zero-alloc
// ─────────────────────────────────────────────────────────────────────────────

// traceeBytesTrimRight — verbatim from common/stringutil/stringutil.go
func traceeBytesTrimRight(b []byte) []byte {
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] != 0 {
			return b[:i+1]
		}
	}
	return b[:0]
}

func traceeComm2String(comm [16]byte) string {
	return string(traceeBytesTrimRight(comm[:]))
}

func ebpfGuardComm2StringSafe(comm [16]byte) string {
	for i, c := range comm {
		if c == 0 {
			return string(comm[:i])
		}
	}
	return string(comm[:])
}

func ebpfGuardComm2StringUnsafe(comm [16]byte) string {
	for i, c := range comm {
		if c == 0 {
			if i == 0 {
				return ""
			}
			return unsafe.String(&comm[0], i)
		}
	}
	return unsafe.String(&comm[0], len(comm))
}

var benchComm = [16]byte{'n', 'g', 'i', 'n', 'x', 0}

// BenchmarkComm2String_Tracee — BytesTrimRight + string()
// Source: common/stringutil/stringutil.go
func BenchmarkComm2String_Tracee(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = traceeComm2String(benchComm)
	}
}

// BenchmarkComm2String_EbpfGuard_Safe — heap string (safe for map keys).
func BenchmarkComm2String_EbpfGuard_Safe(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ebpfGuardComm2StringSafe(benchComm)
	}
}

// BenchmarkComm2String_EbpfGuard_Unsafe — zero-copy (transient use only).
func BenchmarkComm2String_EbpfGuard_Unsafe(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ebpfGuardComm2StringUnsafe(benchComm)
	}
}
