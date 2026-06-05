package policy

import (
	"context"
	"os"
	"testing"

	"github.com/open-policy-agent/opa/rego"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// regoRulesDir is the production rule set relative to this package directory.
// Resolved at test time to <repo_root>/rules/rego/.
const regoRulesDir = "../../rules/rego"

// BenchmarkPolicyEval measures Evaluate() against the full production Rego rule
// set: base, dns, file, k8s, lineage, network, process_injection (7 files,
// 50+ detection rules). All files are compiled once at engine creation time via
// PrepareForEval; only per-call interpretation cost appears in the benchmark.
//
// Hot path per iteration:
//  1. alertToInput   — build input map from Alert (~10 allocations)
//  2. prepared.Eval  — OPA interpreter run against all loaded rules
//  3. result walk    — extract PolicyDecision structs from result set
//
// Performance target: < 500 µs/op
//
// Measured baseline (linux/amd64, Xeon 2.10 GHz, Go 1.25, OPA v0.70.0):
//
//	BenchmarkPolicyEval-4   2392   497217 ns/op   215228 B/op   4923 allocs/op
//
// Result: ~498 µs/op — at the 500 µs budget boundary.
//
// TODO(performance): evaluation sits on the 500 µs budget boundary. To bring it
// below 300 µs, consider: (1) evaluate only the sub-package whose rules are
// relevant for the event type (e.g. skip dns.rego for network events); (2) replace
// the `decisions` full-walk with a partial eval query pre-compiled per rule-set
// partition; (3) reduce alloc pressure (~215 KB/call) by pooling the input map
// and reusing result set buffers via sync.Pool.
//
// Run `go test -bench=BenchmarkPolicyEval -benchmem -count=6 ./internal/policy/`
// and replace the measured baseline above after any change to the evaluation path.
func BenchmarkPolicyEval(b *testing.B) {
	e := newBenchEngine(b)
	alert := newBenchAlert()
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, _ = e.Evaluate(ctx, alert)
	}
}

// BenchmarkPolicyEvalCached contrasts two evaluation strategies on the same
// production rule set to justify and protect the PrepareForEval design.
//
// Sub-benchmarks:
//
//   prepared — current production path: all policies compiled once at
//   NewRegoEngine(), then PreparedEvalQuery.Eval() is called per alert.
//   This is what RegoEngine.Evaluate() calls.
//
//   uncached — baseline for comparison: rego.New(...).Eval() is called on
//   every iteration without PrepareForEval. OPA re-compiles all 7 policy
//   files on every call. Use this number to understand how expensive it would
//   be if the compilation cache were accidentally bypassed (e.g. via Reload()
//   racing with Evaluate()).
//
// The RegoEngine already implements the prepared path. If a future refactor
// introduces an uncached code path, the ratio prepared/uncached quantifies the
// regression budget available before breaching the 500 µs target.
//
// Measured baseline (linux/amd64, Xeon 2.10 GHz, Go 1.25, OPA v0.70.0):
//
//	BenchmarkPolicyEvalCached/prepared-4   2197    484848 ns/op   215555 B/op    4941 allocs/op
//	BenchmarkPolicyEvalCached/uncached-4     42   27473695 ns/op  14204598 B/op  333267 allocs/op
//
// Speedup: prepared is ~56× faster than uncached (27 ms → 485 µs). This quantifies
// the regression budget if PrepareForEval were accidentally bypassed.
func BenchmarkPolicyEvalCached(b *testing.B) {
	e := newBenchEngine(b)
	ctx := context.Background()
	alert := newBenchAlert()

	b.Run("prepared", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			_, _ = e.Evaluate(ctx, alert)
		}
	})

	b.Run("uncached", func(b *testing.B) {
		// Access the loaded policy source through the package-internal field.
		// Build rego.New() options once (string data already in memory), including
		// the input; each Eval() call re-compiles all modules from scratch because
		// PrepareForEval is never called.
		//
		// Note: rego.Rego.Eval() does not accept EvalOption; input is bound via
		// rego.Input() at rego.New() time. The input map is immutable across
		// iterations so sharing the pointer is safe.
		policies := e.policies
		input := alertToInput(alert)

		opts := make([]func(*rego.Rego), 0, len(policies)+2)
		for filename, content := range policies {
			opts = append(opts, rego.Module(filename, content))
		}
		opts = append(opts, rego.Query("data.ebpf_guard"))
		opts = append(opts, rego.Input(input))

		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			r := rego.New(opts...)
			_, _ = r.Eval(ctx)
		}
	})
}

// newBenchEngine creates a RegoEngine backed by the real rules/rego/ directory.
// Skips the benchmark if the directory is not found (e.g. shallow clone).
func newBenchEngine(b *testing.B) *RegoEngine {
	b.Helper()
	if _, err := os.Stat(regoRulesDir); os.IsNotExist(err) {
		b.Skip("rules/rego not found; skipping OPA benchmark")
	}
	e, err := NewRegoEngine(RegoEngineConfig{
		Enabled:  true,
		RulesDir: regoRulesDir,
	})
	if err != nil {
		b.Fatalf("NewRegoEngine: %v", err)
	}
	return e
}

// newBenchAlert returns a realistic network alert: a curl process (spawned by
// nginx) making an outbound HTTPS connection to 8.8.8.8:443.
// This exercises lineage and network rules without triggering most detections,
// reflecting the common production case where the alert passes through cleanly.
func newBenchAlert() types.Alert {
	var comm [16]byte
	copy(comm[:], "curl")
	var parentComm [16]byte
	copy(parentComm[:], "nginx")

	net := types.NetworkEvent{Dport: 443, Sport: 54321, Family: types.AFInet}
	net.Daddr[0], net.Daddr[1], net.Daddr[2], net.Daddr[3] = 8, 8, 8, 8 // 8.8.8.8

	return types.Alert{
		ID:       "bench-001",
		RuleID:   "net_egress",
		Severity: types.SeverityWarning,
		PID:      1234,
		Comm:     "curl",
		Message:  "Outbound connection from web-server child process",
		Event: types.Event{
			Type:       types.EventTCPConnect,
			PID:        1234,
			PPID:       1000,
			Comm:       comm,
			ParentComm: parentComm,
			Network:    &net,
		},
	}
}
