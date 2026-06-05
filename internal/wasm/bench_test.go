package wasm

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// BenchmarkWASMPluginEval measures ns/op and allocs/op for a single Engine.Evaluate()
// call with one noop.wasm plugin (evaluate() always returns 0 = "allow").
//
// Cost breakdown per iteration:
//   - SerializeEvent: JSON-encode the event (~200 B payload)          ~1 µs
//   - Plugin.Evaluate: instantiate a fresh wazero module instance,
//     malloc + write event JSON into linear memory, call evaluate(),
//     free, close module — this is the dominant cost                ~10–20 µs
//
// The fresh-instance-per-call isolation model guarantees zero state leakage
// across events and goroutines at the price of per-call instantiation overhead.
// Compilation is cached at engine load time and does not appear here.
//
// Measured baseline (linux/amd64, Xeon 2.10 GHz, Go 1.25, wazero v1.8.2):
//
//	BenchmarkWASMPluginEval-4   ~53000 ns/op   111024 B/op   95 allocs/op
//
// The 111 KB/op is dominated by wazero allocating one 64 KiB linear-memory page
// per fresh module instance — an inherent cost of the full-isolation model.
// Run `go test -bench=BenchmarkWASMPluginEval -benchmem -count=6 ./internal/wasm/`
// and update this line after any change to the evaluation or instantiation path.
func BenchmarkWASMPluginEval(b *testing.B) {
	e, ctx := benchEngine(b)
	ev := benchEvent()

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_ = e.Evaluate(ctx, ev)
	}
}

// BenchmarkWASMPluginEvalParallel is the concurrent variant of BenchmarkWASMPluginEval.
// b.RunParallel spawns GOMAXPROCS goroutines; each instantiates its own module
// per call so there is no shared mutable state on the hot path — only a brief
// RLock to snapshot the plugins slice.
//
// Per-goroutine ns/op should stay within ~20% of the serial figure; a larger
// spread indicates contention or GC pressure from the fresh-instance model.
//
// Measured baseline (linux/amd64, Xeon 2.10 GHz, Go 1.25, wazero v1.8.2, GOMAXPROCS=4):
//
//	BenchmarkWASMPluginEvalParallel-4   ~49000 ns/op   111035 B/op   95 allocs/op
func BenchmarkWASMPluginEvalParallel(b *testing.B) {
	e, ctx := benchEngine(b)
	ev := benchEvent()

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = e.Evaluate(ctx, ev)
		}
	})
}

// benchEngine creates an Engine loaded with exactly one noop.wasm plugin.
// It stages the file in a temp dir so other testdata artefacts (always_match.wasm)
// do not influence the benchmark result.
func benchEngine(b *testing.B) (*Engine, context.Context) {
	b.Helper()

	src := filepath.Join("testdata", "noop.wasm")
	if _, err := os.Stat(src); os.IsNotExist(err) {
		b.Skip("testdata/noop.wasm not present; skipping WASM benchmark")
	}

	data, err := os.ReadFile(src)
	if err != nil {
		b.Fatalf("read noop.wasm: %v", err)
	}
	dir := b.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "noop.wasm"), data, 0600); err != nil {
		b.Fatalf("stage noop.wasm: %v", err)
	}

	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	e, err := NewEngine(ctx, dir, logger, 0)
	if err != nil {
		b.Fatalf("NewEngine: %v", err)
	}
	b.Cleanup(func() { _ = e.Close(ctx) })

	return e, ctx
}

// benchEvent returns a representative TCP-connect event that exercises the full
// SerializeEvent path: IP formatting + nested "network" JSON object.
func benchEvent() types.Event {
	var comm [16]byte
	copy(comm[:], "nginx")
	net := types.NetworkEvent{Dport: 443, Sport: 54321, Family: types.AFInet}
	net.Daddr[0], net.Daddr[1], net.Daddr[2], net.Daddr[3] = 1, 2, 3, 4
	return types.Event{
		Type:    types.EventTCPConnect,
		PID:     1234,
		PPID:    1,
		Comm:    comm,
		TGID:    1234,
		Network: &net,
	}
}
