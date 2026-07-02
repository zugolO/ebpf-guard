// Command benchmark-harness measures end-to-end detection latency and
// sustained throughput of the production correlation pipeline (built-in rule
// sets + anomaly profiler + dedup/rate-limiting), using the same attack
// scenarios that `ebpf-guard attack-sim` ships.
//
// It reports, per attack scenario:
//   - detection compute latency (synchronous Ingest call) p50/p95/p99/max
//   - end-to-end alert delivery latency via the production async path
//     (IngestAsync -> ingest worker pool -> Flush), polled at 1ms
//
// and globally:
//   - sustained mixed-workload throughput through IngestAsync
//   - process RSS before/after
//
// Run: go run ./benchmark-harness
package main

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zugolO/ebpf-guard/internal/attacker"
	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/pkg/types"
	rulesembed "github.com/zugolO/ebpf-guard/rules"
)

func rssMiB() float64 {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "VmRSS:" {
			kb, _ := strconv.ParseFloat(f[1], 64)
			return kb / 1024
		}
	}
	return -1
}

func pct(d []time.Duration, p float64) time.Duration {
	if len(d) == 0 {
		return 0
	}
	idx := int(float64(len(d)-1) * p)
	return d[idx]
}

func newEngine() *correlator.CorrelationEngine {
	files, err := rulesembed.LoadAll()
	if err != nil {
		panic(err)
	}
	rules, err := correlator.LoadRulesFromEmbedded(files)
	if err != nil {
		panic(err)
	}
	cfg := correlator.DefaultCorrelationEngineConfig()
	cfg.Rules = rules
	fmt.Printf("loaded %d built-in rules\n", len(rules))
	return correlator.NewCorrelationEngineWithConfig(cfg)
}

func main() {
	ctx := context.Background()
	fmt.Printf("GOMAXPROCS=%d\n", runtime.GOMAXPROCS(0))

	// ── Part 1: per-scenario detection compute latency (sync Ingest) ──────
	fmt.Println("\n=== Detection compute latency (sync Ingest, built-in rules) ===")
	engine := newEngine()
	const iters = 2000
	for _, sc := range attacker.BuiltinScenarios() {
		lat := make([]time.Duration, 0, iters)
		detected := 0
		for i := 0; i < iters; i++ {
			e := sc.Event()
			// Vary PID so per-rule dedup/rate-limiting doesn't flatten the run
			// and every iteration exercises the full match path.
			e.PID = uint32(1000 + i)
			e.TGID = e.PID
			e.Timestamp = uint64(time.Now().UnixNano())
			t0 := time.Now()
			alerts := engine.Ingest(ctx, e)
			lat = append(lat, time.Since(t0))
			if len(alerts) > 0 {
				detected++
			}
		}
		engine.Flush() // keep pending buffer from growing across scenarios
		sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
		fmt.Printf("%-28s detected %5d/%d  p50=%-9v p95=%-9v p99=%-9v max=%v\n",
			sc.ID, detected, iters, pct(lat, 0.50), pct(lat, 0.95), pct(lat, 0.99), pct(lat, 0.99999))
	}
	engine.Close()

	// ── Part 2: end-to-end async delivery latency (IngestAsync -> Flush) ──
	fmt.Println("\n=== End-to-end alert delivery latency (IngestAsync -> worker pool -> Flush, 1ms poll) ===")
	engine = newEngine()
	for _, sc := range attacker.BuiltinScenarios() {
		const e2eIters = 50
		lat := make([]time.Duration, 0, e2eIters)
		missed := 0
		for i := 0; i < e2eIters; i++ {
			e := sc.Event()
			e.PID = uint32(50000 + i)
			e.TGID = e.PID
			e.Timestamp = uint64(time.Now().UnixNano())
			t0 := time.Now()
			engine.IngestAsync(ctx, e)
			deadline := time.Now().Add(2 * time.Second)
			got := false
			for time.Now().Before(deadline) {
				if len(engine.Flush()) > 0 {
					got = true
					break
				}
				time.Sleep(time.Millisecond)
			}
			if got {
				lat = append(lat, time.Since(t0))
			} else {
				missed++
			}
		}
		sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
		fmt.Printf("%-28s delivered %3d/%d  p50=%-9v p95=%-9v max=%v\n",
			sc.ID, len(lat), e2eIters, pct(lat, 0.50), pct(lat, 0.95), pct(lat, 0.99999))
	}
	engine.Close()

	// ── Part 3: sustained mixed throughput through the async worker pool ──
	fmt.Println("\n=== Sustained throughput (IngestAsync, mixed benign syscall/network/file events) ===")
	engine = newEngine()
	runtime.GC()
	rssBefore := rssMiB()
	const total = 2_000_000
	mk := func(i int) types.Event {
		e := types.Event{
			Type:      types.EventSyscall,
			Timestamp: uint64(time.Now().UnixNano()),
			PID:       uint32(i % 8192), /* #nosec G115 -- i%8192 is always in [0,8191] */
			TGID:      uint32(i % 8192), /* #nosec G115 -- i%8192 is always in [0,8191] */
			UID:       1000,
		}
		copy(e.Comm[:], "worker")
		e.Syscall = &types.SyscallEvent{Nr: int64(i % 300)}
		switch i % 3 {
		case 1:
			e.Type = types.EventTCPConnect
			e.Syscall = nil
			ne := &types.NetworkEvent{Dport: 443, Proto: 6}
			ne.Daddr[0], ne.Daddr[1], ne.Daddr[2], ne.Daddr[3] = 10, 0, 0, 1
			e.Network = ne
		case 2:
			e.Type = types.EventFileAccess
			e.Syscall = nil
			fe := &types.FileEvent{Flags: 0}
			copy(fe.Filename[:], "/var/log/app.log")
			e.File = fe
		}
		return e
	}
	start := time.Now()
	for i := 0; i < total; i++ {
		engine.IngestAsync(ctx, mk(i))
	}
	drainCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	engine.DrainIngestPool(drainCtx)
	cancel()
	dur := time.Since(start)
	engine.Flush()
	rssAfter := rssMiB()
	fmt.Printf("events=%d  duration=%v  throughput=%.0f events/sec\n", total, dur, float64(total)/dur.Seconds())
	fmt.Printf("RSS before=%.1f MiB  after=%.1f MiB\n", rssBefore, rssAfter)
	engine.Close()
}
