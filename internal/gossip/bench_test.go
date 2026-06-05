package gossip

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// BenchmarkAmplificationStore_SetGet measures Add and ActiveCount throughput
// under parallel contention via b.RunParallel.
//
// Target: < 100 ns/op for all sub-benchmarks.
func BenchmarkAmplificationStore_SetGet(b *testing.B) {
	namespaces := []string{
		"production", "staging", "development", "testing",
		"infra", "monitoring", "logging", "security",
	}

	// Add — concurrent writers, each hitting a rotating namespace.
	// Store deduplicates on source+namespace, so writers contend on Lock.
	b.Run("Add", func(b *testing.B) {
		store := newAmplificationStore(deduplicationTTLDefault)
		expiry := time.Now().Add(time.Hour)
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			var i int
			for pb.Next() {
				store.Add(AmplificationSignal{
					Namespace:           namespaces[i%len(namespaces)],
					Source:              "bench-node",
					ThresholdMultiplier: defaultThresholdMultiplier,
					ExpiresAt:           expiry,
				})
				i++
			}
		})
	})

	// ActiveCount — concurrent readers on a pre-populated store.
	// Exercises RLock + linear scan over 48 signals.
	b.Run("ActiveCount", func(b *testing.B) {
		store := newAmplificationStore(deduplicationTTLDefault)
		expiry := time.Now().Add(time.Hour)
		for i, ns := range namespaces {
			for j := 0; j < 6; j++ {
				store.Add(AmplificationSignal{
					Namespace:           ns,
					Source:              fmt.Sprintf("node-%d", i*6+j),
					ThresholdMultiplier: defaultThresholdMultiplier,
					ExpiresAt:           expiry,
				})
			}
		}
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_ = store.ActiveCount()
			}
		})
	})

	// GetThresholdMultiplier — the hot path called by the correlator on every event.
	b.Run("GetThresholdMultiplier", func(b *testing.B) {
		store := newAmplificationStore(deduplicationTTLDefault)
		expiry := time.Now().Add(time.Hour)
		for i, ns := range namespaces {
			store.Add(AmplificationSignal{
				Namespace:           ns,
				Source:              fmt.Sprintf("node-%d", i),
				ThresholdMultiplier: defaultThresholdMultiplier,
				ExpiresAt:           expiry,
			})
		}
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			var i int
			for pb.Next() {
				_ = store.GetThresholdMultiplier(namespaces[i%len(namespaces)])
				i++
			}
		})
	})

	// Mixed_25pctWrite — 25 % Add, 75 % ActiveCount, simulating steady-state
	// where a few nodes emit signals while the correlator polls continuously.
	b.Run("Mixed_25pctWrite", func(b *testing.B) {
		store := newAmplificationStore(deduplicationTTLDefault)
		expiry := time.Now().Add(time.Hour)
		for i, ns := range namespaces {
			store.Add(AmplificationSignal{
				Namespace:           ns,
				Source:              fmt.Sprintf("seed-%d", i),
				ThresholdMultiplier: defaultThresholdMultiplier,
				ExpiresAt:           expiry,
			})
		}
		var counter atomic.Int64
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				n := counter.Add(1)
				if n%4 == 0 {
					store.Add(AmplificationSignal{
						Namespace:           namespaces[int(n)%len(namespaces)],
						Source:              "bench-writer",
						ThresholdMultiplier: defaultThresholdMultiplier,
						ExpiresAt:           expiry,
					})
				} else {
					_ = store.ActiveCount()
				}
			}
		})
	})
}

// BenchmarkGossipFanout measures the wall-clock time to deliver an
// AmplificationSignal to all N=10 in-process httptest nodes concurrently,
// mirroring the fan-out pattern in flushDelta (one goroutine per peer).
//
// Targets: P50 < 5000 µs, P99 < 10000 µs for 10 nodes on localhost.
//
// Custom metrics emitted (visible with -v):
//
//	p50_us   50th-percentile fan-out latency in microseconds
//	p99_us   99th-percentile fan-out latency in microseconds
func BenchmarkGossipFanout(b *testing.B) {
	const N = 10

	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	baseCfg := Config{
		Enabled:      true,
		IOCTTL:       time.Hour,
		MaxIOCs:      1000,
		PushInterval: time.Hour, // disable background push; we drive it manually
	}

	// Spin up N receiver managers, each backed by a real httptest HTTP server.
	receivers := make([]*Manager, N)
	servers := make([]*httptest.Server, N)
	for i := range N {
		cfg := baseCfg
		cfg.NodeName = fmt.Sprintf("node-%d", i)
		mgr, err := NewManager(cfg, logger)
		if err != nil {
			b.Fatalf("NewManager node-%d: %v", i, err)
		}
		receivers[i] = mgr
		servers[i] = httptest.NewServer(Handler(mgr))
	}
	defer func() {
		for _, srv := range servers {
			srv.Close()
		}
	}()

	// Sender: a bare gossipClient representing the originating node.
	// No secret, plain HTTP — matches the default test setup in gossip_test.go.
	sender := newGossipClient("", nil)

	// Pre-build the signal; refresh ExpiresAt each iteration inside the loop.
	sig := AmplificationSignal{
		Namespace:           "production",
		RuleID:              "bench_rule",
		Severity:            "critical",
		Source:              "sender",
		ThresholdMultiplier: defaultThresholdMultiplier,
	}

	latencies := make([]time.Duration, 0, b.N)

	b.ResetTimer()
	for range b.N {
		sig.ExpiresAt = time.Now().Add(amplificationTTLDefault)

		start := time.Now()

		// Mirror flushDelta: one goroutine per peer, all launched simultaneously.
		var wg sync.WaitGroup
		wg.Add(N)
		for _, srv := range servers {
			srv := srv
			go func() {
				defer wg.Done()
				if err := sender.PushAmplifications(ctx, srv.URL, []AmplificationSignal{sig}); err != nil {
					b.Errorf("PushAmplifications: %v", err)
				}
			}()
		}
		wg.Wait() // all N nodes have received and stored the signal

		latencies = append(latencies, time.Since(start))
	}
	b.StopTimer()

	n := len(latencies)
	if n == 0 {
		return
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })

	p50 := latencies[n/2]
	p99 := latencies[n*99/100]

	// ReportMetric surfaces values in `go test -bench -benchmem` output.
	b.ReportMetric(float64(p50.Microseconds()), "p50_us")
	b.ReportMetric(float64(p99.Microseconds()), "p99_us")

	b.Logf("fanout(%d nodes): P50=%v  P99=%v  samples=%d", N, p50, p99, n)
}
