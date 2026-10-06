package correlator

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Wave 8.1 (№530): protected and bulk events travel over separate per-worker
// channels. Nothing may be lost or double-counted by the split: every event of
// either class queued before DrainIngestPool yields exactly its alert.
func TestIngestAsyncPriority_BothClassesDeliveredOnDrain(t *testing.T) {
	cfg := DefaultCorrelationEngineConfig()
	cfg.Rules = []Rule{
		{ID: "prio_net", Name: "net", EventType: types.EventTCPConnect,
			Condition: RuleCondition{Field: "dport", Op: OpEquals, Values: []string{"8888"}},
			Severity:  types.SeverityWarning, Action: ActionAlert},
		{ID: "prio_file", Name: "file", EventType: types.EventFileAccess,
			Condition: RuleCondition{Field: "filename", Op: OpEquals, Values: []string{"/etc/prio-test"}},
			Severity:  types.SeverityWarning, Action: ActionAlert},
	}
	cfg.EnableDedup = false
	cfg.EnableRateLimit = false
	cfg.IngestWorkerCount = 4

	eng := NewCorrelationEngineWithConfig(cfg)
	defer eng.Close()

	ctx := context.Background()
	const n = 200
	for i := 0; i < n; i++ {
		// Same pid for both classes: they share one worker.
		pid := uint32(i%7 + 1)
		eng.IngestAsyncPriority(ctx, types.Event{
			Type: types.EventTCPConnect, PID: pid, Network: &types.NetworkEvent{Dport: 8888},
		}, true)
		fe := &types.FileEvent{}
		copy(fe.Filename[:], "/etc/prio-test")
		eng.IngestAsyncPriority(ctx, types.Event{Type: types.EventFileAccess, PID: pid, File: fe}, false)
	}

	dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	eng.DrainIngestPool(dctx)

	alerts := eng.Flush()
	byRule := map[string]int{}
	for _, a := range alerts {
		byRule[a.RuleID]++
	}
	assert.Equal(t, n, byRule["prio_net"], "protected-class events")
	assert.Equal(t, n, byRule["prio_file"], "bulk-class events")
}

// The two classes use distinct channels of equal capacity; a protected dispatch
// returns without waiting on the bulk channel.
func TestIngestAsyncPriority_ClassesUseSeparateChannels(t *testing.T) {
	cfg := DefaultCorrelationEngineConfig()
	cfg.IngestWorkerCount = 1
	cfg.IngestWorkerBufferSize = 1
	eng := NewCorrelationEngineWithConfig(cfg)
	defer eng.Close()

	w := eng.ingestPool[0]
	require.NotNil(t, w.chHi)
	assert.NotEqual(t, reflect.ValueOf(w.ch).Pointer(), reflect.ValueOf(w.chHi).Pointer())
	assert.Equal(t, cap(w.ch), cap(w.chHi))

	done := make(chan struct{})
	go func() {
		defer close(done)
		eng.IngestAsyncPriority(context.Background(), types.Event{
			Type: types.EventSyscall, PID: 1, Syscall: &types.SyscallEvent{Nr: 1},
		}, true)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("protected dispatch did not return")
	}
}

// Identity (№530): the same mixed event stream, dispatched once through the
// legacy single-channel path and once through the class-split path, must yield
// the identical multiset of (rule, pid) alerts.
func TestIngestAsyncPriority_AlertIdentityVsLegacy(t *testing.T) {
	run := func(split bool) map[string]int {
		cfg := DefaultCorrelationEngineConfig()
		cfg.Rules = []Rule{
			{ID: "id_net", Name: "net", EventType: types.EventTCPConnect,
				Condition: RuleCondition{Field: "dport", Op: OpEquals, Values: []string{"4444"}},
				Severity:  types.SeverityWarning, Action: ActionAlert},
			{ID: "id_file", Name: "file", EventType: types.EventFileAccess,
				Condition: RuleCondition{Field: "filename", Op: OpEquals, Values: []string{"/etc/id-test"}},
				Severity:  types.SeverityWarning, Action: ActionAlert},
			{ID: "id_sys", Name: "sys", EventType: types.EventSyscall,
				Condition: RuleCondition{Field: "nr", Op: OpEquals, Values: []string{"59"}},
				Severity:  types.SeverityWarning, Action: ActionAlert},
		}
		cfg.EnableDedup = false
		cfg.EnableRateLimit = false
		cfg.IngestWorkerCount = 4
		eng := NewCorrelationEngineWithConfig(cfg)
		defer eng.Close()

		ctx := context.Background()
		send := func(e types.Event) {
			if !split {
				eng.IngestAsync(ctx, e)
				return
			}
			eng.IngestAsyncPriority(ctx, e, e.Type != types.EventFileAccess)
		}
		for i := 0; i < 600; i++ {
			pid := uint32(i%13 + 1)
			switch i % 3 {
			case 0:
				send(types.Event{Type: types.EventTCPConnect, PID: pid, Network: &types.NetworkEvent{Dport: uint16(4440 + i%8)}})
			case 1:
				fe := &types.FileEvent{}
				copy(fe.Filename[:], []string{"/etc/id-test", "/tmp/x"}[i%2])
				send(types.Event{Type: types.EventFileAccess, PID: pid, File: fe})
			default:
				send(types.Event{Type: types.EventSyscall, PID: pid, Syscall: &types.SyscallEvent{Nr: int64(57 + i%4)}})
			}
		}
		dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		eng.DrainIngestPool(dctx)
		got := map[string]int{}
		for _, a := range eng.Flush() {
			got[fmt.Sprintf("%s/%d", a.RuleID, a.PID)]++
		}
		return got
	}
	legacy, split := run(false), run(true)
	require.NotEmpty(t, legacy)
	assert.Equal(t, legacy, split)
}

// №534 (хвост №530): anomaly_detection на одном потоке через старый и
// раздельный путь. Один воркер, чтобы порядок внутри воркера был единственной
// переменной: legacy — порядок отправки; split — protected впереди bulk.
// Детектор ключует профиль по воркладу (comm+ns), а не по pid, и считает
// отдельные измерения по типу события (порты — network, пути — file), поэтому
// межклассовая перестановка не должна менять множество аномалий. Тест
// проверяет это на детерминированном потоке; расхождение — дефект.
func TestIngestAsyncPriority_AnomalyIdentityVsLegacy(t *testing.T) {
	run := func(split bool) map[string]int {
		cfg := DefaultCorrelationEngineConfig()
		cfg.Rules = nil
		cfg.EnableAnomaly = true
		cfg.LearningPeriod = 100 * time.Millisecond
		cfg.MinLearningSamples = 20
		cfg.AnomalyThreshold = 0.5
		cfg.EnableDedup = false
		cfg.EnableRateLimit = false
		cfg.IngestWorkerCount = 1
		eng := NewCorrelationEngineWithConfig(cfg)
		defer eng.Close()

		ctx := context.Background()
		send := func(e types.Event) {
			if !split {
				eng.IngestAsync(ctx, e)
				return
			}
			eng.IngestAsyncPriority(ctx, e, e.Type != types.EventFileAccess)
		}
		mk := func(i int, port uint16, path string) (types.Event, types.Event) {
			var comm [16]byte
			copy(comm[:], "workload")
			ne := types.Event{Type: types.EventTCPConnect, PID: uint32(100 + i%5), Comm: comm,
				Network: &types.NetworkEvent{Dport: port}}
			fe := &types.FileEvent{}
			copy(fe.Filename[:], path)
			return ne, types.Event{Type: types.EventFileAccess, PID: uint32(100 + i%5), Comm: comm, File: fe}
		}
		// learning: stable behaviour, run past the learning period
		for i := 0; i < 200; i++ {
			n, f := mk(i, 443, "/etc/app.conf")
			send(n)
			send(f)
		}
		// DrainIngestPool is final (closes the worker channels), so mid-stream
		// settling is by time: 400 events take far less than this.
		time.Sleep(500 * time.Millisecond)
		for i := 0; i < 50; i++ { // more samples after the period closes
			n, f := mk(i, 443, "/etc/app.conf")
			send(n)
			send(f)
		}
		time.Sleep(300 * time.Millisecond)
		eng.Flush()
		// scoring phase: novel ports and paths interleaved with normal events
		for i := 0; i < 100; i++ {
			n, f := mk(i, uint16(9000+i%10), fmt.Sprintf("/tmp/novel-%d", i%10))
			send(n)
			send(f)
			n, f = mk(i, 443, "/etc/app.conf")
			send(n)
			send(f)
		}
		dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		eng.DrainIngestPool(dctx)
		got := map[string]int{}
		for _, a := range eng.Flush() {
			got[fmt.Sprintf("%s/%d", a.RuleID, a.PID)]++
		}
		return got
	}
	legacy, split := run(false), run(true)
	t.Logf("legacy=%v split=%v", legacy, split)
	require.NotEmpty(t, legacy, "scoring phase must produce anomalies, otherwise the test proves nothing")
	assert.Equal(t, legacy, split)
}
