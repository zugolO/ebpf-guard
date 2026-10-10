package correlator

import (
	"context"
	"fmt"
	"math/rand"
	"runtime"
	"testing"

	"github.com/zugolO/ebpf-guard/internal/bpf"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 8.2, item A2 — офлайн-бенч «байт аллокаций на событие».
//
// Записанного потока событий у стенда нет (архивы хранят счётчики по типам),
// поэтому микс СИНТЕТИЧЕСКИЙ, но в пропорциях ночи №4 (collect-4-night,
// events_total): file 87,3%, syscall 12,6%, network 0,1%. Путь — тот же, что в
// проде от кольца до правил: сырая запись internal/bpf → ToTypesEvent →
// CorrelationEngine.Ingest с ПОСТАВЛЯЕМЫМИ правилами rules/*.yaml. Конверсия
// входит в замер намеренно: FileaccessEvent.ToTypesEvent — 27% потока жизни
// процесса на снимке входа 8.2, её правка (C2) иначе была бы не видна.
//
// Микс детерминирован (seed фиксирован), поэтому число повторяется на маке и в
// CI; стенд правку только подтверждает (правило 2 волны 8.2).

const (
	w82MixSize   = 4096
	w82Warmup    = 20000
	w82Measure   = 60000
	w82Budget    = 300 // 8.2.3: ≤ 300 Б/событие
	w82TickNanos = 666_667
)

// w82AllocCeiling — потолок регресса для CI: измеренное значение на коммите
// входа A2 плюс запас. Опускается вместе с каждой правкой C2, никогда не
// поднимается без записи в plan.md.
var w82AllocCeiling = 860.0 // вход A2 10.10.2026: 778–781 Б/событие (мак, 3 прогона) + 10%

type w82Rec struct {
	file *bpf.FileaccessEvent
	sys  *bpf.SyscallEvent
	net  *types.Event
}

func (r w82Rec) event(ts uint64) types.Event {
	switch {
	case r.file != nil:
		r.file.Timestamp = ts
		return r.file.ToTypesEvent()
	case r.sys != nil:
		r.sys.Timestamp = ts
		return r.sys.ToTypesEvent()
	default:
		e := *r.net
		e.Timestamp = ts
		return e
	}
}

func w82Comm(s string) (c [16]byte) { copy(c[:], s); return }

// w82Mix строит детерминированный микс в пропорциях ночи №4.
func w82Mix(n int) []w82Rec {
	rng := rand.New(rand.NewSource(82))
	comms := []struct {
		comm   string
		weight int
	}{{"k3s-server", 40}, {"containerd", 20}, {"systemd", 10}, {"coredns", 10},
		{"sshd", 5}, {"cron", 5}, {"bash", 5}, {"python3", 5}}
	pickComm := func() string {
		x := rng.Intn(100)
		for _, c := range comms {
			if x < c.weight {
				return c.comm
			}
			x -= c.weight
		}
		return "k3s-server"
	}
	paths := []string{
		"/proc/%d/stat", "/proc/%d/cgroup", "/proc/%d/status", "/proc/self/mountinfo",
		"/sys/fs/cgroup/kubepods.slice/cpu.stat", "/sys/fs/cgroup/system.slice/memory.current",
		"/etc/ld.so.cache", "/usr/lib/x86_64-linux-gnu/libc.so.6", "/etc/nsswitch.conf",
		"/var/lib/rancher/k3s/agent/containerd/io.containerd.metadata.v1.bolt/meta.db",
		"/run/containerd/io.containerd.runtime.v2.task/k8s.io/%d/rootfs/etc/hosts",
		"/var/log/syslog", "/tmp/tmp.%d", "/etc/passwd",
	}
	sysNrs := []int64{56, 56, 56, 59, 59, 41, 41, 42, 42, 157, 62, 105}
	out := make([]w82Rec, 0, n)
	for i := 0; i < n; i++ {
		pid := uint32(1000 + rng.Intn(1000))
		comm := pickComm()
		switch x := rng.Intn(1000); {
		case x < 873:
			f := &bpf.FileaccessEvent{PID: pid, TGID: pid, PPID: 1, Comm: w82Comm(comm),
				ParentComm: w82Comm("systemd"), Flags: 0o2000000, CgroupID: uint64(2 + rng.Intn(64))}
			p := paths[rng.Intn(len(paths))]
			if p == "/etc/passwd" && rng.Intn(10) != 0 { // credential-file reads are rare
				p = "/etc/ld.so.cache"
			}
			copy(f.Filename[:], fmt.Sprintf(p, pid))
			switch y := rng.Intn(100); {
			case y < 60:
				f.Op = 0
			case y < 85:
				f.Op = 1
			case y < 98:
				f.Op, f.Flags = 2, 1
			default:
				f.Op = uint8(4 + rng.Intn(4))
			}
			out = append(out, w82Rec{file: f})
		case x < 999:
			s := &bpf.SyscallEvent{PID: pid, TGID: pid, PPID: 1, Comm: w82Comm(comm),
				ParentComm: w82Comm("systemd"), Nr: sysNrs[rng.Intn(len(sysNrs))], CgroupID: uint64(2 + rng.Intn(64))}
			out = append(out, w82Rec{sys: s})
		default:
			e := &types.Event{Type: types.EventTCPConnect, PID: pid, PPID: 1, Comm: w82Comm(comm),
				Network: &types.NetworkEvent{Dport: []uint16{443, 6443, 53}[rng.Intn(3)], Proto: 6, Family: types.AFInet}}
			out = append(out, w82Rec{net: e})
		}
	}
	return out
}

func w82Engine(tb testing.TB) *CorrelationEngine {
	tb.Helper()
	rules, err := LoadRulesFromDir("../../rules")
	if err != nil {
		tb.Fatalf("load rules: %v", err)
	}
	cfg := DefaultCorrelationEngineConfig()
	cfg.Rules = rules
	return NewCorrelationEngineWithConfig(cfg)
}

// w82Run прогоняет n событий микса, начиная с тика ts; возвращает следующий тик.
func w82Run(ctx context.Context, eng *CorrelationEngine, mix []w82Rec, start, n int, ts uint64) uint64 {
	for i := 0; i < n; i++ {
		ts += w82TickNanos
		eng.Ingest(ctx, mix[(start+i)%len(mix)].event(ts))
	}
	return ts
}

// BenchmarkW82_MixIngest — Б/op и allocs/op здесь — на ОДНО событие микса.
func BenchmarkW82_MixIngest(b *testing.B) {
	eng := w82Engine(b)
	defer eng.Close()
	ctx := context.Background()
	mix := w82Mix(w82MixSize)
	ts := w82Run(ctx, eng, mix, 0, w82Warmup, 1_000_000_000)
	b.ReportAllocs()
	b.ResetTimer()
	w82Run(ctx, eng, mix, w82Warmup, b.N, ts)
	b.StopTimer()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	b.ReportMetric(float64(ms.HeapAlloc)/1048576, "live-heap-MiB")
}

// TestW82_AllocPerEvent — эмиттер метки 8.2.3 (печать вердикта) и сторож
// регресса для CI (падает, только если поток выше потолка w82AllocCeiling).
func TestW82_AllocPerEvent(t *testing.T) {
	if testing.Short() {
		t.Skip("A2: полный микс с поставляемыми правилами")
	}
	eng := w82Engine(t)
	defer eng.Close()
	ctx := context.Background()
	mix := w82Mix(w82MixSize)
	ts := w82Run(ctx, eng, mix, 0, w82Warmup, 1_000_000_000)

	runtime.GC()
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	w82Run(ctx, eng, mix, w82Warmup, w82Measure, ts)
	runtime.ReadMemStats(&m1)

	perEvent := float64(m1.TotalAlloc-m0.TotalAlloc) / w82Measure
	allocs := float64(m1.Mallocs-m0.Mallocs) / w82Measure
	verdict := "ДОСТИГНУТО"
	if perEvent > w82Budget {
		verdict = "ПРОВАЛЕН"
	}
	t.Logf("%s: 8.2.3 %s (поток %.0f Б/событие, %.1f аллокаций/событие против ≤ %d; микс ночи №4, %d событий, поставляемые правила)",
		verdict, verdict, perEvent, allocs, w82Budget, w82Measure)
	if w82AllocCeiling > 0 && perEvent > w82AllocCeiling {
		t.Fatalf("регресс потока аллокаций: %.0f Б/событие > потолка %.0f (A2, волна 8.2)", perEvent, w82AllocCeiling)
	}
}
