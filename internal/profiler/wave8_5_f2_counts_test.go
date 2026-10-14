package profiler

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"math/rand"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 8.5, F2: профиль из счётчиков ядра ≡ профиль из событий (ε по каждому
// номеру). «Ядро» здесь — предикат, отбрасывающий события горячих номеров, и
// счётчик по (pid, nr), который сбрасывается пачкой в произвольные моменты.

var w85HotNrs = map[int64]bool{9: true, 10: true, 158: true}

func w85Comm(s string) [16]byte {
	var b [16]byte
	copy(b[:], s)
	return b
}

type w85Stream struct {
	rng   *rand.Rand
	comms []string
}

func (s *w85Stream) next() types.Event {
	nrs := []int64{0, 1, 2, 3, 9, 9, 9, 10, 10, 158, 59, 257, 321, 41}
	pid := 1000 + uint32(s.rng.Intn(40))
	comm := s.comms[int(pid)%len(s.comms)]
	e := types.Event{PID: pid, Comm: w85Comm(comm)}
	switch r := s.rng.Intn(10); {
	case r < 7:
		e.Type = types.EventSyscall
		e.Syscall = &types.SyscallEvent{Nr: nrs[s.rng.Intn(len(nrs))]}
		e.Syscall.Args[2] = uint64(s.rng.Intn(8))
	case r < 9:
		e.Type = types.EventFileAccess
		fe := &types.FileEvent{}
		fe.Filename = []string{"/etc/passwd", "/var/log/syslog", "/tmp/x.sh"}[s.rng.Intn(3)]
		e.File = fe
	default:
		e.Type = types.EventTCPConnect
		e.Network = &types.NetworkEvent{Dport: uint16(80 + s.rng.Intn(3))}
	}
	return e
}

// kernelDrops — «ядро»: событие горячего номера без признака (arg2 вне 4..7)
// отбрасывается и считается.
func kernelDrops(e types.Event) bool {
	return e.Type == types.EventSyscall && w85HotNrs[e.Syscall.Nr] && (e.Syscall.Args[2] < 4)
}

type w85Counters map[[2]uint64]*SyscallCount

func (c w85Counters) add(e types.Event) {
	k := [2]uint64{uint64(e.PID), uint64(e.Syscall.Nr)}
	sc := c[k]
	if sc == nil {
		sc = &SyscallCount{PID: e.PID, Nr: e.Syscall.Nr}
		c[k] = sc
	}
	sc.Comm = e.Comm
	sc.N++
}

func (c w85Counters) flush(ad *AnomalyDetector) {
	batch := make([]SyscallCount, 0, len(c))
	for k, v := range c {
		batch = append(batch, *v)
		delete(c, k)
	}
	ad.IngestSyscallCounts(batch, nil)
}

func w85CompareProfiles(t *testing.T, a, b *AnomalyDetector) {
	t.Helper()
	pa, pb := a.GetProfileManager(), b.GetProfileManager()
	if pa.Len() != pb.Len() {
		t.Fatalf("число профилей: события=%d счётчики=%d", pa.Len(), pb.Len())
	}
	compared := 0
	for i := range pa.shards {
		for key, profA := range pa.shards[i].profiles {
			profB := pb.GetByKey(key)
			if profB == nil {
				t.Fatalf("профиль %v есть из событий и нет из счётчиков", key)
			}
			if profA.SyscallProfile.TotalSyscalls != profB.SyscallProfile.TotalSyscalls {
				t.Errorf("%v: TotalSyscalls события=%d счётчики=%d", key, profA.SyscallProfile.TotalSyscalls, profB.SyscallProfile.TotalSyscalls)
			}
			if len(profA.SyscallProfile.Syscalls) != len(profB.SyscallProfile.Syscalls) {
				t.Errorf("%v: набор номеров события=%d счётчики=%d", key, len(profA.SyscallProfile.Syscalls), len(profB.SyscallProfile.Syscalls))
			}
			for nr, ea := range profA.SyscallProfile.Syscalls {
				eb := profB.SyscallProfile.Syscalls[nr]
				if eb == nil {
					t.Errorf("%v: номер %d есть из событий и нет из счётчиков", key, nr)
					continue
				}
				if math.Abs(ea.Value()-eb.Value()) > 1e-12 || ea.Count() != eb.Count() {
					t.Errorf("%v nr=%d: EWMA события=(%v,%d) счётчики=(%v,%d)", key, nr, ea.Value(), ea.Count(), eb.Value(), eb.Count())
				}
				compared++
			}
			if len(profA.FileProfile.Directories) != len(profB.FileProfile.Directories) ||
				len(profA.NetworkProfile.DestPorts) != len(profB.NetworkProfile.DestPorts) {
				t.Errorf("%v: файловый/сетевой профиль разошёлся", key)
			}
		}
	}
	if compared == 0 {
		t.Fatal("сравнено ноль номеров — тест вакуумен")
	}
}

func TestW85_F2_ProfileFromCountersEqualsProfileFromEvents(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := NewAnomalyDetectorWithSamples(ctx, 0.7, time.Hour, 0.3, 100, 0)
	b := NewAnomalyDetectorWithSamples(ctx, 0.7, time.Hour, 0.3, 100, 0)

	s := &w85Stream{rng: rand.New(rand.NewSource(8502)), comms: []string{"nginx", "iptables", "curl", "k3s-server", "cron", "bash"}}
	counters := w85Counters{}
	dropped, passed := 0, 0
	for i := 0; i < 30000; i++ {
		e := s.next()
		a.ProcessEvent(e, false)
		if kernelDrops(e) {
			counters.add(e)
			dropped++
		} else {
			b.ProcessEvent(e, false)
			passed++
		}
		// Сброс счётчиков в случайные моменты, а не раз в N событий.
		if s.rng.Intn(500) == 0 {
			counters.flush(b)
		}
	}
	counters.flush(b)
	t.Logf("событий: %d дошло, %d отброшено ядром и учтено счётчиком", passed, dropped)
	if dropped == 0 {
		t.Fatal("ядро ничего не отбросило")
	}
	w85CompareProfiles(t, a, b)
	if a.GetSampleCount() != b.GetSampleCount() {
		t.Errorf("образцов обучения: события=%d счётчики=%d", a.GetSampleCount(), b.GetSampleCount())
	}
}

// После обучения: оценка пропущенного ядром события одинакова, если счётчики
// сброшены до него. Различие живёт только в окне между сбросами — и это окно
// (интервал сброса) оговаривается в plan.md.
func TestW85_F2_ScoringIdenticalWhenCountersAreFlushed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := NewAnomalyDetectorWithSamples(ctx, 0.7, time.Millisecond, 0.3, 10, 0)
	b := NewAnomalyDetectorWithSamples(ctx, 0.7, time.Millisecond, 0.3, 10, 0)
	s := &w85Stream{rng: rand.New(rand.NewSource(8503)), comms: []string{"nginx", "iptables", "curl", "cron"}}
	counters := w85Counters{}

	feed := func(n int, score bool) (cmp int) {
		for i := 0; i < n; i++ {
			e := s.next()
			ra := a.ProcessEvent(e, false)
			if kernelDrops(e) {
				counters.add(e)
				counters.flush(b)
				continue
			}
			rb := b.ProcessEvent(e, false)
			if !score {
				continue
			}
			if (ra == nil) != (rb == nil) {
				t.Fatalf("событие %d: результат оценки nil у одного из детекторов", i)
			}
			if ra != nil {
				cmp++
				if math.Abs(ra.Score-rb.Score) > 1e-12 || ra.IsAnomaly != rb.IsAnomaly {
					t.Fatalf("событие %d (%s): оценка события=%v счётчики=%v", i, string(e.Comm[:4]), ra.Score, rb.Score)
				}
			}
		}
		return cmp
	}
	feed(4000, false)
	time.Sleep(20 * time.Millisecond)
	if !a.IsLearningComplete() || !b.IsLearningComplete() {
		t.Fatalf("обучение не завершилось: события=%v счётчики=%v", a.IsLearningComplete(), b.IsLearningComplete())
	}
	if n := feed(6000, true); n == 0 {
		t.Fatal("ни одной сравнённой оценки — тест вакуумен")
	} else {
		t.Logf("сравнено оценок: %d", n)
	}
	w85CompareProfiles(t, a, b)
}

func TestW85_F2_EWMAUpdateNMatchesSequential(t *testing.T) {
	for _, obs := range []float64{1.0, 0.25} {
		for _, pre := range []int{0, 1, 5} {
			for _, n := range []uint64{1, 2, 7, 1000} {
				seq, bulk := NewEWMA(0.3), NewEWMA(0.3)
				for i := 0; i < pre; i++ {
					seq.Update(0.5)
					bulk.Update(0.5)
				}
				for i := uint64(0); i < n; i++ {
					seq.Update(obs)
				}
				bulk.UpdateN(obs, n)
				if math.Abs(seq.Value()-bulk.Value()) > 1e-12 || seq.Count() != bulk.Count() {
					t.Fatalf("obs=%v pre=%d n=%d: последовательно=(%v,%d) разом=(%v,%d)", obs, pre, n, seq.Value(), seq.Count(), bulk.Value(), bulk.Count())
				}
			}
		}
	}
}

// Волна 8.6, Д4 (№558): Profiler.Ingest и всё, что жило только через него, удалено.
// Сторож заменяет прежний «нет живого вызывающего» (8.5, F2): тот проверял, что
// вход не подключён; этот — что СИМВОЛОВ нет, подключить нечего. Вернуть любой из
// них — значит вернуть мёртвый слой (Марков/EWMA-вход мимо движка, зашитые
// паттерны цепочек) и ложное чувство покрытия: живой детект цепочек — правила.
func TestW86_D4_DeadIngestSymbolsAreGone(t *testing.T) {
	banned := map[string]string{
		"Profiler.Ingest":                 "вход профайлера мимо CorrelationEngine",
		"Profiler.allowlistCheck":         "обёртка allowlist только для Ingest (движок зовёт Record/Check сам)",
		"Profiler.buildAllowlistAnomaly":  "только для Ingest",
		"Profiler.SetLineageMatchHandler": "колбэк совпадений паттернов",
		"LineageTracker.Update":           "зашитые паттерны цепочек",
		"LineageTracker.SetMatchHandler":  "колбэк совпадений паттернов",
		"LineageTracker.checkPattern":     "зашитые паттерны цепочек",
		"LineageTracker.tableParentInfo":  "только для Update",
		"evaluateLineageCondition":        "зашитые паттерны цепочек",
		"matchesAny":                      "зашитые паттерны цепочек",
		"Anomaly":                         "тип результата Ingest",
		"AnomalyType":                     "тип результата Ingest",
		"LineagePattern":                  "зашитые паттерны цепочек",
		"LineageCondition":                "зашитые паттерны цепочек",
		"LineageMatch":                    "зашитые паттерны цепочек",
	}
	fset := token.NewFileSet()
	found := map[string]bool{}
	entries, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range entries {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Fatal(perr)
		}
		for _, d := range f.Decls {
			switch dd := d.(type) {
			case *ast.FuncDecl:
				name := dd.Name.Name
				if dd.Recv != nil && len(dd.Recv.List) == 1 {
					switch rt := dd.Recv.List[0].Type.(type) {
					case *ast.StarExpr:
						if id, ok := rt.X.(*ast.Ident); ok {
							name = id.Name + "." + name
						}
					case *ast.Ident:
						name = rt.Name + "." + name
					}
				}
				found[name] = true
			case *ast.GenDecl:
				for _, sp := range dd.Specs {
					if ts, ok := sp.(*ast.TypeSpec); ok {
						found[ts.Name.Name] = true
					}
				}
			}
		}
	}
	for sym, why := range banned {
		if found[sym] {
			t.Errorf("символ %s вернулся (%s): план 8.6 Д4 — удалён, живой детект цепочек — правила", sym, why)
		}
	}
}
