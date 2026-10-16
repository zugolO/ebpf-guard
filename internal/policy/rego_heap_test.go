//go:build rego

package policy

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// c4StartupBudgetMiB bounds the live heap of the engine right after startup.
const c4StartupBudgetMiB = 1.0

// liveHeap returns the live heap after two collections.
func liveHeap() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// TestC4_LiveHeapAfterStartup prints (and bounds) the heap the Rego engine
// keeps alive right after NewRegoEngine on the shipped policy set. Wave 8.2
// item C4: eager compilation of the full query plus five partitions held
// 7-8 MiB for the whole process life although alerts reach only some of the
// event classes.
func TestC4_LiveHeapAfterStartup(t *testing.T) {
	before := liveHeap()
	e, err := NewRegoEngine(RegoEngineConfig{Enabled: true, RulesDir: "../../rules/rego"})
	if err != nil {
		t.Fatal(err)
	}
	after := liveHeap()
	mib := float64(after-before) / (1 << 20)
	t.Logf("C4 live heap after NewRegoEngine: %.2f MiB", mib)
	if mib > c4StartupBudgetMiB {
		t.Errorf("live heap after startup %.2f MiB > %.1f MiB", mib, c4StartupBudgetMiB)
	}

	// One alert of one class compiles only that class's query.
	var ev types.Event
	ev.Type = types.EventDNS
	if _, err := e.Evaluate(context.Background(), types.Alert{RuleID: "x", Event: ev}); err != nil {
		t.Fatal(err)
	}
	t.Logf("C4 live heap after first dns evaluate: %.2f MiB", float64(liveHeap()-before)/(1<<20))
	runtime.KeepAlive(e)
}

// TestC4_AllClassesHeap records the steady-state cost once alerts of every
// event class have been seen (the busy-node case): the saving of C4 there is
// the fallback and unused partitions only.
func TestC4_AllClassesHeap(t *testing.T) {
	before := liveHeap()
	e, err := NewRegoEngine(RegoEngineConfig{Enabled: true, RulesDir: "../../rules/rego"})
	if err != nil {
		t.Fatal(err)
	}
	for _, et := range []types.EventType{types.EventSyscall, types.EventTCPConnect, types.EventFileAccess, types.EventDNS, types.EventTLS} {
		var ev types.Event
		ev.Type = et
		if _, err := e.Evaluate(context.Background(), types.Alert{RuleID: "x", Event: ev}); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("C4 live heap with every class compiled: %.2f MiB", float64(liveHeap()-before)/(1<<20))
	runtime.KeepAlive(e)
}

// TestC4_BrokenPolicyFailsStartup: lazy compilation must not move policy
// errors from startup to the first alert.
func TestC4_BrokenPolicyFailsStartup(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.rego"), []byte("package ebpf_guard\n\ndecisions[d] { d := undefined_var_xyz }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRegoEngine(RegoEngineConfig{Enabled: true, RulesDir: dir}); err == nil {
		t.Fatal("broken policy accepted at startup")
	}
}

// TestC4_ConcurrentFirstEvaluate: many first alerts of one class share a
// single compile and all succeed (-race).
func TestC4_ConcurrentFirstEvaluate(t *testing.T) {
	e, err := NewRegoEngine(RegoEngineConfig{Enabled: true, RulesDir: "../../rules/rego"})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var ev types.Event
			ev.Type = types.EventFileAccess
			if _, err := e.Evaluate(context.Background(), types.Alert{RuleID: "x", Event: ev}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if st := e.GetStats(); st.EvalErrors != 0 {
		t.Fatalf("eval errors: %d", st.EvalErrors)
	}
}

// Волна 8.7, П5 (№564): первый tls-алерт не компилирует full. Живая куча после
// первого tls-алерта растёт не более чем на 1 МиБ (до П5 — ≈ 2,8 МиБ на ночи 8.6).
func TestP5_FirstTLSAlertHeapStep(t *testing.T) {
	e, err := NewRegoEngine(RegoEngineConfig{Enabled: true, RulesDir: "../../rules/rego"})
	if err != nil {
		t.Fatal(err)
	}
	before := liveHeap()
	var ev types.Event
	ev.Type = types.EventTLS
	ev.TLS = &types.TLSEvent{}
	if _, err := e.Evaluate(context.Background(), types.Alert{RuleID: "x", Event: ev}); err != nil {
		t.Fatal(err)
	}
	step := float64(int64(liveHeap())-int64(before)) / (1 << 20)
	t.Logf("P5: живая куча после первого tls-алерта: %+.2f МиБ", step)
	if step > 1.0 {
		t.Errorf("первый tls-алерт поднял живую кучу на %.2f МиБ > 1,0", step)
	}
	runtime.KeepAlive(e)
}
