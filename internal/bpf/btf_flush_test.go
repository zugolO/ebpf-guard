package bpf

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/require"
)

// TestFlushKernelBTF pins the cross-platform contract of the wave-8.1 item 4
// helper: on Linux it wraps cilium/ebpf's btf.FlushKernelSpec, on the macOS dev
// host it is the no-op stub in btf_stub.go. The memory effect (33,4 МиБ of live
// heap dropped from the process-global kernel BTF cache) needs a host that
// actually loads BPF objects, so it cannot be asserted here — this only proves
// the export exists and the build-tag split compiles and runs on both.
func TestFlushKernelBTF(t *testing.T) {
	require.NotPanics(t, func() { FlushKernelBTF() })
	// The single call site guards itself with sync.Once, but the helper has to
	// tolerate repeated calls on its own: btf.FlushKernelSpec only nils the
	// cached spec (btf/kernel.go), and the !linux stub does nothing at all.
	require.NotPanics(t, func() {
		FlushKernelBTF()
		FlushKernelBTF()
	})
}

// TestFlushKernelBTF_NextLoaderStillWorks pins the risk the flush introduces:
// dropping the cache must not break a loader that runs afterwards (a future
// live update, a collector Reload). Skipped wherever there is no local kernel
// BTF — always, on the macOS dev host, where the stub is a no-op.
func TestFlushKernelBTF_NextLoaderStillWorks(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("kernel BTF is only available on Linux")
	}
	before, err := btf.LoadKernelSpec()
	if err != nil {
		t.Skipf("no local kernel BTF to test against: %v", err)
	}
	var beforeTask *btf.Struct
	if err := before.TypeByName("task_struct", &beforeTask); err != nil {
		t.Fatalf("kernel BTF has no task_struct: %v", err)
	}

	FlushKernelBTF()

	after, err := btf.LoadKernelSpec()
	require.NoError(t, err, "the first loader after a flush must re-parse vmlinux successfully")
	var afterTask *btf.Struct
	require.NoError(t, after.TypeByName("task_struct", &afterTask),
		"the re-parsed kernel BTF must still resolve the types a CO-RE relocation asks for")
	require.Equal(t, len(beforeTask.Members), len(afterTask.Members))
}

// TestKernelBTFFlushGate_FlushOnlyOnLastReport pins the item-4 ordering the main
// agent's closure relies on: the gate must not flush until every armed collector
// has reported, must de-duplicate by collector name, and must run the flush
// exactly once. The countdown in cmd/ebpf-guard/main.go now delegates here.
func TestKernelBTFFlushGate_FlushOnlyOnLastReport(t *testing.T) {
	var flushes atomic.Int64
	g := NewKernelBTFFlushGate()
	g.flush = func() { flushes.Add(1) }
	g.Arm(3)

	require.False(t, g.Report("syscall"))
	require.EqualValues(t, 0, flushes.Load())
	require.EqualValues(t, 2, g.Pending())

	// A repeated report for a name already counted must not consume another
	// collector's slot and fire the flush early.
	require.False(t, g.Report("syscall"))
	require.EqualValues(t, 2, g.Pending())
	require.EqualValues(t, 0, flushes.Load())

	require.False(t, g.Report("network"))
	require.EqualValues(t, 0, flushes.Load())

	require.True(t, g.Report("file"), "the last report drives the countdown to zero")
	require.EqualValues(t, 1, flushes.Load())
	require.EqualValues(t, 0, g.Pending())

	// Post-flush reports are ignored: the sync.Once is spent.
	require.False(t, g.Report("file"))
	require.False(t, g.Report("dns"))
	require.EqualValues(t, 1, flushes.Load())
}

// TestKernelBTFFlushGate_StalledCollectorNeverFlushes pins the fail-safe
// direction: a collector that never reports leaves the countdown > 0 and the
// kernel BTF cache is retained. The gate must never flush early, even though
// that is exactly the silent case the startup warning exists to surface.
func TestKernelBTFFlushGate_StalledCollectorNeverFlushes(t *testing.T) {
	var flushes atomic.Int64
	g := NewKernelBTFFlushGate()
	g.flush = func() { flushes.Add(1) }
	g.Arm(3)

	require.False(t, g.Report("syscall"))
	require.False(t, g.Report("network"))
	require.EqualValues(t, 1, g.Pending())
	require.EqualValues(t, 0, flushes.Load())
}

// TestKernelBTFFlushGate_ZeroArmed pins the dry-run/synthetic case: armed with
// zero (no BPF-loading collector) a stray report must not fire the flush, since
// no object was ever loaded and there is no cache to release.
func TestKernelBTFFlushGate_ZeroArmed(t *testing.T) {
	var flushes atomic.Int64
	g := NewKernelBTFFlushGate()
	g.flush = func() { flushes.Add(1) }
	g.Arm(0)

	require.False(t, g.Report("synthetic"))
	require.EqualValues(t, 0, flushes.Load())
}

// TestKernelBTFFlushGate_ConcurrentReportsFlushOnce pins the sync.Once contract:
// when the last collectors report concurrently, more than one goroutine can
// observe the countdown hit zero, but the flush itself must still run exactly
// once and only one Report may claim it.
func TestKernelBTFFlushGate_ConcurrentReportsFlushOnce(t *testing.T) {
	var flushes atomic.Int64
	g := NewKernelBTFFlushGate()
	g.flush = func() { flushes.Add(1) }
	const n = 64
	g.Arm(n)

	var (
		wg      sync.WaitGroup
		winners atomic.Int64
	)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if g.Report(fmt.Sprintf("collector-%d", i)) {
				winners.Add(1)
			}
		}(i)
	}
	wg.Wait()

	require.EqualValues(t, 1, flushes.Load())
	require.EqualValues(t, 1, winners.Load(), "exactly one report may claim the flush")
	require.EqualValues(t, 0, g.Pending())
}
