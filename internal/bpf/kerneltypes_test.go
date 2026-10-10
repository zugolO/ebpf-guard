package bpf

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/require"
)

// stubKernelSpec подменяет загрузку vmlinux и возвращает счётчик обращений;
// состояние держателя сбрасывается до и после, чтобы тесты не зависели от порядка.
func stubKernelSpec(t *testing.T, fn func() (*btf.Spec, error)) *atomic.Int32 {
	t.Helper()
	var calls atomic.Int32
	orig := loadKernelSpec
	loadKernelSpec = func() (*btf.Spec, error) { calls.Add(1); return fn() }
	reset := func() {
		sharedKernelTypes.Lock()
		sharedKernelTypes.spec, sharedKernelTypes.released = nil, false
		sharedKernelTypes.Unlock()
	}
	reset()
	t.Cleanup(func() { loadKernelSpec = orig; reset() })
	return &calls
}

// Волна 8.2, C3 (№541): весь смысл — ОДИН разбор и ОДИН общий spec на все
// параллельные загрузки; иначе каждая программа с релокациями копирует граф типов.
func TestSharedKernelTypes_OneLoadOneSpecForConcurrentLoaders(t *testing.T) {
	spec := &btf.Spec{}
	calls := stubKernelSpec(t, func() (*btf.Spec, error) { return spec, nil })

	const n = 32
	got := make([]*btf.Spec, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); got[i] = SharedKernelTypes() }(i)
	}
	wg.Wait()

	require.EqualValues(t, 1, calls.Load(), "vmlinux must be parsed once, not once per collector")
	for i := range got {
		require.Same(t, spec, got[i])
	}
}

func TestWithSharedKernelTypes_SetsOptionsAndKeepsExplicit(t *testing.T) {
	spec := &btf.Spec{}
	stubKernelSpec(t, func() (*btf.Spec, error) { return spec, nil })

	require.Same(t, spec, WithSharedKernelTypes(nil).Programs.KernelTypes, "nil opts are created")
	require.Same(t, spec, WithSharedKernelTypes(&ebpf.CollectionOptions{}).Programs.KernelTypes)

	own := &btf.Spec{}
	opts := &ebpf.CollectionOptions{}
	opts.Programs.KernelTypes = own
	require.Same(t, own, WithSharedKernelTypes(opts).Programs.KernelTypes, "a caller-chosen spec must win")
}

// После FlushKernelBTF (последний загрузчик вернулся) общий spec отпущен, и
// поздний загрузчик идёт штатным путём cilium, а не удерживает граф навсегда.
func TestSharedKernelTypes_FlushReleasesAndStaysReleased(t *testing.T) {
	calls := stubKernelSpec(t, func() (*btf.Spec, error) { return &btf.Spec{}, nil })

	require.NotNil(t, SharedKernelTypes())
	FlushKernelBTF()
	require.Nil(t, SharedKernelTypes(), "released: nil means the stock cilium path")
	require.Nil(t, WithSharedKernelTypes(nil).Programs.KernelTypes)
	require.EqualValues(t, 1, calls.Load(), "no re-parse after the release")
}

// Нет BTF — поведение как до C3: nil, и следующий загрузчик пробует снова.
func TestSharedKernelTypes_NoBTFFallsBackAndRetries(t *testing.T) {
	calls := stubKernelSpec(t, func() (*btf.Spec, error) { return nil, errors.New("no BTF") })

	require.Nil(t, SharedKernelTypes())
	require.Nil(t, SharedKernelTypes())
	require.EqualValues(t, 2, calls.Load())
	require.Nil(t, WithSharedKernelTypes(&ebpf.CollectionOptions{}).Programs.KernelTypes)
}
