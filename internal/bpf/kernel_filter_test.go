package bpf

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestFilterMaps builds three in-process ebpf.Map substitutes using the
// fake map helpers provided by the cilium/ebpf testing package.  Because real
// BPF maps require root + a kernel with BPF enabled, we use the library's
// mock objects so the logic can be exercised in unit tests without privileges.
//
// We cannot call ebpf.NewMap in a normal unit test environment, so instead we
// test the pure-Go logic around the controller (nil-map guard, range checks,
// default lists, etc.) and stub out map interactions separately.

func TestDefaultMonitoredSyscalls(t *testing.T) {
	nrs := DefaultMonitoredSyscalls()
	assert.NotEmpty(t, nrs, "default syscall list must not be empty")

	// Spot-check that well-known syscall numbers are present.
	must := map[int]string{
		59:  "execve",
		322: "execveat",
		101: "ptrace",
		319: "memfd_create",
	}
	set := make(map[int]bool, len(nrs))
	for _, n := range nrs {
		set[n] = true
	}
	for nr, name := range must {
		assert.True(t, set[nr], "expected syscall %s (%d) in default list", name, nr)
	}

	// All entries must be in the valid range.
	for _, nr := range nrs {
		assert.GreaterOrEqual(t, nr, 0, "syscall nr must be >= 0")
		assert.Less(t, nr, 512, "syscall nr must be < 512")
	}
}

func TestDefaultCommDenylist(t *testing.T) {
	list := DefaultCommDenylist()
	assert.NotEmpty(t, list, "default comm denylist must not be empty")

	// Each entry must fit in a 15-char comm string (kernel TASK_COMM_LEN - 1).
	for _, c := range list {
		assert.LessOrEqualf(t, len(c), 15,
			"comm %q is longer than 15 chars and will be silently truncated by the kernel", c)
	}

	// Known noisy kernel threads should be present.
	must := []string{"kworker", "ksoftirqd", "migration", "rcu_sched"}
	set := make(map[string]bool, len(list))
	for _, c := range list {
		set[c] = true
	}
	for _, c := range must {
		assert.True(t, set[c], "expected %q in default comm denylist", c)
	}
}

func TestNewKernelFilterController_NilMaps(t *testing.T) {
	_, err := NewKernelFilterController(nil, nil, nil)
	require.Error(t, err, "nil commMap should return error")

	// The error message should identify which map is nil.
	assert.Contains(t, err.Error(), "comm_filter_map")
}

func TestKernelFilterController_SetSyscallFilter_OutOfRange(t *testing.T) {
	kf := &KernelFilterController{}

	// Out-of-range inputs must be rejected before any map access.
	err := kf.SetSyscallFilter(-1, true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "out of range")

	err = kf.SetSyscallFilter(512, true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "out of range")
}

func TestKernelFilterController_SetSyscallFilter_NilMap(t *testing.T) {
	kf := &KernelFilterController{} // nil syscallFilterMap

	// Passes range check but map is nil → nil-map error, not range error.
	err := kf.SetSyscallFilter(59, true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "syscall_filter_map")
	assert.NotContains(t, err.Error(), "out of range")
}

func TestKernelFilterController_SetCommFilter_NilMap(t *testing.T) {
	kf := &KernelFilterController{} // nil commFilterMap

	err := kf.SetCommFilter("kworker", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "comm_filter_map")
}

func TestKernelFilterController_EnableDisable_NilMap(t *testing.T) {
	kf := &KernelFilterController{}

	err := kf.Enable()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kernel_filter_config")

	err = kf.Disable()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kernel_filter_config")
}
