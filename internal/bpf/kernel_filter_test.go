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

func TestDefaultNoisyDaemonDenylist(t *testing.T) {
	list := DefaultNoisyDaemonDenylist()
	assert.NotEmpty(t, list, "default noisy daemon denylist must not be empty")

	// All entries must fit in 15 chars (kernel TASK_COMM_LEN - 1).
	for _, c := range list {
		assert.LessOrEqualf(t, len(c), 15,
			"comm %q exceeds 15 chars and will be silently truncated by the kernel", c)
	}

	// Spot-check that the key daemons from the issue are present.
	must := []string{"systemd-journal", "rsyslogd", "node_exporter"}
	set := make(map[string]bool, len(list))
	for _, c := range list {
		set[c] = true
	}
	for _, c := range must {
		assert.True(t, set[c], "expected daemon %q in default noisy daemon denylist", c)
	}
}

func TestBuildCommDenylist_Defaults(t *testing.T) {
	// No overrides: should get kernel threads + daemons.
	merged := BuildCommDenylist(nil, nil, false)
	assert.NotEmpty(t, merged)

	kernelThreads := DefaultCommDenylist()
	daemons := DefaultNoisyDaemonDenylist()
	assert.Len(t, merged, len(kernelThreads)+len(daemons))

	set := make(map[string]bool, len(merged))
	for _, c := range merged {
		set[c] = true
	}
	for _, c := range kernelThreads {
		assert.True(t, set[c], "expected kernel thread %q in merged list", c)
	}
	for _, c := range daemons {
		assert.True(t, set[c], "expected daemon %q in merged list", c)
	}
}

func TestBuildCommDenylist_DisableDaemons(t *testing.T) {
	merged := BuildCommDenylist(nil, nil, true)
	// Daemon list is disabled: only kernel threads expected.
	assert.Equal(t, DefaultCommDenylist(), merged)
}

func TestBuildCommDenylist_CustomKernelThreads(t *testing.T) {
	custom := []string{"mykworker", "myrcu"}
	merged := BuildCommDenylist(custom, nil, false)
	// Custom kernel-thread list + default daemons.
	assert.Len(t, merged, len(custom)+len(DefaultNoisyDaemonDenylist()))
	assert.Equal(t, custom[0], merged[0])
	assert.Equal(t, custom[1], merged[1])
}

func TestBuildCommDenylist_CustomDaemons(t *testing.T) {
	customDaemons := []string{"mylogger", "myagent"}
	merged := BuildCommDenylist(nil, customDaemons, false)
	// Default kernel threads + custom daemon list.
	assert.Len(t, merged, len(DefaultCommDenylist())+len(customDaemons))
	// Custom daemons must appear at the tail.
	tail := merged[len(DefaultCommDenylist()):]
	assert.Equal(t, customDaemons, tail)
}

func TestBuildCommDenylist_CustomDaemonsWithDisable(t *testing.T) {
	// disableDaemons=true wins even if a custom daemon list is supplied.
	merged := BuildCommDenylist(nil, []string{"mylogger"}, true)
	assert.Equal(t, DefaultCommDenylist(), merged)
}
