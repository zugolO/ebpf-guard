package bpf

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestArrayMap creates a small in-kernel array map for exercising the
// SamplingController. Tests that need it skip when the kernel/runtime does not
// permit BPF map creation (e.g. unprivileged CI sandboxes).
func newTestArrayMap(t *testing.T, valueSize uint32) *ebpf.Map {
	t.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  valueSize,
		MaxEntries: 4,
	})
	if err != nil {
		t.Skipf("BPF map creation unavailable in this environment: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func TestNewSamplingController_NilMap(t *testing.T) {
	_, err := NewSamplingController(nil)
	require.Error(t, err)
}

func TestSamplingController_SettersAndStats(t *testing.T) {
	cfgMap := newTestArrayMap(t, 16) // sizeof(SamplingConfig)

	sc, err := NewSamplingController(cfgMap)
	require.NoError(t, err)

	assert.Equal(t, DefaultSamplingConfig(), sc.GetConfig())

	require.NoError(t, sc.SetSyscallRate(10))
	require.NoError(t, sc.SetNetworkRate(20))
	require.NoError(t, sc.SetFileRate(30))

	got := sc.GetConfig()
	assert.Equal(t, uint32(10), got.SyscallRate)
	assert.Equal(t, uint32(20), got.NetworkRate)
	assert.Equal(t, uint32(30), got.FileRate)
	assert.Equal(t, uint32(1), got.Enabled, "setting a rate enables sampling")

	require.NoError(t, sc.Disable())
	assert.Equal(t, uint32(0), sc.GetConfig().Enabled)

	require.NoError(t, sc.Enable())
	assert.Equal(t, uint32(1), sc.GetConfig().Enabled)

	require.NoError(t, sc.UpdateConfig(SamplingConfig{SyscallRate: 5, Enabled: 1}))
	assert.Equal(t, uint32(5), sc.GetConfig().SyscallRate)

	// GetStats with a nil counters map errors.
	_, err = sc.GetStats(nil)
	require.Error(t, err)

	// GetStats with a real (empty) counters map succeeds with zero counts.
	countersMap := newTestArrayMap(t, 8) // uint64 counters
	stats, err := sc.GetStats(countersMap)
	require.NoError(t, err)
	assert.Equal(t, SamplingStats{}, stats)
}
