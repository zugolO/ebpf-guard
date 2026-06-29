package bpf

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// xdpStatsFakeMap is a minimal bpfMap stub for ReadXDPStats tests.
type xdpStatsFakeMap struct {
	perCPU    []XDPPerCPUStats
	lookupErr error
}

func (f *xdpStatsFakeMap) Update(_, _ interface{}, _ ebpf.MapUpdateFlags) error { return nil }
func (f *xdpStatsFakeMap) Delete(_ interface{}) error                            { return nil }
func (f *xdpStatsFakeMap) Lookup(_, valueOut interface{}) error {
	if f.lookupErr != nil {
		return f.lookupErr
	}
	if ptr, ok := valueOut.(*[]XDPPerCPUStats); ok {
		*ptr = f.perCPU
	}
	return nil
}

func TestReadXDPStats_NilMap(t *testing.T) {
	_, err := ReadXDPStats(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestReadXDPStats_LookupError(t *testing.T) {
	m := &xdpStatsFakeMap{lookupErr: errors.New("map read failed")}
	_, err := ReadXDPStats(m)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "map read failed")
}

func TestReadXDPStats_EmptyPerCPU(t *testing.T) {
	m := &xdpStatsFakeMap{perCPU: []XDPPerCPUStats{}}
	agg, err := ReadXDPStats(m)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), agg.Dropped)
	assert.Equal(t, uint64(0), agg.Passed)
}

func TestReadXDPStats_SingleCPU(t *testing.T) {
	m := &xdpStatsFakeMap{
		perCPU: []XDPPerCPUStats{
			{Dropped: 7, Passed: 42},
		},
	}
	agg, err := ReadXDPStats(m)
	require.NoError(t, err)
	assert.Equal(t, uint64(7), agg.Dropped)
	assert.Equal(t, uint64(42), agg.Passed)
}

func TestReadXDPStats_MultiCPU_SumsAll(t *testing.T) {
	m := &xdpStatsFakeMap{
		perCPU: []XDPPerCPUStats{
			{Dropped: 10, Passed: 100},
			{Dropped: 20, Passed: 200},
			{Dropped: 30, Passed: 300},
		},
	}
	agg, err := ReadXDPStats(m)
	require.NoError(t, err)
	assert.Equal(t, uint64(60), agg.Dropped)
	assert.Equal(t, uint64(600), agg.Passed)
}

func TestReadXDPStats_AllDropped(t *testing.T) {
	m := &xdpStatsFakeMap{
		perCPU: []XDPPerCPUStats{
			{Dropped: 1000, Passed: 0},
			{Dropped: 500, Passed: 0},
		},
	}
	agg, err := ReadXDPStats(m)
	require.NoError(t, err)
	assert.Equal(t, uint64(1500), agg.Dropped)
	assert.Equal(t, uint64(0), agg.Passed)
}

func TestReadXDPStats_AllPassed(t *testing.T) {
	m := &xdpStatsFakeMap{
		perCPU: []XDPPerCPUStats{
			{Dropped: 0, Passed: 999},
			{Dropped: 0, Passed: 1},
		},
	}
	agg, err := ReadXDPStats(m)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), agg.Dropped)
	assert.Equal(t, uint64(1000), agg.Passed)
}

func TestReadXDPStats_ManyCoresHighCounters(t *testing.T) {
	const cpus = 128
	const droppedPerCPU = 1_000_000
	const passedPerCPU = 5_000_000

	var slots []XDPPerCPUStats
	for i := 0; i < cpus; i++ {
		slots = append(slots, XDPPerCPUStats{Dropped: droppedPerCPU, Passed: passedPerCPU})
	}
	m := &xdpStatsFakeMap{perCPU: slots}
	agg, err := ReadXDPStats(m)
	require.NoError(t, err)
	assert.Equal(t, uint64(cpus*droppedPerCPU), agg.Dropped)
	assert.Equal(t, uint64(cpus*passedPerCPU), agg.Passed)
}
