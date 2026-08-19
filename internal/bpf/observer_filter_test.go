package bpf

import (
	"errors"
	"fmt"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeObserverMap is a bpfMap standing in for observer_root_pid /
// observer_excluded_counters. It is separate from network_blocklist_test.go's
// fakeMap because this controller reads scalars (*uint32) as well as per-CPU
// slices, while that one only ever serves []uint64.
type fakeObserverMap struct {
	values    map[string]uint32
	perCPU    []uint64
	updateErr error
	lookupErr error
	updates   int
}

func newFakeObserverMap() *fakeObserverMap {
	return &fakeObserverMap{values: map[string]uint32{}}
}

func (f *fakeObserverMap) Update(key, value interface{}, _ ebpf.MapUpdateFlags) error {
	if f.updateErr != nil {
		return f.updateErr
	}
	f.updates++
	v, _ := value.(uint32)
	f.values[fmt.Sprintf("%v", key)] = v
	return nil
}

func (f *fakeObserverMap) Delete(interface{}) error { return nil }

func (f *fakeObserverMap) Lookup(key, valueOut interface{}) error {
	if f.lookupErr != nil {
		return f.lookupErr
	}
	switch out := valueOut.(type) {
	case *uint32:
		v, ok := f.values[fmt.Sprintf("%v", key)]
		if !ok {
			return ebpf.ErrKeyNotExist
		}
		*out = v
	case *[]uint64:
		*out = f.perCPU
	}
	return nil
}

// ---------------------------------------------------------------------------
// NewObserverFilterController
// ---------------------------------------------------------------------------

func TestNewObserverFilterController_NilRootMap(t *testing.T) {
	_, err := NewObserverFilterController(nil, nil)
	require.Error(t, err, "a nil root map must be an error, not a controller that silently writes nowhere")
	assert.Contains(t, err.Error(), "observer_root_pid")
}

// ---------------------------------------------------------------------------
// SetRootPID / ClearRootPID / RootPID
// ---------------------------------------------------------------------------

func TestObserverFilter_SetRootPID_WritesKeyZero(t *testing.T) {
	m := newFakeObserverMap()
	o := &ObserverFilterController{rootMap: m}

	require.NoError(t, o.SetRootPID(4242))
	assert.Equal(t, uint32(4242), m.values["0"],
		"the root TGID must land on key 0 — the single slot the BPF side reads")
	assert.Equal(t, uint32(4242), o.RootPID())
}

// PID 0 is the BPF side's "filter disabled" sentinel. Accepting it here would
// report success while leaving the filter off — the silent-blindness shape the
// whole wave exists to remove, and the reason ClearRootPID is a separate call.
func TestObserverFilter_SetRootPID_ZeroRejected(t *testing.T) {
	m := newFakeObserverMap()
	o := &ObserverFilterController{rootMap: m}

	require.Error(t, o.SetRootPID(0))
	assert.Equal(t, 0, m.updates, "a rejected root must not be written to the map at all")
}

func TestObserverFilter_SetRootPID_PropagatesMapError(t *testing.T) {
	m := newFakeObserverMap()
	m.updateErr = errors.New("boom")
	o := &ObserverFilterController{rootMap: m}

	err := o.SetRootPID(4242)
	require.Error(t, err, "a failed map write must be reported: main.go counts accepted controllers to decide whether the userspace fallback may be switched off")
	assert.Contains(t, err.Error(), "4242")
}

func TestObserverFilter_ClearRootPID_WritesSentinel(t *testing.T) {
	m := newFakeObserverMap()
	o := &ObserverFilterController{rootMap: m}

	require.NoError(t, o.SetRootPID(4242))
	require.NoError(t, o.ClearRootPID())
	assert.Equal(t, uint32(0), m.values["0"])
	assert.Equal(t, uint32(0), o.RootPID())
}

func TestObserverFilter_RootPID_UnreadableMapReadsZero(t *testing.T) {
	m := newFakeObserverMap()
	m.lookupErr = errors.New("nope")
	o := &ObserverFilterController{rootMap: m}

	assert.Equal(t, uint32(0), o.RootPID(),
		"an unreadable map must read as 'not configured', never as a stale root")
}

// ---------------------------------------------------------------------------
// ReadExcludedCount
// ---------------------------------------------------------------------------

func TestObserverFilter_ReadExcludedCount_SumsPerCPU(t *testing.T) {
	root := newFakeObserverMap()
	counters := newFakeObserverMap()
	counters.perCPU = []uint64{3, 0, 11, 7}
	o := &ObserverFilterController{rootMap: root, countMap: counters}

	total, err := o.ReadExcludedCount()
	require.NoError(t, err)
	assert.Equal(t, uint64(21), total, "the per-CPU array must be summed, not read from CPU 0 only")
}

// The counter is diagnostic: its absence must not look like an error, or a
// build without it would be reported as a broken filter.
func TestObserverFilter_ReadExcludedCount_NoCounterMap(t *testing.T) {
	o := &ObserverFilterController{rootMap: newFakeObserverMap()}

	total, err := o.ReadExcludedCount()
	require.NoError(t, err)
	assert.Equal(t, uint64(0), total)
}

func TestObserverFilter_ReadExcludedCount_PropagatesLookupError(t *testing.T) {
	counters := newFakeObserverMap()
	counters.lookupErr = errors.New("read failed")
	o := &ObserverFilterController{rootMap: newFakeObserverMap(), countMap: counters}

	_, err := o.ReadExcludedCount()
	require.Error(t, err, "a failed counter read must not be reported as zero exclusions — that reads as 'the filter dropped nothing'")
}
