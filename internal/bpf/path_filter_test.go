package bpf

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// pathLPMKey
// ---------------------------------------------------------------------------

func TestPathLPMKey(t *testing.T) {
	k := pathLPMKey("/var/log/")
	assert.Equal(t, uint32(len("/var/log/"))*8, k.PrefixLen)
	assert.Equal(t, "/var/log/", string(k.Path[:len("/var/log/")]))
	// Remainder must be zero-padded.
	for i := len("/var/log/"); i < PathFilterPrefixLen; i++ {
		assert.Zerof(t, k.Path[i], "byte %d should be zero-padded", i)
	}
}

func TestPathLPMKey_TruncatesOverlongPrefix(t *testing.T) {
	long := make([]byte, PathFilterPrefixLen+50)
	for i := range long {
		long[i] = 'a'
	}
	k := pathLPMKey(string(long))
	assert.Equal(t, uint32(PathFilterPrefixLen)*8, k.PrefixLen,
		"prefixlen must be capped at PathFilterPrefixLen bytes, not the input length")
}

func TestPathLPMKey_Empty(t *testing.T) {
	k := pathLPMKey("")
	assert.Equal(t, uint32(0), k.PrefixLen)
}

// ---------------------------------------------------------------------------
// NewPathFilterController
// ---------------------------------------------------------------------------

func TestNewPathFilterController_NilPathMap(t *testing.T) {
	_, err := NewPathFilterController(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "path_filter_map")
}

// ---------------------------------------------------------------------------
// SetDenylist
// ---------------------------------------------------------------------------

func TestSetDenylist_EmptyPrefixRejected(t *testing.T) {
	m := newFakeMap()
	pf := &PathFilterController{pathMap: m}

	err := pf.SetDenylist([]string{"/var/log/", ""})
	require.Error(t, err, "an empty prefix would deny every path and must be refused")
	assert.Equal(t, 0, m.size(), "no entries should be written when the batch is rejected")
}

func TestSetDenylist_InsertsPrefixes(t *testing.T) {
	m := newFakeMap()
	pf := &PathFilterController{pathMap: m}

	require.NoError(t, pf.SetDenylist([]string{"/var/log/", "/tmp/noisy/"}))
	assert.Equal(t, 2, m.size())
}

func TestSetDenylist_HotReload_RemovesStale(t *testing.T) {
	m := newFakeMap()
	pf := &PathFilterController{pathMap: m}

	require.NoError(t, pf.SetDenylist([]string{"/var/log/", "/tmp/noisy/"}))
	assert.Equal(t, 2, m.size())

	// Second call drops "/tmp/noisy/" and adds "/var/cache/".
	require.NoError(t, pf.SetDenylist([]string{"/var/log/", "/var/cache/"}))
	assert.Equal(t, 2, m.size())
}

func TestSetDenylist_EmptyListClearsAll(t *testing.T) {
	m := newFakeMap()
	pf := &PathFilterController{pathMap: m}

	require.NoError(t, pf.SetDenylist([]string{"/var/log/"}))
	assert.Equal(t, 1, m.size())

	require.NoError(t, pf.SetDenylist(nil))
	assert.Equal(t, 0, m.size())
}

func TestSetDenylist_UpdateError(t *testing.T) {
	m := newFakeMap()
	m.callErr = errors.New("update failed")
	pf := &PathFilterController{pathMap: m}

	err := pf.SetDenylist([]string{"/var/log/"})
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// AddPrefix / RemovePrefix
// ---------------------------------------------------------------------------

func TestAddPrefix_EmptyRejected(t *testing.T) {
	pf := &PathFilterController{pathMap: newFakeMap()}
	require.Error(t, pf.AddPrefix(""))
}

func TestAddPrefix_RemovePrefix(t *testing.T) {
	m := newFakeMap()
	pf := &PathFilterController{pathMap: m}

	require.NoError(t, pf.AddPrefix("/var/log/"))
	assert.Equal(t, 1, m.size())

	require.NoError(t, pf.RemovePrefix("/var/log/"))
	assert.Equal(t, 0, m.size())
}

func TestRemovePrefix_NotFoundIsNotAnError(t *testing.T) {
	pf := &PathFilterController{pathMap: newFakeMap()}
	require.NoError(t, pf.RemovePrefix("/never/added/"))
}

// ---------------------------------------------------------------------------
// ReadPathFilterDropCount
// ---------------------------------------------------------------------------

func TestReadPathFilterDropCount_NilCountersMap(t *testing.T) {
	pf := &PathFilterController{pathMap: newFakeMap()}

	total, err := pf.ReadPathFilterDropCount()
	require.NoError(t, err)
	assert.Equal(t, uint64(0), total)
}

func TestReadPathFilterDropCount_SumsPerCPU(t *testing.T) {
	counters := &fakeMap{perCPU: []uint64{5, 10, 15}}
	pf := &PathFilterController{pathMap: newFakeMap(), countMap: counters}

	total, err := pf.ReadPathFilterDropCount()
	require.NoError(t, err)
	assert.Equal(t, uint64(30), total)
}

func TestReadPathFilterDropCount_LookupError(t *testing.T) {
	counters := &fakeMap{lookupErr: errors.New("lookup failed")}
	pf := &PathFilterController{pathMap: newFakeMap(), countMap: counters}

	_, err := pf.ReadPathFilterDropCount()
	require.Error(t, err)
}
