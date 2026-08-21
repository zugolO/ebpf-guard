package bpf

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSumPerCPUUint64_Sums(t *testing.T) {
	m := &fakeMap{perCPU: []uint64{1, 2, 3, 4}}

	total, err := SumPerCPUUint64(m)
	require.NoError(t, err)
	assert.Equal(t, uint64(10), total)
}

func TestSumPerCPUUint64_Zero(t *testing.T) {
	m := &fakeMap{perCPU: []uint64{0, 0, 0}}

	total, err := SumPerCPUUint64(m)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), total)
}

func TestSumPerCPUUint64_LookupError(t *testing.T) {
	m := &fakeMap{lookupErr: errors.New("lookup failed")}

	_, err := SumPerCPUUint64(m)
	require.Error(t, err)
}
