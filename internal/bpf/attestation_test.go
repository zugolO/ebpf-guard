package bpf

import (
	"errors"
	"sync"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	tag1 = "0102030405060708"
	tag2 = "aabbccddeeff0011"
)

func TestAttestationViolation_Error(t *testing.T) {
	v := AttestationViolation{
		Program:     "test_prog",
		ExpectedTag: tag1,
		ActualTag:   tag2,
	}
	msg := v.Error()
	assert.Contains(t, msg, "test_prog")
	assert.Contains(t, msg, tag1)
	assert.Contains(t, msg, tag2)
}

func TestIsAttestationViolation(t *testing.T) {
	v := AttestationViolation{Program: "prog"}
	assert.True(t, IsAttestationViolation(v))
	assert.False(t, IsAttestationViolation(errors.New("other error")))
}

func TestAttestor_NilProgram_Noop(t *testing.T) {
	a := NewAttestor()
	err := a.VerifyProgram("prog", nil)
	assert.NoError(t, err)
	assert.Equal(t, 0, a.RecordedCount())
}

func TestAttestor_VerifyAll_NilOrEmptyMap(t *testing.T) {
	a := NewAttestor()
	assert.NoError(t, a.VerifyAll(nil))
	assert.NoError(t, a.VerifyAll(map[string]*ebpf.Program{}))
	assert.NoError(t, a.VerifyAll(map[string]*ebpf.Program{"p": nil}))
	assert.Equal(t, 0, a.RecordedCount())
}

func TestAttestor_VerifyTag_FirstCallRecords(t *testing.T) {
	a := NewAttestor()

	err := a.verifyTag("prog", tag1)
	require.NoError(t, err)
	assert.Equal(t, 1, a.RecordedCount())

	// Same tag again — no violation.
	err = a.verifyTag("prog", tag1)
	require.NoError(t, err)
	assert.Equal(t, 1, a.RecordedCount())
}

func TestAttestor_VerifyTag_TagChange_Violation(t *testing.T) {
	a := NewAttestor()

	// Record initial tag.
	require.NoError(t, a.verifyTag("prog", tag1))

	// Tag changes → violation.
	err := a.verifyTag("prog", tag2)
	require.Error(t, err)

	var v AttestationViolation
	require.True(t, errors.As(err, &v))
	assert.Equal(t, "prog", v.Program)
	assert.Equal(t, tag1, v.ExpectedTag)
	assert.Equal(t, tag2, v.ActualTag)
}

func TestAttestor_MultiplePrograms_IndependentBaselines(t *testing.T) {
	a := NewAttestor()

	// Two programs with different initial tags.
	require.NoError(t, a.verifyTag("prog_a", tag1))
	require.NoError(t, a.verifyTag("prog_b", tag2))
	assert.Equal(t, 2, a.RecordedCount())

	// Consistent re-checks — no violations.
	assert.NoError(t, a.verifyTag("prog_a", tag1))
	assert.NoError(t, a.verifyTag("prog_b", tag2))

	// Cross-check — violation for prog_a if it now reports prog_b's tag.
	err := a.verifyTag("prog_a", tag2)
	require.Error(t, err)
	var v AttestationViolation
	require.True(t, errors.As(err, &v))
	assert.Equal(t, "prog_a", v.Program)
	assert.Equal(t, tag1, v.ExpectedTag)
	assert.Equal(t, tag2, v.ActualTag)
}

func TestAttestor_VerifyAll_NilProgramsSkipped(t *testing.T) {
	a := NewAttestor()

	// Record a tag for one program.
	require.NoError(t, a.verifyTag("prog", tag1))

	// VerifyAll with nil programs → all skipped, no violation.
	err := a.VerifyAll(map[string]*ebpf.Program{"prog": nil})
	assert.NoError(t, err, "nil program entries must not trigger violations")
}

func TestAttestor_ConcurrentVerifyTag(t *testing.T) {
	a := NewAttestor()

	// Seed the tag first so concurrent calls go through the comparison path.
	require.NoError(t, a.verifyTag("prog", tag1))

	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = a.verifyTag("prog", tag1)
		}()
	}
	wg.Wait()
	assert.Equal(t, 1, a.RecordedCount())
}
