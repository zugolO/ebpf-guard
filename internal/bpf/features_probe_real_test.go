package bpf

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRealFeatureProber_FileExists exercises the production FeatureProber
// (backed by the OS) rather than the fake used elsewhere, so the real
// os.Stat-backed implementation is covered.
func TestRealFeatureProber_FileExists(t *testing.T) {
	p := realFeatureProber{}

	dir := t.TempDir()
	present := filepath.Join(dir, "present")
	require.NoError(t, os.WriteFile(present, []byte("x"), 0o600))

	assert.True(t, p.FileExists(present), "existing file must report present")
	assert.False(t, p.FileExists(filepath.Join(dir, "absent")), "missing file must report absent")
}

// TestRealFeatureProber_ReadFile covers both the success and error paths of the
// production ReadFile implementation.
func TestRealFeatureProber_ReadFile(t *testing.T) {
	p := realFeatureProber{}

	dir := t.TempDir()
	path := filepath.Join(dir, "data")
	want := []byte("hello-kernel")
	require.NoError(t, os.WriteFile(path, want, 0o600))

	got, err := p.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, want, got)

	_, err = p.ReadFile(filepath.Join(dir, "nope"))
	assert.Error(t, err, "reading a missing file must return an error")
}
