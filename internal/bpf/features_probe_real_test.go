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

// TestDetectFeatures_KernelProbesSupported covers the err==nil branches of
// detectFeaturesWithProber (HasRingbuf/HasKprobe/HasTracepoint = true). The
// kernel capability probes are package-level function variables, so we stub
// them to report support without needing a privileged kernel. On CI runners the
// real probes return errors, leaving these assignment lines otherwise
// unexercised.
func TestDetectFeatures_KernelProbesSupported(t *testing.T) {
	restore := func(rb, kp, tp func() error) {
		haveMapTypeRingBuf = rb
		haveProgramTypeKprobe = kp
		haveProgramTypeTracepoint = tp
	}
	defer restore(haveMapTypeRingBuf, haveProgramTypeKprobe, haveProgramTypeTracepoint)

	haveMapTypeRingBuf = func() error { return nil }
	haveProgramTypeKprobe = func() error { return nil }
	haveProgramTypeTracepoint = func() error { return nil }

	prober := &fakeProber{
		files: map[string][]byte{
			"/sys/kernel/btf/vmlinux": []byte("fake-btf"),
			"/proc/version_signature": []byte("Ubuntu 5.15.0-generic"),
		},
	}

	f, err := detectFeaturesWithProber(prober)
	require.NoError(t, err)
	assert.True(t, f.HasRingbuf, "HasRingbuf must be true when the ringbuf probe succeeds")
	assert.True(t, f.HasKprobe, "HasKprobe must be true when the kprobe probe succeeds")
	assert.True(t, f.HasTracepoint, "HasTracepoint must be true when the tracepoint probe succeeds")
}

// TestDetectFeatures_KernelProbesUnsupported covers the err!=nil branches: when
// every capability probe fails, the corresponding feature flags stay false.
func TestDetectFeatures_KernelProbesUnsupported(t *testing.T) {
	restore := func(rb, kp, tp func() error) {
		haveMapTypeRingBuf = rb
		haveProgramTypeKprobe = kp
		haveProgramTypeTracepoint = tp
	}
	defer restore(haveMapTypeRingBuf, haveProgramTypeKprobe, haveProgramTypeTracepoint)

	probeErr := func() error { return assert.AnError }
	haveMapTypeRingBuf = probeErr
	haveProgramTypeKprobe = probeErr
	haveProgramTypeTracepoint = probeErr

	f, err := detectFeaturesWithProber(&fakeProber{files: map[string][]byte{}})
	require.NoError(t, err)
	assert.False(t, f.HasRingbuf)
	assert.False(t, f.HasKprobe)
	assert.False(t, f.HasTracepoint)
}
