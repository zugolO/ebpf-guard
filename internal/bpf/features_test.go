package bpf

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeProber is a test double for FeatureProber.
type fakeProber struct {
	files map[string][]byte // path → content (nil entry means file absent)
}

func (f *fakeProber) FileExists(path string) bool {
	data, ok := f.files[path]
	return ok && data != nil
}

func (f *fakeProber) ReadFile(path string) ([]byte, error) {
	data, ok := f.files[path]
	if !ok || data == nil {
		return nil, fmt.Errorf("fakeProber: no file at %s", path)
	}
	return data, nil
}

func TestDetectFeatures_BTFAvailable(t *testing.T) {
	prober := &fakeProber{
		files: map[string][]byte{
			"/sys/kernel/btf/vmlinux": []byte("fake-btf"),
			"/proc/version_signature": []byte("Ubuntu 5.15.0-generic"),
		},
	}

	f, err := detectFeaturesWithProber(prober)
	require.NoError(t, err)
	assert.True(t, f.HasBTF, "expected HasBTF=true when vmlinux file is present")
	assert.Equal(t, "Ubuntu 5.15.0-generic", f.KernelVersion)
}

func TestDetectFeatures_BTFUnavailable(t *testing.T) {
	prober := &fakeProber{
		// vmlinux absent — do NOT add it to the map
		files: map[string][]byte{
			"/proc/version_signature": []byte("4.14.0"),
		},
	}

	f, err := detectFeaturesWithProber(prober)
	require.NoError(t, err)
	assert.False(t, f.HasBTF, "expected HasBTF=false when vmlinux file is absent")
}

func TestDetectFeatures_UnprivilegedBPF(t *testing.T) {
	cases := []struct {
		sig         string
		wantVersion string
	}{
		{"Ubuntu 5.15.0-100-generic #110-Ubuntu SMP", "Ubuntu 5.15.0-100-generic #110-Ubuntu SMP"},
		{"Debian 5.10.0-21-amd64 #1 SMP", "Debian 5.10.0-21-amd64 #1 SMP"},
	}

	for _, tc := range cases {
		prober := &fakeProber{
			files: map[string][]byte{
				"/proc/version_signature": []byte(tc.sig),
			},
		}
		f, err := detectFeaturesWithProber(prober)
		require.NoError(t, err)
		assert.Equal(t, tc.wantVersion, f.KernelVersion)
	}
}

func TestDetectFeatures_VersionSignatureAbsent(t *testing.T) {
	// When /proc/version_signature is absent the prober should fall back to
	// GOOS/GOARCH — exercising the ReadFile error path.
	prober := &fakeProber{
		files: map[string][]byte{},
	}

	f, err := detectFeaturesWithProber(prober)
	require.NoError(t, err)
	// Fall-back is runtime.GOOS + "/" + runtime.GOARCH.
	assert.Equal(t, runtime.GOOS+"/"+runtime.GOARCH, f.KernelVersion)
}
