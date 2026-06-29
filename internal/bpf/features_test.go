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

// ---------------------------------------------------------------------------
// parseKernelVersion
// ---------------------------------------------------------------------------

func TestParseKernelVersion(t *testing.T) {
	cases := []struct {
		input string
		major int
		minor int
		patch int
	}{
		{"5.15.0-100-generic", 5, 15, 0},
		{"Ubuntu 5.15.0-100-generic #110-Ubuntu SMP", 5, 15, 0},
		{"Debian 5.10.0-21-amd64 #1 SMP", 5, 10, 0},
		{"6.1.0", 6, 1, 0},
		{"5.6.19", 5, 6, 19},
		{"4.14.0", 4, 14, 0},
		{"linux/amd64", 0, 0, 0},     // fallback string — no version
		{"", 0, 0, 0},                // empty string
		{"5.6", 5, 6, 0},             // no patch component
	}
	for _, tc := range cases {
		major, minor, patch := parseKernelVersion(tc.input)
		assert.Equal(t, tc.major, major, "major for %q", tc.input)
		assert.Equal(t, tc.minor, minor, "minor for %q", tc.input)
		assert.Equal(t, tc.patch, patch, "patch for %q", tc.input)
	}
}

// ---------------------------------------------------------------------------
// HasBatchMapOps detection
// ---------------------------------------------------------------------------

func TestDetectFeatures_HasBatchMapOps_Via_OSRelease(t *testing.T) {
	// When /proc/sys/kernel/osrelease reports kernel 5.6+, HasBatchMapOps = true.
	cases := []struct {
		osrelease string
		want      bool
	}{
		{"5.6.0-generic", true},
		{"5.15.0-100-generic", true},
		{"6.1.0", true},
		{"5.5.0", false},
		{"4.19.0", false},
		{"5.6.19", true},
	}

	origFn := haveBatchMapOps
	t.Cleanup(func() { haveBatchMapOps = origFn })

	for _, tc := range cases {
		t.Run(tc.osrelease, func(t *testing.T) {
			prober := &fakeProber{
				files: map[string][]byte{
					"/proc/sys/kernel/osrelease":  []byte(tc.osrelease),
					"/proc/version_signature":     []byte("Ubuntu " + tc.osrelease),
				},
			}
			f, err := detectFeaturesWithProber(prober)
			require.NoError(t, err)
			assert.Equal(t, tc.want, f.HasBatchMapOps, "osrelease=%q", tc.osrelease)
		})
	}
}

func TestDetectFeatures_HasBatchMapOps_Stubbed(t *testing.T) {
	// Replace haveBatchMapOps to force both outcomes regardless of host kernel.
	origFn := haveBatchMapOps
	t.Cleanup(func() { haveBatchMapOps = origFn })

	prober := &fakeProber{
		files: map[string][]byte{
			"/proc/version_signature": []byte("5.15.0"),
		},
	}

	haveBatchMapOps = func(_, _ int) bool { return true }
	f, err := detectFeaturesWithProber(prober)
	require.NoError(t, err)
	assert.True(t, f.HasBatchMapOps)

	haveBatchMapOps = func(_, _ int) bool { return false }
	f, err = detectFeaturesWithProber(prober)
	require.NoError(t, err)
	assert.False(t, f.HasBatchMapOps)
}

func TestKernelFeatures_String_IncludesBatchMapOps(t *testing.T) {
	f := &KernelFeatures{
		KernelVersion:  "5.15.0",
		HasBTF:         true,
		HasRingbuf:     true,
		HasBatchMapOps: true,
	}
	s := f.String()
	assert.Contains(t, s, "BatchMapOps: true")
}
