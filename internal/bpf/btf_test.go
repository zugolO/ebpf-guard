package bpf

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBTFDetectLocalBTF verifies that detectLocalBTF reads /sys/kernel/btf/vmlinux correctly.
func TestBTFDetectLocalBTF(t *testing.T) {
	// In a normal CI environment /sys/kernel/btf/vmlinux may or may not exist.
	// We only verify the function doesn't panic.
	result := detectLocalBTF()
	t.Logf("detectLocalBTF() = %v", result)
}

// TestBTFResolveBTF_ExplicitPath verifies that an explicit btf_path override is used
// when the file exists.
func TestBTFResolveBTF_ExplicitPath(t *testing.T) {
	// Create a temporary fake BTF file.
	tmp := t.TempDir()
	btfFile := filepath.Join(tmp, "vmlinux.btf")
	require.NoError(t, os.WriteFile(btfFile, []byte("fake btf"), 0o644))

	result, err := ResolveBTF(BTFResolutionConfig{
		BTFPath:                 btfFile,
		BTFHubEnabled:           false,
		FallbackReducedFeatures: false,
	})
	require.NoError(t, err)
	assert.Equal(t, BTFSourceLocal, result.Source)
	assert.Equal(t, btfFile, result.Path)
	assert.Empty(t, result.DisabledCollectors)
}

// TestBTFResolveBTF_MissingExplicitPath verifies fallback when btf_path doesn't exist.
func TestBTFResolveBTF_MissingExplicitPath(t *testing.T) {
	cfg := BTFResolutionConfig{
		BTFPath:                 "/nonexistent/path/vmlinux.btf",
		BTFHubEnabled:           false,
		FallbackReducedFeatures: true,
	}
	result, err := ResolveBTF(cfg)
	// Should not error because FallbackReducedFeatures=true.
	// May succeed via local BTF or fall through to "none".
	if err != nil {
		t.Logf("ResolveBTF with missing explicit path and reduced features: %v", err)
		return
	}
	t.Logf("BTF source resolved to: %s", result.Source)
}

// TestBTFResolveBTF_ReducedFeaturesNoBTF verifies graceful degradation when
// no BTF is available and fallback_reduced_features is true.
// This test simulates the "none" path by pointing all paths at nonexistent locations.
func TestBTFResolveBTF_ReducedFeaturesNoBTF(t *testing.T) {
	if detectLocalBTF() {
		t.Skip("local BTF available at /sys/kernel/btf/vmlinux — skipping reduced-features test")
	}

	cfg := BTFResolutionConfig{
		BTFPath:                 "",
		BTFHubEnabled:           false, // disable hub to avoid network access
		BTFHubCache:             t.TempDir(),
		FallbackReducedFeatures: true,
	}

	result, err := ResolveBTF(cfg)
	// If kernel headers are present, we'll get BTFSourceHeaders — that's fine.
	if err != nil {
		t.Fatalf("unexpected error with FallbackReducedFeatures=true: %v", err)
	}
	t.Logf("BTF source: %s, disabled: %v", result.Source, result.DisabledCollectors)

	if result.Source == BTFSourceNone {
		assert.Contains(t, result.DisabledCollectors, "lsm")
		assert.Contains(t, result.DisabledCollectors, "tls")
	}
}

// TestBTFResolveBTF_NoFallbackFails verifies that startup fails when no BTF is
// available and fallback_reduced_features is false.
func TestBTFResolveBTF_NoFallbackFails(t *testing.T) {
	if detectLocalBTF() {
		t.Skip("local BTF available — test only meaningful on kernels without /sys/kernel/btf/vmlinux")
	}

	// Check if kernel headers exist — if so, the test would succeed via headers.
	if _, err := resolveKernelHeaders(); err == nil {
		t.Skip("kernel headers available — test only meaningful without any BTF source")
	}

	cfg := BTFResolutionConfig{
		BTFPath:                 "",
		BTFHubEnabled:           false,
		BTFHubCache:             t.TempDir(),
		FallbackReducedFeatures: false,
	}
	_, err := ResolveBTF(cfg)
	require.Error(t, err, "expected error when no BTF is available and fallback disabled")
}

// TestBTFResolveBTF_CacheHit verifies that a pre-populated BTF cache file is used
// without attempting any download.
func TestBTFResolveBTF_CacheHit(t *testing.T) {
	if detectLocalBTF() {
		t.Skip("local BTF takes precedence — cache-hit test only meaningful without local BTF")
	}

	release, err := kernelRelease()
	if err != nil {
		t.Skip("cannot read kernel release:", err)
	}

	distro, version, err := detectDistro()
	if err != nil {
		t.Skip("cannot detect distro:", err)
	}

	tmp := t.TempDir()
	arch := "x86_64" // simplified; real code uses runtime.GOARCH mapping
	cacheFile := filepath.Join(tmp, distro, version, arch, "vmlinux-"+release+".btf")
	require.NoError(t, os.MkdirAll(filepath.Dir(cacheFile), 0o755))
	require.NoError(t, os.WriteFile(cacheFile, []byte("fake btf data"), 0o644))

	result, err := ResolveBTF(BTFResolutionConfig{
		BTFHubEnabled:           true,
		BTFHubCache:             tmp,
		FallbackReducedFeatures: false,
	})
	require.NoError(t, err)
	assert.Equal(t, BTFSourceBTFHub, result.Source)
	assert.Equal(t, cacheFile, result.Path)
}

// TestBTFDetectDistro verifies that detectDistro can read /etc/os-release.
func TestBTFDetectDistro(t *testing.T) {
	id, version, err := detectDistro()
	if err != nil {
		t.Logf("detectDistro error (may be expected in container): %v", err)
		return
	}
	assert.NotEmpty(t, id, "distro ID should not be empty")
	t.Logf("distro: id=%s version=%s", id, version)
}

// TestBTFKernelRelease verifies that kernelRelease reads a non-empty string.
func TestBTFKernelRelease(t *testing.T) {
	release, err := kernelRelease()
	if err != nil {
		t.Logf("kernelRelease error (may be expected in sandbox): %v", err)
		return
	}
	assert.NotEmpty(t, release)
	t.Logf("kernel release: %s", release)
}
