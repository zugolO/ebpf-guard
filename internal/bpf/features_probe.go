package bpf

import (
	"os"
	"regexp"
	"runtime"
	"strconv"
)

// FeatureProber abstracts OS operations used during kernel feature detection.
// Separating these into an interface makes DetectFeatures fully unit-testable
// without a real kernel or filesystem.
type FeatureProber interface {
	// FileExists reports whether the file at path exists and is reachable.
	FileExists(path string) bool
	// ReadFile reads and returns the full contents of the file at path.
	ReadFile(path string) ([]byte, error)
}

// realFeatureProber is the production implementation backed by the OS.
type realFeatureProber struct{}

func (realFeatureProber) FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (realFeatureProber) ReadFile(path string) ([]byte, error) {
	// #nosec G304 -- path is an internal constant (e.g. /proc, /sys), never user input
	return os.ReadFile(path)
}

// detectFeaturesWithProber is the testable core of DetectFeatures; it accepts a
// FeatureProber so that file-system calls can be replaced by fakes in unit
// tests.
func detectFeaturesWithProber(prober FeatureProber) (*KernelFeatures, error) {
	f := &KernelFeatures{}

	// Detect BTF support: prefer cilium/ebpf probe, fall back to vmlinux file
	// presence.  We use prober.FileExists so tests can control the outcome
	// without a real /sys filesystem.
	const vmlinuxPath = "/sys/kernel/btf/vmlinux"
	if prober.FileExists(vmlinuxPath) {
		f.HasBTF = true
	}

	// Detect ring buffer support (kernel 5.8+).
	// This still uses the real cilium/ebpf feature probe; the prober does not
	// abstract kernel bpf() syscall probing.
	if err := haveMapTypeRingBuf(); err == nil {
		f.HasRingbuf = true
	}

	// Detect kprobe support.
	if err := haveProgramTypeKprobe(); err == nil {
		f.HasKprobe = true
	}

	// Detect tracepoint support.
	if err := haveProgramTypeTracepoint(); err == nil {
		f.HasTracepoint = true
	}

	// Read kernel version via the prober so tests can inject a fake value.
	if data, err := prober.ReadFile("/proc/version_signature"); err == nil {
		f.KernelVersion = string(data)
	} else {
		f.KernelVersion = runtime.GOOS + "/" + runtime.GOARCH
	}

	// /proc/sys/kernel/osrelease gives a clean "major.minor.patch-extra" string
	// and is preferred for version number parsing.  Fall back to version_signature.
	if data, err := prober.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		f.KernelMajor, f.KernelMinor, f.KernelPatch = parseKernelVersion(string(data))
	} else {
		f.KernelMajor, f.KernelMinor, f.KernelPatch = parseKernelVersion(f.KernelVersion)
	}
	f.HasBatchMapOps = haveBatchMapOps(f.KernelMajor, f.KernelMinor)

	return f, nil
}

// kernelVersionRE matches the first "major.minor[.patch]" triplet in a string.
var kernelVersionRE = regexp.MustCompile(`(\d+)\.(\d+)(?:\.(\d+))?`)

// parseKernelVersion extracts (major, minor, patch) from a kernel version string
// such as "5.15.0-100-generic" or "Ubuntu 5.15.0 #110".
func parseKernelVersion(s string) (major, minor, patch int) {
	m := kernelVersionRE.FindStringSubmatch(s)
	if len(m) < 3 {
		return 0, 0, 0
	}
	major, _ = strconv.Atoi(m[1])
	minor, _ = strconv.Atoi(m[2])
	if len(m) >= 4 && m[3] != "" {
		patch, _ = strconv.Atoi(m[3])
	}
	return
}
