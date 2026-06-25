package bpf

import (
	"os"
	"runtime"
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

	return f, nil
}
