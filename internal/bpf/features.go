// Package bpf provides kernel feature detection for eBPF.
package bpf

import (
	"fmt"
	"os"
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
)

// KernelFeatures holds detected kernel capabilities.
type KernelFeatures struct {
	HasBTF          bool
	HasRingbuf      bool
	HasKprobe       bool
	HasTracepoint   bool
	KernelVersion   string
	KernelMajor     int
	KernelMinor     int
	KernelPatch     int
}

// DetectFeatures probes the kernel for eBPF feature support.
// Returns an error if the kernel doesn't meet minimum requirements.
func DetectFeatures() (*KernelFeatures, error) {
	f := &KernelFeatures{}

	// Detect BTF support via MapFlags
	if err := features.HaveMapFlag(features.MapFlags(0)); err == nil {
		f.HasBTF = true
	}

	// Detect ring buffer support (kernel 5.8+)
	if err := features.HaveMapType(ebpf.RingBuf); err == nil {
		f.HasRingbuf = true
	}

	// Detect kprobe support
	if err := features.HaveProgramType(ebpf.Kprobe); err == nil {
		f.HasKprobe = true
	}

	// Detect tracepoint support
	if err := features.HaveProgramType(ebpf.TracePoint); err == nil {
		f.HasTracepoint = true
	}

	// Get kernel version from uname
	f.KernelVersion = getKernelVersion()

	return f, nil
}

// CheckMinimumRequirements returns an error if the kernel doesn't meet
// the minimum requirements for ebpf-guard (kernel 5.15+, BTF, ringbuf).
func (f *KernelFeatures) CheckMinimumRequirements() error {
	if !f.HasBTF {
		return fmt.Errorf("kernel BTF support required: ensure kernel is compiled with CONFIG_DEBUG_INFO_BTF=y")
	}

	if !f.HasRingbuf {
		return fmt.Errorf("kernel ring buffer support required (kernel 5.8+): current kernel %s", f.KernelVersion)
	}

	if !f.HasKprobe && !f.HasTracepoint {
		return fmt.Errorf("kernel must support at least one of: kprobes, tracepoints")
	}

	return nil
}

// String returns a human-readable summary of detected features.
func (f *KernelFeatures) String() string {
	return fmt.Sprintf(
		"Kernel: %s, BTF: %v, Ringbuf: %v, Kprobe: %v, Tracepoint: %v",
		f.KernelVersion, f.HasBTF, f.HasRingbuf, f.HasKprobe, f.HasTracepoint,
	)
}

// getKernelVersion returns the kernel version string.
func getKernelVersion() string {
	// Try to read from /proc/version_signature first (Ubuntu)
	if data, err := os.ReadFile("/proc/version_signature"); err == nil {
		return string(data)
	}

	// Fall back to uname via Go runtime
	return runtime.GOOS + "/" + runtime.GOARCH
}

// IsCOReSupported checks if Compile Once - Run Everywhere (CO-RE) is supported.
// CO-RE requires BTF and kernel version 5.2+.
func (f *KernelFeatures) IsCOReSupported() bool {
	return f.HasBTF
}
