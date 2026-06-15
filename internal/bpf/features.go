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
	// BTFSource records which BTF strategy succeeded during startup.
	// Set by ResolveBTF; empty until that call completes.
	BTFSource BTFSource
}

// DetectFeatures probes the kernel for eBPF feature support.
// Returns an error if the kernel doesn't meet minimum requirements.
func DetectFeatures() (*KernelFeatures, error) {
	f := &KernelFeatures{}

	// Detect BTF support: prefer cilium/ebpf probe, fall back to vmlinux file presence.
	if err := features.HaveMapType(ebpf.Hash); err == nil {
		// If BPF maps work at all, BTF may still be absent — check vmlinux directly.
		if _, statErr := os.Stat("/sys/kernel/btf/vmlinux"); statErr == nil {
			f.HasBTF = true
		}
	}
	// Also accept BTF when vmlinux is present even if the map probe fails (e.g. inside
	// some container runtimes that restrict bpf() syscall probing).
	if !f.HasBTF {
		if _, statErr := os.Stat("/sys/kernel/btf/vmlinux"); statErr == nil {
			f.HasBTF = true
		}
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
// the minimum requirements for ebpf-guard.
// When allowReducedFeatures is true the BTF check is skipped; callers must
// rely on BTFResult.DisabledCollectors to avoid loading BTF-dependent probes.
func (f *KernelFeatures) CheckMinimumRequirements(allowReducedFeatures bool) error {
	if !f.HasBTF && !allowReducedFeatures {
		return fmt.Errorf(
			"kernel BTF support required: compile kernel with CONFIG_DEBUG_INFO_BTF=y " +
				"or set bpf.fallback_reduced_features=true to start with reduced collectors",
		)
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
// CO-RE requires BTF to be available from any source (local, hub, or headers).
func (f *KernelFeatures) IsCOReSupported() bool {
	return f.HasBTF || (f.BTFSource != "" && f.BTFSource != BTFSourceNone)
}
