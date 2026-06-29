// Package bpf provides kernel feature detection for eBPF.
package bpf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
)

// KernelFeatures holds detected kernel capabilities.
type KernelFeatures struct {
	HasBTF         bool
	HasRingbuf     bool
	HasKprobe      bool
	HasTracepoint  bool
	HasBatchMapOps bool // BPF_MAP_LOOKUP_BATCH / UPDATE_BATCH syscalls (kernel 5.6+)
	KernelVersion  string
	KernelMajor    int
	KernelMinor    int
	KernelPatch    int
	// BTFSource records which BTF strategy succeeded during startup.
	// Set by ResolveBTF; empty until that call completes.
	BTFSource BTFSource
}

// DetectFeatures probes the kernel for eBPF feature support.
// Returns an error if the kernel doesn't meet minimum requirements.
func DetectFeatures() (*KernelFeatures, error) {
	return detectFeaturesWithProber(realFeatureProber{})
}

// haveMapTypeRingBuf delegates to the cilium/ebpf features probe.
// Indirected through a package-level var so tests on non-BPF hosts can stub it.
var haveMapTypeRingBuf = func() error { return features.HaveMapType(ebpf.RingBuf) }

// haveProgramTypeKprobe delegates to the cilium/ebpf features probe.
var haveProgramTypeKprobe = func() error { return features.HaveProgramType(ebpf.Kprobe) }

// haveProgramTypeTracepoint delegates to the cilium/ebpf features probe.
var haveProgramTypeTracepoint = func() error { return features.HaveProgramType(ebpf.TracePoint) }

// haveBatchMapOps reports whether the kernel supports BPF batch map operations.
// Kernel 5.6+ added BPF_MAP_LOOKUP_BATCH and BPF_MAP_UPDATE_BATCH.
// Declared as a function var so tests can stub it without a real kernel.
var haveBatchMapOps = func(major, minor int) bool {
	return major > 5 || (major == 5 && minor >= 6)
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
		"Kernel: %s, BTF: %v, Ringbuf: %v, Kprobe: %v, Tracepoint: %v, BatchMapOps: %v",
		f.KernelVersion, f.HasBTF, f.HasRingbuf, f.HasKprobe, f.HasTracepoint, f.HasBatchMapOps,
	)
}

// IsCOReSupported checks if Compile Once - Run Everywhere (CO-RE) is supported.
// CO-RE requires BTF to be available from any source (local, hub, or headers).
func (f *KernelFeatures) IsCOReSupported() bool {
	return f.HasBTF || (f.BTFSource != "" && f.BTFSource != BTFSourceNone)
}
