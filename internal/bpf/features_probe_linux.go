//go:build linux

package bpf

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
)

// defaultHaveMapTypeRingBuf probes the running kernel for BPF ring buffer maps.
func defaultHaveMapTypeRingBuf() error { return features.HaveMapType(ebpf.RingBuf) }

// defaultHaveProgramTypeKprobe probes the running kernel for kprobe programs.
func defaultHaveProgramTypeKprobe() error { return features.HaveProgramType(ebpf.Kprobe) }

// defaultHaveProgramTypeTracepoint probes the running kernel for tracepoint programs.
func defaultHaveProgramTypeTracepoint() error { return features.HaveProgramType(ebpf.TracePoint) }
