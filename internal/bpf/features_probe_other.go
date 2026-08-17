//go:build !linux

package bpf

import (
	"errors"
	"runtime"
)

// errNoBPFPlatform reports that eBPF feature probing is meaningless here: there
// is no bpf(2) syscall outside Linux.
//
// This is deliberately NOT a call into cilium/ebpf. That package's probes go
// straight to the syscall and, on darwin, panic in maskProfilerSignal
// ("unsupported platform darwin/arm64") — a panic, not an error, so it takes
// the entire test binary down with it. Returning an error keeps
// detectFeaturesWithProber usable on a developer's macOS machine, where the
// feature-detection logic itself is still worth unit-testing.
var errNoBPFPlatform = errors.New("bpf: kernel feature probing unsupported on " + runtime.GOOS + " (Linux only)")

// defaultHaveMapTypeRingBuf always reports ring buffer maps as unavailable.
func defaultHaveMapTypeRingBuf() error { return errNoBPFPlatform }

// defaultHaveProgramTypeKprobe always reports kprobe programs as unavailable.
func defaultHaveProgramTypeKprobe() error { return errNoBPFPlatform }

// defaultHaveProgramTypeTracepoint always reports tracepoint programs as unavailable.
func defaultHaveProgramTypeTracepoint() error { return errNoBPFPlatform }
