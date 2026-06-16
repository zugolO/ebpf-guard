// Package bpf contains go:generate directives to compile BPF C programs into
// Go bindings using bpf2go.
//
// Prerequisites:
//   - clang 14+ with BPF target support
//   - Linux kernel headers (linux-headers-$(uname -r) or linux-libc-dev)
//   - libbpf development headers (libbpf-dev)
//   - bpf2go tool: go install github.com/cilium/ebpf/cmd/bpf2go@latest
//   - bpf/vmlinux.h generated via: bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
//
// Run with:
//
//	make generate
//	# or directly:
//	go generate ./internal/bpf/...
//
// Output files (per BPF program, two variants for endianness):
//
//	syscall_bpfel.go / syscall_bpfeb.go
//	network_bpfel.go / network_bpfeb.go
//	fileaccess_bpfel.go / fileaccess_bpfeb.go
//	... etc.
//
// After generation, delete syscall_bpf_gen.go (the stub file) — the generated
// files provide the real XxxObjects types and LoadXxx functions.

package bpf

// Common cflags shared across all BPF programs:
//   -O2            optimise for BPF verifier
//   -g             emit BTF debug info (required for CO-RE)
//   -Wall          surface all warnings
//   -I../../bpf    find common.h and vmlinux.h
//   -I/usr/include system headers (bpf/bpf_helpers.h etc.)

//go:generate /root/go/bin/bpf2go -cc clang -target amd64 -cflags "-O2 -g -Wall -I/usr/include -I../../bpf" Syscall ../../bpf/syscall.bpf.c
//go:generate /root/go/bin/bpf2go -cc clang -target amd64 -cflags "-O2 -g -Wall -I/usr/include -I../../bpf" Network ../../bpf/network.bpf.c
//go:generate /root/go/bin/bpf2go -cc clang -target amd64 -cflags "-O2 -g -Wall -I/usr/include -I../../bpf" Fileaccess ../../bpf/fileaccess.bpf.c
//go:generate /root/go/bin/bpf2go -cc clang -target amd64 -cflags "-O2 -g -Wall -I/usr/include -I../../bpf" Privesc ../../bpf/privesc.bpf.c
//go:generate /root/go/bin/bpf2go -cc clang -target amd64 -cflags "-O2 -g -Wall -I/usr/include -I../../bpf" DNS ../../bpf/dns.bpf.c
//go:generate /root/go/bin/bpf2go -cc clang -target amd64 -cflags "-O2 -g -Wall -I/usr/include -I../../bpf" Iouring ../../bpf/iouring.bpf.c
//go:generate /root/go/bin/bpf2go -cc clang -target amd64 -cflags "-O2 -g -Wall -I/usr/include -I../../bpf" BpfMonitor ../../bpf/bpf_monitor.bpf.c
//go:generate /root/go/bin/bpf2go -cc clang -target amd64 -cflags "-O2 -g -Wall -I/usr/include -I../../bpf" Kmod ../../bpf/lsm.bpf.c
//go:generate /root/go/bin/bpf2go -cc clang -target amd64 -cflags "-O2 -g -Wall -I/usr/include -I../../bpf" Cgroup ../../bpf/cgroup.bpf.c
//go:generate /root/go/bin/bpf2go -cc clang -target amd64 -cflags "-O2 -g -Wall -I/usr/include -I../../bpf" HiddenProcess ../../bpf/hidden_process.bpf.c
//go:generate /root/go/bin/bpf2go -cc clang -target amd64 -cflags "-O2 -g -Wall -I/usr/include -I../../bpf" TlsClientHello ../../bpf/tls_clienthello.bpf.c
//go:generate /root/go/bin/bpf2go -cc clang -target amd64 -cflags "-O2 -g -Wall -I/usr/include -I../../bpf" TlsUprobe ../../bpf/tls_uprobe.bpf.c
//go:generate /root/go/bin/bpf2go -cc clang -target amd64 -cflags "-O2 -g -Wall -I/usr/include -I../../bpf" XDP ../../bpf/xdp_block.bpf.c
//go:generate /root/go/bin/bpf2go -cc clang -target amd64 -cflags "-O2 -g -Wall -I/usr/include -I../../bpf" GpuUprobe ../../bpf/gpu_uprobe.bpf.c
