package collector

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	bpfpkg "github.com/zugolO/ebpf-guard/internal/bpf"
)

// syscallLoader abstracts loading eBPF objects for SyscallCollector.
// The production implementation calls bpf.LoadSyscallObjects directly; tests
// inject a fake that returns a controlled error or populates a stub.
type syscallLoader interface {
	Load(objs *bpfpkg.SyscallObjects, opts *ebpf.CollectionOptions) error
}

// ringbufReader abstracts reading from an eBPF ring buffer.
type ringbufReader interface {
	Read() (ringbuf.Record, error)
	Close() error
}

// ringbufOpener abstracts creating a ringbufReader from an eBPF map.
type ringbufOpener interface {
	NewReader(rb *ebpf.Map) (ringbufReader, error)
}

// linkAttacher abstracts attaching eBPF programs to kernel tracepoints.
type linkAttacher interface {
	Tracepoint(group, name string, prog *ebpf.Program, opts *link.TracepointOptions) (link.Link, error)
}

// --- production implementations ---

// defaultSyscallLoader calls the bpf2go-generated loader.
type defaultSyscallLoader struct{}

func (defaultSyscallLoader) Load(objs *bpfpkg.SyscallObjects, opts *ebpf.CollectionOptions) error {
	return bpfpkg.LoadSyscallObjects(objs, opts)
}

// defaultRingbufOpener wraps bpf.NewRingbufReader.
type defaultRingbufOpener struct{}

func (defaultRingbufOpener) NewReader(rb *ebpf.Map) (ringbufReader, error) {
	return bpfpkg.NewRingbufReader(rb)
}

// defaultLinkAttacher calls the real link.Tracepoint.
type defaultLinkAttacher struct{}

func (defaultLinkAttacher) Tracepoint(group, name string, prog *ebpf.Program, opts *link.TracepointOptions) (link.Link, error) {
	return link.Tracepoint(group, name, prog, opts)
}
