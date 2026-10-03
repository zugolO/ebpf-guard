package collector

import (
	"log/slog"

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
	ReadInto(rec *ringbuf.Record) error
	Close() error
}

// ringbufOpener abstracts creating a ringbufReader from an eBPF map. netpoll
// carries the wave 8.1 item 6 toggle down to the production implementation.
type ringbufOpener interface {
	NewReader(rb *ebpf.Map, netpoll bool) (ringbufReader, error)
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

// defaultRingbufOpener wraps newEventRingReader, which applies the netpoll
// toggle and publishes the mode the reader actually got.
type defaultRingbufOpener struct {
	logger *slog.Logger
}

func (o defaultRingbufOpener) NewReader(rb *ebpf.Map, netpoll bool) (ringbufReader, error) {
	logger := o.logger
	if logger == nil {
		logger = slog.Default()
	}
	return newEventRingReader(logger, "syscall", rb, netpoll)
}

// defaultLinkAttacher calls the real link.Tracepoint.
type defaultLinkAttacher struct{}

func (defaultLinkAttacher) Tracepoint(group, name string, prog *ebpf.Program, opts *link.TracepointOptions) (link.Link, error) {
	return link.Tracepoint(group, name, prog, opts)
}
