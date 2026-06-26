package collector

import (
	"context"
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	bpfpkg "github.com/zugolO/ebpf-guard/internal/bpf"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// fakePopulatingLoader simulates a successful eBPF load and populates the
// optional sched_process_exec program handle so the attach path exercises its
// non-nil branch.
type fakePopulatingLoader struct{}

func (fakePopulatingLoader) Load(objs *bpfpkg.SyscallObjects, _ *ebpf.CollectionOptions) error {
	objs.TraceSchedProcessExec = &ebpf.Program{}
	return nil
}

// fakeOkAttacher reports a successful attach. link.Link has unexported methods
// and cannot be implemented outside cilium/ebpf, so it returns a nil link with a
// nil error — enough to drive the happy attach path without a real kernel.
type fakeOkAttacher struct{ calls int }

func (a *fakeOkAttacher) Tracepoint(_, _ string, _ *ebpf.Program, _ *link.TracepointOptions) (link.Link, error) {
	a.calls++
	return nil, nil
}

// fakeRingReader is a no-op ringbufReader; Read always reports closed.
type fakeRingReader struct{}

func (fakeRingReader) Read() (ringbuf.Record, error) { return ringbuf.Record{}, errors.New("closed") }
func (fakeRingReader) Close() error                  { return nil }

// fakeOkOpener hands back a fakeRingReader.
type fakeOkOpener struct{}

func (fakeOkOpener) NewReader(_ *ebpf.Map) (ringbufReader, error) { return fakeRingReader{}, nil }

// TestSyscallCollector_Start_HappyPath drives Start through the successful
// load → attach (all three tracepoints) → open-ringbuf path using injected
// fakes, covering the attach/open lines that otherwise only run on a real
// kernel. The context is pre-cancelled so Start returns once the read loop has
// been launched.
func TestSyscallCollector_Start_HappyPath(t *testing.T) {
	c := newTestSyscallCollector(t)
	c.loader = fakePopulatingLoader{}
	attacher := &fakeOkAttacher{}
	c.attacher = attacher
	c.opener = fakeOkOpener{}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	out := make(chan types.Event, 1)
	require.NoError(t, c.Start(ctx, out))

	assert.Equal(t, 3, attacher.calls, "sys_enter, sys_exit and sched_process_exec must all attach")
	assert.True(t, c.IsAttached(), "links must be recorded after a successful attach")
	assert.True(t, c.IsHealthy(), "a fully started collector reports healthy")
}
