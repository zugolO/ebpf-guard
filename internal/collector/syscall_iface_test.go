package collector

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	bpfpkg "github.com/zugolO/ebpf-guard/internal/bpf"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// --- fake syscallLoader ---

// fakeErrLoader returns err from Load. A zero-value fakeErrLoader (err == nil)
// simulates a successful load that leaves objs empty but non-nil.
type fakeErrLoader struct{ err error }

func (f fakeErrLoader) Load(_ *bpfpkg.SyscallObjects, _ *ebpf.CollectionOptions) error {
	return f.err
}

// --- fake linkAttacher ---

// fakeLinkAttacher always fails: when err is set it returns it, otherwise it
// returns a generic error. It never returns a real link.Link because that
// interface has unexported methods and cannot be implemented outside cilium/ebpf.
type fakeLinkAttacher struct {
	err error
}

func (a *fakeLinkAttacher) Tracepoint(_ string, _ string, _ *ebpf.Program, _ *link.Options) (link.Link, error) {
	if a.err != nil {
		return nil, a.err
	}
	return nil, errors.New("no real kernel in unit test")
}

// --- helper ---

func newTestSyscallCollector(t *testing.T) *SyscallCollector {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c, err := NewSyscallCollector(logger)
	require.NoError(t, err)
	return c
}

// --- tests ---

func TestSyscallCollector_Name(t *testing.T) {
	c := newTestSyscallCollector(t)
	assert.Equal(t, "syscall", c.Name())
}

func TestSyscallCollector_LoadError_WhenLoaderFails(t *testing.T) {
	c := newTestSyscallCollector(t)
	loadErr := errors.New("simulated load failure")
	c.loader = fakeErrLoader{err: loadErr}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately so Start doesn't block

	out := make(chan types.Event, 1)
	err := c.Start(ctx, out)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "load eBPF objects")

	// After a failed load, the collector must not be considered healthy.
	assert.False(t, c.IsHealthy())
}

func TestSyscallCollector_AttachError_WhenAttacherFails(t *testing.T) {
	c := newTestSyscallCollector(t)
	// Load succeeds (objs becomes non-nil but empty) so Start proceeds to attach.
	c.loader = fakeErrLoader{}
	c.attacher = &fakeLinkAttacher{err: errors.New("simulated attach failure")}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately so Start doesn't block

	out := make(chan types.Event, 1)
	err := c.Start(ctx, out)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "attach programs")

	// A failed attach must leave the collector unhealthy.
	assert.False(t, c.IsHealthy())
}

func TestSyscallCollector_Close_NoObjs(t *testing.T) {
	c := newTestSyscallCollector(t)
	// objs is nil — Close must not panic and must return nil.
	require.NotPanics(t, func() {
		err := c.Close()
		assert.NoError(t, err)
	})
}

func TestSyscallCollector_IsAttached_AfterClose(t *testing.T) {
	c := newTestSyscallCollector(t)
	// Even if we force some links into the slice, Close must clear them.
	// We test the nil-objs path: IsAttached returns false when objs is nil.
	assert.False(t, c.IsAttached())

	// Calling Close again on an already-clean collector must also be safe.
	require.NoError(t, c.Close())
	assert.False(t, c.IsAttached())
}
