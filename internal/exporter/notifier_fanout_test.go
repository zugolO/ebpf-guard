package exporter

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeNotifier struct {
	name    string
	enabled bool
	sends   int32
	closed  int32
}

func (f *fakeNotifier) Name() string  { return f.name }
func (f *fakeNotifier) Enabled() bool  { return f.enabled }
func (f *fakeNotifier) Send(_ context.Context, _ types.Alert) error {
	atomic.AddInt32(&f.sends, 1)
	return nil
}
func (f *fakeNotifier) Close() error {
	atomic.AddInt32(&f.closed, 1)
	return nil
}

func TestFanoutNotifier_Dispatch(t *testing.T) {
	a := &fakeNotifier{name: "a", enabled: true}
	b := &fakeNotifier{name: "b", enabled: true}

	f := &FanoutNotifier{
		notifiers: []Notifier{a, b},
		timeout:   time.Second,
		logger:    notifierLogger(),
	}

	assert.ElementsMatch(t, []string{"a", "b"}, f.NotifierNames())

	f.SendAlert(context.Background(), criticalAlert())

	assert.Equal(t, int32(1), atomic.LoadInt32(&a.sends))
	assert.Equal(t, int32(1), atomic.LoadInt32(&b.sends))

	require.NoError(t, f.Close())
	assert.Equal(t, int32(1), atomic.LoadInt32(&a.closed))
	assert.Equal(t, int32(1), atomic.LoadInt32(&b.closed))
}
