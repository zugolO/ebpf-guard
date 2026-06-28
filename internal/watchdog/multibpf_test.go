// multibpf_test.go — Tests for MultiBPFController

package watchdog

import (
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

// fakeRateController records the last rate set per event type and can be made
// to fail, exercising the multiplexer's error-logging path.
type fakeRateController struct {
	mu    sync.Mutex
	rates map[string]float64
	calls int
	err   error
}

func newFakeRateController() *fakeRateController {
	return &fakeRateController{rates: make(map[string]float64)}
}

func (f *fakeRateController) SetSamplingRate(eventType string, rate float64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return f.err
	}
	f.rates[eventType] = rate
	return nil
}

func (f *fakeRateController) rate(eventType string) (float64, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.rates[eventType]
	return v, ok
}

func TestMultiBPFController_RoutesByEventType(t *testing.T) {
	m := NewMultiBPFController(nil)
	fileCtrl := newFakeRateController()
	sysCtrl := newFakeRateController()
	m.Register("file", fileCtrl)
	m.Register("syscall", sysCtrl)

	m.SetSamplingRate("file", 0.1)
	m.SetSamplingRate("syscall", 0.5)

	got, ok := fileCtrl.rate("file")
	assert.True(t, ok)
	assert.Equal(t, 0.1, got)
	got, ok = sysCtrl.rate("syscall")
	assert.True(t, ok)
	assert.Equal(t, 0.5, got)

	// Cross-talk: the file controller must not have seen the syscall write.
	_, ok = fileCtrl.rate("syscall")
	assert.False(t, ok)
}

func TestMultiBPFController_UnregisteredEventTypeIsNoOp(t *testing.T) {
	m := NewMultiBPFController(nil)
	// No controller registered for "network" — must not panic.
	assert.NotPanics(t, func() { m.SetSamplingRate("network", 0.1) })
}

func TestMultiBPFController_NilControllerIgnored(t *testing.T) {
	m := NewMultiBPFController(nil)
	m.Register("file", nil) // ignored
	assert.NotPanics(t, func() { m.SetSamplingRate("file", 0.1) })
}

func TestMultiBPFController_ReRegisterReplaces(t *testing.T) {
	m := NewMultiBPFController(nil)
	first := newFakeRateController()
	second := newFakeRateController()
	m.Register("file", first)
	m.Register("file", second)

	m.SetSamplingRate("file", 0.2)
	assert.Equal(t, 0, first.calls)
	assert.Equal(t, 1, second.calls)
}

func TestMultiBPFController_ErrorIsSwallowed(t *testing.T) {
	m := NewMultiBPFController(nil)
	bad := newFakeRateController()
	bad.err = errors.New("map write failed")
	m.Register("file", bad)

	// The error is logged, not propagated; the call must complete cleanly.
	assert.NotPanics(t, func() { m.SetSamplingRate("file", 0.1) })
	assert.Equal(t, 1, bad.calls)
}

// MultiBPFController must satisfy the BPFSamplingController interface so it can
// be handed to the pressure watchers.
func TestMultiBPFController_ImplementsInterface(t *testing.T) {
	var _ BPFSamplingController = NewMultiBPFController(nil)
}
