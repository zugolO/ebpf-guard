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
	var _ BPFSamplingController = NewMultiBPFController(nil).Controller("x")
}

// A controller's recovery (multiplier back to 1.0) must restore the operator's
// configured base rate, not a hardcoded 1.0. Regression for issue #304 part 1.
func TestMultiBPFController_RecoveryRestoresBaseNotOne(t *testing.T) {
	m := NewMultiBPFController(nil)
	sysCtrl := newFakeRateController()
	m.Register("syscall", sysCtrl)
	m.SetBaseRate("syscall", 0.25) // operator configured 1-in-4

	// Base is applied immediately.
	got, _ := sysCtrl.rate("syscall")
	assert.Equal(t, 0.25, got)

	cpu := m.Controller("cpu_pressure")
	cpu.SetSamplingRate("syscall", 0.1) // shed: multiplier 0.1
	got, _ = sysCtrl.rate("syscall")
	assert.InDelta(t, 0.025, got, 1e-9, "shed applies base x multiplier")

	cpu.SetSamplingRate("syscall", 1.0) // recover: multiplier back to 1.0
	got, _ = sysCtrl.rate("syscall")
	assert.Equal(t, 0.25, got, "recovery must restore the configured base, not 1.0")

	assert.Equal(t, 0.25, m.EffectiveRates()["syscall"])
}

// Two independent controllers must not tug: one recovering must not undo the
// other's active degradation. Regression for issue #304 part 2.
func TestMultiBPFController_TwoControllersDoNotTug(t *testing.T) {
	m := NewMultiBPFController(nil)
	sysCtrl := newFakeRateController()
	m.Register("syscall", sysCtrl)
	// Base 1.0 (default, no SetBaseRate).

	cpu := m.Controller("cpu_pressure")
	ringbuf := m.Controller("ringbuf_load")

	// Ring-buffer controller degrades syscall to 0.25 due to a full channel.
	ringbuf.SetSamplingRate("syscall", 0.25)
	got, _ := sysCtrl.rate("syscall")
	assert.Equal(t, 0.25, got)

	// CPU watcher sheds harder, to 0.1 — effective is the tighter of the two.
	cpu.SetSamplingRate("syscall", 0.1)
	got, _ = sysCtrl.rate("syscall")
	assert.Equal(t, 0.1, got)

	// CPU watcher recovers. The ring-buffer controller still wants 0.25, so the
	// effective rate must fall back to 0.25 — NOT jump to 1.0.
	cpu.SetSamplingRate("syscall", 1.0)
	got, _ = sysCtrl.rate("syscall")
	assert.Equal(t, 0.25, got, "one controller's recovery must not overwrite the other's degradation")

	// Ring-buffer finally recovers too: back to full.
	ringbuf.SetSamplingRate("syscall", 1.0)
	got, _ = sysCtrl.rate("syscall")
	assert.Equal(t, 1.0, got)
}

// A degradation applied before the collector's controller registers must be
// picked up at registration time.
func TestMultiBPFController_PendingDegradationAppliedOnRegister(t *testing.T) {
	m := NewMultiBPFController(nil)
	m.Controller("cpu_pressure").SetSamplingRate("file", 0.1) // no controller yet

	fileCtrl := newFakeRateController()
	m.Register("file", fileCtrl)

	got, ok := fileCtrl.rate("file")
	assert.True(t, ok, "registration must flush the pending degraded rate")
	assert.Equal(t, 0.1, got)
}
