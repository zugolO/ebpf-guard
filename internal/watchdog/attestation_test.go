package watchdog

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// mockProvider implements both BPFProgramChecker and BPFProgramProvider.
type mockProvider struct {
	mockChecker
	programs map[string]*ebpf.Program
}

func (m *mockProvider) GetPrograms() map[string]*ebpf.Program {
	return m.programs
}

// Compile-time interface checks.
var _ BPFProgramChecker = &mockProvider{}
var _ BPFProgramProvider = &mockProvider{}

func newLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, nil))
}

func TestBPFProgramProvider_InterfaceSatisfied(t *testing.T) {
	p := &mockProvider{
		mockChecker: mockChecker{name: "test", attached: true},
		programs:    nil,
	}
	var _ BPFProgramProvider = p // compile-time check
	assert.NotNil(t, p)
}

func TestRunAttestation_NonProvider_Skipped(t *testing.T) {
	w := New(newLogger(), DefaultConfig())
	checker := &mockChecker{name: "plain", attached: true}

	var alerts []types.Alert
	w.alertFunc = func(a types.Alert) { alerts = append(alerts, a) }

	w.runAttestation(checker)
	assert.Empty(t, alerts, "plain checker has no programs to attest")
}

func TestRunAttestation_NilPrograms_NoPanic(t *testing.T) {
	w := New(newLogger(), DefaultConfig())
	provider := &mockProvider{
		mockChecker: mockChecker{name: "test", attached: true},
		programs:    nil,
	}

	var alerts []types.Alert
	w.alertFunc = func(a types.Alert) { alerts = append(alerts, a) }

	require.NotPanics(t, func() { w.runAttestation(provider) })
	assert.Empty(t, alerts)
}

func TestRunAttestation_EmptyPrograms_NoPanic(t *testing.T) {
	w := New(newLogger(), DefaultConfig())
	provider := &mockProvider{
		mockChecker: mockChecker{name: "test", attached: true},
		programs:    map[string]*ebpf.Program{},
	}

	var alerts []types.Alert
	w.alertFunc = func(a types.Alert) { alerts = append(alerts, a) }

	require.NotPanics(t, func() { w.runAttestation(provider) })
	assert.Empty(t, alerts)
}

func TestRunAttestation_NilProgramValues_StubMode(t *testing.T) {
	// nil *ebpf.Program (stub/test mode) → verifyTag skipped → no violation.
	w := New(newLogger(), DefaultConfig())
	provider := &mockProvider{
		mockChecker: mockChecker{name: "syscall", attached: true},
		programs: map[string]*ebpf.Program{
			"trace_sys_enter": nil,
			"trace_sys_exit":  nil,
		},
	}

	var alerts []types.Alert
	w.alertFunc = func(a types.Alert) { alerts = append(alerts, a) }

	// Call twice — first records (skipped for nil), second checks again.
	w.runAttestation(provider)
	w.runAttestation(provider)
	assert.Empty(t, alerts, "nil programs must never produce alerts in stub mode")
}

func TestRunAttestation_ChecksTotal_Incremented(t *testing.T) {
	w := New(newLogger(), DefaultConfig())
	require.NotNil(t, w.checksTotal)

	provider := &mockProvider{
		mockChecker: mockChecker{name: "syscall", attached: true},
		programs: map[string]*ebpf.Program{
			"trace_sys_enter": nil,
			"trace_sys_exit":  nil,
		},
	}

	before := testutil.ToFloat64(w.checksTotal)
	w.runAttestation(provider)
	after := testutil.ToFloat64(w.checksTotal)

	assert.Equal(t, float64(2), after-before, "two programs → checksTotal +2")
}

func TestCheckProgram_AttachedProvider_CallsAttestation(t *testing.T) {
	w := New(newLogger(), Config{AlertFunc: func(types.Alert) {}})

	provider := &mockProvider{
		mockChecker: mockChecker{name: "syscall", attached: true},
		programs:    map[string]*ebpf.Program{"trace_sys_enter": nil},
	}
	w.RegisterChecker(provider)

	// Must not panic in stub mode.
	require.NotPanics(t, func() { w.checkProgram(provider) })
}

func TestWatchdog_AttestationMetrics_Initialised(t *testing.T) {
	w := New(newLogger(), DefaultConfig())
	assert.NotNil(t, w.tamperingTotal, "tamperingTotal must be initialised")
	assert.NotNil(t, w.checksTotal, "checksTotal must be initialised")
	assert.NotNil(t, w.attestor, "attestor must be initialised")
}

func TestWatchdog_StartWithProvider_NoRace(t *testing.T) {
	w := New(newLogger(), Config{
		HeartbeatInterval: 50 * time.Millisecond,
		CheckInterval:     50 * time.Millisecond,
	})

	provider := &mockProvider{
		mockChecker: mockChecker{name: "test", attached: true},
		programs:    map[string]*ebpf.Program{"prog": nil},
	}
	w.RegisterChecker(provider)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w.Start(ctx)
	time.Sleep(120 * time.Millisecond)
}
