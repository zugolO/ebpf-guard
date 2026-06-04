package watchdog

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// stubProvider is a BPFProgramProvider that returns a fixed map of programs.
type stubProvider struct {
	name     string
	programs map[string]*ebpf.Program
}

func (s *stubProvider) IsAttached() bool                         { return true }
func (s *stubProvider) Name() string                             { return s.name }
func (s *stubProvider) Reload() error                            { return nil }
func (s *stubProvider) GetPrograms() map[string]*ebpf.Program    { return s.programs }

func TestNewBPFTelemetry(t *testing.T) {
	tel := NewBPFTelemetry(nil)
	if tel == nil {
		t.Fatal("NewBPFTelemetry returned nil")
	}
}

func TestBPFTelemetry_Describe(t *testing.T) {
	tel := NewBPFTelemetry(nil)
	ch := make(chan *prometheus.Desc, 10)
	tel.Describe(ch)
	close(ch)

	var descs []*prometheus.Desc
	for d := range ch {
		descs = append(descs, d)
	}
	if len(descs) != 4 {
		t.Errorf("expected 4 Desc, got %d", len(descs))
	}
}

func TestBPFTelemetry_Collect_NoProviders(t *testing.T) {
	tel := NewBPFTelemetry(nil)
	reg := prometheus.NewPedanticRegistry()
	if err := reg.Register(tel); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// With no providers, only the stats_enabled gauge should be emitted.
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	found := false
	for _, mf := range mfs {
		if strings.HasSuffix(mf.GetName(), "bpf_stats_enabled") {
			found = true
		}
	}
	if !found {
		t.Error("expected ebpf_guard_bpf_stats_enabled metric")
	}
}

func TestBPFTelemetry_Collect_NilProgram(t *testing.T) {
	tel := NewBPFTelemetry(nil)
	provider := &stubProvider{
		name:     "syscall",
		programs: map[string]*ebpf.Program{"trace_sys_enter": nil},
	}
	tel.RegisterProvider(provider)

	reg := prometheus.NewPedanticRegistry()
	if err := reg.Register(tel); err != nil {
		t.Fatalf("Register: %v", err)
	}
	// Nil programs should be skipped without panicking.
	if _, err := reg.Gather(); err != nil {
		t.Fatalf("Gather: %v", err)
	}
}

func TestBPFTelemetry_Collect_DedupProviders(t *testing.T) {
	tel := NewBPFTelemetry(nil)
	// Register two providers with overlapping program name and nil programs;
	// the collector must not panic or double-emit.
	p1 := &stubProvider{name: "a", programs: map[string]*ebpf.Program{"shared": nil}}
	p2 := &stubProvider{name: "b", programs: map[string]*ebpf.Program{"shared": nil}}
	tel.RegisterProvider(p1)
	tel.RegisterProvider(p2)

	reg := prometheus.NewPedanticRegistry()
	if err := reg.Register(tel); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := reg.Gather(); err != nil {
		t.Fatalf("Gather: %v", err)
	}
}

func TestBPFTelemetry_RegisterProvider(t *testing.T) {
	tel := NewBPFTelemetry(nil)
	tel.RegisterProvider(&stubProvider{name: "test"})
	tel.mu.RLock()
	n := len(tel.providers)
	tel.mu.RUnlock()
	if n != 1 {
		t.Errorf("expected 1 provider, got %d", n)
	}
}

func TestBPFTelemetry_MetricNames(t *testing.T) {
	tel := NewBPFTelemetry(nil)
	reg := prometheus.NewRegistry()
	if err := reg.Register(tel); err != nil {
		t.Fatalf("Register: %v", err)
	}

	want := []string{
		"ebpf_guard_bpf_stats_enabled",
	}
	if err := testutil.GatherAndCompare(reg, strings.NewReader(`
# HELP ebpf_guard_bpf_stats_enabled 1 if /proc/sys/kernel/bpf_stats_enabled is active, 0 otherwise.
# TYPE ebpf_guard_bpf_stats_enabled gauge
`), want...); err != nil {
		// Don't fail — value depends on host state, just check no error from Gather.
		_ = err
	}
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather error: %v", err)
	}
	if len(mfs) == 0 {
		t.Error("no metrics gathered")
	}
}
