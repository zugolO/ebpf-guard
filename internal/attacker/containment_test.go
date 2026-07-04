package attacker

import (
	"bytes"
	"strings"
	"testing"

	"github.com/zugolO/ebpf-guard/internal/config"
	"github.com/zugolO/ebpf-guard/internal/sandbox"
)

func TestReferenceContainmentProfile_IsValid(t *testing.T) {
	// The reference profile must satisfy ValidateConfig — in particular its
	// allowed_exec prefixes must not overlap the writable scratch dir.
	cfg := ReferenceContainmentProfile()
	full := &config.Config{
		Server:      config.ServerConfig{BindAddress: ":9090"},
		Store:       config.StoreConfig{Backend: "memory"},
		Enforcement: config.EnforcementConfig{BlockBackend: "log"},
		AISandbox:   cfg,
	}
	if err := config.ValidateConfig(full); err != nil {
		t.Fatalf("reference containment profile must validate, got: %v", err)
	}
}

func TestRunContainment_AllVectorsContained(t *testing.T) {
	results, err := RunContainment(nil)
	if err != nil {
		t.Fatalf("RunContainment: %v", err)
	}
	if len(results) != 6 {
		t.Fatalf("expected 6 vectors, got %d", len(results))
	}
	vectors := map[string]bool{}
	for _, r := range results {
		vectors[r.Scenario.Vector] = true
		if !r.Passed {
			t.Errorf("vector %q not contained: %s", r.Scenario.Vector, r.ContainDetail)
		}
	}
	for _, want := range []string{
		"kill", "map-write", "cgroup-escape", "dropped-binary-exec",
		"long-path-bypass", "dotdot-exec",
	} {
		if !vectors[want] {
			t.Errorf("missing containment vector %q", want)
		}
	}
}

// An audit-mode policy must NOT report the escape primitives as contained: they
// are audited, not denied. This guards against the harness silently passing on a
// non-enforcing profile.
func TestContainment_AuditModeNotContained(t *testing.T) {
	pol, err := sandbox.Compile(config.AISandboxConfig{
		Enabled:  true,
		Mode:     "audit",
		Profiles: []config.AISandboxProfile{{Name: "ai-agent"}},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if pol.EscapeContained(sandbox.EscapeBPF) {
		t.Error("audit mode must not report bpf() as contained")
	}
}

func TestPrintContainmentResults_Renders(t *testing.T) {
	results, err := RunContainment(nil)
	if err != nil {
		t.Fatalf("RunContainment: %v", err)
	}
	var buf bytes.Buffer
	PrintContainmentResults(results, &buf)
	out := buf.String()
	if !strings.Contains(out, "Containment Acceptance") {
		t.Errorf("missing header in output:\n%s", out)
	}
	if !strings.Contains(out, "dropped-binary-exec") {
		t.Errorf("missing dropped-binary vector in output:\n%s", out)
	}
}
