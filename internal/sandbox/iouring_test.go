package sandbox

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zugolO/ebpf-guard/internal/config"
)

func TestIOUringExposed(t *testing.T) {
	orig := ioUringDisabledPath
	t.Cleanup(func() { ioUringDisabledPath = orig })

	write := func(t *testing.T, contents string) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "io_uring_disabled")
		if err := os.WriteFile(p, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	cases := []struct {
		name     string
		contents string
		want     bool
	}{
		{"enabled_for_all", "0\n", true},
		{"disabled_except_admin", "1\n", false},
		{"disabled_for_all", "2\n", false},
		{"whitespace_only_disabled", "  2 \n", false},
		{"unparseable_fails_open_to_exposed", "garbage\n", true},
		{"empty_fails_open_to_exposed", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ioUringDisabledPath = write(t, tc.contents)
			if got := ioUringExposed(); got != tc.want {
				t.Errorf("ioUringExposed() = %v, want %v", got, tc.want)
			}
		})
	}

	t.Run("absent_sysctl_is_exposed", func(t *testing.T) {
		ioUringDisabledPath = filepath.Join(t.TempDir(), "does-not-exist")
		if !ioUringExposed() {
			t.Error("a missing io_uring_disabled sysctl must read as exposed (fail closed)")
		}
	})
}

// markUnsafeLocked must accumulate distinct reasons and deduplicate repeats, so
// an io_uring downgrade (issue #277 P0) and a privileged-target downgrade both
// surface even when they latch in either order.
func TestManager_MarkUnsafeAccumulates(t *testing.T) {
	m, err := New(aiCfg("enforce", config.AISandboxProfile{Name: "agent"}), nil)
	if err != nil {
		t.Fatal(err)
	}
	m.kernelMode = true
	m.execHookAttached = true

	m.mu.Lock()
	m.markUnsafeLocked("io_uring uncontained")
	added := m.markUnsafeLocked("io_uring uncontained") // duplicate — ignored
	m.mu.Unlock()
	if added != 0 {
		t.Errorf("re-adding an existing reason should add 0, got %d", added)
	}

	// A subsequent GuardTarget-style downgrade appends its own reason rather than
	// being swallowed because the manager was already latched.
	m.applyGuard(EnforcementSafety{Safe: false, Reasons: []string{"target holds CAP_BPF"}})

	if m.KernelEnforced() {
		t.Error("KernelEnforced must be false once enforcement is unsafe")
	}
	unsafe, reasons := m.EnforcementUnsafe()
	if !unsafe || len(reasons) != 2 {
		t.Fatalf("EnforcementUnsafe = (%v, %v), want (true, 2 reasons)", unsafe, reasons)
	}
}
