package sandbox

import (
	"os"
	"testing"
)

func TestParseCapEff(t *testing.T) {
	status := "Name:\tbash\n" +
		"Uid:\t0\t0\t0\t0\n" +
		"CapEff:\t000001ffffffffff\n" +
		"Seccomp:\t0\n"
	v, ok := parseCapEff(status)
	if !ok {
		t.Fatal("expected CapEff to parse")
	}
	if v != 0x000001ffffffffff {
		t.Errorf("CapEff = %#x, want 0x1ffffffffff", v)
	}
}

func TestParseCapEff_Missing(t *testing.T) {
	if _, ok := parseCapEff("Name:\tbash\nUid:\t0\n"); ok {
		t.Error("missing CapEff should not parse")
	}
	if _, ok := parseCapEff("CapEff:\tnothex\n"); ok {
		t.Error("non-hex CapEff should not parse")
	}
}

func TestCapReasons(t *testing.T) {
	cases := []struct {
		name    string
		capEff  uint64
		wantLen int
	}{
		{"unprivileged", 0x0, 0},
		{"only CAP_BPF", uint64(1) << capBPF, 1},
		{"admin+ptrace", (uint64(1) << capSysAdmin) | (uint64(1) << capSysPtrace), 2},
		{"all three", (uint64(1) << capBPF) | (uint64(1) << capSysAdmin) | (uint64(1) << capSysPtrace), 3},
		// A capability we don't care about must not trip the check.
		{"benign cap only", uint64(1) << 0 /* CAP_CHOWN */, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := len(capReasons(tc.capEff)); got != tc.wantLen {
				t.Errorf("capReasons len = %d, want %d", got, tc.wantLen)
			}
		})
	}
}

func TestAssessTamperMounts(t *testing.T) {
	// bpffs writable, cgroupfs not.
	writable := func(p string) bool { return p == "/sys/fs/bpf" }
	got := assessTamperMounts(writable)
	if len(got) != 1 {
		t.Fatalf("reasons = %v, want exactly one", got)
	}
	if assessTamperMounts(func(string) bool { return false }) != nil {
		t.Error("no writable mounts should yield no reasons")
	}
}

func TestAssessProcess_UnreadablePidFailsClosed(t *testing.T) {
	// Stub the mount probe so the verdict depends only on capabilities.
	restore := accessWritable
	accessWritable = func(string) bool { return false }
	defer func() { accessWritable = restore }()

	// PID 1 exists but is unlikely to be readable for CapEff in all CI envs;
	// use a PID that cannot exist to force the unreadable path deterministically.
	res := AssessProcess(1 << 30)
	if res.Safe {
		t.Error("an unreadable target must be treated as unsafe (fail closed)")
	}
	if len(res.Reasons) == 0 {
		t.Error("expected a reason explaining why the target could not be verified")
	}
}

func TestAssessProcess_SelfMatchesOwnCaps(t *testing.T) {
	restore := accessWritable
	accessWritable = func(string) bool { return false }
	defer func() { accessWritable = restore }()

	// Whatever caps the test process holds, AssessProcess(self) must agree with
	// a direct read of its own effective set — no false positives/negatives.
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Skipf("cannot read own status: %v", err)
	}
	capEff, ok := parseCapEff(string(data))
	if !ok {
		t.Skip("own status has no CapEff line")
	}
	want := len(capReasons(capEff)) == 0
	if got := AssessProcess(os.Getpid()).Safe; got != want {
		t.Errorf("AssessProcess(self).Safe = %v, want %v", got, want)
	}
}
