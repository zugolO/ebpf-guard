package profiler

import (
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

func fileEventForPath(comm string, path string) types.Event {
	var filename [256]byte
	copy(filename[:], path)
	return types.Event{
		Type: types.EventFileAccess,
		Comm: commBytes(comm),
		File: &types.FileEvent{Filename: filename},
	}
}

func syscallEventForExec(comm string, nr int, procArgs string) types.Event {
	return types.Event{
		Type:     types.EventSyscall,
		Comm:     commBytes(comm),
		Syscall:  &types.SyscallEvent{Nr: int64(nr)},
		ProcArgs: procArgs,
	}
}

// TestDriftBaselineProfiler_SyscallSignatureIncludesProcArgs guards against a
// defect found while designing wave 6.0's positive control: a bare syscall
// number (e.g. execve's Nr) is the same for every binary a workload ever
// runs, so without folding proc.args into the signature, learning one exec
// permanently suppressed drift_exec_from_system_bin for every OTHER binary
// the same comm later executed too — a rule whose own condition matches on
// proc.args (which binary path ran) would never actually alert on a novel
// binary once baseline learning completed.
func TestDriftBaselineProfiler_SyscallSignatureIncludesProcArgs(t *testing.T) {
	cfg := DriftBaselineConfig{
		Enabled:        true,
		LearningPeriod: 0,
		MinSamples:     1,
		PerWorkload:    true,
	}
	p := NewDriftBaselineProfiler(cfg, nil)

	// sshd's baseline learns execve of the real sshd binary.
	assert.False(t, p.Observe("drift_exec_from_system_bin", syscallEventForExec("sshd", 59, "/usr/sbin/sshd -D -R")))
	assert.Equal(t, 0, p.LearningWorkloads(), "workload should have switched to enforcing")

	// The same known binary path is suppressed as baseline-known.
	assert.False(t, p.Observe("drift_exec_from_system_bin", syscallEventForExec("sshd", 59, "/usr/sbin/sshd -D -R")))

	// A different binary under the same comm, same syscall number, is a
	// genuine deviation and must NOT be swallowed by the syscall-number-only
	// signature that ldconfig/systemd-style file events don't have.
	assert.True(t, p.Observe("drift_exec_from_system_bin", syscallEventForExec("sshd", 59, "/usr/local/bin/drift-pc -x")))
}

func TestDriftBaselineProfiler_DisabledPassesThrough(t *testing.T) {
	p := NewDriftBaselineProfiler(DriftBaselineConfig{Enabled: false}, nil)
	for i := 0; i < 5; i++ {
		assert.True(t, p.Observe("drift_rule", fileEventForPath("ldconfig", "/etc/ld.so.cache")))
	}
}

func TestDriftBaselineProfiler_SuppressesDuringLearning(t *testing.T) {
	cfg := DriftBaselineConfig{
		Enabled:        true,
		LearningPeriod: 3600, // won't elapse during the test
		MinSamples:     3,
		PerWorkload:    true,
	}
	p := NewDriftBaselineProfiler(cfg, nil)

	for i := 0; i < 10; i++ {
		got := p.Observe("drift_rule", fileEventForPath("systemd", "/etc/systemd/system/foo.service"))
		assert.False(t, got, "matches during learning must be suppressed")
	}
	assert.Equal(t, 1, p.LearningWorkloads())
}

func TestDriftBaselineProfiler_KnownSignatureSuppressedAfterEnforcing(t *testing.T) {
	cfg := DriftBaselineConfig{
		Enabled:        true,
		LearningPeriod: 0, // learning completes as soon as MinSamples is hit
		MinSamples:     2,
		PerWorkload:    true,
	}
	p := NewDriftBaselineProfiler(cfg, nil)

	// Learning phase: observe the same signature twice to complete learning.
	assert.False(t, p.Observe("drift_rule", fileEventForPath("ldconfig", "/etc/ld.so.cache")))
	assert.False(t, p.Observe("drift_rule", fileEventForPath("ldconfig", "/etc/ld.so.cache")))
	assert.Equal(t, 0, p.LearningWorkloads(), "workload should have switched to enforcing")

	// Enforcing phase: the same signature is now known-baseline, so it is
	// suppressed rather than alerted.
	assert.False(t, p.Observe("drift_rule", fileEventForPath("ldconfig", "/etc/ld.so.cache")))

	// A signature never seen during learning is a genuine deviation.
	assert.True(t, p.Observe("drift_rule", fileEventForPath("ldconfig", "/root/.ssh/authorized_keys")))
}

func TestDriftBaselineProfiler_PerWorkloadIsolation(t *testing.T) {
	cfg := DriftBaselineConfig{
		Enabled:        true,
		LearningPeriod: 0,
		MinSamples:     1,
		PerWorkload:    true,
	}
	p := NewDriftBaselineProfiler(cfg, nil)

	// systemd's baseline learns /etc/systemd/system.
	assert.False(t, p.Observe("drift_rule", fileEventForPath("systemd", "/etc/systemd/system/foo.service")))

	// A different workload (curl) has an independent, still-learning baseline
	// even though systemd already finished learning the same rule ID.
	assert.False(t, p.Observe("drift_rule", fileEventForPath("curl", "/etc/systemd/system/foo.service")))
}

func TestDriftBaselineProfiler_GlobalBaselineWhenPerWorkloadDisabled(t *testing.T) {
	cfg := DriftBaselineConfig{
		Enabled:        true,
		LearningPeriod: 0,
		MinSamples:     1,
		PerWorkload:    false,
	}
	p := NewDriftBaselineProfiler(cfg, nil)

	assert.False(t, p.Observe("drift_rule", fileEventForPath("systemd", "/etc/systemd/system/foo.service")))
	// Different comm, but PerWorkload=false means one shared baseline — the
	// signature learned above is already known, so this is suppressed too.
	assert.False(t, p.Observe("drift_rule", fileEventForPath("curl", "/etc/systemd/system/foo.service")))
}

func TestDriftBaselineProfiler_ProfileCapBoundsMemory(t *testing.T) {
	const cap = 50
	cfg := DriftBaselineConfig{
		Enabled:        true,
		LearningPeriod: 3600,
		MinSamples:     20,
		PerWorkload:    true,
		MaxWorkloads:   cap,
	}
	p := NewDriftBaselineProfiler(cfg, nil)

	// Simulate an attacker spawning processes under random comm names: each
	// distinct comm would otherwise create its own never-evicted profile.
	for i := 0; i < cap*20; i++ {
		comm := fmt.Sprintf("evil-%d", i)
		p.Observe("drift_rule", fileEventForPath(comm, "/etc/ld.so.cache"))
	}

	assert.LessOrEqual(t, p.ProfileCount(), cap,
		"profile count must stay bounded by MaxWorkloads regardless of comm cardinality")
}

func TestDriftBaselineProfiler_EnforcesAfterDeadlineDespiteLowSamples(t *testing.T) {
	cfg := DriftBaselineConfig{
		Enabled:                true,
		LearningPeriod:         3600, // 1h
		MinSamples:             20,   // never reached by a ~1 event/hour workload
		PerWorkload:            true,
		EnforceDeadlinePeriods: 2, // deadline = 2h
	}
	p := NewDriftBaselineProfiler(cfg, nil)

	base := time.Now()
	current := base
	p.nowFn = func() time.Time { return current }

	// One event learns signature A. Far below MinSamples, so the normal
	// completion path can never fire.
	require.False(t, p.Observe("drift_rule", fileEventForPath("cron", "/etc/cron.d/job")))
	assert.Equal(t, 1, p.LearningWorkloads())

	// Past one LearningPeriod but before the deadline: still learning, and now
	// visible as a stuck (blind-spot) workload.
	current = base.Add(90 * time.Minute)
	assert.Equal(t, 1, p.StuckLearningWorkloads())
	require.False(t, p.Observe("drift_rule", fileEventForPath("cron", "/etc/cron.d/job")))

	// Past the 2h deadline: the next observation promotes the workload to
	// enforcing even though MinSamples was never met.
	current = base.Add(2*time.Hour + time.Minute)
	require.False(t, p.Observe("drift_rule", fileEventForPath("cron", "/etc/cron.d/job")))
	assert.Equal(t, 0, p.LearningWorkloads(), "deadline must force the workload out of learning")
	assert.Equal(t, 0, p.StuckLearningWorkloads())

	// Now enforcing: a signature never seen during learning alerts, proving the
	// low-traffic workload is no longer a silent blind spot.
	assert.True(t, p.Observe("drift_rule", fileEventForPath("cron", "/root/.ssh/authorized_keys")),
		"a novel signature must alert once the deadline has forced enforcing")
	// The learned signature is still suppressed as known-baseline.
	assert.False(t, p.Observe("drift_rule", fileEventForPath("cron", "/etc/cron.d/job")))
}

func TestNormalizeDriftPath(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"", ""},
		{"/etc/passwd", "/etc/passwd"},
		{"/etc/shadow", "/etc/shadow"},
		{"/proc/12345/mem", "/proc/*/mem"},
		{"/proc/12345/maps", "/proc/*/maps"},
		{"/usr/lib/x86_64-linux-gnu/libc.so.6", "/usr/lib/x86_64-linux-gnu/libc.so.6"},
		// 6.0: paths that used to collapse to their first two segments and so
		// made the "new binary / new library / new file" rules unable to tell
		// novel from routine. Regression guard for the 6.0.3 positive control.
		{"/usr/local/bin/drift-pc", "/usr/local/bin/drift-pc"},
		{"/usr/local/bin/drift-pc-attack-window/drift-pc", "/usr/local/bin/drift-pc-attack-window/drift-pc"},
		{"/usr/bin/curl", "/usr/bin/curl"},
		{"/usr/bin/python3", "/usr/bin/python3"},
		{"/usr/sbin/sshd", "/usr/sbin/sshd"},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, normalizeDriftPath(c.path), "path=%q", c.path)
	}
}

// TestDriftBaselineDistinguishesBinariesInSameDir is the unit-level twin of the
// 6.0.3 positive control that failed live on measurement №6.0: a workload that
// learned one binary under a system bin dir must still alert on a different
// binary under that same dir.
func TestDriftBaselineDistinguishesBinariesInSameDir(t *testing.T) {
	current := time.Now()
	p := NewDriftBaselineProfiler(DriftBaselineConfig{
		Enabled: true, LearningPeriod: 60, MinSamples: 2, PerWorkload: true,
	}, slog.Default())
	p.nowFn = func() time.Time { return current }

	seed := syscallEventForExec("drift-pc", 59, "/usr/local/bin/drift-pc")
	require.False(t, p.Observe("drift_exec_from_system_bin", seed))
	require.False(t, p.Observe("drift_exec_from_system_bin", seed))

	current = current.Add(2 * time.Minute)
	require.False(t, p.Observe("drift_exec_from_system_bin", seed),
		"the observation that closes learning is itself suppressed")
	require.Equal(t, 0, p.LearningWorkloads(), "workload must be enforcing by now")

	require.False(t, p.Observe("drift_exec_from_system_bin", seed),
		"the learned binary stays suppressed as known baseline")
	assert.True(t, p.Observe("drift_exec_from_system_bin",
		syscallEventForExec("drift-pc", 59, "/usr/local/bin/drift-pc-attack-window/drift-pc")),
		"a different binary under the same system bin dir must alert")
	assert.True(t, p.Observe("drift_exec_from_system_bin",
		syscallEventForExec("drift-pc", 59, "/usr/bin/curl")),
		"a binary under a different system bin dir must alert")
}

// TestDriftBaselineSignatureCapFreezesBaseline pins the bound that replaced the
// depth truncation: the signature set stops growing at the cap, the profile is
// reported as saturated, and unlearned signatures alert rather than vanish.
func TestDriftBaselineSignatureCapFreezesBaseline(t *testing.T) {
	current := time.Now()
	p := NewDriftBaselineProfiler(DriftBaselineConfig{
		Enabled: true, LearningPeriod: 60, MinSamples: 1, PerWorkload: true,
		MaxSignaturesPerWorkload: 3,
	}, slog.Default())
	p.nowFn = func() time.Time { return current }

	for i := 0; i < 10; i++ {
		p.Observe("drift_exec_from_system_bin",
			syscallEventForExec("busy", 59, fmt.Sprintf("/usr/bin/tool%d", i)))
	}
	assert.Equal(t, 1, p.SaturatedWorkloads(), "profile must be flagged saturated")

	current = current.Add(2 * time.Minute)
	require.False(t, p.Observe("drift_exec_from_system_bin",
		syscallEventForExec("busy", 59, "/usr/bin/tool0")), "learned signature stays known")
	assert.True(t, p.Observe("drift_exec_from_system_bin",
		syscallEventForExec("busy", 59, "/usr/bin/tool9")),
		"a signature dropped by the cap must alert, not be silently trusted")
}

// syscallEventWithArgs builds a syscall event carrying register arguments,
// the way the collector delivers ptrace/mount/bpf/... events (no proc.args).
func syscallEventWithArgs(comm string, nr int, args ...uint64) types.Event {
	var a [6]uint64
	copy(a[:], args)
	return types.Event{
		Type:    types.EventSyscall,
		Comm:    commBytes(comm),
		Syscall: &types.SyscallEvent{Nr: int64(nr), Args: a},
	}
}

// TestDriftBaselineDistinguishesDangerousSyscallArgs is the unit twin of the
// second blind spot measurement №6.0 exposed: drift_dangerous_syscall matched
// on the syscall number alone, so one bpf() or mount() call during learning
// suppressed every later one for that workload — including the escape the rule
// is named after. The register arguments were carried end-to-end all along.
func TestDriftBaselineDistinguishesDangerousSyscallArgs(t *testing.T) {
	const (
		nrMount   = 165
		nrBPF     = 321
		nrPtrace  = 101
		nrUnshare = 272
	)
	cases := []struct {
		name     string
		learned  types.Event
		attack   types.Event
		whatever string
	}{
		{
			name:     "bpf map lookup does not mask prog load",
			learned:  syscallEventWithArgs("systemd", nrBPF, 1), // BPF_MAP_LOOKUP_ELEM
			attack:   syscallEventWithArgs("systemd", nrBPF, 5), // BPF_PROG_LOAD
			whatever: "bpf",
		},
		{
			name:     "namespace mount does not mask a bind mount",
			learned:  syscallEventWithArgs("containerd", nrMount, 0, 0, 0, 1),    // MS_RDONLY
			attack:   syscallEventWithArgs("containerd", nrMount, 0, 0, 0, 4096), // MS_BIND
			whatever: "mount",
		},
		{
			name:     "reading own registers does not mask attaching to another process",
			learned:  syscallEventWithArgs("gdb", nrPtrace, 12), // PTRACE_GETREGS
			attack:   syscallEventWithArgs("gdb", nrPtrace, 16), // PTRACE_ATTACH
			whatever: "ptrace",
		},
		{
			name:     "mount namespace does not mask a user namespace",
			learned:  syscallEventWithArgs("runc", nrUnshare, 0x00020000), // CLONE_NEWNS
			attack:   syscallEventWithArgs("runc", nrUnshare, 0x10000000), // CLONE_NEWUSER
			whatever: "unshare",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := NewDriftBaselineProfiler(DriftBaselineConfig{
				Enabled:        true,
				LearningPeriod: 0,
				MinSamples:     1,
				PerWorkload:    true,
			}, nil)

			// Learn the benign form, then promote.
			p.Observe("drift_dangerous_syscall", tc.learned)
			if p.Observe("drift_dangerous_syscall", tc.learned) {
				t.Fatal("learned signature alerted after promotion")
			}
			if !p.Observe("drift_dangerous_syscall", tc.attack) {
				t.Fatalf("%s: novel argument did not alert — signature collapsed to the bare syscall number", tc.whatever)
			}
		})
	}
}

// TestDriftSyscallArgsAllZeroIsNotBPFMapCreate pins the guard against the
// sys_exit path: when the syscall_args map misses, the event arrives with all
// six registers zero. bpf(0, ...) is BPF_MAP_CREATE, so an unguarded read
// would learn a real escape primitive from a dropped map entry.
func TestDriftSyscallArgsAllZeroIsNotBPFMapCreate(t *testing.T) {
	lost := driftSignatureTarget(syscallEventWithArgs("systemd", 321))
	mapCreate := driftSignatureTarget(syscallEventWithArgs("systemd", 321, 0, 1))
	if lost == mapCreate {
		t.Fatalf("lost arguments and BPF_MAP_CREATE share signature %q", lost)
	}
	if !strings.Contains(lost, driftSyscallArgUnknown) {
		t.Fatalf("lost arguments rendered as %q, want the %q marker", lost, driftSyscallArgUnknown)
	}
	if !strings.Contains(mapCreate, "MAP_CREATE") {
		t.Fatalf("bpf cmd not decoded: %q", mapCreate)
	}
}

// TestDriftSyscallArgFormatting pins the human-readable form of the signature
// fragment, since it is what an operator reads in /debug/state and in the
// alert. Unknown flag bits must survive as a hex remainder rather than being
// dropped, or two different flag sets collapse into one signature.
func TestDriftSyscallArgFormatting(t *testing.T) {
	if got := mountFlagNames(4096 | 16384); got != "MS_BIND|MS_REC" {
		t.Errorf("mount flags: got %q", got)
	}
	if got := mountFlagNames(0xC0ED0000 | 1); got != "MS_RDONLY" {
		t.Errorf("MS_MGC_VAL not masked: got %q", got)
	}
	if got := cloneNamespaceFlagNames(0x10000000 | 0x00020000); got != "CLONE_NEWNS|CLONE_NEWUSER" {
		t.Errorf("clone flags: got %q", got)
	}
	if got := mountFlagNames(1 << 30); got != "0x40000000" {
		t.Errorf("unknown flag bits must survive: got %q", got)
	}
	if got := ptraceRequestName(0x4206); got != "PTRACE_SEIZE" {
		t.Errorf("ptrace request: got %q", got)
	}
}

// TestDriftBaselineReportsEachSignatureOnce covers the volume half of the
// problem. A drift rule reports a change of state, and a state change deserves
// one alert — not one per recurrence of the new binary. Before this, alert
// volume tracked how often the novel thing ran (a property of the workload,
// not of the drift), which is what made measurement №6.0's <=100/hour ceiling
// unusable as a criterion.
func TestDriftBaselineReportsEachSignatureOnce(t *testing.T) {
	p := NewDriftBaselineProfiler(DriftBaselineConfig{
		Enabled:        true,
		LearningPeriod: 0,
		MinSamples:     1,
		PerWorkload:    true,
	}, nil)

	known := syscallEventForExec("cron", 59, "/usr/bin/known")
	p.Observe("drift_exec_from_system_bin", known)
	p.Observe("drift_exec_from_system_bin", known)

	novel := syscallEventForExec("cron", 59, "/usr/bin/novel")
	if !p.Observe("drift_exec_from_system_bin", novel) {
		t.Fatal("first occurrence of a novel signature must alert")
	}
	for i := 0; i < 50; i++ {
		if p.Observe("drift_exec_from_system_bin", novel) {
			t.Fatalf("occurrence %d of the same drift alerted again", i+2)
		}
	}

	// A DIFFERENT novel signature still alerts — report-once must dedupe per
	// signature, not silence the workload.
	other := syscallEventForExec("cron", 59, "/usr/bin/other")
	if !p.Observe("drift_exec_from_system_bin", other) {
		t.Fatal("a second, distinct drift was suppressed by report-once")
	}

	states := p.WorkloadStates()
	if len(states) != 1 {
		t.Fatalf("want 1 workload, got %d", len(states))
	}
	if states[0].Reported != 2 {
		t.Errorf("reported count = %d, want 2", states[0].Reported)
	}
}

// TestDriftBaselineRawAnomalyVolumeStaysMeasurable pins the deliberate
// asymmetry: report-once changes what is ALERTED, not what is COUNTED. The
// anomalies_total counter must keep the raw volume so a run can show both what
// the host did and what the operator was paged about.
func TestDriftBaselineRawAnomalyVolumeStaysMeasurable(t *testing.T) {
	p := NewDriftBaselineProfiler(DriftBaselineConfig{
		Enabled:        true,
		LearningPeriod: 0,
		MinSamples:     1,
		PerWorkload:    true,
	}, nil)

	known := syscallEventForExec("cron", 59, "/usr/bin/known")
	p.Observe("drift_exec_from_system_bin", known)
	p.Observe("drift_exec_from_system_bin", known)

	novel := syscallEventForExec("cron", 59, "/usr/bin/novel")
	alerts := 0
	for i := 0; i < 10; i++ {
		if p.Observe("drift_exec_from_system_bin", novel) {
			alerts++
		}
	}
	if alerts != 1 {
		t.Fatalf("alerts = %d, want 1", alerts)
	}
	if got := testutil.ToFloat64(p.anomaliesTotal.WithLabelValues("drift_exec_from_system_bin")); got != 10 {
		t.Errorf("anomalies_total = %v, want 10 (raw volume must survive report-once)", got)
	}
	if got := testutil.ToFloat64(p.suppressedTotal.WithLabelValues("drift_exec_from_system_bin", "already_reported")); got != 9 {
		t.Errorf("suppressed already_reported = %v, want 9", got)
	}
}
