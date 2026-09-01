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

	// sshd's baseline learns execve of the real sshd binary. First-ever-on-host,
	// so it alerts via the №193a global fallback even though sshd itself
	// promotes to enforcing within this same call (MinSamples=1).
	assert.True(t, p.Observe("drift_exec_from_system_bin", syscallEventForExec("sshd", 59, "/usr/sbin/sshd -D -R")))
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
		if i == 0 {
			// №193a: a signature no workload on the host has ever produced
			// alerts on first sight, even while THIS workload is still
			// learning — that is the whole point of the global fallback
			// baseline (an unconditional free pass here is exactly what let
			// a brand-new attacker-controlled workload hide).
			assert.True(t, got, "first-ever-on-host signature must alert even during learning")
			continue
		}
		assert.False(t, got, "repeat matches once the host has seen the signature must be suppressed")
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
	// The first occurrence is novel to the whole host (№193a global fallback),
	// so it alerts despite the workload still learning; the second is already
	// known to the global baseline from the first, so it is suppressed.
	assert.True(t, p.Observe("drift_rule", fileEventForPath("ldconfig", "/etc/ld.so.cache")))
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

	// systemd's baseline learns /etc/systemd/system. First-ever-on-host, so it
	// alerts via the №193a global fallback despite systemd itself still
	// nominally being in its own learning window.
	assert.True(t, p.Observe("drift_rule", fileEventForPath("systemd", "/etc/systemd/system/foo.service")))

	// A different workload (curl) has an independent, still-learning baseline
	// even though systemd already finished learning the same rule ID. Its own
	// baseline hasn't seen this signature, but the GLOBAL one now has (from
	// systemd above), so curl gets the benefit of the global fallback and is
	// suppressed rather than alerting a second time for the same host-wide fact.
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
	// completion path can never fire. First-ever-on-host, so it alerts via
	// the №193a global fallback even though the workload is brand new.
	require.True(t, p.Observe("drift_rule", fileEventForPath("cron", "/etc/cron.d/job")))
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

// Wave 6.0d, finding №198: promotion used to be entirely lazy — a workload
// past its deadline stayed "learning" forever if nothing ever observed
// another match for it, because the deadline was only checked inside
// Observe(). This proves PromoteExpiredWorkloads (and UpdateLearningGauge,
// which now calls it) forces the transition on its own, with no further
// event required.
func TestDriftBaselineProfiler_PeriodicSweepPromotesWithoutFurtherEvents(t *testing.T) {
	cfg := DriftBaselineConfig{
		Enabled:                true,
		LearningPeriod:         3600, // 1h
		MinSamples:             20,   // never reached by this workload
		PerWorkload:            true,
		EnforceDeadlinePeriods: 2, // deadline = 2h
	}
	p := NewDriftBaselineProfiler(cfg, nil)

	base := time.Now()
	current := base
	p.nowFn = func() time.Time { return current }

	require.True(t, p.Observe("drift_rule", fileEventForPath("cron", "/etc/cron.d/job")))

	// Past one LearningPeriod but before the deadline: a genuine blind spot,
	// counted by both the new "stuck" and the old "overdue" definitions.
	current = base.Add(90 * time.Minute)
	assert.Equal(t, 1, p.StuckLearningWorkloads())
	assert.Equal(t, 1, p.LearningOverdueWorkloads())

	// Past the deadline, but crucially: no Observe() call happens here.
	// Lazy promotion (checked only inside Observe) would leave this workload
	// in learning indefinitely.
	current = base.Add(2*time.Hour + time.Minute)
	assert.Equal(t, 1, p.LearningWorkloads(), "still learning until something promotes it")

	promoted := p.PromoteExpiredWorkloads()
	assert.Equal(t, 1, promoted)
	assert.Equal(t, 0, p.LearningWorkloads(), "periodic sweep must promote without waiting for another event")

	// Past the deadline: excluded from "stuck" (genuinely blind right now)
	// but still visible in the deadline-agnostic "overdue" series had it not
	// already promoted — since it's enforcing now, both read 0.
	assert.Equal(t, 0, p.StuckLearningWorkloads())
	assert.Equal(t, 0, p.LearningOverdueWorkloads())

	// A signature never seen during learning alerts, proving enforcing took
	// effect for real, not just in the gauges.
	assert.True(t, p.Observe("drift_rule", fileEventForPath("cron", "/root/.ssh/authorized_keys")))
}

// StuckLearningWorkloads (deadline-aware) and LearningOverdueWorkloads
// (deadline-agnostic) must actually diverge somewhere, or splitting the
// metric into two series (finding №198) was pointless. This puts one
// workload on each side of the deadline within the same snapshot.
func TestDriftBaselineProfiler_StuckVsOverdueDiverge(t *testing.T) {
	cfg := DriftBaselineConfig{
		Enabled:                true,
		LearningPeriod:         3600, // 1h
		MinSamples:             20,
		PerWorkload:            true,
		EnforceDeadlinePeriods: 2, // deadline = 2h
	}
	p := NewDriftBaselineProfiler(cfg, nil)

	base := time.Now()
	current := base
	p.nowFn = func() time.Time { return current }

	require.True(t, p.Observe("drift_rule", fileEventForPath("cron", "/etc/cron.d/job")))

	// Second workload starts an hour later, so at the check time below it is
	// past its LearningPeriod but not past its deadline, while the first is
	// past both.
	current = base.Add(1 * time.Hour)
	require.True(t, p.Observe("drift_rule", fileEventForPath("logrotate", "/etc/logrotate.d/job")))

	current = base.Add(2*time.Hour + time.Minute)
	// cron: elapsed 2h1m — past its 2h deadline, no sweep has run yet.
	// logrotate: elapsed 1h1m — past its 1h LearningPeriod, well inside its
	// own 2h deadline (which started when IT began learning, at base+1h).
	assert.Equal(t, 1, p.StuckLearningWorkloads(), "only logrotate is a live blind spot; cron's deadline has already passed")
	assert.Equal(t, 2, p.LearningOverdueWorkloads(), "both are learning past one period under the old, deadline-agnostic count")
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
	// First-ever-on-host: alerts via the №193a global fallback even though
	// drift-pc is a brand-new workload still in its own learning window.
	require.True(t, p.Observe("drift_exec_from_system_bin", seed))
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
	// Both the "busy" workload's own profile AND the №193a global fallback
	// baseline see the same 10 distinct signatures and hit the same
	// MaxSignaturesPerWorkload cap — the global one saturates first in
	// practice (it sees every workload's signatures), but here there is only
	// one workload, so both saturate together.
	assert.Equal(t, 2, p.SaturatedWorkloads(), "both the workload profile and the global fallback baseline must be flagged saturated")

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

	// "known"'s own first occurrence is itself novel to the whole host, so it
	// alerts via the №193a global fallback (and closes learning, MinSamples=1)
	// before settling into ordinary baseline-known suppression on repeat.
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

	// WorkloadStates also surfaces the №193a global fallback baseline as its
	// own synthetic entry, alongside the one real "cron" workload profile.
	states := p.WorkloadStates()
	if len(states) != 2 {
		t.Fatalf("want 2 states (cron workload + global fallback baseline), got %d", len(states))
	}
	var cronState *DriftWorkloadState
	for i := range states {
		if states[i].Comm == "cron" {
			cronState = &states[i]
		}
	}
	if cronState == nil {
		t.Fatalf("no state for workload cron among %+v", states)
	}
	// 3, not 2: "known"'s own first-ever occurrence also went through the
	// №193a global-fallback alert path (see the comment above the "known"
	// Observe calls) and so is itself marked reported, in addition to "novel"
	// and "other".
	if cronState.Reported != 3 {
		t.Errorf("reported count = %d, want 3", cronState.Reported)
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

	// "known"'s own first occurrence is itself novel to the whole host (№193a
	// global fallback), so it counts one anomaly of its own before settling
	// into ordinary baseline-known suppression on repeat.
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
	if got := testutil.ToFloat64(p.anomaliesTotal.WithLabelValues("drift_exec_from_system_bin")); got != 11 {
		t.Errorf("anomalies_total = %v, want 11 (10 raw novel occurrences + 1 from known's own first-ever-on-host alert)", got)
	}
	if got := testutil.ToFloat64(p.suppressedTotal.WithLabelValues("drift_exec_from_system_bin", "already_reported")); got != 9 {
		t.Errorf("suppressed already_reported = %v, want 9", got)
	}
}

// TestDriftBaselineGlobalFallbackCoversNewWorkload is the direct regression
// guard for finding №193: a workload that has never been seen before, doing
// something no OTHER workload has ever done either, must not get a free pass
// merely because it is new. Before this, a brand-new workload's entire
// learning window suppressed every drift-class match unconditionally — which
// is exactly the shape of an attacker arriving as (or spawning) a workload
// the profiler has no history for.
func TestDriftBaselineGlobalFallbackCoversNewWorkload(t *testing.T) {
	p := NewDriftBaselineProfiler(DriftBaselineConfig{
		Enabled:        true,
		LearningPeriod: 0, // learning completes as soon as MinSamples is hit
		MinSamples:     20,
		PerWorkload:    true,
	}, nil)

	// A well-established workload (already enforcing) generates a signature.
	established := syscallEventForExec("nginx", 165, "") // mount, no proc.args
	for i := 0; i < 25; i++ {
		p.Observe("drift_new_library_in_system_dir", established)
	}
	require.Equal(t, 0, p.LearningWorkloads(), "nginx should have promoted to enforcing")

	// A workload the profiler has NEVER seen before makes the SAME kind of
	// call (same rule, same signature target). It is brand new — the
	// pre-6.0d behavior would suppress this unconditionally as "learning" —
	// but the global baseline already knows this exact signature from nginx,
	// so it is not the free-pass case finding №193 is about.
	newButKnownGlobally := syscallEventForExec("some-new-daemon", 165, "")
	assert.False(t, p.Observe("drift_new_library_in_system_dir", newButKnownGlobally),
		"a signature already known host-wide must stay suppressed for a new workload")

	// A DIFFERENT new workload does something no workload — new or
	// established — has ever done on this host. This is the actual finding
	// №193 scenario, and it must alert despite the workload being new and
	// still deep in its own learning window.
	genuinelyNovel := syscallEventForExec("another-new-daemon", 272, "") // unshare
	assert.True(t, p.Observe("drift_dangerous_syscall", genuinelyNovel),
		"a signature unknown to every workload on the host must alert even for a brand-new workload")
}

// TestDriftBaselineNovelWorkloadFlagBypassesGlobalFallback covers finding
// №193(б): for the subset of rules flagged DriftNovelWorkload=alert
// (container/namespace-escape primitives), a new workload gets NEITHER its
// own presumption of innocence NOR the global fallback's — even a signature
// every other workload on the host produces routinely still alerts the first
// time THIS workload makes it, because the rule considers "normal for
// everyone else" an insufficient excuse for "novel to me".
func TestDriftBaselineNovelWorkloadFlagBypassesGlobalFallback(t *testing.T) {
	p := NewDriftBaselineProfiler(DriftBaselineConfig{
		Enabled:        true,
		LearningPeriod: 0, // learning completes as soon as MinSamples is hit
		MinSamples:     20,
		PerWorkload:    true,
	}, nil)

	// runc routinely calls unshare(CLONE_NEWUSER) while building container
	// namespaces; its own baseline (and the global one) learns this as normal.
	routine := syscallEventWithArgs("runc", 272, 0x10000000) // CLONE_NEWUSER
	for i := 0; i < 25; i++ {
		p.ObserveRule("container_escape_unshare_user", routine, false)
	}
	require.Equal(t, 0, p.LearningWorkloads(), "runc should have promoted to enforcing")

	// Without the flag, a brand-new workload doing the exact same routine
	// call gets the global fallback's benefit of the doubt.
	assert.False(t, p.ObserveRule("container_escape_unshare_user",
		syscallEventWithArgs("evil-new-proc", 272, 0x10000000), false),
		"without the flag, a new workload is covered by the global fallback for a host-routine signature")

	// WITH the flag, a different brand-new workload doing the identical call
	// is not excused by either its own learning phase or the global fallback.
	assert.True(t, p.ObserveRule("container_escape_unshare_user",
		syscallEventWithArgs("another-evil-proc", 272, 0x10000000), true),
		"drift_novel_workload:alert must not be excused by the global fallback either")
}

// TestDriftBaselineGlobalFallbackSuppressionHasOwnReason is the regression
// guard for wave 6.0f (№203): a learning-phase suppression that goes through
// because the GLOBAL fallback baseline already knows the signature must be
// counted under reason="global_baseline_known", not lumped into the generic
// "learning" bucket alongside "nobody has any information yet" — the two
// are different mechanisms and criterion 6.0.11 needs to tell them apart.
func TestDriftBaselineGlobalFallbackSuppressionHasOwnReason(t *testing.T) {
	p := NewDriftBaselineProfiler(DriftBaselineConfig{
		Enabled:        true,
		LearningPeriod: 0,
		MinSamples:     20,
		PerWorkload:    true,
	}, nil)

	established := syscallEventForExec("nginx", 59, "/usr/bin/known")
	for i := 0; i < 25; i++ {
		p.Observe("drift_exec_from_system_bin", established)
	}
	require.Equal(t, 0, p.LearningWorkloads(), "nginx should have promoted to enforcing")

	// nginx's own learning already routes 19 of its 25 calls through
	// global_baseline_known: call 1 is genuinely novel (alerts, not
	// suppressed), calls 2-20 repeat the same signature while nginx itself
	// is still learning but the global fallback (taught by call 1) already
	// knows it, and calls 21-25 land in ordinary per-workload
	// baseline_known once nginx promotes to enforcing at call 20.
	before := testutil.ToFloat64(p.suppressedTotal.WithLabelValues("drift_exec_from_system_bin", "global_baseline_known"))
	require.Equal(t, float64(19), before)

	// A brand-new workload repeats the exact signature nginx already taught
	// the global fallback. It is suppressed (still learning, global knows
	// it) — that suppression must land under global_baseline_known too.
	newWorkload := syscallEventForExec("some-new-daemon", 59, "/usr/bin/known")
	assert.False(t, p.Observe("drift_exec_from_system_bin", newWorkload))

	if got := testutil.ToFloat64(p.suppressedTotal.WithLabelValues("drift_exec_from_system_bin", "global_baseline_known")); got != before+1 {
		t.Errorf("suppressed global_baseline_known = %v, want %v", got, before+1)
	}
	if got := testutil.ToFloat64(p.suppressedTotal.WithLabelValues("drift_exec_from_system_bin", "learning")); got != 0 {
		t.Errorf("suppressed learning = %v, want 0 — this suppression must not double-count under the generic reason", got)
	}
}

// TestDriftBaselineWorkloadStatesAgreeWithGauges pins the /debug/state ↔
// /metrics agreement the 6.0d redefinitions could silently break. Two
// separate ways they could disagree, both of the 5.9.4c class ("two registers
// about the same set of rules did not match"):
//
//   - the global fallback baseline (№193a) is exempt from MaxWorkloads and
//     absent from ProfileCount(), so it must carry its own state label rather
//     than being counted as a workload profile;
//   - "stuck" was redefined by №198 to exclude past-deadline workloads (the
//     periodic sweep promotes those without waiting for a match), so the
//     per-row state string must use the same cut as StuckLearningWorkloads()
//     instead of the pre-6.0d, deadline-agnostic one.
func TestDriftBaselineWorkloadStatesAgreeWithGauges(t *testing.T) {
	cfg := DriftBaselineConfig{
		Enabled:                true,
		LearningPeriod:         3600, // 1h
		MinSamples:             20,
		PerWorkload:            true,
		EnforceDeadlinePeriods: 2, // deadline = 2h
	}
	p := NewDriftBaselineProfiler(cfg, nil)

	base := time.Now()
	current := base
	p.nowFn = func() time.Time { return current }

	require.True(t, p.Observe("drift_rule", fileEventForPath("cron", "/etc/cron.d/job")))
	current = base.Add(1 * time.Hour)
	require.True(t, p.Observe("drift_rule", fileEventForPath("logrotate", "/etc/logrotate.d/job")))
	current = base.Add(2*time.Hour + time.Minute)

	byState := map[string]int{}
	for _, w := range p.WorkloadStates() {
		byState[w.State]++
	}
	assert.Equal(t, 1, byState["stuck"], "stuck rows must match StuckLearningWorkloads()")
	assert.Equal(t, byState["stuck"], p.StuckLearningWorkloads())
	assert.Equal(t, 1, byState["overdue"], "past-deadline learning is overdue, not stuck (№198)")
	assert.Equal(t, byState["stuck"]+byState["overdue"], p.LearningOverdueWorkloads())
	assert.Equal(t, 1, byState["global"], "the global fallback baseline gets its own row (№193a)")

	// The global row is NOT a workload profile: it must not inflate the count
	// the profiles gauge reports.
	assert.Equal(t, 2, p.ProfileCount())
	assert.Equal(t, len(p.WorkloadStates())-1, p.ProfileCount(),
		"WorkloadStates carries exactly one row beyond the profile count: the global baseline")
}
