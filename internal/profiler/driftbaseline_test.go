package profiler

import (
	"fmt"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestNormalizeDriftPathPrefix(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"", ""},
		{"/etc/passwd", "/etc/passwd"},
		{"/etc/shadow", "/etc/shadow"},
		{"/proc/12345/mem", "/proc/*"},
		{"/proc/12345/maps", "/proc/*"},
		{"/usr/lib/x86_64-linux-gnu/libc.so.6", "/usr/lib"},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, normalizeDriftPathPrefix(c.path), "path=%q", c.path)
	}
}
