package profiler

import (
	"testing"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
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
