package watchdog

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseCPUMax(t *testing.T) {
	c, ok := parseCPUMax("50000 100000\n")
	assert.True(t, ok)
	assert.InDelta(t, 0.5, c, 1e-9)

	c, ok = parseCPUMax("200000 100000")
	assert.True(t, ok)
	assert.InDelta(t, 2.0, c, 1e-9)

	_, ok = parseCPUMax("max 100000")
	assert.False(t, ok)
	_, ok = parseCPUMax("")
	assert.False(t, ok)
	_, ok = parseCPUMax("garbage")
	assert.False(t, ok)
}

func TestParseCFSQuota(t *testing.T) {
	c, ok := parseCFSQuota("50000\n", "100000\n")
	assert.True(t, ok)
	assert.InDelta(t, 0.5, c, 1e-9)
	_, ok = parseCFSQuota("-1\n", "100000\n")
	assert.False(t, ok)
}

// fakeCgroup points the package at a temp cgroup tree.
func fakeCgroup(t *testing.T, selfCgroup string, files map[string]string) {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(root, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(content), 0o644))
	}
	self := filepath.Join(t.TempDir(), "cgroup")
	require.NoError(t, os.WriteFile(self, []byte(selfCgroup), 0o644))
	oldRoot, oldSelf := cgroupRoot, procSelfCgroup
	cgroupRoot, procSelfCgroup = root, self
	t.Cleanup(func() { cgroupRoot, procSelfCgroup = oldRoot, oldSelf })
}

func TestCgroupCPUQuota_V2OwnLevel(t *testing.T) {
	fakeCgroup(t, "0::/kubepods/pod1/ctr\n", map[string]string{
		"kubepods/pod1/ctr/cpu.max": "50000 100000\n",
	})
	c, ok := cgroupCPUQuota()
	assert.True(t, ok)
	assert.InDelta(t, 0.5, c, 1e-9)
}

func TestCgroupCPUQuota_V2ParentLimitWins(t *testing.T) {
	fakeCgroup(t, "0::/kubepods/pod1/ctr\n", map[string]string{
		"kubepods/pod1/ctr/cpu.max": "max 100000\n",
		"kubepods/pod1/cpu.max":     "150000 100000\n",
		"cpu.max":                   "max 100000\n",
	})
	c, ok := cgroupCPUQuota()
	assert.True(t, ok)
	assert.InDelta(t, 1.5, c, 1e-9)
}

func TestCgroupCPUQuota_NamespacedRoot(t *testing.T) {
	// A container with its own cgroup namespace sees "/" and a root cpu.max.
	fakeCgroup(t, "0::/\n", map[string]string{"cpu.max": "50000 100000\n"})
	c, ok := cgroupCPUQuota()
	assert.True(t, ok)
	assert.InDelta(t, 0.5, c, 1e-9)
}

func TestCgroupCPUQuota_V1(t *testing.T) {
	fakeCgroup(t, "4:cpu,cpuacct:/kubepods/ctr\n3:memory:/x\n", map[string]string{
		"cpu,cpuacct/kubepods/ctr/cpu.cfs_quota_us":  "50000\n",
		"cpu,cpuacct/kubepods/ctr/cpu.cfs_period_us": "100000\n",
	})
	c, ok := cgroupCPUQuota()
	assert.True(t, ok)
	assert.InDelta(t, 0.5, c, 1e-9)
}

func TestCgroupCPUQuota_NoQuota(t *testing.T) {
	fakeCgroup(t, "0::/user.slice\n", map[string]string{"user.slice/cpu.max": "max 100000\n"})
	_, ok := cgroupCPUQuota()
	assert.False(t, ok)
	n, src := effectiveCPUs()
	assert.Equal(t, "numcpu", src)
	assert.GreaterOrEqual(t, n, 1.0)
}

// Р2 / 8.8.5: in a pod with a 0.5-core quota the thresholds must be 0.5× the
// per-core defaults (file shed at 20% of one core), so shedding is reachable.
func TestCPUWatcher_ThresholdsFollowCgroupQuota(t *testing.T) {
	fakeCgroup(t, "0::/ctr\n", map[string]string{"ctr/cpu.max": "50000 100000\n"})
	w := NewCPUPressureWatcher(DefaultCPUConfig(), nil, nil)
	assert.InDelta(t, 0.5, w.budgetCores, 1e-9)
	assert.Equal(t, "cgroup", w.budgetSource)
	assert.InDelta(t, 20.0, w.fileShedThreshold, 1e-9)
	assert.InDelta(t, 35.0, w.allShedThreshold, 1e-9)
	assert.InDelta(t, 10.0, w.recoveryThreshold, 1e-9)
	_ = time.Second
}
