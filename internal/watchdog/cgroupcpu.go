// cgroupcpu.go — effective CPU budget of the agent's own cgroup.
//
// The CPU pressure watcher scales its thresholds by "how many cores the agent
// may use". runtime.NumCPU() answers that for a host, but in a pod with
// limits.cpu=500m it still reports the node's cores: the L1 threshold became
// 4 × 40% = 160% of one core, unreachable under a 0.5-core quota, so shedding
// never fired in the pod (plan.md волна 8.8, Р2 / Е6 finding 6). The cgroup
// quota is the real budget; NumCPU is only the fallback when no quota is set.

package watchdog

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// cgroupRoot is the cgroup filesystem mount point; a variable for tests.
var cgroupRoot = "/sys/fs/cgroup"

// procSelfCgroup is the file naming this process's cgroup; a variable for tests.
var procSelfCgroup = "/proc/self/cgroup"

// parseCPUMax parses cgroup v2 cpu.max ("<quota|max> <period>") into cores.
// ok is false for "max" (no quota) or malformed input.
func parseCPUMax(data string) (cores float64, ok bool) {
	f := strings.Fields(data)
	if len(f) < 1 || f[0] == "max" {
		return 0, false
	}
	quota, err := strconv.ParseFloat(f[0], 64)
	if err != nil || quota <= 0 {
		return 0, false
	}
	period := 100000.0 // kernel default
	if len(f) >= 2 {
		if p, err := strconv.ParseFloat(f[1], 64); err == nil && p > 0 {
			period = p
		}
	}
	return quota / period, true
}

// parseCFSQuota parses cgroup v1 cpu.cfs_quota_us and cpu.cfs_period_us.
func parseCFSQuota(quotaData, periodData string) (cores float64, ok bool) {
	quota, err := strconv.ParseFloat(strings.TrimSpace(quotaData), 64)
	if err != nil || quota <= 0 { // -1 == unlimited
		return 0, false
	}
	period, err := strconv.ParseFloat(strings.TrimSpace(periodData), 64)
	if err != nil || period <= 0 {
		return 0, false
	}
	return quota / period, true
}

// cgroupPaths returns the relative cgroup paths of this process: v2 ("0::")
// first, then v1 "cpu"/"cpu,cpuacct" controller paths. A container with its own
// cgroup namespace reports "/", which resolves to the mount root itself.
func cgroupPaths() (v2 string, v1 string) {
	b, err := os.ReadFile(procSelfCgroup)
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		switch {
		case parts[0] == "0" && parts[1] == "":
			v2 = parts[2]
		case parts[1] == "cpu" || parts[1] == "cpu,cpuacct" || parts[1] == "cpuacct,cpu":
			v1 = parts[2]
		}
	}
	return v2, v1
}

// cgroupCPUQuota returns the tightest CPU quota (in cores) that applies to this
// process, walking from its cgroup up to the mount root: a pod limit may sit on
// the parent of the container's own cgroup. ok is false when no level sets one.
func cgroupCPUQuota() (cores float64, ok bool) {
	v2, v1 := cgroupPaths()
	best := 0.0
	found := false
	consider := func(c float64, have bool) {
		if have && (!found || c < best) {
			best, found = c, true
		}
	}

	// v2: walk "<root>/<v2>" up to "<root>".
	dir := filepath.Join(cgroupRoot, filepath.Clean("/"+v2))
	for {
		if b, err := os.ReadFile(filepath.Join(dir, "cpu.max")); err == nil {
			consider(parseCPUMax(string(b)))
		}
		if dir == cgroupRoot || !strings.HasPrefix(dir, cgroupRoot) {
			break
		}
		dir = filepath.Dir(dir)
	}
	if found {
		return best, true
	}

	// v1: <root>/cpu[,cpuacct]/<v1>
	for _, ctrl := range []string{"cpu", "cpu,cpuacct"} {
		base := filepath.Join(cgroupRoot, ctrl)
		dir := filepath.Join(base, filepath.Clean("/"+v1))
		for {
			q, errQ := os.ReadFile(filepath.Join(dir, "cpu.cfs_quota_us"))
			p, errP := os.ReadFile(filepath.Join(dir, "cpu.cfs_period_us"))
			if errQ == nil && errP == nil {
				consider(parseCFSQuota(string(q), string(p)))
			}
			if dir == base || !strings.HasPrefix(dir, base) {
				break
			}
			dir = filepath.Dir(dir)
		}
		if found {
			return best, true
		}
	}
	return 0, false
}

// effectiveCPUs is the CPU budget thresholds are scaled by: the cgroup quota
// when set (never above the host's cores), otherwise runtime.NumCPU(). The
// second result names the source ("cgroup" or "numcpu") for the log line.
func effectiveCPUs() (float64, string) {
	n := float64(runtime.NumCPU())
	if n < 1 {
		n = 1
	}
	if q, ok := cgroupCPUQuota(); ok {
		if q > n {
			q = n
		}
		return q, "cgroup"
	}
	return n, "numcpu"
}
