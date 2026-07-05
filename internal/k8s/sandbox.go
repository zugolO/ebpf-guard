package k8s

import (
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// CgroupRegistrar is the subset of *sandbox.Manager the controller needs. Kept
// as an interface so this package doesn't import internal/sandbox and so the
// controller can be unit-tested with a fake.
type CgroupRegistrar interface {
	RegisterCgroup(cgroupID uint64, profileName string) error
	UnregisterCgroup(cgroupID uint64) error
}

// CgroupResolver maps a container ID to the cgroup IDs (directory inodes) of
// its cgroup v2 subtree. Injected so the label matching can be tested without a
// real cgroup filesystem.
type CgroupResolver func(containerID string) ([]uint64, error)

// SandboxController watches pod events and applies an ai_sandbox profile to the
// cgroups of pods carrying the sandbox label (issue #255, sub-task 4). The
// label's value names the profile; removing the label or deleting the pod
// unregisters its cgroups.
type SandboxController struct {
	label    string
	reg      CgroupRegistrar
	resolver CgroupResolver
	logger   *slog.Logger

	// now is the clock used to measure the unenforced startup window; a field so
	// tests can pin it. Defaults to time.Now.
	now func() time.Time

	mu      sync.Mutex
	tracked map[string][]uint64 // pod UID -> registered cgroup IDs

	// Unenforced-window accounting (issue #277 P1). A pod's containers run from
	// the moment the kubelet starts them (image entrypoint, init) but the
	// sandbox profile only attaches once the pod informer fires and the
	// container cgroups resolve — so there is a window in which the workload is
	// live but unsandboxed. Post-hoc cgroup labeling cannot close it; we surface
	// it instead so operators can size the mitigation (init delay / readiness
	// gate) and know it is non-zero. See docs/ai-agent-sandbox.md.
	lateRegistrations int           // pods sandboxed after their containers had already started
	maxWindow         time.Duration // largest observed start→enforce gap
}

// NewSandboxController creates a controller that applies profiles named by the
// value of labelKey. A nil resolver defaults to the on-node cgroupfs resolver.
func NewSandboxController(labelKey string, reg CgroupRegistrar, resolver CgroupResolver, logger *slog.Logger) *SandboxController {
	if logger == nil {
		logger = slog.Default()
	}
	if resolver == nil {
		resolver = resolveContainerCgroupIDs
	}
	return &SandboxController{
		label:    labelKey,
		reg:      reg,
		resolver: resolver,
		logger:   logger.With("component", "ai_sandbox_k8s"),
		now:      time.Now,
		tracked:  make(map[string][]uint64),
	}
}

// Register wires the controller into a Watcher's pod event stream.
func (c *SandboxController) Register(w *Watcher) {
	w.AddPodEventHandler(c.OnPodEvent)
}

// OnPodEvent reconciles one pod lifecycle event against the sandbox label.
func (c *SandboxController) OnPodEvent(evt PodEvent, info *PodInfo) {
	if info == nil {
		return
	}
	profile := info.Labels[c.label]

	if evt == PodDeleted || profile == "" {
		// Pod gone, or label absent/removed → drop any tracked registration.
		c.release(info.UID)
		return
	}
	c.apply(info, profile)
}

// apply registers the pod's container cgroups under profile, idempotently.
func (c *SandboxController) apply(info *PodInfo, profile string) {
	c.mu.Lock()
	_, already := c.tracked[info.UID]
	c.mu.Unlock()
	if already {
		return // already registered; profile changes require pod recreation
	}

	var ids []uint64
	for _, cid := range info.ContainerIDs {
		cgIDs, err := c.resolver(cid)
		if err != nil {
			c.logger.Warn("resolve container cgroup",
				"pod", info.Name, "container", cid, "error", err)
			continue
		}
		for _, id := range cgIDs {
			if err := c.reg.RegisterCgroup(id, profile); err != nil {
				c.logger.Warn("register cgroup", "pod", info.Name, "cgroup_id", id, "error", err)
				continue
			}
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return
	}
	c.mu.Lock()
	c.tracked[info.UID] = ids
	c.mu.Unlock()
	c.logger.Info("pod placed under ai_sandbox profile",
		"pod", info.Name, "namespace", info.Namespace, "profile", profile, "cgroups", len(ids))
	c.recordEnforcementWindow(info, profile)
}

// recordEnforcementWindow measures and surfaces the unenforced startup window
// for a pod we just placed under a profile (issue #277 P1). StartTime is when
// the kubelet began the pod's containers; the difference to now is how long the
// workload ran unsandboxed before enforcement attached. This is a real gap that
// post-hoc cgroup registration cannot close — it is intrinsic to informer-driven
// targeting — so we make it visible (warn + accounting) rather than pretend the
// pod was contained from birth. A zero/absent StartTime (kubelet has not set it,
// or a synthetic PodInfo) is skipped: there is nothing to measure.
func (c *SandboxController) recordEnforcementWindow(info *PodInfo, profile string) {
	if info.StartTime.IsZero() {
		return
	}
	window := c.now().Sub(info.StartTime)
	if window <= 0 {
		return // started at/after enforcement — no observable unenforced window
	}
	c.mu.Lock()
	c.lateRegistrations++
	if window > c.maxWindow {
		c.maxWindow = window
	}
	c.mu.Unlock()
	c.logger.Warn("ai_sandbox: pod ran unsandboxed before enforcement attached — "+
		"its containers started before the informer could register their cgroups; "+
		"the image entrypoint/init ran outside the sandbox for this window",
		"pod", info.Name, "namespace", info.Namespace, "profile", profile,
		"unenforced_window", window.Round(time.Millisecond).String(),
		"mitigation", "gate the workload behind an init container / readiness delay, or "+
			"pre-register the cgroup at admission time (a CRI/OCI hook); see "+
			"docs/ai-agent-sandbox.md#kubernetes-the-unenforced-startup-window")
}

// UnenforcedWindowStats reports how many pods were sandboxed only after their
// containers had already started, and the largest observed start→enforce gap.
// Exposed for status/metrics so an operator can see the unenforced startup
// window is non-zero and size the mitigation (issue #277 P1).
func (c *SandboxController) UnenforcedWindowStats() (lateRegistrations int, maxWindow time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lateRegistrations, c.maxWindow
}

// release unregisters all cgroups previously tracked for a pod UID.
func (c *SandboxController) release(uid string) {
	c.mu.Lock()
	ids := c.tracked[uid]
	delete(c.tracked, uid)
	c.mu.Unlock()
	for _, id := range ids {
		if err := c.reg.UnregisterCgroup(id); err != nil {
			c.logger.Warn("unregister cgroup", "cgroup_id", id, "error", err)
		}
	}
	if len(ids) > 0 {
		c.logger.Info("pod removed from ai_sandbox", "uid", uid, "cgroups", len(ids))
	}
}

// nonPodCgroupSlices are top-level cgroupfs subtrees that never contain
// container/pod cgroups under any of the common driver layouts. Kubernetes
// containers always live under kubepods(.slice); pruning these well-known
// sibling slices avoids a full recursive walk of the entire host cgroup tree
// (which can hold thousands of entries) for every container lookup (issue
// #272). Unrecognised top-level entries are still walked, so this is
// conservative rather than an exhaustive allow-list.
var nonPodCgroupSlices = map[string]bool{
	"init.scope":    true,
	"system.slice":  true,
	"user.slice":    true,
	"machine.slice": true,
}

// resolveContainerCgroupIDs finds the cgroup v2 directories belonging to a
// container and returns their inode numbers (== kernel cgroup IDs). It matches
// on the container ID substring in the cgroup path, which covers the common
// systemd (`...-<id>.scope`) and cgroupfs (`.../<id>`) driver layouts.
func resolveContainerCgroupIDs(containerID string) ([]uint64, error) {
	const cgroupRoot = "/sys/fs/cgroup"
	if containerID == "" {
		return nil, fmt.Errorf("empty container id")
	}
	var ids []uint64
	err := filepath.WalkDir(cgroupRoot, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || !d.IsDir() {
			return nil
		}
		// Prune known non-pod slices right at the top level instead of
		// descending into them (they can hold most of a busy host's cgroups).
		if rel, relErr := filepath.Rel(cgroupRoot, path); relErr == nil && nonPodCgroupSlices[rel] {
			return fs.SkipDir
		}
		if !strings.Contains(filepath.Base(path), containerID) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			ids = append(ids, st.Ino)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", cgroupRoot, err)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("no cgroup dir found for container %s", containerID)
	}
	return ids, nil
}
