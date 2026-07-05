package k8s

import (
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
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

	mu      sync.Mutex
	tracked map[string][]uint64 // pod UID -> registered cgroup IDs
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
