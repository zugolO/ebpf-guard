package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

// cgroupRoot is the cgroup v2 unified hierarchy mount point.
const cgroupRoot = "/sys/fs/cgroup"

// Cgroup is a transient cgroup v2 directory created by `ebpf-guard run` to
// scope a sandboxed child process. Its inode number is the cgroup ID that
// bpf_get_current_cgroup_id() reports in the LSM hooks, so registering that ID
// with the Manager brings the child (and everything it spawns) under policy.
type Cgroup struct {
	path string
	id   uint64
}

// NewCgroup creates /sys/fs/cgroup/ebpf-guard.sandbox/<name> and returns a
// handle carrying its cgroup ID. Requires cgroup v2 and root.
func NewCgroup(name string) (*Cgroup, error) {
	if _, err := os.Stat(filepath.Join(cgroupRoot, "cgroup.controllers")); err != nil {
		return nil, fmt.Errorf("cgroup v2 not mounted at %s: %w", cgroupRoot, err)
	}
	parent := filepath.Join(cgroupRoot, "ebpf-guard.sandbox")
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return nil, fmt.Errorf("create sandbox parent cgroup: %w", err)
	}
	dir := filepath.Join(parent, name)
	if err := os.Mkdir(dir, 0o755); err != nil && !os.IsExist(err) {
		return nil, fmt.Errorf("create cgroup %s: %w", dir, err)
	}
	id, err := cgroupInode(dir)
	if err != nil {
		return nil, err
	}
	return &Cgroup{path: dir, id: id}, nil
}

// cgroupInode returns the directory inode number, which equals the kernel
// cgroup ID for cgroup v2.
func cgroupInode(dir string) (uint64, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(dir, &st); err != nil {
		return 0, fmt.Errorf("stat cgroup %s: %w", dir, err)
	}
	return st.Ino, nil
}

// ID returns the cgroup ID (directory inode number).
func (c *Cgroup) ID() uint64 { return c.id }

// Path returns the cgroup directory path.
func (c *Cgroup) Path() string { return c.path }

// AddPID moves a process into the cgroup by writing to cgroup.procs.
func (c *Cgroup) AddPID(pid int) error {
	procs := filepath.Join(c.path, "cgroup.procs")
	if err := os.WriteFile(procs, []byte(strconv.Itoa(pid)), 0o644); err != nil {
		return fmt.Errorf("add pid %d to cgroup: %w", pid, err)
	}
	return nil
}

// Remove deletes the cgroup directory. It only succeeds once the cgroup has no
// member processes, so call it after the child has exited.
func (c *Cgroup) Remove() error {
	if err := os.Remove(c.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove cgroup %s: %w", c.path, err)
	}
	return nil
}
