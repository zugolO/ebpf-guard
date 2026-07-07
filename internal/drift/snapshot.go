// Package drift implements container drift detection by comparing runtime
// behaviour against a per-container baseline captured at startup.
package drift

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// ImageSnapshotter captures the set of executable files present in a container
// image at startup by walking overlayfs lower directories. This enables
// drift detection against the actual image manifest rather than relying
// solely on a runtime learning window.
type ImageSnapshotter struct {
	logger *slog.Logger
}

// NewImageSnapshotter creates a snapshotter with the given logger.
func NewImageSnapshotter(logger *slog.Logger) *ImageSnapshotter {
	return &ImageSnapshotter{logger: logger}
}

// ImageManifest holds the set of paths found in a container image's layers.
type ImageManifest struct {
	ContainerID string
	ExecPaths   map[string]struct{} // absolute paths to executable files in the image
	TotalFiles  int                 // total regular files scanned
	Error       error               // non-nil if snapshot failed
}

// SnapshotFromPID captures the set of executable file paths visible in the
// container identified by pid. It reads /proc/[pid]/mountinfo to find
// overlayfs lower directories, then walks them to collect all regular files
// with executable permissions.
//
// Returns nil if the snapshot cannot be performed (container already exited,
// no overlayfs mounts found, no access to lowerdir).
func (s *ImageSnapshotter) SnapshotFromPID(containerID string, pid uint32) *ImageManifest {
	m := &ImageManifest{
		ContainerID: containerID,
		ExecPaths:   make(map[string]struct{}),
	}

	lowerDirs, err := readOverlayLowerDirs(pid)
	if err != nil {
		m.Error = fmt.Errorf("read overlay lowerdirs: %w", err)
		s.logger.Debug("drift: image snapshot failed — overlayfs",
			slog.String("container_id", containerID),
			slog.Any("error", err))
		return m
	}

	if len(lowerDirs) == 0 {
		m.Error = fmt.Errorf("no overlayfs lowerdirs found")
		return m
	}

	s.walkLowerDirs(m, lowerDirs)

	s.logger.Info("drift: image manifest snapshot complete",
		slog.String("container_id", containerID),
		slog.Int("exec_paths", len(m.ExecPaths)),
		slog.Int("total_files", m.TotalFiles),
	)
	return m
}

// walkLowerDirs walks each overlayfs lower directory, recording every regular,
// non-symlink file with an executable bit set into m.ExecPaths. Split out from
// SnapshotFromPID so the walk itself can be exercised with real temp
// directories in tests, independent of the container's mount namespace.
func (s *ImageSnapshotter) walkLowerDirs(m *ImageManifest, lowerDirs []string) {
	for _, dir := range lowerDirs {
		walkErr := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil // skip unreadable entries
			}
			if d.IsDir() {
				return nil
			}
			if d.Type()&os.ModeSymlink != 0 {
				return nil // skip symlinks; the target is in another layer
			}
			m.TotalFiles++
			info, statErr := d.Info()
			if statErr != nil {
				return nil
			}
			if info.Mode()&0111 != 0 {
				m.ExecPaths[path] = struct{}{}
			}
			return nil
		})
		if walkErr != nil {
			s.logger.Debug("drift: image snapshot walk error",
				slog.String("dir", dir),
				slog.Any("error", walkErr))
		}
	}
}

// readOverlayLowerDirs reads /proc/[pid]/mountinfo and extracts the lowerdir
// paths for all overlay filesystem mounts in the container's mount namespace.
// Returns a deduplicated, ordered list of layer directories.
func readOverlayLowerDirs(pid uint32) ([]string, error) {
	mi, err := os.Open(fmt.Sprintf("/proc/%d/mountinfo", pid))
	if err != nil {
		return nil, err
	}
	defer mi.Close()
	return parseOverlayLowerDirs(mi)
}

// parseOverlayLowerDirs scans mountinfo content for overlay mounts and
// returns their deduplicated, existing lowerdir paths. Split out from
// readOverlayLowerDirs so the parsing logic can be tested against synthetic
// mountinfo content instead of requiring a real overlayfs mount.
func parseOverlayLowerDirs(mountinfo io.Reader) ([]string, error) {
	seen := make(map[string]struct{})
	var dirs []string

	scanner := bufio.NewScanner(mountinfo)
	for scanner.Scan() {
		line := scanner.Text()
		dir, ok := extractOverlayLowerDir(line)
		if !ok {
			continue
		}
		for _, d := range splitLowerDirs(dir) {
			d = strings.TrimSpace(d)
			if d == "" {
				continue
			}
			// Resolve symlinks in the layer path.
			if resolved, err := filepath.EvalSymlinks(d); err == nil {
				d = resolved
			}
			if _, exists := seen[d]; exists {
				continue
			}
			// Verify the directory still exists and is accessible.
			if fi, err := os.Stat(d); err == nil && fi.IsDir() {
				seen[d] = struct{}{}
				dirs = append(dirs, d)
			}
		}
	}
	return dirs, scanner.Err()
}

// extractOverlayLowerDir parses a mountinfo line and returns the lowerdir
// value if it is an overlay filesystem mount.
//
// mountinfo format (procfs(5)):
//
//	36 35 98:0 / /mnt rw,noatime master:1 - ext3 /dev/root rw,noatime
//	(1)(2) (3) (4)(5)     (6)      (7)   (8)(9)     (10)       (11)
//
// Fields 7+ are zero or more optional fields, terminated by a literal "-"
// separator token. The lowerdir= option lives in the super options, i.e. the
// third token after the separator (fs type, mount source, super options) —
// NOT in the pre-separator mount options field (which only carries VFS-level
// flags like "rw,relatime" for overlay mounts).
func extractOverlayLowerDir(line string) (string, bool) {
	fields := strings.Fields(line)

	sepIdx := -1
	for i, f := range fields {
		if f == "-" {
			sepIdx = i
			break
		}
	}
	// Need at least "- fstype source superopts" after the separator.
	if sepIdx < 0 || sepIdx+3 >= len(fields) {
		return "", false
	}
	if fields[sepIdx+1] != "overlay" {
		return "", false
	}

	superOpts := fields[sepIdx+3]
	for _, opt := range strings.Split(superOpts, ",") {
		if strings.HasPrefix(opt, "lowerdir=") {
			return strings.TrimPrefix(opt, "lowerdir="), true
		}
	}
	return "", false
}

// splitLowerDirs splits a lowerdir value by colons, respecting escaped colons.
func splitLowerDirs(lowerDir string) []string {
	var dirs []string
	current := strings.Builder{}
	escapeNext := false

	for _, ch := range lowerDir {
		if escapeNext {
			current.WriteRune(ch)
			escapeNext = false
			continue
		}
		if ch == '\\' {
			escapeNext = true
			continue
		}
		if ch == ':' {
			dirs = append(dirs, current.String())
			current.Reset()
			continue
		}
		current.WriteRune(ch)
	}
	if current.Len() > 0 {
		dirs = append(dirs, current.String())
	}
	return dirs
}
