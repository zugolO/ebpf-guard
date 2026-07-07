package drift

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─────────────────────────────────────────────────────────────────────────────
// parseOverlayLowerDirs
// ─────────────────────────────────────────────────────────────────────────────

func TestParseOverlayLowerDirs_ExistingDirsReturned(t *testing.T) {
	layer1 := t.TempDir()
	layer2 := t.TempDir()

	mountinfo := "46 37 0:36 / /merged rw,relatime - overlay overlay " +
		"rw,lowerdir=" + layer1 + ":" + layer2 + ",upperdir=/u,workdir=/w\n"

	dirs, err := parseOverlayLowerDirs(strings.NewReader(mountinfo))
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{layer1, layer2}, dirs)
}

func TestParseOverlayLowerDirs_NonexistentDirFiltered(t *testing.T) {
	real := t.TempDir()
	fake := filepath.Join(t.TempDir(), "does-not-exist")

	mountinfo := "46 37 0:36 / /merged rw,relatime - overlay overlay " +
		"rw,lowerdir=" + fake + ":" + real + ",upperdir=/u,workdir=/w\n"

	dirs, err := parseOverlayLowerDirs(strings.NewReader(mountinfo))
	require.NoError(t, err)
	assert.Equal(t, []string{real}, dirs)
}

func TestParseOverlayLowerDirs_DeduplicatesAcrossLines(t *testing.T) {
	shared := t.TempDir()

	mountinfo := "46 37 0:36 / /m1 rw,relatime - overlay overlay rw,lowerdir=" + shared + ",upperdir=/u1,workdir=/w1\n" +
		"47 37 0:37 / /m2 rw,relatime shared:1 master:2 - overlay overlay rw,lowerdir=" + shared + ",upperdir=/u2,workdir=/w2\n"

	dirs, err := parseOverlayLowerDirs(strings.NewReader(mountinfo))
	require.NoError(t, err)
	assert.Equal(t, []string{shared}, dirs)
}

func TestParseOverlayLowerDirs_IgnoresNonOverlayLines(t *testing.T) {
	mountinfo := "36 35 98:0 / /mnt rw,noatime shared:1 - ext4 /dev/root rw\n" +
		"not a mountinfo line at all\n"

	dirs, err := parseOverlayLowerDirs(strings.NewReader(mountinfo))
	require.NoError(t, err)
	assert.Empty(t, dirs)
}

func TestParseOverlayLowerDirs_EmptyInput(t *testing.T) {
	dirs, err := parseOverlayLowerDirs(strings.NewReader(""))
	require.NoError(t, err)
	assert.Empty(t, dirs)
}

// ─────────────────────────────────────────────────────────────────────────────
// readOverlayLowerDirs — real /proc access, error branch
// ─────────────────────────────────────────────────────────────────────────────

func TestReadOverlayLowerDirs_NoSuchProcess(t *testing.T) {
	_, err := readOverlayLowerDirs(999999937)
	require.Error(t, err)
}

// ─────────────────────────────────────────────────────────────────────────────
// ImageSnapshotter.walkLowerDirs
// ─────────────────────────────────────────────────────────────────────────────

func TestWalkLowerDirs_FindsExecutablesRecursively(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "regular.txt"), []byte("data"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "tool"), []byte("#!/bin/sh\n"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "sub"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "sub", "nested-tool"), []byte("x"), 0o755))
	require.NoError(t, os.Symlink(filepath.Join(root, "tool"), filepath.Join(root, "link-to-tool")))

	s := NewImageSnapshotter(discardLogger())
	m := &ImageManifest{ExecPaths: make(map[string]struct{})}
	s.walkLowerDirs(m, []string{root})

	assert.Equal(t, 3, m.TotalFiles) // regular.txt, tool, nested-tool (symlink excluded before counting)
	_, hasTool := m.ExecPaths[filepath.Join(root, "tool")]
	_, hasNested := m.ExecPaths[filepath.Join(root, "sub", "nested-tool")]
	_, hasRegular := m.ExecPaths[filepath.Join(root, "regular.txt")]
	_, hasSymlink := m.ExecPaths[filepath.Join(root, "link-to-tool")]
	assert.True(t, hasTool)
	assert.True(t, hasNested)
	assert.False(t, hasRegular)
	assert.False(t, hasSymlink)
}

func TestWalkLowerDirs_MultipleDirs(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dirA, "a-tool"), []byte("x"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dirB, "b-tool"), []byte("x"), 0o755))

	s := NewImageSnapshotter(discardLogger())
	m := &ImageManifest{ExecPaths: make(map[string]struct{})}
	s.walkLowerDirs(m, []string{dirA, dirB})

	assert.Len(t, m.ExecPaths, 2)
}

// ─────────────────────────────────────────────────────────────────────────────
// SnapshotFromPID — error branches
// ─────────────────────────────────────────────────────────────────────────────

func TestSnapshotFromPID_MountinfoUnreadable(t *testing.T) {
	s := NewImageSnapshotter(discardLogger())
	m := s.SnapshotFromPID("container-x", 999999937)
	require.Error(t, m.Error)
	assert.Contains(t, m.Error.Error(), "read overlay lowerdirs")
}

func TestSnapshotFromPID_RealProcessDoesNotPanic(t *testing.T) {
	s := NewImageSnapshotter(discardLogger())
	m := s.SnapshotFromPID("container-y", uint32(os.Getpid()))
	require.NotNil(t, m)
	assert.Equal(t, "container-y", m.ContainerID)
}
