package drift

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSplitLowerDirs(t *testing.T) {
	assert.Equal(t, []string{"/a", "/b", "/c"}, splitLowerDirs("/a:/b:/c"))
	assert.Equal(t, []string{"/only"}, splitLowerDirs("/only"))

	// Escaped colon stays part of the path.
	got := splitLowerDirs(`/a\:x:/b`)
	assert.Equal(t, []string{"/a:x", "/b"}, got)
}

func TestExtractOverlayLowerDir(t *testing.T) {
	// Non-overlay filesystem → not matched.
	_, ok := extractOverlayLowerDir("36 35 98:0 / /mnt rw,noatime shared:1 - ext4 /dev/root rw")
	assert.False(t, ok)

	// Garbage line → not matched.
	_, ok = extractOverlayLowerDir("not a mountinfo line")
	assert.False(t, ok)

	// Real overlay mount, no optional fields (as observed from an actual
	// kernel mount): lowerdir lives in the super options, after the
	// "- overlay overlay" separator/fstype/source triplet.
	dir, ok := extractOverlayLowerDir(
		"46 37 0:36 / /merged rw,relatime - overlay overlay rw,lowerdir=/l1:/l2,upperdir=/u,workdir=/w")
	require.True(t, ok)
	assert.Equal(t, "/l1:/l2", dir)

	// Real overlay mount WITH optional peer-group fields (common for
	// shared/slave propagation, e.g. under Docker's overlay2 driver).
	dir, ok = extractOverlayLowerDir(
		"46 37 0:36 / /merged rw,relatime shared:1 master:2 - overlay overlay rw,lowerdir=/a:/b,upperdir=/u,workdir=/w")
	require.True(t, ok)
	assert.Equal(t, "/a:/b", dir)
}
