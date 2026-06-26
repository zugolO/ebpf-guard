package drift

import (
	"testing"

	"github.com/stretchr/testify/assert"
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

	// Overlay mount whose 6th field carries the lowerdir option.
	dir, ok := extractOverlayLowerDir(
		"36 35 0:50 / /merged rw,lowerdir=/l1:/l2 shared:1 master:2 - overlay overlay rw")
	if ok {
		assert.Equal(t, "/l1:/l2", dir)
	}
}
