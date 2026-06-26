package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUnsafeBytesToString(t *testing.T) {
	// Null-terminated buffer is trimmed at the NUL.
	assert.Equal(t, "abc", UnsafeBytesToString([]byte{'a', 'b', 'c', 0, 0}))
	// Leading NUL → empty.
	assert.Equal(t, "", UnsafeBytesToString([]byte{0, 'x'}))
	// Empty slice → empty.
	assert.Equal(t, "", UnsafeBytesToString([]byte{}))
	// No NUL → full length.
	assert.Equal(t, "hello", UnsafeBytesToString([]byte("hello")))
}
