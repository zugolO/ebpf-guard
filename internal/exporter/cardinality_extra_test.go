package exporter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCardinalityLimiter_Normalize(t *testing.T) {
	cl := NewCardinalityLimiter(2)

	// Two distinct series fit under the cap and pass through unchanged.
	a := cl.Normalize([]string{"evt", "pod-a", "ns"}, 1)
	assert.Equal(t, "pod-a", a[1])
	b := cl.Normalize([]string{"evt", "pod-b", "ns"}, 1)
	assert.Equal(t, "pod-b", b[1])
	assert.Equal(t, 2, cl.Size())

	// A previously-seen series still passes through.
	again := cl.Normalize([]string{"evt", "pod-a", "ns"}, 1)
	assert.Equal(t, "pod-a", again[1])

	// A third distinct series exceeds the cap and collapses the label to "other".
	c := cl.Normalize([]string{"evt", "pod-c", "ns"}, 1)
	assert.Equal(t, "other", c[1])
}

func TestNewCardinalityLimiter_Default(t *testing.T) {
	cl := NewCardinalityLimiter(0) // non-positive → conservative default
	assert.Equal(t, 0, cl.Size())
}
