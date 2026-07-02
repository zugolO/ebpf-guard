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

// TestCardinalityLimiter_CollapsesAllHighCardinalityLabels verifies the guard
// collapses every high-cardinality dimension (not just one) once the limit is
// exceeded, so namespace/pod/node can't individually blow up the series count.
func TestCardinalityLimiter_CollapsesMultipleLabels(t *testing.T) {
	cl := NewCardinalityLimiter(1)

	// First series is admitted verbatim.
	first := cl.Normalize([]string{"rule", "warning", "ns-a", "pod-a", "node-a"}, 2, 3, 4)
	assert.Equal(t, []string{"rule", "warning", "ns-a", "pod-a", "node-a"}, first)

	// The next distinct series exceeds the cap: namespace(2), pod(3), and node(4)
	// all collapse to "other" while rule_id(0)/severity(1) are preserved.
	over := cl.Normalize([]string{"rule", "warning", "ns-b", "pod-b", "node-b"}, 2, 3, 4)
	assert.Equal(t, []string{"rule", "warning", "other", "other", "other"}, over)
}
