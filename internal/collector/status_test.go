package collector

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNoopStatusReporter_SetUp(t *testing.T) {
	// NoopStatusReporter.SetUp must not panic.
	r := NoopStatusReporter{}
	require.NotPanics(t, func() {
		r.SetUp("test-collector", true)
		r.SetUp("test-collector", false)
	})
}

func TestStatusReporterFunc_SetUp(t *testing.T) {
	var gotName string
	var gotUp bool

	f := StatusReporterFunc(func(name string, up bool) {
		gotName = name
		gotUp = up
	})

	f.SetUp("syscall", true)

	assert.Equal(t, "syscall", gotName)
	assert.True(t, gotUp)
}

func TestStatusReporterFunc_MultipleCallbacks(t *testing.T) {
	calls := make([]struct {
		name string
		up   bool
	}, 0, 3)

	f := StatusReporterFunc(func(name string, up bool) {
		calls = append(calls, struct {
			name string
			up   bool
		}{name, up})
	})

	f.SetUp("network", true)
	f.SetUp("syscall", false)
	f.SetUp("network", false)

	require.Len(t, calls, 3)
	assert.Equal(t, "network", calls[0].name)
	assert.True(t, calls[0].up)
	assert.Equal(t, "syscall", calls[1].name)
	assert.False(t, calls[1].up)
	assert.Equal(t, "network", calls[2].name)
	assert.False(t, calls[2].up)
}
