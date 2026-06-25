package collector

import (
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNetworkCollector_Name(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c, err := NewNetworkCollector(logger)
	require.NoError(t, err)
	assert.Equal(t, "network", c.Name())
}

func TestNetworkCollector_InitialState(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c, err := NewNetworkCollector(logger)
	require.NoError(t, err)

	// Before Start, objs is nil → IsHealthy must be false.
	assert.False(t, c.IsHealthy())
	// No links attached yet.
	assert.False(t, c.IsAttached())
}
