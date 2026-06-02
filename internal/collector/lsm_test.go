// lsm_test.go — Tests for LSM collector

package collector

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLSMConfig_Default(t *testing.T) {
	config := DefaultLSMConfig()
	assert.Equal(t, "auto", config.Enabled)
}

func TestNewLSMCollector(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	tests := []struct {
		name      string
		config    LSMConfig
		wantAvail bool
		wantErr   bool
	}{
		{
			name:      "auto mode with no kernel support",
			config:    LSMConfig{Enabled: "auto"},
			wantAvail: false,
			wantErr:   false,
		},
		{
			name:      "disabled mode",
			config:    LSMConfig{Enabled: "false"},
			wantAvail: false,
			wantErr:   false,
		},
		{
			name:      "forced mode with no kernel support",
			config:    LSMConfig{Enabled: "true"},
			wantAvail: false,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lc, err := NewLSMCollector(tt.config, logger)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantAvail, lc.IsAvailable())
		})
	}
}

func TestLSMCollector_Name(t *testing.T) {
	lc := &LSMCollector{}
	assert.Equal(t, "lsm", lc.Name())
}

func TestLSMCollector_RegisterMetrics(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	lc, err := NewLSMCollector(DefaultLSMConfig(), logger)
	require.NoError(t, err)

	reg := prometheus.NewRegistry()
	err = lc.RegisterMetrics(reg)
	require.NoError(t, err)

	// Verify metrics are registered
	families, err := reg.Gather()
	require.NoError(t, err)
	require.Len(t, families, 1)
	assert.Equal(t, "ebpf_guard_lsm_blocks_total", *families[0].Name)
}

func TestLSMCollector_StartStop(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	lc, err := NewLSMCollector(LSMConfig{Enabled: "false"}, logger)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	out := make(chan types.Event, 10)
	errChan := make(chan error, 1)

	go func() {
		errChan <- lc.Start(ctx, out)
	}()

	// Wait for context timeout
	err = <-errChan
	assert.Equal(t, context.DeadlineExceeded, err)
}

func TestLSMCollector_BlocklistOperations(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	lc, err := NewLSMCollector(LSMConfig{Enabled: "false"}, logger)
	require.NoError(t, err)

	// Should fail when not available
	err = lc.AddToBlocklist(1234)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not available")

	err = lc.RemoveFromBlocklist(1234)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not available")
}

func TestLSMCollector_Close(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	lc, err := NewLSMCollector(LSMConfig{Enabled: "false"}, logger)
	require.NoError(t, err)

	err = lc.Close()
	assert.NoError(t, err)
}

func TestLSMCollector_checkAvailability(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	lc := &LSMCollector{
		logger: logger,
	}

	// This will return false in test environment without LSM support
	avail := lc.checkAvailability()
	// Just verify it doesn't panic
	_ = avail
}
