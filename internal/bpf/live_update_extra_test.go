package bpf

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func quietLU(cfg LiveUpdateConfig) *LiveUpdater {
	return NewLiveUpdater(slog.New(slog.NewTextHandler(io.Discard, nil)), cfg)
}

func TestLiveUpdater_Accessors(t *testing.T) {
	lu := quietLU(LiveUpdateConfig{})
	lu.RegisterLink("sys_enter", &fakeLink{})
	lu.SetCurrentCollection(nil)

	assert.NotNil(t, lu.UpdatesTotal())
	assert.NotNil(t, lu.ErrorsTotal())
	require.NoError(t, lu.RegisterMetrics(prometheus.NewRegistry()))

	// Reload with an invalid object file path surfaces an error.
	err := lu.Reload(context.Background(), filepath.Join(t.TempDir(), "nope.o"))
	require.Error(t, err)
}

func TestLiveUpdater_FileWatcher(t *testing.T) {
	// Empty watch path disables the watcher (no-op success).
	luNone := quietLU(LiveUpdateConfig{})
	require.NoError(t, luNone.StartFileWatcher(context.Background()))
	luNone.Close()

	// Non-existent watch directory yields an error.
	luBad := quietLU(LiveUpdateConfig{WatchPath: "/no/such/dir-xyz"})
	require.Error(t, luBad.StartFileWatcher(context.Background()))

	// A real directory starts the watcher; writing a .o file drives watchLoop.
	dir := t.TempDir()
	lu := quietLU(LiveUpdateConfig{WatchPath: dir})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, lu.StartFileWatcher(ctx))

	// Writing a .o file triggers a reload attempt (which fails on the invalid
	// ELF, exercising the watcher's error branch without crashing).
	require.NoError(t, os.WriteFile(filepath.Join(dir, "syscall.o"), []byte("not-an-elf"), 0o644))
	time.Sleep(50 * time.Millisecond)

	lu.Close()
}
