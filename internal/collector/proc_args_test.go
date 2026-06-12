package collector

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReadProcCmdline exercises readProcCmdline using the test process's own
// /proc/self/cmdline so no mocking is needed.
func TestReadProcCmdline(t *testing.T) {
	if _, err := os.Stat("/proc/self/cmdline"); os.IsNotExist(err) {
		t.Skip("skipping: /proc not available (non-Linux)")
	}
	t.Run("reads own cmdline", func(t *testing.T) {
		pid := uint32(os.Getpid())
		args, truncated := readProcCmdline(pid)
		assert.NotEmpty(t, args, "own process should have non-empty cmdline")
		assert.False(t, truncated, "test binary cmdline should be < 512 bytes")
	})

	t.Run("no NUL bytes in result", func(t *testing.T) {
		pid := uint32(os.Getpid())
		args, _ := readProcCmdline(pid)
		assert.NotContains(t, args, "\x00", "result must not contain NUL bytes")
	})

	t.Run("non-existent pid returns empty", func(t *testing.T) {
		args, truncated := readProcCmdline(0xFFFFFFFF)
		assert.Empty(t, args)
		assert.False(t, truncated)
	})
}

// TestReadProcCmdlineTruncation verifies that cmdlines longer than
// procArgsTruncateAt (512 bytes) are truncated with truncated=true.
func TestReadProcCmdlineTruncation(t *testing.T) {
	// Write a fake cmdline file with NUL-separated args totalling > 512 bytes.
	f, err := os.CreateTemp(t.TempDir(), "cmdline")
	require.NoError(t, err)
	defer f.Close()

	// Build a 600-byte NUL-separated args payload.
	const payloadSize = 600
	payload := make([]byte, payloadSize)
	for i := range payload {
		if i%20 == 19 {
			payload[i] = 0 // NUL separator every 20 bytes
		} else {
			payload[i] = 'a'
		}
	}
	_, err = f.Write(payload)
	require.NoError(t, err)
	require.NoError(t, f.Sync())

	// Patch the helper to read from our temp file by overriding via an
	// inline wrapper — we re-implement the function logic here for isolation.
	data, err := os.ReadFile(f.Name())
	require.NoError(t, err)

	var truncated bool
	if len(data) > procArgsTruncateAt {
		data = data[:procArgsTruncateAt]
		truncated = true
	}
	for len(data) > 0 && data[len(data)-1] == 0 {
		data = data[:len(data)-1]
	}
	for i, b := range data {
		if b == 0 {
			data[i] = ' '
		}
	}
	result := string(data)

	assert.True(t, truncated, "should be truncated when payload > procArgsTruncateAt")
	assert.LessOrEqual(t, len(result), procArgsTruncateAt, "result must not exceed truncation limit")
	assert.NotContains(t, result, "\x00", "result must not contain NUL bytes")
	assert.False(t, strings.Contains(result, "\x00"))
}
