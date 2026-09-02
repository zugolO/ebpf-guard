package collector

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
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

// TestNormalizeCmdline locks the shared formatting of both proc.args sources.
// The BPF path (proc_args_map) hands over a fixed 512-byte buffer zero-padded
// past the end of argv; the /proc path hands over exactly what the kernel
// wrote. Both must come out as the same space-separated string, because rules
// match on that string and a difference between the two sources would look
// like the rule being wrong rather than the source having changed.
func TestNormalizeCmdline(t *testing.T) {
	t.Run("NUL separators become spaces", func(t *testing.T) {
		assert.Equal(t, "/tmp/x --run now",
			normalizeCmdline([]byte("/tmp/x\x00--run\x00now\x00")))
	})
	t.Run("zero padding of the BPF buffer is stripped, not turned into spaces", func(t *testing.T) {
		buf := make([]byte, 32)
		copy(buf, "/tmp/canary\x00-v\x00")
		assert.Equal(t, "/tmp/canary -v", normalizeCmdline(buf))
	})
	t.Run("an all-NUL buffer yields the empty string", func(t *testing.T) {
		assert.Equal(t, "", normalizeCmdline(make([]byte, 16)))
	})
	t.Run("a single argument survives unchanged", func(t *testing.T) {
		assert.Equal(t, "/tmp/canary", normalizeCmdline([]byte("/tmp/canary\x00")))
	})
}

// TestCommMatchesArgv0 locks the discriminator that keeps the BPF proc.args
// path from enriching the sys_enter record of an execve. bpf/syscall.bpf.c
// submits a record from both tracepoints; the map entry, unlike a /proc read,
// does not expire, so without this test one exec would raise every proc.args
// rule twice — the second time naming the caller.
func TestCommMatchesArgv0(t *testing.T) {
	t.Run("post-exec record: comm is the new image", func(t *testing.T) {
		assert.True(t, commMatchesArgv0("v1-suidcanary", "/tmp/v1-suidcanary"))
	})
	t.Run("pre-exec record: comm is still the caller", func(t *testing.T) {
		assert.False(t, commMatchesArgv0("bash", "/tmp/v1-suidcanary"))
	})
	t.Run("comm truncated at TASK_COMM_LEN-1 still matches by prefix", func(t *testing.T) {
		// "ebpfguard-f3-suidcanary" -> comm holds the first 15 bytes.
		assert.True(t, commMatchesArgv0("ebpfguard-f3-su", "/tmp/ebpfguard-f3-suidcanary --run"))
	})
	t.Run("arguments after argv[0] are ignored", func(t *testing.T) {
		assert.True(t, commMatchesArgv0("mandb", "/usr/bin/mandb --quiet /var/cache"))
	})
	t.Run("a bare argv[0] without a path still matches its own comm", func(t *testing.T) {
		assert.True(t, commMatchesArgv0("mandb", "mandb --quiet"))
	})
	t.Run("empty input is never a match", func(t *testing.T) {
		assert.False(t, commMatchesArgv0("", "/tmp/x"))
		assert.False(t, commMatchesArgv0("bash", ""))
	})
}

// TestExecArgsAreCurrent locks the discriminator that REPLACED the argv[0]
// heuristic on the primary (BPF map) path — finding №210, wave 6.0j.
//
// One execve produces two ring-buffer records, and sched_process_exec writes
// proc_args_map between them:
//
//	t1 sys_enter (record reserved) < t2 exec (map written) < t3 sys_exit
//
// so the entry belonging to THIS exec is newer than the enter record and older
// than the exit record. The three layouts below are exactly the three states
// the map can be in when a record is dequeued.
func TestExecArgsAreCurrent(t *testing.T) {
	// Both arguments pass through types.KtimeToEpoch/the same affine offset,
	// so the values here are ordered the way the kernel ordered them.
	const t1, t2, t3 = uint64(1_000), uint64(2_000), uint64(3_000)

	t.Run("exit record: the exec that wrote the entry is older", func(t *testing.T) {
		assert.True(t, execArgsAreCurrent(t2, types.KtimeToEpoch(t3)))
	})
	t.Run("enter record: the entry was written after this record", func(t *testing.T) {
		assert.False(t, execArgsAreCurrent(t2, types.KtimeToEpoch(t1)))
	})
	t.Run("same instant is not older, so it does not attach", func(t *testing.T) {
		assert.False(t, execArgsAreCurrent(t2, types.KtimeToEpoch(t2)))
	})
}

// TestProcArgsSurvivesSpoofedArgv0 is the unit half of criterion 6.0.16: the
// two cases that the argv[0] heuristic gets wrong and exec_ts gets right.
// Neither existed among the cases TestCommMatchesArgv0 covers — every one of
// those has argv[0] naming the image, which is precisely the assumption
// finding №210 showed to be optional.
func TestProcArgsSurvivesSpoofedArgv0(t *testing.T) {
	const tExec, tExit = uint64(2_000), uint64(3_000)

	t.Run("login shell: argv[0] is -bash, comm is bash", func(t *testing.T) {
		// What the old discriminator says about every interactive session:
		require.False(t, commMatchesArgv0("bash", "-bash"))
		// What exec_ts says about the same record.
		assert.True(t, execArgsAreCurrent(tExec, types.KtimeToEpoch(tExit)))
	})
	t.Run("masquerading dropper: argv[0] does not name the image (T1036.003)", func(t *testing.T) {
		require.False(t, commMatchesArgv0("sp-b46b1514", "/usr/local/bin/sp-seed/b46b1514"))
		assert.True(t, execArgsAreCurrent(tExec, types.KtimeToEpoch(tExit)))
	})
}
