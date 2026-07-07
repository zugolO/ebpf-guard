package correlator

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// spawnWithEnv starts a long-lived child process with exactly extraEnv as its
// environment (no inherited vars) and returns its PID. This lets tests exercise
// extractTraceContext's real /proc/<pid>/environ read end to end, instead of
// only the sub-parsers it delegates to. The caller must invoke the returned
// cleanup function to terminate the process.
//
// There is a brief window between fork() and execve() during which
// /proc/<pid>/environ is not yet populated with the new program's
// environment, so this polls until the file is readable and non-empty
// (or extraEnv is itself empty) instead of racing a fixed sleep.
func spawnWithEnv(t *testing.T, extraEnv []string) (pid uint32, cleanup func()) {
	t.Helper()
	cmd := exec.Command("/usr/bin/sleep", "30")
	cmd.Env = extraEnv
	require.NoError(t, cmd.Start())
	p := uint32(cmd.Process.Pid)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", p))
		if err == nil && len(data) > 0 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}

	return p, func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
}

func TestExtractTraceContext_RealProcess_W3C(t *testing.T) {
	traceID := "4bf92f3577b34da6a3ce929d0e0e4736"
	spanID := "00f067aa0ba902b7"
	pid, cleanup := spawnWithEnv(t, []string{
		"TRACEPARENT=00-" + traceID + "-" + spanID + "-01",
		"TRACESTATE=vendor=value",
	})
	defer cleanup()

	tc := extractTraceContext(pid)
	require.NotNil(t, tc)
	assert.Equal(t, traceID, tc.TraceID)
	assert.Equal(t, spanID, tc.SpanID)
	assert.Equal(t, "environ", tc.Source)
	assert.Equal(t, "vendor=value", tc.TraceState)
}

func TestExtractTraceContext_RealProcess_InvalidTraceparentFallsThroughToOTEL(t *testing.T) {
	pid, cleanup := spawnWithEnv(t, []string{
		"TRACEPARENT=not-a-valid-traceparent",
		"OTEL_TRACE_ID=abc123",
		"OTEL_SPAN_ID=def456",
	})
	defer cleanup()

	tc := extractTraceContext(pid)
	require.NotNil(t, tc)
	assert.Equal(t, "abc123", tc.TraceID)
	assert.Equal(t, "def456", tc.SpanID)
	assert.Equal(t, "environ", tc.Source)
}

func TestExtractTraceContext_RealProcess_Datadog(t *testing.T) {
	pid, cleanup := spawnWithEnv(t, []string{
		"DD_TRACE_ID=1",
		"DD_SPAN_ID=255",
	})
	defer cleanup()

	tc := extractTraceContext(pid)
	require.NotNil(t, tc)
	assert.Equal(t, "00000000000000000000000000000001", tc.TraceID)
	assert.Equal(t, "000000000000000000000000000000ff", tc.SpanID)
	assert.Equal(t, "environ", tc.Source)
}

func TestExtractTraceContext_RealProcess_DatadogInvalidFallsThrough(t *testing.T) {
	pid, cleanup := spawnWithEnv(t, []string{
		"DD_TRACE_ID=not-a-number",
		"UBER_TRACE_ID=4bf92f3577b34da6a3ce929d0e0e4736:00f067aa0ba902b7:0:1",
	})
	defer cleanup()

	tc := extractTraceContext(pid)
	require.NotNil(t, tc, "invalid Datadog ID must fall through to Jaeger")
	assert.Equal(t, "4bf92f3577b34da6a3ce929d0e0e4736", tc.TraceID)
	assert.Equal(t, "00f067aa0ba902b7", tc.SpanID)
}

func TestExtractTraceContext_RealProcess_JaegerShortIDsPadded(t *testing.T) {
	pid, cleanup := spawnWithEnv(t, []string{
		"JAEGER_TRACE_ID=1a2b3c:4d5e:0:1",
	})
	defer cleanup()

	tc := extractTraceContext(pid)
	require.NotNil(t, tc)
	assert.Len(t, tc.TraceID, 32)
	assert.Len(t, tc.SpanID, 16)
	assert.Equal(t, "environ", tc.Source)
}

func TestExtractTraceContext_RealProcess_NoTraceVars(t *testing.T) {
	pid, cleanup := spawnWithEnv(t, []string{"PATH=/usr/bin", "UNRELATED=1"})
	defer cleanup()

	tc := extractTraceContext(pid)
	assert.Nil(t, tc)
}
