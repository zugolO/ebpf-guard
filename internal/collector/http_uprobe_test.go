// Package collector provides tests for plaintext HTTP event collection.
package collector

import (
	"context"
	"log/slog"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// TestHTTPEventRawToTypesEvent verifies conversion from raw BPF event to types.Event.
func TestHTTPEventRawToTypesEvent(t *testing.T) {
	tests := []struct {
		name     string
		raw      HTTPEventRaw
		expected types.Event
	}{
		{
			name: "HTTP request event (direction 0)",
			raw: HTTPEventRaw{
				Type:        uint32(types.EventHTTPPlaintext),
				Timestamp:   1234567890,
				PID:         1234,
				TGID:        1234,
				PPID:        1,
				UID:         1000,
				Comm:        [16]byte{'n', 'g', 'i', 'n', 'x'},
				ParentComm:  [16]byte{'s', 'y', 's', 't', 'e', 'm', 'd'},
				Direction:   0, // HTTPDirectionRequest
				DataLen:     100,
				CapturedLen: 100,
				Data:        [256]byte{'G', 'E', 'T', ' ', '/', 'a', 'p', 'i'},
			},
			expected: types.Event{
				Type:       types.EventHTTPPlaintext,
				Timestamp:  1234567890,
				PID:        1234,
				TGID:       1234,
				PPID:       1,
				UID:        1000,
				Comm:       [16]byte{'n', 'g', 'i', 'n', 'x'},
				ParentComm: [16]byte{'s', 'y', 's', 't', 'e', 'm', 'd'},
				HTTPPlaintext: &types.HTTPEvent{
					Direction: types.HTTPDirectionRequest,
					DataLen:   100,
					Data:      [256]byte{'G', 'E', 'T', ' ', '/', 'a', 'p', 'i'},
				},
			},
		},
		{
			name: "HTTP response event (direction 1)",
			raw: HTTPEventRaw{
				Type:        uint32(types.EventHTTPPlaintext),
				Timestamp:   1234567891,
				PID:         5678,
				TGID:        5678,
				PPID:        1234,
				UID:         1000,
				Comm:        [16]byte{'a', 'p', 'a', 'c', 'h', 'e', '2'},
				ParentComm:  [16]byte{'s', 'y', 's', 't', 'e', 'm', 'd'},
				Direction:   1, // HTTPDirectionResponse
				DataLen:     2048,
				CapturedLen: 256,
				Data:        [256]byte{'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', '2', '0', '0'},
			},
			expected: types.Event{
				Type:       types.EventHTTPPlaintext,
				Timestamp:  1234567891,
				PID:        5678,
				TGID:       5678,
				PPID:       1234,
				UID:        1000,
				Comm:       [16]byte{'a', 'p', 'a', 'c', 'h', 'e', '2'},
				ParentComm: [16]byte{'s', 'y', 's', 't', 'e', 'm', 'd'},
				HTTPPlaintext: &types.HTTPEvent{
					Direction: types.HTTPDirectionResponse,
					DataLen:   2048,
					Data:      [256]byte{'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', '2', '0', '0'},
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

			require.NotNil(t, result.HTTPPlaintext)
			assert.Equal(t, tt.expected.HTTPPlaintext.Direction, result.HTTPPlaintext.Direction)
			assert.Equal(t, tt.expected.HTTPPlaintext.DataLen, result.HTTPPlaintext.DataLen)
			assert.Equal(t, tt.expected.HTTPPlaintext.Data, result.HTTPPlaintext.Data)
		})
	}
}

// TestNewHTTPCollector verifies the constructor behavior.
func TestNewHTTPCollector(t *testing.T) {
	tests := []struct {
		name        string
		enabled     bool
		serverComms []string
		expectError bool
	}{
		{
			name:        "disabled collector",
			enabled:     false,
			serverComms: nil,
			expectError: false,
		},
		{
			name:        "enabled with default server comms",
			enabled:     true,
			serverComms: nil,
			expectError: false,
		},
		{
			name:        "enabled with custom server comms",
			enabled:     true,
			serverComms: []string{"nginx", "apache2"},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
			coll, err := NewHTTPCollector(logger, tt.enabled, tt.serverComms)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, coll)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, coll)
				assert.Equal(t, tt.enabled, coll.enabled)

				// Verify default server comms are used when none provided
				if len(tt.serverComms) == 0 {
					assert.NotEmpty(t, coll.serverComms)
					assert.Contains(t, coll.serverComms, "nginx")
					assert.Contains(t, coll.serverComms, "apache2")
				} else {
					assert.Contains(t, coll.serverComms, "nginx")
					assert.Contains(t, coll.serverComms, "apache2")
				}
			}
		})
	}
}

// TestHTTPCollectorStartDisabled verifies that a disabled collector starts and stops cleanly.
func TestHTTPCollectorStartDisabled(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	coll, err := NewHTTPCollector(logger, false, nil)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	out := make(chan types.Event, 10)

	// Should complete immediately without error
	err = coll.Start(ctx, out)
	assert.NoError(t, err)

	// Verify no events were sent
	assert.Empty(t, out)
}

// TestHTTPCollectorStartDisabledIsHealthy verifies IsHealthy for disabled collector.
func TestHTTPCollectorStartDisabledIsHealthy(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	coll, err := NewHTTPCollector(logger, false, nil)
	require.NoError(t, err)

	// Disabled collectors are considered healthy
	assert.True(t, coll.IsHealthy())
	assert.NoError(t, coll.LoadError())
}

// TestHTTPCollectorIsAttached verifies IsAttached behavior.
func TestHTTPCollectorStartIsAttached(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	coll, err := NewHTTPCollector(logger, true, nil)
	require.NoError(t, err)

	// Before Start, no BPF objects loaded
	assert.False(t, coll.IsAttached())
}

// TestHTTPCollectorLostEvents verifies LostEvents counter.
func TestHTTPCollectorStartLostEvents(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	coll, err := NewHTTPCollector(logger, true, nil)
	require.NoError(t, err)

	// Initially no lost events
	assert.Equal(t, uint64(0), coll.LostEvents())

	// Increment via atomic
	coll.lostTotal.Add(5)
	assert.Equal(t, uint64(5), coll.LostEvents())
}

// TestHTTPCollectorGetAttachedPIDs verifies GetAttachedPIDs behavior.
func TestHTTPCollectorStartGetAttachedPIDs(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	coll, err := NewHTTPCollector(logger, true, nil)
	require.NoError(t, err)

	// Initially no attached PIDs
	pids := coll.GetAttachedPIDs()
	assert.Empty(t, pids)

	// Add a PID
	coll.mu.Lock()
	coll.attachedPaths[1234] = "/usr/bin/nginx"
	coll.mu.Unlock()

	pids = coll.GetAttachedPIDs()
	assert.Len(t, pids, 1)
	assert.Contains(t, pids, uint32(1234))
}

// TestHTTPCollectorWithStatusReporter verifies WithStatusReporter builder.
func TestHTTPCollectorWithStatusReporter(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	coll, err := NewHTTPCollector(logger, true, nil)
	require.NoError(t, err)

	reporter := &mockStatusReporter{}
	coll.WithStatusReporter(reporter)
	assert.Equal(t, reporter, coll.status)
}

// TestHTTPCollectorWithBackpressureStrategy verifies WithBackpressureStrategy builder.
func TestHTTPCollectorWithBackpressureStrategy(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	coll, err := NewHTTPCollector(logger, true, nil)
	require.NoError(t, err)

	coll.WithBackpressureStrategy(StrategyBlock)
	assert.Equal(t, StrategyBlock, coll.strategy)
}

// TestHTTPCollectorWithRingBufSize verifies WithRingBufSize builder.
func TestHTTPCollectorWithRingBufSize(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	coll, err := NewHTTPCollector(logger, true, nil)
	require.NoError(t, err)

	coll.WithRingBufSize(512 * 1024)
	assert.Equal(t, 512*1024, coll.ringBufSize)
}

// TestHTTPCollectorName verifies Name returns the correct identifier.
func TestHTTPCollectorName(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	coll, err := NewHTTPCollector(logger, true, nil)
	require.NoError(t, err)

	assert.Equal(t, "http_plaintext", coll.Name())
}

// TestHTTPCollectorClose verifies Close releases resources.
func TestHTTPCollectorClose(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	coll, err := NewHTTPCollector(logger, true, nil)
	require.NoError(t, err)

	// Close should not panic
	assert.NoError(t, coll.Close())

	// After close, should be not attached
	assert.False(t, coll.IsAttached())
}

// TestHTTPCollectorParseEvent verifies parseEvent behavior.
func TestHTTPCollectorParseEvent(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	coll, err := NewHTTPCollector(logger, true, nil)
	require.NoError(t, err)

	tests := []struct {
		name        string
		raw         []byte
		expectError bool
	}{
		{
			name:        "event too short (less than 4 bytes)",
			raw:         []byte{1, 2, 3},
			expectError: true,
		},
		{
			name:        "HTTP event too short (less than 340 bytes)",
			raw:         make([]byte, 100),
			expectError: true,
		},
		{
			name:        "wrong event type",
			raw:         buildRawHTTPEndpoint(0xFFFFFFFF),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, err := coll.parseEvent(tt.raw)
			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, event)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, event)
			}
		})
	}
}

// buildRawHTTPEndpoint creates a minimal raw HTTP event for testing.
func buildRawHTTPEndpoint(eventType uint32) []byte {
	raw := make([]byte, 340)
	// Set event type at offset 0
	raw[0] = byte(eventType)
	raw[1] = byte(eventType >> 8)
	raw[2] = byte(eventType >> 16)
	raw[3] = byte(eventType >> 24)
	return raw
}

// TestHTTPCollectorClose verifies httpObjects Close behavior.
func TestCloseHTTPObjects(t *testing.T) {
	objs := &httpObjects{
		HttpEvents:       nil,
		HttpReadContexts: nil,
		TraceReadEntry:   nil,
		TraceReadRet:     nil,
		TraceRecvEntry:   nil,
		TraceRecvRet:     nil,
	}

	// Close with all nil fields should not error
	assert.NoError(t, closeHTTPObjects(objs))
}

// mockStatusReporter is a test double for StatusReporter.
type mockStatusReporter struct {
	up atomic.Bool
}

func (m *mockStatusReporter) SetUp(component string, isUp bool) {
	if isUp {
		m.up.Store(true)
	} else {
		m.up.Store(false)
	}
}

func (m *mockStatusReporter) IsUp(component string) bool {
	return m.up.Load()
}
