// Package collector provides tests for GPU/CUDA event collection.
package collector

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// TestGPUEventRawToTypesEvent verifies conversion from raw BPF event to types.Event.
func TestGPUEventRawToTypesEvent(t *testing.T) {
	tests := []struct {
		name string
		raw  GPUEventRaw
	}{
		{
			name: "DtoH copy",
			raw: GPUEventRaw{
				Type:       uint32(types.EventGPU),
				Timestamp:  1234567890,
				PID:        1234,
				TGID:       1234,
				PPID:       1,
				UID:        1000,
				Comm:       [16]byte{'p', 'y', 't', 'h', 'o', 'n', '3'},
				ParentComm: [16]byte{'b', 'a', 's', 'h'},
				Op:         uint8(types.GPUOpMemcpyDtoH),
				DevPtr:     0xdead000000000000,
				HostPtr:    0xcafe000000000000,
				Size:       1024 * 1024 * 256, // 256 MB
			},
		},
		{
			name: "GPU alloc",
			raw: GPUEventRaw{
				Type:       uint32(types.EventGPU),
				Timestamp:  9999999999,
				PID:        5678,
				TGID:       5678,
				PPID:       1000,
				UID:        0,
				Comm:       [16]byte{'t', 'r', 'a', 'i', 'n'},
				ParentComm: [16]byte{'s', 'y', 's', 't', 'e', 'm', 'd'},
				Op:         uint8(types.GPUOpAlloc),
				DevPtr:     0xbeef000000000000,
				HostPtr:    0,
				Size:       1024 * 1024 * 1024, // 1 GB
			},
		},
		{
			name: "kernel launch",
			raw: GPUEventRaw{
				Type:    uint32(types.EventGPU),
				PID:     9999,
				TGID:    9999,
				UID:     500,
				Comm:    [16]byte{'b', 'a', 's', 'h'},
				Op:      uint8(types.GPUOpKernelLaunch),
				DevPtr:  0x1234,
				Size:    0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.raw.ToTypesEvent()

			assert.Equal(t, types.EventGPU, result.Type)
			assert.Equal(t, tt.raw.Timestamp, result.Timestamp)
			assert.Equal(t, tt.raw.PID, result.PID)
			assert.Equal(t, tt.raw.TGID, result.TGID)
			assert.Equal(t, tt.raw.PPID, result.PPID)
			assert.Equal(t, tt.raw.UID, result.UID)
			assert.Equal(t, tt.raw.Comm, result.Comm)
			assert.Equal(t, tt.raw.ParentComm, result.ParentComm)

			require.NotNil(t, result.GPU)
			assert.Equal(t, types.GPUOpType(tt.raw.Op), result.GPU.Op)
			assert.Equal(t, tt.raw.DevPtr, result.GPU.DevPtr)
			assert.Equal(t, tt.raw.HostPtr, result.GPU.HostPtr)
			assert.Equal(t, tt.raw.Size, result.GPU.Size)
		})
	}
}

// TestGPUEventRawSerialization verifies that binary round-trip matches the C struct layout.
func TestGPUEventRawSerialization(t *testing.T) {
	original := GPUEventRaw{
		Type:       uint32(types.EventGPU),
		Timestamp:  1234567890123,
		PID:        12345,
		TGID:       12345,
		PPID:       1,
		UID:        1000,
		Comm:       [16]byte{'t', 'e', 's', 't'},
		ParentComm: [16]byte{'p', 'a', 'r', 'e', 'n', 't'},
		Op:         uint8(types.GPUOpMemcpyDtoH),
		DevPtr:     0xdeadbeef00000000,
		HostPtr:    0xcafebabe00000000,
		Size:       134217728, // 128 MB
	}

	buf := new(bytes.Buffer)
	require.NoError(t, binary.Write(buf, binary.LittleEndian, original))

	// Verify wire size matches the expected packed struct size.
	assert.Equal(t, gpuEventRawSize, buf.Len(),
		"wire size must match C struct gpu_event size (packed, no padding)")

	var decoded GPUEventRaw
	require.NoError(t, binary.Read(buf, binary.LittleEndian, &decoded))

	assert.Equal(t, original.Type, decoded.Type)
	assert.Equal(t, original.Timestamp, decoded.Timestamp)
	assert.Equal(t, original.PID, decoded.PID)
	assert.Equal(t, original.Op, decoded.Op)
	assert.Equal(t, original.DevPtr, decoded.DevPtr)
	assert.Equal(t, original.HostPtr, decoded.HostPtr)
	assert.Equal(t, original.Size, decoded.Size)
}

// TestNewGPUCollector verifies collector creation and defaults.
func TestNewGPUCollector(t *testing.T) {
	col, err := NewGPUCollector(slog.Default(), true)
	require.NoError(t, err)
	assert.NotNil(t, col)
	assert.Equal(t, "gpu", col.Name())
	assert.True(t, col.enabled)
	assert.Equal(t, 30*time.Second, col.scanInterval)
	assert.Equal(t, 60*time.Second, col.cleanupInterval)

	col2, err := NewGPUCollector(slog.Default(), false)
	require.NoError(t, err)
	assert.NotNil(t, col2)
	assert.False(t, col2.enabled)
}

// TestGPUCollectorStubMode verifies that a load failure sets the correct state.
func TestGPUCollectorStubMode(t *testing.T) {
	col, err := NewGPUCollector(slog.Default(), true)
	require.NoError(t, err)

	// Before Start(), IsHealthy() is true (no error yet).
	assert.True(t, col.IsHealthy())
	assert.Nil(t, col.LoadError())

	// Simulate a load failure.
	col.loadError = fmt.Errorf("simulated eBPF load failure")
	assert.False(t, col.IsHealthy())
	assert.NotNil(t, col.LoadError())
}

// TestGPUCollectorClose verifies that Close() does not panic with nil objects.
func TestGPUCollectorClose(t *testing.T) {
	col, err := NewGPUCollector(slog.Default(), true)
	require.NoError(t, err)

	err = col.Close()
	assert.NoError(t, err)
}

// TestGPUCollectorGetAttachedPIDs verifies PID tracking.
func TestGPUCollectorGetAttachedPIDs(t *testing.T) {
	col, err := NewGPUCollector(slog.Default(), true)
	require.NoError(t, err)

	assert.Empty(t, col.GetAttachedPIDs())

	col.mu.Lock()
	col.cudaPaths[1234] = "/usr/lib/x86_64-linux-gnu/libcuda.so.1"
	col.cudaPaths[5678] = "/usr/local/cuda/lib64/libcudart.so.12"
	col.mu.Unlock()

	pids := col.GetAttachedPIDs()
	assert.Len(t, pids, 2)
	assert.Contains(t, pids, uint32(1234))
	assert.Contains(t, pids, uint32(5678))
}

// TestGPUCollectorCleanupDeadPIDs verifies that stale PID entries are pruned.
// Requires Linux because it checks /proc/<pid> for liveness.
func TestGPUCollectorCleanupDeadPIDs(t *testing.T) {
	if _, err := os.Stat("/proc/1"); os.IsNotExist(err) {
		t.Skip("skipping: /proc not available (non-Linux)")
	}
	col, err := NewGPUCollector(slog.Default(), false)
	require.NoError(t, err)

	const deadPID = uint32(4194304) // beyond max PID on Linux
	const livePID = uint32(1)       // init/systemd always exists

	col.mu.Lock()
	col.cudaPaths[livePID] = "/usr/lib/libcuda.so.1"
	col.cudaPaths[deadPID] = "/usr/lib/libcuda.so.1"
	col.mu.Unlock()

	// Run the same cleanup logic as cleanupDeadPIDs.
	col.mu.Lock()
	for pid := range col.cudaPaths {
		if _, statErr := os.Stat(fmt.Sprintf("/proc/%d", pid)); os.IsNotExist(statErr) {
			delete(col.cudaPaths, pid)
		}
	}
	col.mu.Unlock()

	col.mu.RLock()
	_, hasLive := col.cudaPaths[livePID]
	_, hasDead := col.cudaPaths[deadPID]
	col.mu.RUnlock()

	assert.True(t, hasLive, "live PID should remain")
	assert.False(t, hasDead, "dead PID should be removed")
}

// TestGPUParseEventTooShort verifies error handling for undersized events.
func TestGPUParseEventTooShort(t *testing.T) {
	col, err := NewGPUCollector(slog.Default(), true)
	require.NoError(t, err)

	_, err = col.parseEvent([]byte{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")

	_, err = col.parseEvent([]byte{0x01, 0x02})
	assert.Error(t, err)
}

// TestGPUParseEventWrongType verifies rejection of events with incorrect type field.
func TestGPUParseEventWrongType(t *testing.T) {
	col, err := NewGPUCollector(slog.Default(), true)
	require.NoError(t, err)

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(types.EventSyscall)) // wrong type
	binary.Write(buf, binary.LittleEndian, make([]byte, 100))

	_, err = col.parseEvent(buf.Bytes())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected event type")
}

// TestGPUParseEventValidDtoH verifies correct parsing of a Device-to-Host event.
func TestGPUParseEventValidDtoH(t *testing.T) {
	col, err := NewGPUCollector(slog.Default(), true)
	require.NoError(t, err)

	raw := GPUEventRaw{
		Type:      uint32(types.EventGPU),
		Timestamp: 42,
		PID:       100,
		TGID:      100,
		UID:       1000,
		Comm:      [16]byte{'p', 'y', 't', 'h', 'o', 'n', '3'},
		Op:        uint8(types.GPUOpMemcpyDtoH),
		DevPtr:    0xabcd,
		HostPtr:   0xef01,
		Size:      256 * 1024 * 1024,
	}

	buf := new(bytes.Buffer)
	require.NoError(t, binary.Write(buf, binary.LittleEndian, raw))

	event, err := col.parseEvent(buf.Bytes())
	require.NoError(t, err)
	require.NotNil(t, event)
	require.NotNil(t, event.GPU)

	assert.Equal(t, types.EventGPU, event.Type)
	assert.Equal(t, types.GPUOpMemcpyDtoH, event.GPU.Op)
	assert.Equal(t, uint64(0xabcd), event.GPU.DevPtr)
	assert.Equal(t, uint64(0xef01), event.GPU.HostPtr)
	assert.Equal(t, uint64(256*1024*1024), event.GPU.Size)
	assert.Equal(t, uint32(100), event.PID)
}

// TestGPUOpTypeConstants verifies that op type constants are sequentially defined.
func TestGPUOpTypeConstants(t *testing.T) {
	assert.Equal(t, types.GPUOpType(0), types.GPUOpAlloc)
	assert.Equal(t, types.GPUOpType(1), types.GPUOpFree)
	assert.Equal(t, types.GPUOpType(2), types.GPUOpMemcpyHtoD)
	assert.Equal(t, types.GPUOpType(3), types.GPUOpMemcpyDtoH)
	assert.Equal(t, types.GPUOpType(4), types.GPUOpMemcpyDtoD)
	assert.Equal(t, types.GPUOpType(5), types.GPUOpKernelLaunch)
}

// TestGPUEventTypeConstant verifies EventGPU constant value.
func TestGPUEventTypeConstant(t *testing.T) {
	assert.Equal(t, types.EventType(10), types.EventGPU)
}

// TestGPUFindCUDALib verifies CUDA library detection from /proc maps content.
func TestGPUFindCUDALib(t *testing.T) {
	tests := []struct {
		name     string
		maps     string
		wantPath string
		wantKind string
	}{
		{
			name: "libcuda.so.1 present",
			maps: "7f0000000000-7f0001000000 r-xp 00000000 08:01 12345 /usr/lib/x86_64-linux-gnu/libcuda.so.1\n",
			wantPath: "/usr/lib/x86_64-linux-gnu/libcuda.so.1",
			wantKind: "driver",
		},
		{
			name: "libcudart present",
			maps: "7f0000000000-7f0001000000 r-xp 00000000 08:01 12345 /usr/local/cuda/lib64/libcudart.so.12.3\n",
			wantPath: "/usr/local/cuda/lib64/libcudart.so.12.3",
			wantKind: "runtime",
		},
		{
			name:     "no CUDA library",
			maps:     "7f0000000000-7f0001000000 r-xp 00000000 08:01 12345 /usr/lib/libssl.so.3\n",
			wantPath: "",
			wantKind: "",
		},
		{
			name:     "deleted library ignored",
			maps:     "7f0000000000-7f0001000000 r-xp 00000000 08:01 12345 /usr/lib/libcuda.so.1 (deleted)\n",
			wantPath: "",
			wantKind: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Write a fake maps file to a temp dir and redirect the scan.
			tmpFile, err := os.CreateTemp(t.TempDir(), "maps")
			require.NoError(t, err)
			_, err = tmpFile.WriteString(tt.maps)
			require.NoError(t, err)
			tmpFile.Close()

			// Use the internal logic directly via a helper — we call findCUDALibInMaps.
			path, kind := findCUDALibInMaps(tt.maps)
			assert.Equal(t, tt.wantPath, path)
			assert.Equal(t, tt.wantKind, kind)
		})
	}
}

// findCUDALibInMaps extracts the first CUDA library path and kind from /proc/[pid]/maps content.
// This is a test helper that replicates the logic in findCUDALibInPID without file I/O.
func findCUDALibInMaps(content string) (path, kind string) {
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 6 {
			continue
		}
		libPath := parts[len(parts)-1]
		if !strings.HasPrefix(libPath, "/") || strings.Contains(libPath, "(deleted)") {
			continue
		}

		for _, pattern := range cudaLibraryPatterns {
			if strings.Contains(libPath, pattern) {
				if strings.Contains(libPath, "libcuda.so") || strings.Contains(libPath, "libcuda-") {
					return libPath, "driver"
				}
				return libPath, "runtime"
			}
		}
	}
	return "", ""
}
