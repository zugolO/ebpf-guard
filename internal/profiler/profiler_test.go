// Package profiler provides behavioral profiling and anomaly detection for processes.
package profiler

import (
	"math"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/internal/util"
	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestEWMA(t *testing.T) {
	tests := []struct {
		name         string
		weight       float64
		observations []float64
		expected     float64
		tolerance    float64
	}{
		{
			name:         "single observation",
			weight:       0.3,
			observations: []float64{10.0},
			expected:     10.0,
			tolerance:    0.001,
		},
		{
			name:         "two observations",
			weight:       0.5,
			observations: []float64{10.0, 20.0},
			expected:     15.0, // 0.5*20 + 0.5*10
			tolerance:    0.001,
		},
		{
			name:         "converges to recent",
			weight:       0.9,
			observations: []float64{0.0, 0.0, 0.0, 10.0, 10.0, 10.0},
			expected:     9.999, // Heavily weighted toward recent
			tolerance:    0.5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ewma := NewEWMA(tt.weight)
			for _, obs := range tt.observations {
				ewma.Update(obs)
			}
			assert.InDelta(t, tt.expected, ewma.Value(), tt.tolerance)
			assert.Equal(t, uint64(len(tt.observations)), ewma.Count())
		})
	}
}

func TestEWMA_DefaultWeight(t *testing.T) {
	// Test invalid weight defaults to 0.3
	ewma := NewEWMA(0)
	ewma.Update(10.0)
	assert.Equal(t, 10.0, ewma.Value())

	ewma2 := NewEWMA(1.5)
	ewma2.Update(10.0)
	assert.Equal(t, 10.0, ewma2.Value())
}

func TestBaselineLearner(t *testing.T) {
	learner := NewBaselineLearner(100*time.Millisecond, 10)

	// Initially not complete
	assert.False(t, learner.IsLearningComplete())
	assert.Greater(t, learner.TimeRemaining(), time.Duration(0))

	// Record samples
	for i := 0; i < 5; i++ {
		learner.RecordSample()
	}
	assert.Equal(t, uint64(5), learner.GetSampleCount())

	// Progress should be based on samples (5/10 = 0.5)
	progress := learner.LearningProgress()
	assert.GreaterOrEqual(t, progress, 0.0)
	assert.Less(t, progress, 1.0)

	// Wait for learning period
	time.Sleep(150 * time.Millisecond)

	// Still need more samples
	assert.False(t, learner.IsLearningComplete())

	// Add remaining samples
	for i := 0; i < 5; i++ {
		learner.RecordSample()
	}

	// Now learning should be complete
	assert.True(t, learner.IsLearningComplete())
	assert.Equal(t, 1.0, learner.LearningProgress())
	assert.Equal(t, time.Duration(0), learner.TimeRemaining())
}

func TestProcessProfile(t *testing.T) {
	profile := NewProcessProfile(1234, "test_process")

	assert.Equal(t, uint32(1234), profile.PID)
	assert.Equal(t, "test_process", profile.Comm)
	assert.NotNil(t, profile.NetworkProfile.DestPorts)
	assert.NotNil(t, profile.FileProfile.Directories)
	assert.NotNil(t, profile.SyscallProfile.Syscalls)

	// Test network event recording
	netEvent := &types.NetworkEvent{
		Dport: 8080,
		Daddr: [16]byte{192, 168, 1, 1},
	}
	profile.RecordNetworkEvent(netEvent, 0.3)
	assert.Equal(t, uint64(1), profile.NetworkProfile.TotalConnections)

	// Test file event recording
	var filename [256]byte
	copy(filename[:], "/etc/passwd")
	fileEvent := &types.FileEvent{
		Filename: filename,
	}
	profile.RecordFileEvent(fileEvent, 0.3)
	assert.Equal(t, uint64(1), profile.FileProfile.TotalOperations)

	// Test syscall event recording
	syscallEvent := &types.SyscallEvent{
		Nr: 1, // write
	}
	profile.RecordSyscallEvent(syscallEvent, 0.3)
	assert.Equal(t, uint64(1), profile.SyscallProfile.TotalSyscalls)

	// Test anomaly score
	profile.SetAnomalyScore(0.75)
	assert.Equal(t, 0.75, profile.GetAnomalyScore())

	// Test not expired
	assert.False(t, profile.IsExpired(time.Hour))
}

func TestProfileManager(t *testing.T) {
	pm := NewProfileManager(0.3, time.Hour)

	// Get or create profile
	profile := pm.GetOrCreate(1234, "test")
	assert.NotNil(t, profile)
	assert.Equal(t, uint32(1234), profile.PID)

	// Get existing
	profile2 := pm.GetOrCreate(1234, "different_name")
	assert.Equal(t, profile, profile2) // Same instance

	// Get by PID
	p := pm.Get(1234)
	assert.Equal(t, profile, p)

	// Get non-existent
	p = pm.Get(9999)
	assert.Nil(t, p)

	// PIDs list
	pm.GetOrCreate(5678, "test2")
	pids := pm.PIDs()
	assert.Len(t, pids, 2)

	// Get all
	all := pm.GetAll()
	assert.Len(t, all, 2)

	// Remove
	pm.Remove(1234)
	assert.Nil(t, pm.Get(1234))

	// Cleanup expired
	pmShort := NewProfileManager(0.3, 1*time.Millisecond)
	pmShort.GetOrCreate(1000, "short")
	time.Sleep(2 * time.Millisecond)
	removed := pmShort.CleanupExpired()
	assert.Equal(t, 1, removed)
	assert.Nil(t, pmShort.Get(1000))
}

func TestProfileManager_RecordEvent(t *testing.T) {
	pm := NewProfileManager(0.3, time.Hour)

	// Record network event
	netEvent := types.Event{
		Type: types.EventTCPConnect,
		PID:  1234,
		Comm: [16]byte{'t', 'e', 's', 't'},
		Network: &types.NetworkEvent{
			Dport: 8080,
		},
	}
	pm.RecordEvent(netEvent)

	profile := pm.Get(1234)
	assert.NotNil(t, profile)
	assert.Equal(t, uint64(1), profile.NetworkProfile.TotalConnections)

	// Record file event
	var filename [256]byte
	copy(filename[:], "/tmp/test.txt")
	fileEvent := types.Event{
		Type: types.EventFileAccess,
		PID:  1234,
		File: &types.FileEvent{
			Filename: filename,
		},
	}
	pm.RecordEvent(fileEvent)
	assert.Equal(t, uint64(1), profile.FileProfile.TotalOperations)

	// Record syscall event
	syscallEvent := types.Event{
		Type: types.EventSyscall,
		PID:  1234,
		Syscall: &types.SyscallEvent{
			Nr: 0, // read
		},
	}
	pm.RecordEvent(syscallEvent)
	assert.Equal(t, uint64(1), profile.SyscallProfile.TotalSyscalls)
}

func TestCalculateStats(t *testing.T) {
	values := []float64{1.0, 2.0, 3.0, 4.0, 5.0}
	stats := CalculateStats(values)

	assert.Equal(t, 3.0, stats.Mean)
	assert.Equal(t, uint64(5), stats.Count)
	assert.Equal(t, 1.0, stats.Min)
	assert.Equal(t, 5.0, stats.Max)
	assert.Greater(t, stats.StdDev, 0.0)

	// Empty slice
	emptyStats := CalculateStats([]float64{})
	assert.Equal(t, 0.0, emptyStats.Mean)
}

func TestZScore(t *testing.T) {
	// Normal case
	z := ZScore(15.0, 10.0, 2.5)
	assert.InDelta(t, 2.0, z, 0.001)

	// Zero stddev, same value
	z = ZScore(10.0, 10.0, 0.0)
	assert.Equal(t, 0.0, z)

	// Zero stddev, different value
	z = ZScore(15.0, 10.0, 0.0)
	assert.Equal(t, math.Inf(1), z)
}

func TestNormalize(t *testing.T) {
	// Normal case
	n := Normalize(75.0, 0.0, 100.0)
	assert.InDelta(t, 0.75, n, 0.001)

	// Min value
	n = Normalize(0.0, 0.0, 100.0)
	assert.Equal(t, 0.0, n)

	// Max value
	n = Normalize(100.0, 0.0, 100.0)
	assert.Equal(t, 1.0, n)

	// Same min/max - returns 0.5 for equal values
	n = Normalize(100.0, 100.0, 100.0)
	assert.Equal(t, 0.5, n)

	// Out of range
	n = Normalize(150.0, 0.0, 100.0)
	assert.Equal(t, 1.0, n)
}

func TestAnomalyDetector(t *testing.T) {
	// Create detector with very short learning period
	ad := NewAnomalyDetector(0.5, 50*time.Millisecond, 0.3)

	// Initially in learning phase
	assert.False(t, ad.IsLearningComplete())
	assert.GreaterOrEqual(t, ad.LearningProgress(), 0.0)

	// Process events during learning
	for i := 0; i < 10; i++ {
		event := types.Event{
			Type: types.EventTCPConnect,
			PID:  1234,
			Comm: [16]byte{'t', 'e', 's', 't'},
			Network: &types.NetworkEvent{
				Dport: 8080,
				Daddr: [16]byte{192, 168, 1, 1},
			},
		}
		result := ad.ProcessEvent(event, false)
		assert.Nil(t, result) // No results during learning
	}

	// Wait for learning to complete
	time.Sleep(100 * time.Millisecond)

	// Add more samples to complete learning
	for i := 0; i < 100; i++ {
		event := types.Event{
			Type: types.EventTCPConnect,
			PID:  1234,
			Network: &types.NetworkEvent{
				Dport: 8080,
				Daddr: [16]byte{192, 168, 1, 1},
			},
		}
		ad.ProcessEvent(event, false)
	}

	// Now learning should be complete
	assert.True(t, ad.IsLearningComplete())
	assert.Equal(t, 1.0, ad.LearningProgress())

	// Process anomalous event (different port)
	anomalousEvent := types.Event{
		Type: types.EventTCPConnect,
		PID:  1234,
		Network: &types.NetworkEvent{
			Dport: 9999, // Different port
			Daddr: [16]byte{192, 168, 1, 1},
		},
	}
	result := ad.ProcessEvent(anomalousEvent, false)
	assert.NotNil(t, result)
	assert.Equal(t, uint32(1234), result.PID)
	assert.True(t, result.Score >= 0)
}

func TestAnomalyDetector_FileBehavior(t *testing.T) {
	ad := NewAnomalyDetector(0.5, 50*time.Millisecond, 0.3)

	// Learn normal file access
	for i := 0; i < 150; i++ {
		var filename [256]byte
		copy(filename[:], "/tmp/normal.txt")
		event := types.Event{
			Type: types.EventFileAccess,
			PID:  1234,
			File: &types.FileEvent{
				Filename: filename,
			},
		}
		ad.ProcessEvent(event, false)
	}

	// Wait and ensure learning is complete
	time.Sleep(100 * time.Millisecond)

	// Anomalous file access
	var filename [256]byte
	copy(filename[:], "/etc/shadow")
	event := types.Event{
		Type: types.EventFileAccess,
		PID:  1234,
		File: &types.FileEvent{
			Filename: filename,
		},
	}
	result := ad.ProcessEvent(event, false)
	assert.NotNil(t, result)
	assert.True(t, result.Score >= 0)
}

func TestHelperFunctions(t *testing.T) {
	// Test extractDirectory
	assert.Equal(t, "/etc/", extractDirectory("/etc/passwd"))
	assert.Equal(t, "/tmp/", extractDirectory("/tmp/test.txt"))
	assert.Equal(t, "/", extractDirectory("/file"))
	assert.Equal(t, "", extractDirectory("file"))

	// Test extractExtension
	assert.Equal(t, ".txt", extractExtension("/tmp/test.txt"))
	assert.Equal(t, ".conf", extractExtension("/etc/nginx.conf"))
	assert.Equal(t, "", extractExtension("/etc/passwd"))
	assert.Equal(t, "", extractExtension("file"))

	// Test bytesToString
	b := []byte{'h', 'e', 'l', 'l', 'o', 0, 'w', 'o', 'r', 'l', 'd'}
	assert.Equal(t, "hello", string(bytesToString(b)))

	// Test formatIP - returns proper dotted-decimal notation
	ip := [16]byte{192, 168, 1, 1}
	formatted := util.FormatIP16(ip, types.AFInet)
	assert.Equal(t, "192.168.1.1", formatted)

	// Test formatPort - returns proper string representation
	assert.Equal(t, "80", formatPort(80))
	assert.Equal(t, "443", formatPort(443))
	assert.Equal(t, "8080", formatPort(8080))

	// Test formatSyscall - returns proper syscall name
	assert.Equal(t, "syscall_0", formatSyscall(0))
	assert.Equal(t, "syscall_300", formatSyscall(300))
	assert.Equal(t, "syscall_450", formatSyscall(450))
}
