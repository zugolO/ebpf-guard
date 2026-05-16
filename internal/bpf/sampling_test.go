package bpf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultSamplingConfig(t *testing.T) {
	cfg := DefaultSamplingConfig()

	assert.Equal(t, uint32(1), cfg.SyscallRate)
	assert.Equal(t, uint32(1), cfg.NetworkRate)
	assert.Equal(t, uint32(1), cfg.FileRate)
	assert.Equal(t, uint32(0), cfg.Enabled)
}

func TestRateLimiter_AllowSyscall(t *testing.T) {
	rl := NewRateLimiter(5, 1, 1) // Sample 1 in 5 syscalls
	rl.Enable()

	// First event should be allowed
	assert.True(t, rl.AllowSyscall())

	// Next 3 should be dropped
	assert.False(t, rl.AllowSyscall())
	assert.False(t, rl.AllowSyscall())
	assert.False(t, rl.AllowSyscall())

	// 5th should be allowed
	assert.False(t, rl.AllowSyscall())

	// 6th should be allowed (new cycle)
	assert.True(t, rl.AllowSyscall())
}

func TestRateLimiter_AllowNetwork(t *testing.T) {
	rl := NewRateLimiter(1, 3, 1) // Sample 1 in 3 network events
	rl.Enable()

	// First event should be allowed
	assert.True(t, rl.AllowNetwork())

	// Next 2 should be dropped
	assert.False(t, rl.AllowNetwork())
	assert.False(t, rl.AllowNetwork())

	// 4th should be allowed (new cycle)
	assert.True(t, rl.AllowNetwork())
}

func TestRateLimiter_AllowFile(t *testing.T) {
	rl := NewRateLimiter(1, 1, 2) // Sample 1 in 2 file events
	rl.Enable()

	// First event should be allowed
	assert.True(t, rl.AllowFile())

	// Next should be dropped
	assert.False(t, rl.AllowFile())

	// 3rd should be allowed (new cycle)
	assert.True(t, rl.AllowFile())
}

func TestRateLimiter_Disabled(t *testing.T) {
	rl := NewRateLimiter(10, 10, 10)
	rl.Disable()

	// All events should be allowed when disabled
	for i := 0; i < 100; i++ {
		assert.True(t, rl.AllowSyscall())
		assert.True(t, rl.AllowNetwork())
		assert.True(t, rl.AllowFile())
	}
}

func TestRateLimiter_RateOne(t *testing.T) {
	rl := NewRateLimiter(1, 1, 1)
	rl.Enable()

	// All events should be allowed when rate is 1
	for i := 0; i < 100; i++ {
		assert.True(t, rl.AllowSyscall())
		assert.True(t, rl.AllowNetwork())
		assert.True(t, rl.AllowFile())
	}
}

func TestRateLimiter_SetRates(t *testing.T) {
	rl := NewRateLimiter(1, 1, 1)
	rl.Enable()

	// Change rates
	rl.SetRates(5, 5, 5)

	// Verify new rates are applied
	assert.True(t, rl.AllowSyscall())
	assert.False(t, rl.AllowSyscall())
}

func BenchmarkRateLimiter_AllowSyscall(b *testing.B) {
	rl := NewRateLimiter(10, 10, 10)
	rl.Enable()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rl.AllowSyscall()
		}
	})
}

func BenchmarkRateLimiter_AllowSyscallDisabled(b *testing.B) {
	rl := NewRateLimiter(10, 10, 10)
	rl.Disable()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rl.AllowSyscall()
		}
	})
}
