// Package bpf provides eBPF program loading and management.
package bpf

import (
	"fmt"
	"sync/atomic"

	"github.com/cilium/ebpf"
)

// SamplingConfig represents the BPF-side sampling configuration.
// This struct must match the C struct sampling_config in bpf/common.h
type SamplingConfig struct {
	SyscallRate uint32 // Sample 1 in N syscall events (0 = disable, 1 = all)
	NetworkRate uint32 // Sample 1 in N network events (0 = disable, 1 = all)
	FileRate    uint32 // Sample 1 in N file events (0 = disable, 1 = all)
	Enabled     uint32 // Global sampling enable flag
}

// DefaultSamplingConfig returns the default sampling configuration (all events).
func DefaultSamplingConfig() SamplingConfig {
	return SamplingConfig{
		SyscallRate: 1, // All events
		NetworkRate: 1, // All events
		FileRate:    1, // All events
		Enabled:     0, // Disabled by default
	}
}

// SamplingController manages BPF-side event sampling configuration.
type SamplingController struct {
	configMap *ebpf.Map
	config    atomic.Value // stores SamplingConfig
}

// NewSamplingController creates a new sampling controller.
func NewSamplingController(configMap *ebpf.Map) (*SamplingController, error) {
	if configMap == nil {
		return nil, fmt.Errorf("bpf: sampling config map is nil")
	}

	sc := &SamplingController{
		configMap: configMap,
	}
	sc.config.Store(DefaultSamplingConfig())

	return sc, nil
}

// UpdateConfig updates the sampling configuration in BPF.
func (sc *SamplingController) UpdateConfig(cfg SamplingConfig) error {
	key := uint32(0)
	if err := sc.configMap.Update(key, cfg, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("bpf: update sampling config: %w", err)
	}
	sc.config.Store(cfg)
	return nil
}

// GetConfig returns the current sampling configuration.
func (sc *SamplingController) GetConfig() SamplingConfig {
	return sc.config.Load().(SamplingConfig)
}

// SetSyscallRate sets the sampling rate for syscall events.
// rate=0 disables syscall events, rate=1 captures all, rate=N captures 1 in N.
func (sc *SamplingController) SetSyscallRate(rate uint32) error {
	cfg := sc.GetConfig()
	cfg.SyscallRate = rate
	cfg.Enabled = 1
	return sc.UpdateConfig(cfg)
}

// SetNetworkRate sets the sampling rate for network events.
// rate=0 disables network events, rate=1 captures all, rate=N captures 1 in N.
func (sc *SamplingController) SetNetworkRate(rate uint32) error {
	cfg := sc.GetConfig()
	cfg.NetworkRate = rate
	cfg.Enabled = 1
	return sc.UpdateConfig(cfg)
}

// SetFileRate sets the sampling rate for file access events.
// rate=0 disables file events, rate=1 captures all, rate=N captures 1 in N.
func (sc *SamplingController) SetFileRate(rate uint32) error {
	cfg := sc.GetConfig()
	cfg.FileRate = rate
	cfg.Enabled = 1
	return sc.UpdateConfig(cfg)
}

// Enable enables BPF-side sampling with current configuration.
func (sc *SamplingController) Enable() error {
	cfg := sc.GetConfig()
	cfg.Enabled = 1
	return sc.UpdateConfig(cfg)
}

// Disable disables BPF-side sampling (all events pass through).
func (sc *SamplingController) Disable() error {
	cfg := sc.GetConfig()
	cfg.Enabled = 0
	return sc.UpdateConfig(cfg)
}

// SamplingStats represents statistics from BPF event counters.
type SamplingStats struct {
	SyscallEvents uint64
	NetworkEvents uint64
	FileEvents    uint64
}

// GetStats retrieves event counter statistics from BPF.
// Note: This resets the per-CPU counters.
func (sc *SamplingController) GetStats(countersMap *ebpf.Map) (SamplingStats, error) {
	var stats SamplingStats

	if countersMap == nil {
		return stats, fmt.Errorf("bpf: counters map is nil")
	}

	// Read and reset counters for each event type
	for i := uint32(0); i < 3; i++ {
		var count uint64
		if err := countersMap.LookupAndDelete(i, &count); err != nil {
			// Counter might not exist yet, that's ok
			continue
		}

		switch i {
		case 0:
			stats.SyscallEvents = count
		case 1:
			stats.NetworkEvents = count
		case 2:
			stats.FileEvents = count
		}
	}

	return stats, nil
}

// RateLimiter provides userspace rate limiting for events.
// This is a simpler alternative to BPF-side sampling for cases where
// BPF maps are not available.
type RateLimiter struct {
	syscallCounter atomic.Uint64
	networkCounter atomic.Uint64
	fileCounter    atomic.Uint64

	syscallRate uint32
	networkRate uint32
	fileRate    uint32
	enabled     atomic.Bool
}

// NewRateLimiter creates a new userspace rate limiter.
func NewRateLimiter(syscallRate, networkRate, fileRate uint32) *RateLimiter {
	return &RateLimiter{
		syscallRate: syscallRate,
		networkRate: networkRate,
		fileRate:    fileRate,
	}
}

// AllowSyscall checks if a syscall event should be allowed.
func (rl *RateLimiter) AllowSyscall() bool {
	if !rl.enabled.Load() || rl.syscallRate <= 1 {
		return true
	}
	count := rl.syscallCounter.Add(1)
	return (count % uint64(rl.syscallRate)) == 1
}

// AllowNetwork checks if a network event should be allowed.
func (rl *RateLimiter) AllowNetwork() bool {
	if !rl.enabled.Load() || rl.networkRate <= 1 {
		return true
	}
	count := rl.networkCounter.Add(1)
	return (count % uint64(rl.networkRate)) == 1
}

// AllowFile checks if a file event should be allowed.
func (rl *RateLimiter) AllowFile() bool {
	if !rl.enabled.Load() || rl.fileRate <= 1 {
		return true
	}
	count := rl.fileCounter.Add(1)
	return (count % uint64(rl.fileRate)) == 1
}

// Enable enables rate limiting.
func (rl *RateLimiter) Enable() {
	rl.enabled.Store(true)
}

// Disable disables rate limiting.
func (rl *RateLimiter) Disable() {
	rl.enabled.Store(false)
}

// SetRates updates the rate limits.
func (rl *RateLimiter) SetRates(syscallRate, networkRate, fileRate uint32) {
	rl.syscallRate = syscallRate
	rl.networkRate = networkRate
	rl.fileRate = fileRate
}

// SetSamplingRate sets the sampling rate for a specific event type.
// This method implements the BPFSamplingController interface.
// rate should be in range [0.0, 1.0] where 1.0 means 100% sampling.
func (rl *RateLimiter) SetSamplingRate(eventType string, rate float64) {
	// Convert float64 rate to uint32 (1/rate)
	// rate=1.0 -> sample every 1 event
	// rate=0.1 -> sample every 10 events
	// rate=0.0 -> disable (sample every 0 = disable)
	var sampleRate uint32
	if rate <= 0 {
		sampleRate = 0 // Disable
	} else if rate >= 1.0 {
		sampleRate = 1 // All events
	} else {
		sampleRate = uint32(1.0 / rate)
		if sampleRate < 1 {
			sampleRate = 1
		}
	}

	switch eventType {
	case "syscall":
		rl.syscallRate = sampleRate
	case "network":
		rl.networkRate = sampleRate
	case "file":
		rl.fileRate = sampleRate
	}
}

// SetSamplingRateFloat sets the sampling rate using float64 for all event types.
// This is a convenience method for memory pressure handling.
func (sc *SamplingController) SetSamplingRate(eventType string, rate float64) error {
	// Convert float64 rate to uint32
	var sampleRate uint32
	if rate <= 0 {
		sampleRate = 0
	} else if rate >= 1.0 {
		sampleRate = 1
	} else {
		sampleRate = uint32(1.0 / rate)
		if sampleRate < 1 {
			sampleRate = 1
		}
	}

	switch eventType {
	case "syscall":
		return sc.SetSyscallRate(sampleRate)
	case "network":
		return sc.SetNetworkRate(sampleRate)
	case "file":
		return sc.SetFileRate(sampleRate)
	default:
		return fmt.Errorf("bpf: unknown event type: %s", eventType)
	}
}
