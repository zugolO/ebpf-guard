// Package bpf provides eBPF program loading and management.
package bpf

import (
	"errors"
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
	hasBatch  bool
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

// SetBatchMode enables or disables batch map operations in GetStats.
// Call with KernelFeatures.HasBatchMapOps after constructing.
func (sc *SamplingController) SetBatchMode(enabled bool) {
	sc.hasBatch = enabled
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

// getStatsBatchFn and getStatsSequentialFn are package-level vars so tests can
// inject fakes to exercise the fallback path without a real kernel.
var getStatsBatchFn = getStatsBatch
var getStatsSequentialFn = getStatsSequential

// GetStats retrieves event counter statistics from BPF and resets the counters.
// When batch map operations are enabled (SetBatchMode(true)), a single
// BatchLookupAndDelete syscall is used instead of one syscall per counter.
// On failure the batch path falls back to per-element reads automatically.
func (sc *SamplingController) GetStats(countersMap *ebpf.Map) (SamplingStats, error) {
	if countersMap == nil {
		return SamplingStats{}, fmt.Errorf("bpf: counters map is nil")
	}
	if sc.hasBatch {
		if stats, err := getStatsBatchFn(countersMap); err == nil {
			return stats, nil
		}
		// Fall through to per-element on any batch error.
	}
	return getStatsSequentialFn(countersMap)
}

// getStatsBatch reads all three event counters in one BatchLookupAndDelete syscall.
// Returns an error if the batch call itself fails (callers should fall back to
// getStatsSequential in that case).
func getStatsBatch(m *ebpf.Map) (SamplingStats, error) {
	var cursor ebpf.MapBatchCursor
	keys := make([]uint32, 3)
	values := make([]uint64, 3)
	n, err := m.BatchLookupAndDelete(&cursor, keys, values, nil)
	// ErrKeyNotExist is the normal "end-of-map" sentinel from cilium/ebpf; it
	// means all entries were consumed, not a real error.
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return SamplingStats{}, fmt.Errorf("bpf: batch stats read: %w", err)
	}
	var stats SamplingStats
	for i := 0; i < n; i++ {
		switch keys[i] {
		case 0:
			stats.SyscallEvents = values[i]
		case 1:
			stats.NetworkEvents = values[i]
		case 2:
			stats.FileEvents = values[i]
		}
	}
	return stats, nil
}

// getStatsSequential reads the three event counters one at a time (one syscall
// per entry). Used as the fallback when batch operations are unavailable.
func getStatsSequential(m *ebpf.Map) (SamplingStats, error) {
	var stats SamplingStats
	for i := uint32(0); i < 3; i++ {
		var count uint64
		if err := m.LookupAndDelete(i, &count); err != nil {
			// Counter might not exist yet; skip silently.
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

// DefaultMonitoredSyscalls returns the syscall numbers that should be monitored
// by default: execve/execveat, ptrace, capset, setns, unshare, memfd_create,
// mount, umount2, pivot_root, chroot, process_vm_writev, process_vm_readv,
// perf_event_open.
func DefaultMonitoredSyscalls() []int {
	return []int{
		59,  // execve
		322, // execveat
		101, // ptrace
		126, // capset
		308, // setns
		272, // unshare
		319, // memfd_create
		165, // mount
		166, // umount2
		155, // pivot_root
		161, // chroot
		311, // process_vm_writev
		310, // process_vm_readv
		241, // perf_event_open
	}
}

// DefaultCommDenylist returns kernel worker comm names that should be silenced
// by default to avoid noise from high-frequency kernel threads.
func DefaultCommDenylist() []string {
	return []string{
		"kworker",
		"ksoftirqd",
		"migration",
		"rcu_sched",
		"rcu_preempt",
		"kswapd0",
		"kswapd1",
	}
}

// DefaultNoisyDaemonDenylist returns well-known user-space monitoring and
// logging daemons that generate high syscall volume but are unlikely to be
// involved in security incidents under normal operation.
//
// SECURITY NOTE: Linux comm names are not a security boundary — any process
// can call prctl(PR_SET_NAME, ...) to adopt an arbitrary name. An attacker
// running as a sufficiently privileged user can spoof any name in this list
// and have their events silently dropped at the kernel level. Use this list
// conservatively and review it periodically alongside your threat model.
// It can be disabled via bpf.kernel_filter.disable_default_daemon_denylist.
func DefaultNoisyDaemonDenylist() []string {
	return []string{
		"systemd-journal", // systemd journal daemon (journald)
		"rsyslogd",        // rsyslog system logger
		"syslogd",         // classic BSD syslog
		"node_exporter",   // Prometheus node exporter
		"telegraf",        // Telegraf metrics collection agent
		"filebeat",        // Elastic Filebeat log shipper
		"fluentd",         // Fluentd log aggregator
		"fluent-bit",      // Fluent Bit lightweight log forwarder
	}
}

// BuildCommDenylist merges the kernel-thread denylist and the optional noisy
// daemon denylist into a single slice for loading into comm_filter_map.
//
// kernelThreads defaults to DefaultCommDenylist() when empty.
// If disableDaemons is true the daemon list is omitted entirely.
// daemons defaults to DefaultNoisyDaemonDenylist() when nil/empty AND
// disableDaemons is false.
//
// Duplicates between the two lists are silently kept — BPF map updates are
// idempotent so writing the same key twice is harmless.
func BuildCommDenylist(kernelThreads []string, daemons []string, disableDaemons bool) []string {
	if len(kernelThreads) == 0 {
		kernelThreads = DefaultCommDenylist()
	}
	if disableDaemons {
		return kernelThreads
	}
	if len(daemons) == 0 {
		daemons = DefaultNoisyDaemonDenylist()
	}
	merged := make([]string, 0, len(kernelThreads)+len(daemons))
	merged = append(merged, kernelThreads...)
	merged = append(merged, daemons...)
	return merged
}

// KernelFilterController manages the BPF-side content-based event filters:
// the comm denylist, the syscall allowlist, and the global filter enable flag.
type KernelFilterController struct {
	commFilterMap      *ebpf.Map // comm_filter_map: key char[16], value uint8
	syscallFilterMap   *ebpf.Map // syscall_filter_map: key uint32, value uint8
	kernelFilterConfig *ebpf.Map // kernel_filter_config: key uint32, value uint8
	hasBatch           bool
}

// NewKernelFilterController creates a controller for the three filter maps.
// All three maps must be non-nil.
func NewKernelFilterController(commMap, syscallMap, cfgMap *ebpf.Map) (*KernelFilterController, error) {
	if commMap == nil {
		return nil, fmt.Errorf("bpf: comm_filter_map is nil")
	}
	if syscallMap == nil {
		return nil, fmt.Errorf("bpf: syscall_filter_map is nil")
	}
	if cfgMap == nil {
		return nil, fmt.Errorf("bpf: kernel_filter_config is nil")
	}
	return &KernelFilterController{
		commFilterMap:      commMap,
		syscallFilterMap:   syscallMap,
		kernelFilterConfig: cfgMap,
	}, nil
}

// SetCommFilter inserts or updates a comm entry in the BPF filter map.
// pass=true allows events from that comm, pass=false drops them in the kernel.
func (kf *KernelFilterController) SetCommFilter(comm string, pass bool) error {
	if kf.commFilterMap == nil {
		return fmt.Errorf("bpf: comm_filter_map is nil")
	}
	key := [16]byte{}
	copy(key[:], comm)
	var val uint8
	if pass {
		val = 1
	}
	if err := kf.commFilterMap.Update(key, val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("bpf: set comm filter %q: %w", comm, err)
	}
	return nil
}

// SetBatchMode enables or disables batch map operations in UpdateSyscallFilter.
// Call with KernelFeatures.HasBatchMapOps after constructing.
func (kf *KernelFilterController) SetBatchMode(enabled bool) {
	kf.hasBatch = enabled
}

// SetSyscallFilter sets whether syscall number nr should be monitored (true)
// or silently discarded at the kernel level (false).
func (kf *KernelFilterController) SetSyscallFilter(nr int, monitor bool) error {
	if nr < 0 || nr >= 512 {
		return fmt.Errorf("bpf: syscall number %d out of range [0, 512)", nr)
	}
	if kf.syscallFilterMap == nil {
		return fmt.Errorf("bpf: syscall_filter_map is nil")
	}
	key := uint32(nr)
	var val uint8
	if monitor {
		val = 1
	}
	if err := kf.syscallFilterMap.Update(key, val, ebpf.UpdateExist); err != nil {
		// ARRAY maps always have entries; fall back to UpdateAny on first use.
		if err := kf.syscallFilterMap.Update(key, val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("bpf: set syscall filter %d: %w", nr, err)
		}
	}
	return nil
}

// Enable activates BPF-side content filtering.
func (kf *KernelFilterController) Enable() error {
	if kf.kernelFilterConfig == nil {
		return fmt.Errorf("bpf: kernel_filter_config is nil")
	}
	key := uint32(0)
	val := uint8(1)
	if err := kf.kernelFilterConfig.Update(key, val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("bpf: enable kernel filter: %w", err)
	}
	return nil
}

// Disable deactivates BPF-side content filtering (all events pass through).
func (kf *KernelFilterController) Disable() error {
	if kf.kernelFilterConfig == nil {
		return fmt.Errorf("bpf: kernel_filter_config is nil")
	}
	key := uint32(0)
	val := uint8(0)
	if err := kf.kernelFilterConfig.Update(key, val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("bpf: disable kernel filter: %w", err)
	}
	return nil
}

// LoadDefaultFilters populates the filter maps with the default monitored
// syscall set and the default comm denylist, then enables filtering.
// Should be called once during startup after the BPF programs are loaded.
func (kf *KernelFilterController) LoadDefaultFilters() error {
	for _, nr := range DefaultMonitoredSyscalls() {
		if err := kf.SetSyscallFilter(nr, true); err != nil {
			return err
		}
	}
	for _, comm := range DefaultCommDenylist() {
		if err := kf.SetCommFilter(comm, false); err != nil {
			return err
		}
	}
	return kf.Enable()
}

// UpdateSyscallFilter atomically replaces the BPF syscall allowlist with the
// given set of syscall numbers.  All 512 map slots are written: entries in nrs
// are set to 1 (forward to userspace), the rest are cleared to 0 (drop).
//
// On kernels 5.6+ (HasBatchMapOps) all 512 slots are written in a single
// BatchUpdate syscall.  On older kernels the per-element path is used; batch
// errors also fall back to the per-element path automatically.
//
// This is called on startup after rules are loaded and again on every hot-reload
// so that the BPF filter tracks the active rule set without a process restart.
//
// If nrs is empty the call falls back to DefaultMonitoredSyscalls so filtering
// is never accidentally left in an "allow-nothing" state.
func (kf *KernelFilterController) UpdateSyscallFilter(nrs []uint32) error {
	if kf.syscallFilterMap == nil {
		return fmt.Errorf("bpf: syscall_filter_map is nil")
	}

	if len(nrs) == 0 {
		nrs = make([]uint32, len(DefaultMonitoredSyscalls()))
		for i, n := range DefaultMonitoredSyscalls() {
			nrs[i] = uint32(n)
		}
	}

	// Build a fast lookup set.
	allow := make(map[uint32]bool, len(nrs))
	for _, nr := range nrs {
		if nr < 512 {
			allow[nr] = true
		}
	}

	if kf.hasBatch {
		if err := updateSyscallFilterBatchFn(kf, allow); err == nil {
			return nil
		}
		// Fall through to per-element on any batch error.
	}
	return kf.updateSyscallFilterSequential(allow)
}

// updateSyscallFilterBatchFn is a package-level var so tests can inject a fake
// to exercise the fallback path without a real kernel or BPF map.
var updateSyscallFilterBatchFn = (*KernelFilterController).updateSyscallFilterBatch

// updateSyscallFilterBatch writes all 512 syscall filter slots in one
// BatchUpdate syscall (kernel 5.6+).
func (kf *KernelFilterController) updateSyscallFilterBatch(allow map[uint32]bool) error {
	keys := make([]uint32, 512)
	values := make([]uint8, 512)
	for i := uint32(0); i < 512; i++ {
		keys[i] = i
		if allow[i] {
			values[i] = 1
		}
	}
	_, err := kf.syscallFilterMap.BatchUpdate(keys, values, &ebpf.BatchOptions{
		ElemFlags: uint64(ebpf.UpdateAny),
	})
	return err
}

// updateSyscallFilterSequential writes all 512 syscall filter slots one at a
// time (one syscall per slot). Used on older kernels or as a batch fallback.
func (kf *KernelFilterController) updateSyscallFilterSequential(allow map[uint32]bool) error {
	for i := uint32(0); i < 512; i++ {
		var val uint8
		if allow[i] {
			val = 1
		}
		if err := kf.syscallFilterMap.Update(i, val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("bpf: update syscall filter slot %d: %w", i, err)
		}
	}
	return nil
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
