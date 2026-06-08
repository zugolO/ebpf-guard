package profiler

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// ProfilerState is the JSON-serializable snapshot of the AnomalyDetector's
// learned state. Written on graceful shutdown; read on startup to allow the
// agent to skip the learning period after a pod restart.
type ProfilerState struct {
	// SavedAt is when the state was written; used for the staleness check.
	SavedAt time.Time `json:"saved_at"`
	// LearningPeriod is the configured learning period at save time.
	LearningPeriod time.Duration `json:"learning_period"`
	// LearningComplete is true when the learning phase had finished.
	LearningComplete bool `json:"learning_complete"`
	// LearningStartTime is the original wall-clock start of the learning phase.
	LearningStartTime time.Time `json:"learning_start_time"`
	// SampleCount is the number of events recorded during learning.
	SampleCount uint64 `json:"sample_count"`
	// Profiles maps WorkloadKey.String() to a serialized behavioral profile.
	Profiles map[string]persistedProfile `json:"profiles,omitempty"`
}

// persistedEWMA is a compact, JSON-friendly snapshot of an EWMA.
type persistedEWMA struct {
	Value  float64 `json:"v"`
	Count  uint64  `json:"n"`
	Weight float64 `json:"w"`
}

func snapshotEWMA(e *EWMA) persistedEWMA {
	if e == nil {
		return persistedEWMA{}
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return persistedEWMA{Value: e.value, Count: e.count, Weight: e.weight}
}

func restoreEWMA(p persistedEWMA) *EWMA {
	weight := p.Weight
	if weight <= 0 || weight > 1 {
		weight = 0.3
	}
	e := &EWMA{weight: weight}
	e.value = p.Value
	e.count = p.Count
	return e
}

// persistedNetworkProfile is a JSON-friendly snapshot of NetworkProfile.
type persistedNetworkProfile struct {
	// DestPorts keyed by decimal port string.
	DestPorts map[string]persistedEWMA `json:"dest_ports,omitempty"`
	// DestAddrs keyed by 32-char lower-hex encoding of the raw [16]byte address.
	DestAddrs        map[string]persistedEWMA `json:"dest_addrs,omitempty"`
	TotalConnections uint64                    `json:"total_connections"`
}

// persistedFileProfile is a JSON-friendly snapshot of FileProfile.
type persistedFileProfile struct {
	Directories     map[string]persistedEWMA `json:"directories,omitempty"`
	Extensions      map[string]persistedEWMA `json:"extensions,omitempty"`
	TotalOperations uint64                    `json:"total_operations"`
}

// persistedSyscallProfile is a JSON-friendly snapshot of SyscallProfile.
type persistedSyscallProfile struct {
	// Syscalls keyed by decimal syscall-number string.
	Syscalls      map[string]persistedEWMA `json:"syscalls,omitempty"`
	TotalSyscalls uint64                    `json:"total_syscalls"`
}

// persistedGPUProfile is a JSON-friendly snapshot of GPUProfile.
type persistedGPUProfile struct {
	// OpCounts keyed by decimal GPUOpType string.
	OpCounts map[string]persistedEWMA `json:"op_counts,omitempty"`
	// AllocSizeBuckets keyed by decimal bucket-index string.
	AllocSizeBuckets map[string]persistedEWMA `json:"alloc_size_buckets,omitempty"`
	TotalOps         uint64                    `json:"total_ops"`
}

// persistedProfile is a JSON-friendly snapshot of ProcessProfile.
type persistedProfile struct {
	Comm       string    `json:"comm"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`

	Network persistedNetworkProfile `json:"network"`
	File    persistedFileProfile    `json:"file"`
	Syscall persistedSyscallProfile `json:"syscall"`
	GPU     persistedGPUProfile     `json:"gpu"`

	AnomalyScore float64 `json:"anomaly_score"`
	AlertCount   uint64  `json:"alert_count"`
}

// snapshotProfile snapshots a ProcessProfile under its own lock.
// The caller must NOT hold profile.mu.
func snapshotProfile(p *ProcessProfile) persistedProfile {
	p.mu.Lock()
	defer p.mu.Unlock()

	pp := persistedProfile{
		Comm:         p.Comm,
		CreatedAt:    p.CreatedAt,
		LastSeenAt:   p.LastSeenAt,
		AnomalyScore: p.AnomalyScore,
		AlertCount:   p.AlertCount,
	}

	// Network
	pp.Network.TotalConnections = p.NetworkProfile.TotalConnections
	if len(p.NetworkProfile.DestPorts) > 0 {
		pp.Network.DestPorts = make(map[string]persistedEWMA, len(p.NetworkProfile.DestPorts))
		for port, e := range p.NetworkProfile.DestPorts {
			pp.Network.DestPorts[strconv.Itoa(int(port))] = snapshotEWMA(e)
		}
	}
	if len(p.NetworkProfile.DestAddrs) > 0 {
		pp.Network.DestAddrs = make(map[string]persistedEWMA, len(p.NetworkProfile.DestAddrs))
		for addr, e := range p.NetworkProfile.DestAddrs {
			pp.Network.DestAddrs[hex.EncodeToString(addr[:])] = snapshotEWMA(e)
		}
	}

	// File
	pp.File.TotalOperations = p.FileProfile.TotalOperations
	if len(p.FileProfile.Directories) > 0 {
		pp.File.Directories = make(map[string]persistedEWMA, len(p.FileProfile.Directories))
		for dir, e := range p.FileProfile.Directories {
			pp.File.Directories[dir] = snapshotEWMA(e)
		}
	}
	if len(p.FileProfile.Extensions) > 0 {
		pp.File.Extensions = make(map[string]persistedEWMA, len(p.FileProfile.Extensions))
		for ext, e := range p.FileProfile.Extensions {
			pp.File.Extensions[ext] = snapshotEWMA(e)
		}
	}

	// Syscall
	pp.Syscall.TotalSyscalls = p.SyscallProfile.TotalSyscalls
	if len(p.SyscallProfile.Syscalls) > 0 {
		pp.Syscall.Syscalls = make(map[string]persistedEWMA, len(p.SyscallProfile.Syscalls))
		for nr, e := range p.SyscallProfile.Syscalls {
			pp.Syscall.Syscalls[strconv.FormatInt(nr, 10)] = snapshotEWMA(e)
		}
	}

	// GPU
	pp.GPU.TotalOps = p.GPUProfile.TotalOps
	if len(p.GPUProfile.OpCounts) > 0 {
		pp.GPU.OpCounts = make(map[string]persistedEWMA, len(p.GPUProfile.OpCounts))
		for op, e := range p.GPUProfile.OpCounts {
			pp.GPU.OpCounts[strconv.Itoa(int(op))] = snapshotEWMA(e)
		}
	}
	if len(p.GPUProfile.AllocSizeBuckets) > 0 {
		pp.GPU.AllocSizeBuckets = make(map[string]persistedEWMA, len(p.GPUProfile.AllocSizeBuckets))
		for b, e := range p.GPUProfile.AllocSizeBuckets {
			pp.GPU.AllocSizeBuckets[strconv.Itoa(int(b))] = snapshotEWMA(e)
		}
	}

	return pp
}

// restoreProfile reconstructs a ProcessProfile from a persisted snapshot.
func restoreProfile(pp persistedProfile, key WorkloadKey, weight float64) *ProcessProfile {
	p := NewProcessProfileForWorkload(key)
	p.Comm = pp.Comm
	p.CreatedAt = pp.CreatedAt
	p.LastSeenAt = pp.LastSeenAt
	p.AnomalyScore = pp.AnomalyScore
	p.AlertCount = pp.AlertCount

	// Network
	p.NetworkProfile.TotalConnections = pp.Network.TotalConnections
	for portStr, pe := range pp.Network.DestPorts {
		v, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			continue
		}
		p.NetworkProfile.DestPorts[uint16(v)] = restoreEWMA(pe)
	}
	for addrHex, pe := range pp.Network.DestAddrs {
		b, err := hex.DecodeString(addrHex)
		if err != nil || len(b) != 16 {
			continue
		}
		var addr [16]byte
		copy(addr[:], b)
		p.NetworkProfile.DestAddrs[addr] = restoreEWMA(pe)
	}

	// File
	p.FileProfile.TotalOperations = pp.File.TotalOperations
	for dir, pe := range pp.File.Directories {
		p.FileProfile.Directories[dir] = restoreEWMA(pe)
	}
	for ext, pe := range pp.File.Extensions {
		p.FileProfile.Extensions[ext] = restoreEWMA(pe)
	}

	// Syscall
	p.SyscallProfile.TotalSyscalls = pp.Syscall.TotalSyscalls
	for nrStr, pe := range pp.Syscall.Syscalls {
		nr, err := strconv.ParseInt(nrStr, 10, 64)
		if err != nil {
			continue
		}
		p.SyscallProfile.Syscalls[nr] = restoreEWMA(pe)
	}

	// GPU
	p.GPUProfile.TotalOps = pp.GPU.TotalOps
	for opStr, pe := range pp.GPU.OpCounts {
		v, err := strconv.ParseUint(opStr, 10, 8)
		if err != nil {
			continue
		}
		p.GPUProfile.OpCounts[types.GPUOpType(v)] = restoreEWMA(pe)
	}
	for bucketStr, pe := range pp.GPU.AllocSizeBuckets {
		v, err := strconv.ParseUint(bucketStr, 10, 8)
		if err != nil {
			continue
		}
		p.GPUProfile.AllocSizeBuckets[uint8(v)] = restoreEWMA(pe)
	}

	_ = weight // weight is embedded in each EWMA already
	return p
}

// workloadKeyFromString parses the canonical string produced by WorkloadKey.String().
// Format: "comm|namespace|applabel" — SplitN 3 handles applabels that contain "|".
func workloadKeyFromString(s string) WorkloadKey {
	parts := strings.SplitN(s, "|", 3)
	switch len(parts) {
	case 3:
		return WorkloadKey{Comm: parts[0], Namespace: parts[1], AppLabel: parts[2]}
	case 2:
		return WorkloadKey{Comm: parts[0], Namespace: parts[1]}
	default:
		return WorkloadKey{Comm: s}
	}
}

// SaveState serializes the AnomalyDetector's learned state to a JSON file at
// path.  The write is atomic: a temp file is written and renamed so a crash
// during the write cannot leave a corrupt state file.
func (ad *AnomalyDetector) SaveState(path string) error {
	// Collect learner state under its lock.
	ad.learner.mu.RLock()
	startTime := ad.learner.startTime
	sampleCount := ad.learner.sampleCount
	learningComplete := ad.learner.learningComplete
	ad.learner.mu.RUnlock()

	// Collect config under the detector lock.
	ad.mu.RLock()
	learningPeriod := ad.learningPeriod
	ad.mu.RUnlock()

	// Snapshot profiles: first collect pointers under the manager lock, then
	// snapshot each profile under its own lock (correct lock ordering).
	ad.profileManager.mu.RLock()
	type keyedProfile struct {
		key  WorkloadKey
		prof *ProcessProfile
	}
	pairs := make([]keyedProfile, 0, len(ad.profileManager.profiles))
	for k, p := range ad.profileManager.profiles {
		pairs = append(pairs, keyedProfile{key: k, prof: p})
	}
	ad.profileManager.mu.RUnlock()

	profiles := make(map[string]persistedProfile, len(pairs))
	for _, kp := range pairs {
		profiles[kp.key.String()] = snapshotProfile(kp.prof)
	}

	state := ProfilerState{
		SavedAt:           time.Now(),
		LearningPeriod:    learningPeriod,
		LearningComplete:  learningComplete,
		LearningStartTime: startTime,
		SampleCount:       sampleCount,
		Profiles:          profiles,
	}

	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("profiler: marshal state: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("profiler: create state dir: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("profiler: write state: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("profiler: rename state file: %w", err)
	}
	return nil
}

// LoadState restores a previously saved profiler state from path.
// learningPeriod is the current configured learning period; state older than
// 2× this value is considered stale and silently ignored.
//
// Returns (true, nil) when the state was loaded and learning was already
// complete, (false, nil) when state was absent or stale, and (false, err)
// on I/O or parse errors.
func (ad *AnomalyDetector) LoadState(path string, learningPeriod time.Duration) (bool, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return false, nil // normal first boot — no state file yet
	}
	if err != nil {
		return false, fmt.Errorf("profiler: read state: %w", err)
	}

	var state ProfilerState
	if err := json.Unmarshal(data, &state); err != nil {
		return false, fmt.Errorf("profiler: parse state: %w", err)
	}

	// Freshness check: reject state older than 2× the learning period.
	if time.Since(state.SavedAt) > 2*learningPeriod {
		return false, nil
	}

	// Restore learner.
	ad.learner.mu.Lock()
	ad.learner.startTime = state.LearningStartTime
	ad.learner.sampleCount = state.SampleCount
	ad.learner.learningComplete = state.LearningComplete
	ad.learner.mu.Unlock()

	if state.LearningComplete {
		ad.learningComplete.Store(true)
	}

	// Restore workload profiles.
	if len(state.Profiles) > 0 {
		ad.profileManager.mu.Lock()
		for keyStr, pp := range state.Profiles {
			key := workloadKeyFromString(keyStr)
			if _, exists := ad.profileManager.profiles[key]; exists {
				continue // skip — already populated by events arriving during startup
			}
			profile := restoreProfile(pp, key, ad.profileManager.weight)
			ad.profileManager.profiles[key] = profile
			ad.profileManager.lruIndex.push(&ad.profileManager.lruHeap, key)
		}
		ad.profileManager.mu.Unlock()
	}

	return state.LearningComplete, nil
}
