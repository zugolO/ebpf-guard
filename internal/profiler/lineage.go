// Package profiler provides process lineage tracking for detecting suspicious parent-child relationships.
package profiler

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// parentInfoPool reduces per-event heap allocations for parentInfo structs.
var parentInfoPool = sync.Pool{
	New: func() any { return &parentInfo{} },
}

// LineageCondition defines an additional constraint that must be satisfied
// for a lineage pattern to fire. It is evaluated against the child process
// event after the parent/child comm lists have already matched.
//
// Supported fields: comm, parent_comm, uid, pid, ppid.
// Supported ops:    in, not_in, eq (equals), neq (not_equals).
type LineageCondition struct {
	Field  string   `yaml:"field"`
	Op     string   `yaml:"op"`
	Values []string `yaml:"values"`
}

// LineagePattern defines a suspicious parent-child relationship pattern.
type LineagePattern struct {
	Name        string            `yaml:"name"`
	Description string            `yaml:"description"`
	ParentComms []string          `yaml:"parent_comms"`
	ChildComms  []string          `yaml:"child_comms"`
	Severity    string            `yaml:"severity"`
	Condition   *LineageCondition `yaml:"condition,omitempty"`
}

// LineageConfig holds configuration for lineage tracking.
type LineageConfig struct {
	// Enabled controls whether lineage tracking is active. When false, both
	// Track() (ancestry building) and Update() (pattern detection) are no-ops.
	// Disable this if process tree enrichment is not needed to avoid the
	// per-event cost (~2.3 µs/op, 442 B, 4 allocs for Update).
	Enabled  bool             `yaml:"enabled"`
	TTL      time.Duration    `yaml:"ttl"`
	Patterns []LineagePattern `yaml:"patterns"`
	// MaxDepth is the maximum number of ancestors stored per process.
	// Zero or negative values default to 16.
	MaxDepth int `yaml:"max_depth"`
}

// DefaultLineageConfig returns default lineage configuration.
func DefaultLineageConfig() LineageConfig {
	return LineageConfig{
		Enabled:  true,
		TTL:      5 * time.Minute,
		MaxDepth: 8,
		Patterns: []LineagePattern{
			{
				Name:        "web_shell_spawn",
				Description: "Web server spawning shell - potential RCE or webshell",
				ParentComms: []string{"nginx", "apache2", "httpd", "node", "nodejs", "python", "python3", "gunicorn", "uwsgi"},
				ChildComms:  []string{"sh", "bash", "dash", "zsh", "fish"},
				Severity:    "critical",
			},
			{
				Name:        "shell_network_tool",
				Description: "Shell spawning network tool - potential data exfil or lateral movement",
				ParentComms: []string{"sh", "bash", "dash", "zsh", "fish"},
				ChildComms:  []string{"curl", "wget", "nc", "netcat", "ncat", "python", "python3", "ruby", "perl"},
				Severity:    "critical",
			},
			{
				Name:        "shell_recon_tool",
				Description: "Shell spawning reconnaissance tool",
				ParentComms: []string{"sh", "bash", "dash", "zsh", "fish"},
				ChildComms:  []string{"nmap", "masscan", "zmap", "dig", "nslookup"},
				Severity:    "warning",
			},
		},
	}
}

// parentInfo tracks parent process information.
type parentInfo struct {
	PPID       uint32
	ParentComm string
	Timestamp  time.Time
}

// procEntry caches a /proc lookup result for a PID, avoiding repeated reads.
// Both comm and ppid are populated by readProcStatus in a single syscall.
type procEntry struct {
	comm      string
	ppid      uint32
	timestamp time.Time
}

// LineageMatch represents a detected suspicious lineage pattern.
type LineageMatch struct {
	Pattern    LineagePattern
	PID        uint32
	Comm       string
	PPID       uint32
	ParentComm string
	Timestamp  time.Time
}

// lineageShardCount is the number of PID-keyed shards the tracker is split into.
// A single global mutex previously serialised every per-event Track call across
// the entire PID-partitioned ingest worker pool, negating its parallelism.
// Sharding by PID lets independent PIDs proceed concurrently. Must be a power of
// two so lineageShardMask can select a shard with a bitmask.
const lineageShardCount = 16
const lineageShardMask = lineageShardCount - 1

// lineageShard holds the lineage/ancestry/procCache maps for a subset of PIDs,
// guarded by its own RWMutex.
type lineageShard struct {
	mu        sync.RWMutex
	lineage   map[uint32]*parentInfo
	ancestry  map[uint32][]types.ProcessNode // PID → full ancestor chain (root → PID)
	procCache map[uint32]*procEntry          // pid → (comm, ppid, ts), avoids repeated /proc reads
}

// LineageTracker tracks process parent-child relationships and detects suspicious patterns.
type LineageTracker struct {
	config   LineageConfig
	logger   *slog.Logger
	shards   [lineageShardCount]*lineageShard
	maxDepth int
	onMatch  func(LineageMatch)
}

// shardFor returns the shard owning pid.
func (lt *LineageTracker) shardFor(pid uint32) *lineageShard {
	return lt.shards[pid&lineageShardMask]
}

// NewLineageTracker creates a new lineage tracker.
func NewLineageTracker(config LineageConfig, logger *slog.Logger) *LineageTracker {
	if config.TTL <= 0 {
		config.TTL = 5 * time.Minute
	}
	maxDepth := config.MaxDepth
	if maxDepth <= 0 {
		maxDepth = 16
	}

	lt := &LineageTracker{
		config:   config,
		logger:   logger,
		maxDepth: maxDepth,
		onMatch:  func(m LineageMatch) {}, // no-op default
	}
	for i := range lt.shards {
		lt.shards[i] = &lineageShard{
			lineage:   make(map[uint32]*parentInfo),
			ancestry:  make(map[uint32][]types.ProcessNode),
			procCache: make(map[uint32]*procEntry),
		}
	}

	return lt
}

// SetMatchHandler sets the callback for lineage pattern matches.
func (lt *LineageTracker) SetMatchHandler(handler func(LineageMatch)) {
	lt.onMatch = handler
}

// Track records the process ancestry for e without performing pattern detection.
// It is safe to call concurrently with Update.
// CorrelationEngine calls this on every event so that GetProcessTree can later
// return the full ancestor chain when enriching alerts.
//
// Performance: steady state (PID/PPID/comm unchanged since the last call, the
// overwhelmingly common case for a long-lived process) is a single shard lock
// plus a comparison — no allocation. A changed PPID/comm triggers a full
// ancestry rebuild, priced at ~2.3 µs/op, 442 B, 4 allocs (via
// BenchmarkLineageTrackerUpdate). Callers should gate this behind
// config.Enabled and ppid>0 checks. For high-throughput deployments where
// process tree enrichment is not required, set LineageConfig.Enabled=false to
// eliminate this per-event cost entirely.
func (lt *LineageTracker) Track(e types.Event) {
	if !lt.config.Enabled {
		return
	}
	ppid, parentComm := lt.getParentInfo(e)
	if ppid == 0 {
		return
	}
	comm := cleanComm(e.Comm[:])
	lt.store(e.PID, ppid, parentComm, comm)
}

// store records lineage/procCache for pid and (re)builds its ancestry chain.
// Shared by Track and Update.
//
// Steady state fast path: a long-lived process emits a stream of events with
// the same PID/PPID/comm on every call. When the recorded lineage and the
// last ancestry node already match, only the timestamp is refreshed (for TTL
// purposes) under a single lock — no allocation, no ancestry rebuild.
func (lt *LineageTracker) store(pid, ppid uint32, parentComm, comm string) {
	now := time.Now()
	s := lt.shardFor(pid)

	s.mu.Lock()
	if info, ok := s.lineage[pid]; ok && info.PPID == ppid && info.ParentComm == parentComm {
		if chain := s.ancestry[pid]; len(chain) > 0 {
			if last := chain[len(chain)-1]; last.PID == pid && last.PPID == ppid && last.Comm == comm {
				info.Timestamp = now
				if entry, ok := s.procCache[pid]; ok {
					entry.comm, entry.ppid, entry.timestamp = comm, ppid, now
				} else if comm != "" || ppid > 0 {
					s.procCache[pid] = &procEntry{comm: comm, ppid: ppid, timestamp: now}
				}
				s.mu.Unlock()
				return
			}
		}
	}
	s.mu.Unlock()

	info := parentInfoPool.Get().(*parentInfo)
	info.PPID = ppid
	info.ParentComm = parentComm
	info.Timestamp = now

	s.mu.Lock()
	if old := s.lineage[pid]; old != nil && old != info {
		// Return the displaced entry to the pool instead of leaking it to GC;
		// only Cleanup used to do this, so hot PIDs bypassed the pool entirely.
		old.PPID = 0
		old.ParentComm = ""
		parentInfoPool.Put(old)
	}
	s.lineage[pid] = info
	// Eagerly cache BPF-provided comm+ppid so buildChainFromProc avoids
	// /proc reads when this process becomes a parent in later chain builds.
	if entry, ok := s.procCache[pid]; ok {
		entry.comm, entry.ppid, entry.timestamp = comm, ppid, now
	} else if comm != "" || ppid > 0 {
		s.procCache[pid] = &procEntry{comm: comm, ppid: ppid, timestamp: now}
	}
	s.mu.Unlock()

	lt.buildAncestry(pid, ppid, parentComm, comm)
}

// Update processes an event, updates lineage information, and returns a match if
// a suspicious pattern is detected.
func (lt *LineageTracker) Update(e types.Event) *LineageMatch {
	if !lt.config.Enabled {
		return nil
	}

	// Extract parent info from event or /proc
	ppid, parentComm := lt.getParentInfo(e)
	if ppid == 0 {
		return nil
	}

	comm := cleanComm(e.Comm[:])

	// Store lineage info and update the ancestry chain (sharded by PID).
	lt.store(e.PID, ppid, parentComm, comm)

	// Check for pattern match
	match := lt.checkPattern(e, parentComm, comm)
	if match != nil {
		result := LineageMatch{
			Pattern:    *match,
			PID:        e.PID,
			Comm:       comm,
			PPID:       ppid,
			ParentComm: parentComm,
			Timestamp:  time.Now(),
		}

		lt.logger.Warn("lineage: suspicious parent-child relationship detected",
			slog.String("pattern", match.Name),
			slog.String("parent", parentComm),
			slog.String("child", comm),
			slog.Uint64("ppid", uint64(ppid)),
			slog.Uint64("pid", uint64(e.PID)),
			slog.String("severity", match.Severity),
		)

		if lt.onMatch != nil {
			lt.onMatch(result)
		}

		return &result
	}

	return nil
}

// GetProcessTree returns the full ancestor chain for pid, ordered from the
// oldest known ancestor to pid itself.  Returns nil if no ancestry has been
// recorded for the PID.
func (lt *LineageTracker) GetProcessTree(pid uint32) types.ProcessTree {
	s := lt.shardFor(pid)
	s.mu.RLock()
	chain := s.ancestry[pid]
	if len(chain) == 0 {
		s.mu.RUnlock()
		return nil
	}
	result := make(types.ProcessTree, len(chain))
	copy(result, chain)
	s.mu.RUnlock()
	return result
}

// buildAncestry extends the ancestry chain for pid. It is deadlock-free under
// sharding: it reads (and may bootstrap) the parent's chain in the parent's
// shard, releases that lock, then writes pid's chain in pid's shard — the two
// shard locks are never held simultaneously.
func (lt *LineageTracker) buildAncestry(pid, ppid uint32, parentComm, comm string) {
	ps := lt.shardFor(ppid)
	ps.mu.RLock()
	parentChain := ps.ancestry[ppid]
	ps.mu.RUnlock()

	if len(parentChain) == 0 {
		// We haven't seen the parent's events yet; try to bootstrap from /proc.
		parentChain = lt.buildChainFromProc(ppid, lt.maxDepth-1)
		// Cache so subsequent events with the same ppid skip /proc entirely.
		if len(parentChain) > 0 {
			ps.mu.Lock()
			// Re-check: another goroutine may have built the chain meanwhile.
			if existing := ps.ancestry[ppid]; len(existing) == 0 {
				ps.ancestry[ppid] = parentChain
			} else {
				parentChain = existing
			}
			ps.mu.Unlock()
		}
	}

	node := types.ProcessNode{PID: pid, PPID: ppid, Comm: comm}
	newLen := len(parentChain) + 1
	newChain := make([]types.ProcessNode, newLen, newLen)
	copy(newChain, parentChain)
	newChain[len(parentChain)] = node

	// Ensure the parent node's Comm is set correctly (may have been set to "" by /proc miss).
	if len(newChain) >= 2 {
		parent := &newChain[len(newChain)-2]
		if parent.PID == ppid && parent.Comm == "" {
			parent.Comm = parentComm
		}
	}

	if len(newChain) > lt.maxDepth {
		newChain = newChain[len(newChain)-lt.maxDepth:]
	}

	s := lt.shardFor(pid)
	s.mu.Lock()
	s.ancestry[pid] = newChain
	s.mu.Unlock()
}

// buildChainFromProc walks /proc to reconstruct up to maxDepth ancestors for pid.
// Results are ordered from oldest ancestor to pid.  Per-process /proc results are
// cached in the owning shard's procCache so that subsequent chain builds (for
// different children of the same subtree) avoid repeated syscalls.
//
// Locking: each ancestor's procCache entry is read/written under that PID's own
// shard lock, acquired and released per iteration. The lock is never held across
// the readProcStatus syscall, so a slow /proc read cannot block other PIDs.
//
// Uses readProcStatus to fetch both comm and ppid in a single /proc read,
// halving the number of /proc syscalls per ancestor compared to separate
// readProcComm + readProcPPID calls.
func (lt *LineageTracker) buildChainFromProc(pid uint32, maxDepth int) []types.ProcessNode {
	if maxDepth <= 0 {
		return nil
	}
	var chain []types.ProcessNode
	cur := pid
	for len(chain) < maxDepth && cur > 1 {
		s := lt.shardFor(cur)
		s.mu.RLock()
		entry, ok := s.procCache[cur]
		var comm string
		var ppid uint32
		cached := ok && entry.comm != "" && entry.ppid > 0
		if cached {
			comm = entry.comm
			ppid = entry.ppid
		}
		s.mu.RUnlock()

		if !cached {
			// Read /proc without holding any shard lock.
			comm, ppid = readProcStatus(cur)
			if comm != "" || ppid > 0 {
				s.mu.Lock()
				if e2, ok2 := s.procCache[cur]; ok2 {
					e2.comm = comm
					e2.ppid = ppid
					e2.timestamp = time.Now()
				} else {
					s.procCache[cur] = &procEntry{comm: comm, ppid: ppid, timestamp: time.Now()}
				}
				s.mu.Unlock()
			}
		}
		chain = append([]types.ProcessNode{{PID: cur, PPID: ppid, Comm: comm}}, chain...)
		if ppid == 0 || ppid == cur {
			break
		}
		cur = ppid
	}
	return chain
}

// readProcStatus reads the process name and parent PID from /proc/<pid>/status
// in a single syscall, replacing the separate readProcComm + readProcPPID calls
// that previously required two /proc reads per level.
func readProcStatus(pid uint32) (comm string, ppid uint32) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return "", 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Name:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				comm = fields[1]
			}
		} else if strings.HasPrefix(line, "PPid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				v, err := strconv.ParseUint(fields[1], 10, 32)
				if err == nil {
					ppid = uint32(v)
				}
			}
		}
		if comm != "" && ppid > 0 {
			break
		}
	}
	return comm, ppid
}

// getParentInfo extracts parent PID and comm from event or /proc.
func (lt *LineageTracker) getParentInfo(e types.Event) (uint32, string) {
	// First try to get from event (if BPF provides PPID)
	if e.PPID > 0 {
		// Prefer the parent comm captured by BPF at fork/exec time. This is
		// authoritative and, crucially, survives short-lived parents (e.g. the
		// bash in nginx→bash→curl) that may already have exited before we can
		// read /proc. Without this, attack-chain detection silently misses the
		// most interesting cases.
		if parentComm := cleanComm(e.ParentComm[:]); parentComm != "" {
			return e.PPID, parentComm
		}

		// Check lineage map and procCache under a single RLock on the ppid shard.
		ps := lt.shardFor(e.PPID)
		ps.mu.RLock()
		if info, ok := ps.lineage[e.PPID]; ok {
			comm := info.ParentComm
			ps.mu.RUnlock()
			return e.PPID, comm
		}
		if entry, ok := ps.procCache[e.PPID]; ok && entry.comm != "" {
			comm := entry.comm
			ps.mu.RUnlock()
			return e.PPID, comm
		}
		ps.mu.RUnlock()

		// Cache miss: read /proc/<ppid>/status (single syscall for comm+ppid).
		comm, grandPPID := readProcStatus(e.PPID)
		if comm != "" || grandPPID > 0 {
			ps.mu.Lock()
			ps.procCache[e.PPID] = &procEntry{comm: comm, ppid: grandPPID, timestamp: time.Now()}
			ps.mu.Unlock()
		}
		return e.PPID, comm
	}

	// e.PPID == 0 means BPF did not populate the parent PID field (common for
	// synthetic/test events and non-exec syscall tracepoints). Skip the /proc
	// fallback to avoid a per-event syscall; real BPF events always carry PPID.
	return 0, ""
}

// checkPattern checks if the parent-child combination matches any pattern,
// including evaluating any structured condition attached to the pattern.
func (lt *LineageTracker) checkPattern(e types.Event, parentComm, childComm string) *LineagePattern {
	for i := range lt.config.Patterns {
		pattern := &lt.config.Patterns[i]

		if matchesAny(parentComm, pattern.ParentComms) &&
			matchesAny(childComm, pattern.ChildComms) &&
			evaluateLineageCondition(e, parentComm, pattern.Condition) {
			return pattern
		}
	}
	return nil
}

// evaluateLineageCondition returns true when cond is nil (unconditional) or when
// the condition is satisfied by event e. Supported fields: comm, parent_comm,
// uid, pid, ppid. Supported ops: in, not_in, eq, neq.
func evaluateLineageCondition(e types.Event, parentComm string, cond *LineageCondition) bool {
	if cond == nil {
		return true
	}

	var value string
	switch cond.Field {
	case "comm":
		value = cleanComm(e.Comm[:])
	case "parent_comm":
		value = parentComm
	case "uid":
		value = strconv.FormatUint(uint64(e.UID), 10)
	case "pid":
		value = strconv.FormatUint(uint64(e.PID), 10)
	case "ppid":
		value = strconv.FormatUint(uint64(e.PPID), 10)
	default:
		return false
	}

	switch strings.ToLower(cond.Op) {
	case "in":
		for _, v := range cond.Values {
			if value == v {
				return true
			}
		}
		return false
	case "not_in":
		for _, v := range cond.Values {
			if value == v {
				return false
			}
		}
		return true
	case "eq", "equals":
		return len(cond.Values) > 0 && value == cond.Values[0]
	case "neq", "not_equals":
		return len(cond.Values) == 0 || value != cond.Values[0]
	default:
		return false
	}
}

// matchesAny checks if a string matches any pattern in the list.
// Exact matches always succeed. Prefix matches succeed only when the
// character immediately after the pattern is a hyphen or ASCII digit —
// allowing nginx-worker and python3 to match their base names while
// preventing false positives such as "node_exporter" matching "node".
func matchesAny(s string, patterns []string) bool {
	for _, p := range patterns {
		if s == p {
			return true
		}
		if strings.HasPrefix(s, p) && len(s) > len(p) {
			next := s[len(p)]
			if next == '-' || (next >= '0' && next <= '9') {
				return true
			}
		}
	}
	return false
}

// cleanComm removes null bytes from comm string.
func cleanComm(comm []byte) string {
	for i := 0; i < len(comm); i++ {
		if comm[i] == 0 {
			return string(comm[:i])
		}
	}
	return string(comm)
}

// Cleanup removes stale lineage and ancestry entries across all shards.
func (lt *LineageTracker) Cleanup(now time.Time) {
	cutoff := now.Add(-lt.config.TTL)
	for _, s := range lt.shards {
		s.mu.Lock()
		for pid, info := range s.lineage {
			if now.Sub(info.Timestamp) > lt.config.TTL {
				delete(s.lineage, pid)
				delete(s.ancestry, pid)
				// Reset and return to pool to amortise allocations across long-lived processes.
				info.PPID = 0
				info.ParentComm = ""
				parentInfoPool.Put(info)
			}
		}
		// Evict procCache entries older than TTL rather than clearing wholesale.
		for pid, entry := range s.procCache {
			if entry.timestamp.Before(cutoff) {
				delete(s.procCache, pid)
			}
		}
		s.mu.Unlock()
	}
}

// GetLineage returns the parent info for a PID (for testing).
func (lt *LineageTracker) GetLineage(pid uint32) (*parentInfo, bool) {
	s := lt.shardFor(pid)
	s.mu.RLock()
	defer s.mu.RUnlock()
	info, ok := s.lineage[pid]
	return info, ok
}

// Size returns the number of tracked processes across all shards.
func (lt *LineageTracker) Size() int {
	n := 0
	for _, s := range lt.shards {
		s.mu.RLock()
		n += len(s.lineage)
		s.mu.RUnlock()
	}
	return n
}
