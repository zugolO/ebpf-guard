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

// LineageTracker tracks process parent-child relationships and detects suspicious patterns.
type LineageTracker struct {
	config    LineageConfig
	logger    *slog.Logger
	lineage   map[uint32]*parentInfo
	ancestry  map[uint32][]types.ProcessNode // PID → full ancestor chain (root → PID)
	procCache map[uint32]*procEntry // pid → (comm, ppid, ts), avoids repeated /proc reads
	maxDepth  int
	mu        sync.RWMutex
	onMatch   func(LineageMatch)
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
		config:    config,
		logger:    logger,
		lineage:   make(map[uint32]*parentInfo),
		ancestry:  make(map[uint32][]types.ProcessNode),
		procCache: make(map[uint32]*procEntry),
		maxDepth:  maxDepth,
		onMatch:   func(m LineageMatch) {}, // no-op default
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
func (lt *LineageTracker) Track(e types.Event) {
	if !lt.config.Enabled {
		return
	}
	ppid, parentComm := lt.getParentInfo(e)
	if ppid == 0 {
		return
	}
	comm := cleanComm(e.Comm[:])
	info := parentInfoPool.Get().(*parentInfo)
	info.PPID = ppid
	info.ParentComm = parentComm
	info.Timestamp = time.Now()
	lt.mu.Lock()
	lt.lineage[e.PID] = info
	// Eagerly cache BPF-provided comm+ppid so buildChainFromProc avoids
	// /proc reads when this process becomes a parent in later chain builds.
	if comm != "" || ppid > 0 {
		lt.procCache[e.PID] = &procEntry{comm: comm, ppid: ppid, timestamp: info.Timestamp}
	}
	lt.buildAncestryLocked(e.PID, ppid, parentComm, comm)
	lt.mu.Unlock()
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

	// Store lineage info and update ancestry chain under a single lock acquisition.
	info := parentInfoPool.Get().(*parentInfo)
	info.PPID = ppid
	info.ParentComm = parentComm
	info.Timestamp = time.Now()
	lt.mu.Lock()
	lt.lineage[e.PID] = info
	// Eagerly cache BPF-provided comm+ppid so buildChainFromProc avoids
	// /proc reads when this process becomes a parent in later chain builds.
	if comm != "" || ppid > 0 {
		lt.procCache[e.PID] = &procEntry{comm: comm, ppid: ppid, timestamp: info.Timestamp}
	}
	lt.buildAncestryLocked(e.PID, ppid, parentComm, comm)
	lt.mu.Unlock()

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
	lt.mu.RLock()
	defer lt.mu.RUnlock()
	chain := lt.ancestry[pid]
	if len(chain) == 0 {
		return nil
	}
	result := make(types.ProcessTree, len(chain))
	copy(result, chain)
	return result
}

// buildAncestryLocked extends the ancestry chain for pid. Must be called with lt.mu held for writing.
func (lt *LineageTracker) buildAncestryLocked(pid, ppid uint32, parentComm, comm string) {
	parentChain := lt.ancestry[ppid]
	if len(parentChain) == 0 {
		// We haven't seen the parent's events yet; try to bootstrap from /proc.
		parentChain = lt.buildChainFromProc(ppid, lt.maxDepth-1)
		// Cache so subsequent events with the same ppid skip /proc entirely.
		if len(parentChain) > 0 {
			lt.ancestry[ppid] = parentChain
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
	lt.ancestry[pid] = newChain
}

// buildChainFromProc walks /proc to reconstruct up to maxDepth ancestors for pid.
// Must be called with lt.mu held for writing. Results are ordered from oldest
// ancestor to pid.  Per-process /proc results are cached in lt.procCache so that
// subsequent chain builds (for different children of the same subtree) avoid
// repeated syscalls.
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
		entry, ok := lt.procCache[cur]
		var comm string
		var ppid uint32
		if ok && entry.comm != "" && entry.ppid > 0 {
			comm = entry.comm
			ppid = entry.ppid
		} else {
			comm, ppid = readProcStatus(cur)
			if ok {
				entry.comm = comm
				entry.ppid = ppid
				entry.timestamp = time.Now()
			} else if comm != "" || ppid > 0 {
				lt.procCache[cur] = &procEntry{comm: comm, ppid: ppid, timestamp: time.Now()}
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

		// Check lineage map and procCache under a single RLock.
		lt.mu.RLock()
		if info, ok := lt.lineage[e.PPID]; ok {
			comm := info.ParentComm
			lt.mu.RUnlock()
			return e.PPID, comm
		}
		if entry, ok := lt.procCache[e.PPID]; ok && entry.comm != "" {
			comm := entry.comm
			lt.mu.RUnlock()
			return e.PPID, comm
		}
		lt.mu.RUnlock()

		// Cache miss: read /proc/<ppid>/status (single syscall for comm+ppid).
		comm, grandPPID := readProcStatus(e.PPID)
		if comm != "" || grandPPID > 0 {
			lt.mu.Lock()
			lt.procCache[e.PPID] = &procEntry{comm: comm, ppid: grandPPID, timestamp: time.Now()}
			lt.mu.Unlock()
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

// Cleanup removes stale lineage and ancestry entries.
func (lt *LineageTracker) Cleanup(now time.Time) {
	lt.mu.Lock()
	defer lt.mu.Unlock()

	for pid, info := range lt.lineage {
		if now.Sub(info.Timestamp) > lt.config.TTL {
			delete(lt.lineage, pid)
			delete(lt.ancestry, pid)
			// Reset and return to pool to amortise allocations across long-lived processes.
			info.PPID = 0
			info.ParentComm = ""
			parentInfoPool.Put(info)
		}
	}
	// Evict procCache entries older than TTL rather than clearing wholesale.
	cutoff := now.Add(-lt.config.TTL)
	for pid, entry := range lt.procCache {
		if entry.timestamp.Before(cutoff) {
			delete(lt.procCache, pid)
		}
	}
}

// GetLineage returns the parent info for a PID (for testing).
func (lt *LineageTracker) GetLineage(pid uint32) (*parentInfo, bool) {
	lt.mu.RLock()
	defer lt.mu.RUnlock()
	info, ok := lt.lineage[pid]
	return info, ok
}

// Size returns the number of tracked processes.
func (lt *LineageTracker) Size() int {
	lt.mu.RLock()
	defer lt.mu.RUnlock()
	return len(lt.lineage)
}
