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

// chainSlice wraps a pooled ProcessNode slice. Storing a *chainSlice in
// sync.Pool costs zero allocations when boxing into interface{} because a
// pointer (8 bytes) fits inline in the interface word, unlike a raw slice
// header (24 bytes) which would require a heap allocation on every Put.
type chainSlice struct {
	nodes []types.ProcessNode
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
	config     LineageConfig
	logger     *slog.Logger
	lineage    map[uint32]*parentInfo
	ancestry   map[uint32]*chainSlice  // PID → pooled ancestor chain (root → PID)
	commCache  map[uint32]string       // ppid → comm, avoids repeated /proc reads
	commIntern map[[16]byte]string     // raw comm bytes → interned string (eliminates per-event string allocs)
	maxDepth   int
	chainPool  sync.Pool // items are *chainSlice pre-allocated to maxDepth capacity
	mu         sync.RWMutex
	onMatch    func(LineageMatch)
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
		config:     config,
		logger:     logger,
		lineage:    make(map[uint32]*parentInfo),
		ancestry:   make(map[uint32]*chainSlice),
		commCache:  make(map[uint32]string),
		commIntern: make(map[[16]byte]string, 64),
		maxDepth:   maxDepth,
		onMatch:    func(m LineageMatch) {}, // no-op default
	}
	lt.chainPool.New = func() any {
		return &chainSlice{nodes: make([]types.ProcessNode, 0, maxDepth)}
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
	info := parentInfoPool.Get().(*parentInfo)
	info.PPID = ppid
	info.ParentComm = parentComm
	info.Timestamp = time.Now()
	lt.mu.Lock()
	if old := lt.lineage[e.PID]; old != nil {
		old.PPID = 0
		old.ParentComm = ""
		parentInfoPool.Put(old)
	}
	lt.lineage[e.PID] = info
	lt.buildAncestryLocked(e.PID, ppid, parentComm, e.Comm)
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

	// Store lineage info and update ancestry chain under a single lock acquisition.
	info := parentInfoPool.Get().(*parentInfo)
	info.PPID = ppid
	info.ParentComm = parentComm
	info.Timestamp = time.Now()
	lt.mu.Lock()
	// Return the previous parentInfo for this PID to the pool before replacing it.
	if old := lt.lineage[e.PID]; old != nil {
		old.PPID = 0
		old.ParentComm = ""
		parentInfoPool.Put(old)
	}
	lt.lineage[e.PID] = info
	comm := lt.buildAncestryLocked(e.PID, ppid, parentComm, e.Comm)
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
	entry := lt.ancestry[pid]
	if entry == nil || len(entry.nodes) == 0 {
		return nil
	}
	result := make(types.ProcessTree, len(entry.nodes))
	copy(result, entry.nodes)
	return result
}

// buildAncestryLocked extends the ancestry chain for pid. Must be called with
// lt.mu held for writing. Returns the interned comm string for pid.
func (lt *LineageTracker) buildAncestryLocked(pid, ppid uint32, parentComm string, rawComm [16]byte) string {
	comm := lt.internCommLocked(rawComm)

	// Locate the parent's existing chain.
	var parentNodes []types.ProcessNode
	if parentEntry := lt.ancestry[ppid]; parentEntry != nil {
		parentNodes = parentEntry.nodes
	} else {
		// We haven't seen the parent's events yet; try to bootstrap from /proc.
		parentNodes = buildChainFromProc(ppid, lt.maxDepth-1)
		if len(parentNodes) > 0 {
			// Wrap in a chainSlice so the ancestry map is type-consistent.
			// This entry has a smaller-than-maxDepth cap so it will not be
			// returned to the pool on eviction.
			lt.ancestry[ppid] = &chainSlice{nodes: parentNodes}
		}
	}

	// Get a pre-allocated *chainSlice from the pool (0 alloc when warm).
	entry := lt.chainPool.Get().(*chainSlice)
	entry.nodes = entry.nodes[:0]

	// Copy parent entries, trimmed so the combined chain stays within maxDepth.
	start := 0
	if len(parentNodes) >= lt.maxDepth {
		start = len(parentNodes) - lt.maxDepth + 1
	}
	entry.nodes = append(entry.nodes, parentNodes[start:]...)
	entry.nodes = append(entry.nodes, types.ProcessNode{PID: pid, PPID: ppid, Comm: comm})

	// Ensure the parent node's Comm is set correctly (may have been set to "" by /proc miss).
	if len(entry.nodes) >= 2 {
		parent := &entry.nodes[len(entry.nodes)-2]
		if parent.PID == ppid && parent.Comm == "" {
			parent.Comm = parentComm
		}
	}

	// Return the old chain entry to the pool before replacing it.
	// Only pool-sourced entries (cap >= maxDepth) are eligible; /proc-bootstrapped
	// entries have a smaller cap and are left for the GC.
	if old, ok := lt.ancestry[pid]; ok && cap(old.nodes) >= lt.maxDepth {
		old.nodes = old.nodes[:0]
		lt.chainPool.Put(old)
	}

	lt.ancestry[pid] = entry
	return comm
}

// internCommLocked returns the interned string for the given raw comm bytes,
// caching the result so subsequent calls with the same bytes cost 0 allocs.
// Must be called with lt.mu held for writing.
func (lt *LineageTracker) internCommLocked(raw [16]byte) string {
	if s, ok := lt.commIntern[raw]; ok {
		return s
	}
	s := cleanComm(raw[:])
	lt.commIntern[raw] = s
	return s
}

// buildChainFromProc walks /proc to reconstruct up to maxDepth ancestors for pid.
// Results are ordered from oldest ancestor to pid.
func buildChainFromProc(pid uint32, maxDepth int) []types.ProcessNode {
	if maxDepth <= 0 {
		return nil
	}
	var chain []types.ProcessNode
	cur := pid
	for len(chain) < maxDepth && cur > 1 {
		comm := readProcComm(cur)
		ppid := readProcPPID(cur)
		chain = append([]types.ProcessNode{{PID: cur, PPID: ppid, Comm: comm}}, chain...)
		if ppid == 0 || ppid == cur {
			break
		}
		cur = ppid
	}
	return chain
}

// readProcPPID reads the parent PID for a process from /proc/<pid>/status.
func readProcPPID(pid uint32) uint32 {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PPid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				v, err := strconv.ParseUint(fields[1], 10, 32)
				if err == nil {
					return uint32(v)
				}
			}
			break
		}
	}
	return 0
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

		// Check lineage map and commCache under a single RLock.
		lt.mu.RLock()
		if info, ok := lt.lineage[e.PPID]; ok {
			comm := info.ParentComm
			lt.mu.RUnlock()
			return e.PPID, comm
		}
		if comm, ok := lt.commCache[e.PPID]; ok {
			lt.mu.RUnlock()
			return e.PPID, comm
		}
		lt.mu.RUnlock()

		// Cache miss: read from /proc/<ppid>/comm and populate commCache.
		comm := readProcComm(e.PPID)
		if comm != "" {
			lt.mu.Lock()
			lt.commCache[e.PPID] = comm
			lt.mu.Unlock()
		}
		return e.PPID, comm
	}

	// e.PPID == 0 means BPF did not populate the parent PID field (common for
	// synthetic/test events and non-exec syscall tracepoints). Skip the /proc
	// fallback to avoid a per-event syscall; real BPF events always carry PPID.
	return 0, ""
}

// readParentFromProc reads parent PID from /proc/<pid>/status.
func (lt *LineageTracker) readParentFromProc(pid uint32) (uint32, string) {
	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return 0, ""
	}

	var ppid uint32
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "PPid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				ppid64, err := strconv.ParseUint(fields[1], 10, 32)
				if err == nil {
					ppid = uint32(ppid64)
				}
			}
			break
		}
	}

	if ppid == 0 {
		return 0, ""
	}

	comm := readProcComm(ppid)
	return ppid, comm
}

// readProcComm reads process name from /proc/<pid>/comm.
func readProcComm(pid uint32) string {
	commPath := fmt.Sprintf("/proc/%d/comm", pid)
	data, err := os.ReadFile(commPath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
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

// Cleanup removes stale lineage and ancestry entries, returning pooled objects
// to their respective pools.
func (lt *LineageTracker) Cleanup(now time.Time) {
	lt.mu.Lock()
	defer lt.mu.Unlock()

	for pid, info := range lt.lineage {
		if now.Sub(info.Timestamp) > lt.config.TTL {
			delete(lt.lineage, pid)
			if entry, ok := lt.ancestry[pid]; ok {
				delete(lt.ancestry, pid)
				// Return pool-sourced entries (cap >= maxDepth) for reuse;
				// /proc-bootstrapped entries have smaller cap and are GC'd.
				if cap(entry.nodes) >= lt.maxDepth {
					entry.nodes = entry.nodes[:0]
					lt.chainPool.Put(entry)
				}
			}
			// Reset and return to pool to amortise allocations across long-lived processes.
			info.PPID = 0
			info.ParentComm = ""
			parentInfoPool.Put(info)
		}
	}
	// commCache is keyed by ppid and may outlive individual PID entries; clear it
	// wholesale each Cleanup cycle so stale proc-comm mappings don't accumulate.
	for k := range lt.commCache {
		delete(lt.commCache, k)
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
