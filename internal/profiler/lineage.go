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

	"github.com/ebpf-guard/ebpf-guard/pkg/types"
)

// LineagePattern defines a suspicious parent-child relationship pattern.
type LineagePattern struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	ParentComms []string `yaml:"parent_comms"`
	ChildComms  []string `yaml:"child_comms"`
	Severity    string   `yaml:"severity"`
}

// LineageConfig holds configuration for lineage tracking.
type LineageConfig struct {
	Enabled  bool             `yaml:"enabled"`
	TTL      time.Duration    `yaml:"ttl"`
	Patterns []LineagePattern `yaml:"patterns"`
}

// DefaultLineageConfig returns default lineage configuration.
func DefaultLineageConfig() LineageConfig {
	return LineageConfig{
		Enabled: true,
		TTL:     5 * time.Minute,
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
	config  LineageConfig
	logger  *slog.Logger
	lineage map[uint32]*parentInfo
	mu      sync.RWMutex
	onMatch func(LineageMatch)
}

// NewLineageTracker creates a new lineage tracker.
func NewLineageTracker(config LineageConfig, logger *slog.Logger) *LineageTracker {
	if config.TTL <= 0 {
		config.TTL = 5 * time.Minute
	}

	return &LineageTracker{
		config:  config,
		logger:  logger,
		lineage: make(map[uint32]*parentInfo),
		onMatch: func(m LineageMatch) {}, // no-op default
	}
}

// SetMatchHandler sets the callback for lineage pattern matches.
func (lt *LineageTracker) SetMatchHandler(handler func(LineageMatch)) {
	lt.onMatch = handler
}

// Update processes an event and updates lineage information.
// Returns a match if a suspicious pattern is detected.
func (lt *LineageTracker) Update(e types.Event) *LineageMatch {
	if !lt.config.Enabled {
		return nil
	}

	// Extract parent info from event or /proc
	ppid, parentComm := lt.getParentInfo(e)
	if ppid == 0 {
		return nil
	}

	// Store lineage info
	lt.mu.Lock()
	lt.lineage[e.PID] = &parentInfo{
		PPID:       ppid,
		ParentComm: parentComm,
		Timestamp:  time.Now(),
	}
	lt.mu.Unlock()

	// Check for pattern match
	comm := cleanComm(e.Comm[:])
	match := lt.checkPattern(parentComm, comm)
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

		// Otherwise reuse a parent comm cached from a previous event.
		lt.mu.RLock()
		if info, ok := lt.lineage[e.PPID]; ok {
			lt.mu.RUnlock()
			return e.PPID, info.ParentComm
		}
		lt.mu.RUnlock()

		// Last resort: read from /proc/<ppid>/comm (parent may already be gone).
		comm := readProcComm(e.PPID)
		return e.PPID, comm
	}

	// Fallback: read from /proc/<pid>/status
	return lt.readParentFromProc(e.PID)
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

// checkPattern checks if parent-child combination matches any pattern.
func (lt *LineageTracker) checkPattern(parentComm, childComm string) *LineagePattern {
	for i := range lt.config.Patterns {
		pattern := &lt.config.Patterns[i]

		if matchesAny(parentComm, pattern.ParentComms) &&
			matchesAny(childComm, pattern.ChildComms) {
			return pattern
		}
	}
	return nil
}

// matchesAny checks if a string matches any pattern in the list.
func matchesAny(s string, patterns []string) bool {
	for _, p := range patterns {
		if s == p || strings.HasPrefix(s, p) {
			return true
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

// Cleanup removes stale lineage entries.
func (lt *LineageTracker) Cleanup(now time.Time) {
	lt.mu.Lock()
	defer lt.mu.Unlock()

	for pid, info := range lt.lineage {
		if now.Sub(info.Timestamp) > lt.config.TTL {
			delete(lt.lineage, pid)
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
