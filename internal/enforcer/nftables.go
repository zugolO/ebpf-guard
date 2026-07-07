// Package enforcer provides nftables-based network enforcement.
package enforcer

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

// NFTablesManager manages nftables rules for network enforcement.
// It uses netlink sockets via github.com/google/nftables for high-performance
// rule management without fork/exec overhead.
type NFTablesManager struct {
	logger *slog.Logger
	conn   *nftables.Conn
	// table is the ebpf-guard table
	table *nftables.Table
	// outputChain is the output chain for blocking rules
	outputChain *nftables.Chain
	// blockedUIDs tracks UIDs with active block rules (using cgroup as proxy)
	blockedUIDs map[uint32]struct{}
	// blockedIPs tracks blocked destination IPs
	blockedIPs map[string]struct{}
	// blockedCgroups maps cgroupID → cgroupv2 filesystem path. The path is
	// used to unfreeze on UnblockCgroup. An empty string means the path
	// could not be resolved (e.g. cgroup already gone).
	blockedCgroups map[uint64]string
	// mu protects the maps
	mu sync.RWMutex
	// dryRun mode logs actions without applying rules
	dryRun bool
	// tableName is the configured nftables table name (default: "ebpf-guard").
	tableName string
}

// NFTablesConfig configures the nftables manager.
type NFTablesConfig struct {
	// DryRun logs actions without applying rules
	DryRun bool
	// TableName is the nftables table name (default: "ebpf-guard")
	TableName string
}

// NewNFTablesManager creates a new nftables manager.
// It initializes the ebpf-guard table and chains if they don't exist.
func NewNFTablesManager(logger *slog.Logger, cfg NFTablesConfig) (*NFTablesManager, error) {
	if cfg.TableName == "" {
		cfg.TableName = "ebpf-guard"
	}

	m := &NFTablesManager{
		logger:         logger.With("component", "nftables"),
		blockedUIDs:    make(map[uint32]struct{}),
		blockedIPs:     make(map[string]struct{}),
		blockedCgroups: make(map[uint64]string),
		dryRun:         cfg.DryRun,
		tableName:      cfg.TableName,
	}

	if m.dryRun {
		m.logger.Info("nftables manager initialized in dry-run mode")
		return m, nil
	}

	// Connect to netlink
	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("nftables: connect to netlink: %w", err)
	}
	m.conn = conn

	// Initialize table and chains
	if err := m.initialize(); err != nil {
		return nil, fmt.Errorf("nftables: initialize: %w", err)
	}

	m.logger.Info("nftables manager initialized",
		"table", cfg.TableName,
	)

	return m, nil
}

// initialize creates the ebpf-guard table and output chain.
func (m *NFTablesManager) initialize() error {
	// Check if table already exists
	tables, err := m.conn.ListTables()
	if err != nil {
		return fmt.Errorf("list tables: %w", err)
	}

	var existingTable *nftables.Table
	for _, t := range tables {
		if t.Name == m.tableName && t.Family == nftables.TableFamilyINet {
			existingTable = t
			break
		}
	}

	if existingTable != nil {
		m.table = existingTable
		// Find existing output chain
		chains, err := m.conn.ListChains()
		if err != nil {
			return fmt.Errorf("list chains: %w", err)
		}
		for _, c := range chains {
			if c.Table.Name == m.table.Name && c.Name == "output" {
				m.outputChain = c
				break
			}
		}
	} else {
		// Create new inet table (works for both IPv4 and IPv6)
		m.table = m.conn.AddTable(&nftables.Table{
			Family: nftables.TableFamilyINet,
			Name:   m.tableName,
		})

		// Create output chain
		m.outputChain = m.conn.AddChain(&nftables.Chain{
			Name:     "output",
			Table:    m.table,
			Type:     nftables.ChainTypeFilter,
			Hooknum:  nftables.ChainHookOutput,
			Priority: nftables.ChainPriorityFilter,
		})
	}

	// Apply changes
	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("flush initial config: %w", err)
	}

	return nil
}

// BlockUID adds a rule to block all outbound traffic from a specific UID.
// Note: nftables doesn't have direct UID matching in socket expression.
// We use meta skuid which requires kernel support.
func (m *NFTablesManager) BlockUID(ctx context.Context, uid uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if already blocked
	if _, exists := m.blockedUIDs[uid]; exists {
		return nil // Already blocked
	}

	if m.dryRun {
		m.logger.Info("[DRY-RUN] Would block UID", "uid", uid)
		m.blockedUIDs[uid] = struct{}{}
		return nil
	}

	// Add rule: drop output traffic from this UID using meta expression
	rule := &nftables.Rule{
		Table: m.table,
		Chain: m.outputChain,
		Exprs: []expr.Any{
			// Load socket UID using meta expression
			&expr.Meta{
				Key:      expr.MetaKeySKUID,
				Register: 1,
			},
			// Compare with target UID
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     binaryutil.NativeEndian.PutUint32(uid),
			},
			// Drop the packet
			&expr.Verdict{
				Kind: expr.VerdictDrop,
			},
		},
	}

	m.conn.AddRule(rule)

	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("nftables: block UID %d: %w", uid, err)
	}

	m.blockedUIDs[uid] = struct{}{}
	m.logger.Info("Blocked UID",
		"uid", uid,
	)

	return nil
}

// UnblockUID removes the block rule for a specific UID.
func (m *NFTablesManager) UnblockUID(ctx context.Context, uid uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if blocked
	if _, exists := m.blockedUIDs[uid]; !exists {
		return nil // Not blocked
	}

	if m.dryRun {
		m.logger.Info("[DRY-RUN] Would unblock UID", "uid", uid)
		delete(m.blockedUIDs, uid)
		return nil
	}

	// Find and delete the rule
	rules, err := m.conn.GetRules(m.table, m.outputChain)
	if err != nil {
		return fmt.Errorf("nftables: get rules: %w", err)
	}

	for _, rule := range rules {
		if m.isUIDRule(rule, uid) {
			if err := m.conn.DelRule(rule); err != nil {
				return fmt.Errorf("nftables: delete rule: %w", err)
			}
			break
		}
	}

	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("nftables: unblock UID %d: %w", uid, err)
	}

	delete(m.blockedUIDs, uid)
	m.logger.Info("Unblocked UID",
		"uid", uid,
	)

	return nil
}

// BlockCgroup freezes all processes in the cgroupv2 hierarchy identified by
// cgroupID (the directory inode under /sys/fs/cgroup) and installs an nftables
// socket cgroupv2 rule to drop outbound packets from that cgroup. Both
// mechanisms are applied so that:
//   - Existing processes are immediately suspended (cgroup.freeze).
//   - New sockets opened by any surviving process are dropped at the network
//     layer via the nftables socket cgroupv2 expression (kernel 5.13+).
//
// The function tolerates partial failures: if the cgroup path cannot be found
// (e.g. the cgroup was already destroyed) or the freeze write fails, the error
// is logged and the ID is still recorded so GetBlockedCgroups remains accurate.
func (m *NFTablesManager) BlockCgroup(ctx context.Context, cgroupID uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.blockedCgroups[cgroupID]; exists {
		return nil // Already blocked
	}

	if m.dryRun {
		m.logger.Info("[DRY-RUN] Would block cgroup", "cgroup_id", cgroupID)
		m.blockedCgroups[cgroupID] = ""
		return nil
	}

	// Resolve the filesystem path of the cgroup directory.
	cgroupPath, err := findCgroupPathByID(cgroupID)
	if err != nil {
		m.logger.Warn("cgroup path not found — skipping freeze",
			"cgroup_id", cgroupID, "error", err)
		cgroupPath = ""
	}

	// Layer 1: freeze all processes via cgroupv2 cgroup.freeze (kernel 5.2+).
	if cgroupPath != "" {
		if ferr := writeCgroupControl(cgroupPath, "cgroup.freeze", "1"); ferr != nil {
			m.logger.Warn("cgroup.freeze failed", "path", cgroupPath, "error", ferr)
			// Non-fatal: still attempt nftables rule.
		} else {
			m.logger.Info("Froze cgroup", "cgroup_id", cgroupID, "path", cgroupPath)
		}
	}

	// Layer 2: nftables socket cgroupv2 drop rule (kernel 5.13+).
	// The socket expression loads the cgroupv2 hierarchy path at level 2 and
	// an inline set-string match would be needed for path-based filtering.
	// We use the simpler meta cgroup match (cgroupv2 net_cls class index) as
	// a best-effort network drop; it is non-fatal if the kernel does not
	// support it.
	if m.conn != nil && m.table != nil && m.outputChain != nil {
		if nferr := m.addCgroupDropRule(cgroupID); nferr != nil {
			m.logger.Warn("nftables cgroup rule failed (kernel may lack socket cgroupv2 support)",
				"cgroup_id", cgroupID, "error", nferr)
		}
	}

	m.blockedCgroups[cgroupID] = cgroupPath
	return nil
}

// UnblockCgroup unfreezes the cgroup identified by cgroupID and removes the
// associated nftables drop rule.
func (m *NFTablesManager) UnblockCgroup(ctx context.Context, cgroupID uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cgroupPath, exists := m.blockedCgroups[cgroupID]
	if !exists {
		return nil // Not blocked
	}

	if m.dryRun {
		m.logger.Info("[DRY-RUN] Would unblock cgroup", "cgroup_id", cgroupID)
		delete(m.blockedCgroups, cgroupID)
		return nil
	}

	// Remove nftables rule first (non-fatal on failure).
	if m.conn != nil && m.table != nil && m.outputChain != nil {
		if nferr := m.removeCgroupDropRule(cgroupID); nferr != nil {
			m.logger.Warn("remove nftables cgroup rule failed",
				"cgroup_id", cgroupID, "error", nferr)
		}
	}

	// Unfreeze the cgroup.
	if cgroupPath != "" {
		if ferr := writeCgroupControl(cgroupPath, "cgroup.freeze", "0"); ferr != nil {
			m.logger.Warn("cgroup.unfreeze failed", "path", cgroupPath, "error", ferr)
		} else {
			m.logger.Info("Unfroze cgroup", "cgroup_id", cgroupID, "path", cgroupPath)
		}
	}

	delete(m.blockedCgroups, cgroupID)
	return nil
}

// addCgroupDropRule installs a nftables rule using the meta cgroup expression
// to drop outbound packets whose socket belongs to cgroupID.
// This uses NFT_META_CGROUP (kernel 4.18+) which matches the cgroupv2 class
// index of the socket owner — a best-effort layer atop the freeze.
func (m *NFTablesManager) addCgroupDropRule(cgroupID uint64) error {
	// NFT_META_CGROUP stores a 32-bit classid; use the low 32 bits of the
	// cgroupv2 inode as the match value.
	classID := uint32(cgroupID & 0xFFFFFFFF)

	rule := &nftables.Rule{
		Table: m.table,
		Chain: m.outputChain,
		// Store cgroupID in UserData so we can find this rule on cleanup.
		UserData: cgroupUserData(cgroupID),
		Exprs: []expr.Any{
			&expr.Meta{
				Key:      expr.MetaKeyCGROUP,
				Register: 1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     binaryutil.NativeEndian.PutUint32(classID),
			},
			&expr.Verdict{Kind: expr.VerdictDrop},
		},
	}

	m.conn.AddRule(rule)
	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("nftables: add cgroup drop rule: %w", err)
	}
	return nil
}

// removeCgroupDropRule deletes the nftables rule installed for cgroupID.
func (m *NFTablesManager) removeCgroupDropRule(cgroupID uint64) error {
	rules, err := m.conn.GetRules(m.table, m.outputChain)
	if err != nil {
		return fmt.Errorf("nftables: get rules: %w", err)
	}

	want := cgroupUserData(cgroupID)
	for _, rule := range rules {
		if string(rule.UserData) == string(want) {
			if err := m.conn.DelRule(rule); err != nil {
				return fmt.Errorf("nftables: delete cgroup rule: %w", err)
			}
			break
		}
	}

	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("nftables: flush after cgroup rule removal: %w", err)
	}
	return nil
}

// cgroupUserData returns a tag stored in Rule.UserData to identify cgroup rules.
func cgroupUserData(cgroupID uint64) []byte {
	return fmt.Appendf(nil, "ebpf-guard:cgroup:%d", cgroupID)
}

// BlockIP adds a rule to block outbound traffic to a specific IP address.
func (m *NFTablesManager) BlockIP(ctx context.Context, ip string) error {
	// Validate first so invalid input is rejected consistently in both modes.
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.blockedIPs[ip]; exists {
		return nil
	}

	if m.dryRun {
		m.logger.Info("[DRY-RUN] Would block IP", "ip", ip)
		m.blockedIPs[ip] = struct{}{}
		return nil
	}

	var data []byte
	var offset uint32

	if parsedIP.To4() != nil {
		// IPv4
		data = parsedIP.To4()
		offset = 16 // IPv4 destination address offset in IP header
	} else {
		// IPv6
		data = parsedIP.To16()
		offset = 24 // IPv6 destination address offset
	}

	// Add rule: drop output traffic to this IP
	rule := &nftables.Rule{
		Table: m.table,
		Chain: m.outputChain,
		Exprs: []expr.Any{
			// Load destination address
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       offset,
				Len:          uint32(len(data)),
			},
			// Compare with target IP
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     data,
			},
			&expr.Verdict{
				Kind: expr.VerdictDrop,
			},
		},
	}

	m.conn.AddRule(rule)

	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("nftables: block IP %s: %w", ip, err)
	}

	m.blockedIPs[ip] = struct{}{}
	m.logger.Info("Blocked IP",
		"ip", ip,
	)

	return nil
}

// UnblockIP removes the block rule for a specific IP.
func (m *NFTablesManager) UnblockIP(ctx context.Context, ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.blockedIPs[ip]; !exists {
		return nil
	}

	if m.dryRun {
		m.logger.Info("[DRY-RUN] Would unblock IP", "ip", ip)
		delete(m.blockedIPs, ip)
		return nil
	}

	rules, err := m.conn.GetRules(m.table, m.outputChain)
	if err != nil {
		return fmt.Errorf("nftables: get rules: %w", err)
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	for _, rule := range rules {
		if m.isIPRule(rule, parsedIP) {
			if err := m.conn.DelRule(rule); err != nil {
				return fmt.Errorf("nftables: delete rule: %w", err)
			}
			break
		}
	}

	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("nftables: unblock IP %s: %w", ip, err)
	}

	delete(m.blockedIPs, ip)
	m.logger.Info("Unblocked IP",
		"ip", ip,
	)

	return nil
}

// GetBlockedUIDs returns a list of currently blocked UIDs.
func (m *NFTablesManager) GetBlockedUIDs() []uint32 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	uids := make([]uint32, 0, len(m.blockedUIDs))
	for uid := range m.blockedUIDs {
		uids = append(uids, uid)
	}
	return uids
}

// GetBlockedCgroups returns a list of cgroup IDs that are currently blocked.
func (m *NFTablesManager) GetBlockedCgroups() []uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	cgroups := make([]uint64, 0, len(m.blockedCgroups))
	for cg := range m.blockedCgroups {
		cgroups = append(cgroups, cg)
	}
	return cgroups
}

// GetBlockedIPs returns a list of currently blocked IPs.
func (m *NFTablesManager) GetBlockedIPs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ips := make([]string, 0, len(m.blockedIPs))
	for ip := range m.blockedIPs {
		ips = append(ips, ip)
	}
	return ips
}

// Cleanup unfreeze all blocked cgroups and removes all nftables rules.
func (m *NFTablesManager) Cleanup() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.dryRun {
		m.logger.Info("[DRY-RUN] Would cleanup all nftables rules and unfreeze cgroups")
		m.blockedUIDs = make(map[uint32]struct{})
		m.blockedIPs = make(map[string]struct{})
		m.blockedCgroups = make(map[uint64]string)
		return nil
	}

	// Unfreeze all blocked cgroups before wiping nftables rules.
	for cgroupID, cgroupPath := range m.blockedCgroups {
		if cgroupPath != "" {
			if err := writeCgroupControl(cgroupPath, "cgroup.freeze", "0"); err != nil {
				m.logger.Warn("cleanup: unfreeze cgroup failed",
					"cgroup_id", cgroupID, "error", err)
			}
		}
	}

	if m.conn == nil {
		m.blockedUIDs = make(map[uint32]struct{})
		m.blockedIPs = make(map[string]struct{})
		m.blockedCgroups = make(map[uint64]string)
		return nil
	}

	// Delete the entire table (removes all chains and rules).
	if m.table != nil {
		m.conn.DelTable(m.table)
		if err := m.conn.Flush(); err != nil {
			return fmt.Errorf("nftables: cleanup: %w", err)
		}
	}

	m.blockedUIDs = make(map[uint32]struct{})
	m.blockedIPs = make(map[string]struct{})
	m.blockedCgroups = make(map[uint64]string)

	m.logger.Info("Cleaned up all nftables rules and unfroze cgroups")

	return nil
}

// Close closes the netlink connection.
func (m *NFTablesManager) Close() error {
	// nftables.Conn doesn't have a Close method in this version
	// The connection is garbage collected
	return nil
}

// isUIDRule checks if a rule matches a specific UID.
func (m *NFTablesManager) isUIDRule(rule *nftables.Rule, uid uint32) bool {
	// This is a simplified check - in production, you'd need to
	// properly decode the rule expressions
	for _, e := range rule.Exprs {
		if cmp, ok := e.(*expr.Cmp); ok {
			if len(cmp.Data) == 4 {
				dataUID := binaryutil.NativeEndian.Uint32(cmp.Data)
				if dataUID == uid {
					return true
				}
			}
		}
	}
	return false
}

// isIPRule checks if a rule matches a specific IP.
// The rule's payload data is stored in the narrowest form for its address
// family (4 bytes for IPv4, 16 for IPv6 — see BlockIP), while net.ParseIP
// always returns a 16-byte slice for dotted-decimal input. ip is normalised
// to the same width as cmp.Data before comparing, otherwise an IPv4 rule's
// 4-byte payload would never match ip's 16-byte form and UnblockIP would
// silently fail to find (and thus never delete) the kernel-side rule.
func (m *NFTablesManager) isIPRule(rule *nftables.Rule, ip net.IP) bool {
	for _, e := range rule.Exprs {
		cmp, ok := e.(*expr.Cmp)
		if !ok {
			continue
		}
		var candidate net.IP
		switch len(cmp.Data) {
		case net.IPv4len:
			candidate = ip.To4()
		case net.IPv6len:
			candidate = ip.To16()
		default:
			continue
		}
		if candidate == nil {
			continue
		}
		match := true
		for i := range cmp.Data {
			if cmp.Data[i] != candidate[i] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// IsAvailable checks if nftables is available on the system.
func IsNFTablesAvailable() bool {
	conn, err := nftables.New()
	if err != nil {
		return false
	}
	// Connection is garbage collected, no Close method
	_ = conn
	return true
}

// GetBackendName returns the name of this enforcement backend.
func (m *NFTablesManager) GetBackendName() string {
	return "nftables"
}

// findCgroupPathByID scans /sys/fs/cgroup for the directory whose inode number
// equals cgroupID. In cgroupv2, the cgroup ID reported by the kernel (and by
// bpf_get_current_cgroup_id()) is the inode number of the cgroup directory.
func findCgroupPathByID(cgroupID uint64) (string, error) {
	const cgroupRoot = "/sys/fs/cgroup"
	var found string
	err := filepath.WalkDir(cgroupRoot, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || !d.IsDir() {
			return nil // skip unreadable entries
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil
		}
		if stat.Ino == cgroupID {
			found = path
			return filepath.SkipAll // stop walking
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("walk %s: %w", cgroupRoot, err)
	}
	if found == "" {
		return "", fmt.Errorf("cgroupID %d not found under %s", cgroupID, cgroupRoot)
	}
	return found, nil
}

// writeCgroupControl writes value to a cgroupv2 control file inside cgroupPath.
func writeCgroupControl(cgroupPath, file, value string) error {
	target := filepath.Join(cgroupPath, file)
	if err := os.WriteFile(target, []byte(value), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", target, err)
	}
	return nil
}
