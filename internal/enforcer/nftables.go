// Package enforcer provides nftables-based network enforcement.
package enforcer

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"

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
	// mu protects the maps
	mu sync.RWMutex
	// dryRun mode logs actions without applying rules
	dryRun bool
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
		logger:      logger.With("component", "nftables"),
		blockedUIDs: make(map[uint32]struct{}),
		blockedIPs:  make(map[string]struct{}),
		dryRun:      cfg.DryRun,
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
		if t.Name == "ebpf-guard" && t.Family == nftables.TableFamilyINet {
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
			Name:   "ebpf-guard",
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
	if m.dryRun {
		m.logger.Info("[DRY-RUN] Would block UID",
			"uid", uid,
		)
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if already blocked
	if _, exists := m.blockedUIDs[uid]; exists {
		return nil // Already blocked
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
	if m.dryRun {
		m.logger.Info("[DRY-RUN] Would unblock UID",
			"uid", uid,
		)
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if blocked
	if _, exists := m.blockedUIDs[uid]; !exists {
		return nil // Not blocked
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

// BlockCgroup adds a rule to block outbound traffic from a specific cgroup.
// Note: This is a placeholder as cgroup matching requires kernel support
// that may not be available in all environments.
func (m *NFTablesManager) BlockCgroup(ctx context.Context, cgroupID uint64) error {
	if m.dryRun {
		m.logger.Info("[DRY-RUN] Would block cgroup",
			"cgroup_id", cgroupID,
		)
		return nil
	}

	// Cgroup matching via nftables requires specific kernel support.
	// For now, we log the request and return without error.
	// In production, this could use socket cgroupv2 matching if available.
	m.logger.Info("Cgroup blocking requested (not implemented)",
		"cgroup_id", cgroupID,
	)

	return nil
}

// UnblockCgroup removes the block rule for a specific cgroup.
func (m *NFTablesManager) UnblockCgroup(ctx context.Context, cgroupID uint64) error {
	if m.dryRun {
		m.logger.Info("[DRY-RUN] Would unblock cgroup",
			"cgroup_id", cgroupID,
		)
		return nil
	}

	// Cgroup blocking is not implemented, nothing to do
	m.logger.Info("Cgroup unblocking requested (not implemented)",
		"cgroup_id", cgroupID,
	)

	return nil
}

// BlockIP adds a rule to block outbound traffic to a specific IP address.
func (m *NFTablesManager) BlockIP(ctx context.Context, ip string) error {
	if m.dryRun {
		m.logger.Info("[DRY-RUN] Would block IP",
			"ip", ip,
		)
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.blockedIPs[ip]; exists {
		return nil
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
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
	if m.dryRun {
		m.logger.Info("[DRY-RUN] Would unblock IP",
			"ip", ip,
		)
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.blockedIPs[ip]; !exists {
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

// GetBlockedCgroups returns a list of currently blocked cgroups.
// Note: Always returns empty as cgroup blocking is not implemented.
func (m *NFTablesManager) GetBlockedCgroups() []uint64 {
	// Cgroup blocking is not implemented
	return []uint64{}
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

// Cleanup removes all rules added by this manager.
func (m *NFTablesManager) Cleanup() error {
	if m.dryRun {
		m.logger.Info("[DRY-RUN] Would cleanup all nftables rules")
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.conn == nil {
		return nil
	}

	// Delete the entire table (removes all chains and rules)
	if m.table != nil {
		m.conn.DelTable(m.table)
		if err := m.conn.Flush(); err != nil {
			return fmt.Errorf("nftables: cleanup: %w", err)
		}
	}

	// Clear tracking maps
	m.blockedUIDs = make(map[uint32]struct{})
	m.blockedIPs = make(map[string]struct{})

	m.logger.Info("Cleaned up all nftables rules")

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
func (m *NFTablesManager) isIPRule(rule *nftables.Rule, ip net.IP) bool {
	for _, e := range rule.Exprs {
		if cmp, ok := e.(*expr.Cmp); ok {
			if len(cmp.Data) == len(ip) {
				match := true
				for i := range cmp.Data {
					if cmp.Data[i] != ip[i] {
						match = false
						break
					}
				}
				if match {
					return true
				}
			}
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
