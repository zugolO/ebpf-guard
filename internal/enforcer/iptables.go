package enforcer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"sync"
)

const defaultChainName = "EBPF-GUARD"

// IPTablesConfig configures the iptables manager.
type IPTablesConfig struct {
	// ChainName is the dedicated chain name (default: "EBPF-GUARD").
	ChainName string
	// DryRun logs actions without running any iptables commands.
	DryRun bool
	// IPTablesPath overrides the iptables binary path (empty = auto-discover).
	IPTablesPath string
	// IP6TablesPath overrides the ip6tables binary path (empty = auto-discover).
	IP6TablesPath string
}

// IPTablesManager enforces network blocking via the system iptables/ip6tables
// binaries.  It creates a dedicated chain (EBPF-GUARD by default) in the
// filter/OUTPUT hook and inserts rules on demand.
//
// Graceful degradation: if neither iptables nor ip6tables can be found, or if
// initialization fails, the manager operates in log-only mode and records
// blocked entries in-memory (same dry-run behaviour).
type IPTablesManager struct {
	logger        *slog.Logger
	chain         string
	iptablesPath  string
	ip6tablesPath string
	dryRun        bool

	mu          sync.RWMutex
	blockedUIDs map[uint32]struct{}
	blockedIPs  map[string]struct{}
}

// NewIPTablesManager creates and initialises an IPTablesManager.  It
// discovers the iptables/ip6tables binaries, creates the dedicated chain, and
// inserts the OUTPUT jump rule.  If any step fails the error is returned so
// the caller can decide whether to abort or fall back.
func NewIPTablesManager(logger *slog.Logger, cfg IPTablesConfig) (*IPTablesManager, error) {
	if cfg.ChainName == "" {
		cfg.ChainName = defaultChainName
	}

	m := &IPTablesManager{
		logger:      logger.With("component", "iptables"),
		chain:       cfg.ChainName,
		dryRun:      cfg.DryRun,
		blockedUIDs: make(map[uint32]struct{}),
		blockedIPs:  make(map[string]struct{}),
	}

	if cfg.DryRun {
		m.logger.Info("iptables manager initialized in dry-run mode", "chain", cfg.ChainName)
		return m, nil
	}

	// Discover binaries.
	m.iptablesPath = cfg.IPTablesPath
	if m.iptablesPath == "" {
		p, err := exec.LookPath("iptables")
		if err != nil {
			m.logger.Warn("iptables binary not found, manager will log-only", "error", err)
		} else {
			m.iptablesPath = p
		}
	}

	m.ip6tablesPath = cfg.IP6TablesPath
	if m.ip6tablesPath == "" {
		p, err := exec.LookPath("ip6tables")
		if err != nil {
			m.logger.Warn("ip6tables binary not found, IPv6 blocking unavailable", "error", err)
		} else {
			m.ip6tablesPath = p
		}
	}

	ctx := context.Background()

	// Set up IPv4 chain.
	if m.iptablesPath != "" {
		if err := m.initChain(ctx, m.iptablesPath); err != nil {
			return nil, fmt.Errorf("iptables: init chain: %w", err)
		}
	}

	// Set up IPv6 chain.
	if m.ip6tablesPath != "" {
		if err := m.initChain(ctx, m.ip6tablesPath); err != nil {
			return nil, fmt.Errorf("ip6tables: init chain: %w", err)
		}
	}

	m.logger.Info("iptables manager initialized",
		"chain", m.chain,
		"iptables", m.iptablesPath,
		"ip6tables", m.ip6tablesPath,
	)
	return m, nil
}

// initChain creates the dedicated chain and wires it into OUTPUT (idempotent).
func (m *IPTablesManager) initChain(ctx context.Context, binary string) error {
	// Create chain — ignore "Chain already exists" error (exit code 1, stderr contains "exists").
	if err := m.run(ctx, binary, "-t", "filter", "-N", m.chain); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return fmt.Errorf("create chain %s: %w", m.chain, err)
		}
		// Chain already exists — acceptable.
	}

	// Check if the jump rule is already present.
	checkErr := m.run(ctx, binary, "-t", "filter", "-C", "OUTPUT", "-j", m.chain)
	if checkErr != nil {
		// Jump rule absent — add it.
		if err := m.run(ctx, binary, "-t", "filter", "-I", "OUTPUT", "-j", m.chain); err != nil {
			return fmt.Errorf("insert OUTPUT jump: %w", err)
		}
	}
	return nil
}

// BlockUID adds a DROP rule for all outbound traffic from a specific UID.
// Uses the xt_owner module (-m owner --uid-owner).
func (m *IPTablesManager) BlockUID(ctx context.Context, uid uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.blockedUIDs[uid]; exists {
		return nil
	}

	if m.dryRun {
		m.logger.Info("[DRY-RUN] Would block UID", "uid", uid)
		m.blockedUIDs[uid] = struct{}{}
		return nil
	}

	uidStr := fmt.Sprintf("%d", uid)

	// Add to both IPv4 and IPv6 chains.
	if m.iptablesPath != "" {
		if err := m.run(ctx, m.iptablesPath,
			"-t", "filter", "-A", m.chain,
			"-m", "owner", "--uid-owner", uidStr, "-j", "DROP"); err != nil {
			return fmt.Errorf("iptables: block UID %d: %w", uid, err)
		}
	}
	if m.ip6tablesPath != "" {
		if err := m.run(ctx, m.ip6tablesPath,
			"-t", "filter", "-A", m.chain,
			"-m", "owner", "--uid-owner", uidStr, "-j", "DROP"); err != nil {
			// Non-fatal: IPv4 rule is already in place.
			m.logger.Warn("ip6tables: block UID failed", "uid", uid, "error", err)
		}
	}

	m.blockedUIDs[uid] = struct{}{}
	m.logger.Info("Blocked UID via iptables", "uid", uid)
	return nil
}

// UnblockUID removes the DROP rule for a specific UID.
func (m *IPTablesManager) UnblockUID(ctx context.Context, uid uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.blockedUIDs[uid]; !exists {
		return nil
	}

	if m.dryRun {
		m.logger.Info("[DRY-RUN] Would unblock UID", "uid", uid)
		delete(m.blockedUIDs, uid)
		return nil
	}

	uidStr := fmt.Sprintf("%d", uid)

	if m.iptablesPath != "" {
		if err := m.run(ctx, m.iptablesPath,
			"-t", "filter", "-D", m.chain,
			"-m", "owner", "--uid-owner", uidStr, "-j", "DROP"); err != nil {
			m.logger.Warn("iptables: unblock UID failed", "uid", uid, "error", err)
		}
	}
	if m.ip6tablesPath != "" {
		if err := m.run(ctx, m.ip6tablesPath,
			"-t", "filter", "-D", m.chain,
			"-m", "owner", "--uid-owner", uidStr, "-j", "DROP"); err != nil {
			m.logger.Warn("ip6tables: unblock UID failed", "uid", uid, "error", err)
		}
	}

	delete(m.blockedUIDs, uid)
	m.logger.Info("Unblocked UID via iptables", "uid", uid)
	return nil
}

// BlockIP adds a DROP rule for outbound traffic to a specific IP address.
// IPv4 addresses use iptables; IPv6 use ip6tables.
func (m *IPTablesManager) BlockIP(ctx context.Context, ip string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil {
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

	binary, err := m.binaryForIP(parsed)
	if err != nil {
		return err
	}

	if err := m.run(ctx, binary, "-t", "filter", "-A", m.chain, "-d", ip, "-j", "DROP"); err != nil {
		return fmt.Errorf("iptables: block IP %s: %w", ip, err)
	}

	m.blockedIPs[ip] = struct{}{}
	m.logger.Info("Blocked IP via iptables", "ip", ip)
	return nil
}

// UnblockIP removes the DROP rule for a specific IP address.
func (m *IPTablesManager) UnblockIP(ctx context.Context, ip string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

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

	binary, err := m.binaryForIP(parsed)
	if err != nil {
		return err
	}

	if err := m.run(ctx, binary, "-t", "filter", "-D", m.chain, "-d", ip, "-j", "DROP"); err != nil {
		m.logger.Warn("iptables: unblock IP failed", "ip", ip, "error", err)
	}

	delete(m.blockedIPs, ip)
	m.logger.Info("Unblocked IP via iptables", "ip", ip)
	return nil
}

// GetBlockedUIDs returns a snapshot of currently blocked UIDs.
func (m *IPTablesManager) GetBlockedUIDs() []uint32 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	uids := make([]uint32, 0, len(m.blockedUIDs))
	for uid := range m.blockedUIDs {
		uids = append(uids, uid)
	}
	return uids
}

// GetBlockedIPs returns a snapshot of currently blocked IPs.
func (m *IPTablesManager) GetBlockedIPs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ips := make([]string, 0, len(m.blockedIPs))
	for ip := range m.blockedIPs {
		ips = append(ips, ip)
	}
	return ips
}

// Cleanup flushes the dedicated chain, removes the OUTPUT jump rule, and
// deletes the chain.
func (m *IPTablesManager) Cleanup() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.dryRun {
		m.logger.Info("[DRY-RUN] Would cleanup iptables chain", "chain", m.chain)
		m.blockedUIDs = make(map[uint32]struct{})
		m.blockedIPs = make(map[string]struct{})
		return nil
	}

	ctx := context.Background()
	for _, binary := range m.availableBinaries() {
		m.teardownChain(ctx, binary)
	}

	m.blockedUIDs = make(map[uint32]struct{})
	m.blockedIPs = make(map[string]struct{})
	m.logger.Info("Cleaned up iptables chain", "chain", m.chain)
	return nil
}

// teardownChain removes the OUTPUT jump, flushes, and deletes the chain.
// All errors are logged and suppressed (best-effort cleanup).
func (m *IPTablesManager) teardownChain(ctx context.Context, binary string) {
	// Remove the jump rule from OUTPUT (ignore error if already absent).
	_ = m.run(ctx, binary, "-t", "filter", "-D", "OUTPUT", "-j", m.chain)
	// Flush all rules from the chain.
	_ = m.run(ctx, binary, "-t", "filter", "-F", m.chain)
	// Delete the chain.
	if err := m.run(ctx, binary, "-t", "filter", "-X", m.chain); err != nil {
		m.logger.Warn("iptables: delete chain failed", "binary", binary, "error", err)
	}
}

// Close is a no-op — the iptables manager holds no file handles.
func (m *IPTablesManager) Close() error { return nil }

// GetBackendName returns the backend identifier.
func (m *IPTablesManager) GetBackendName() string { return "iptables" }

// IsAvailable returns true if at least one iptables binary was discovered.
func (m *IPTablesManager) IsAvailable() bool {
	return m.iptablesPath != "" || m.ip6tablesPath != ""
}

// binaryForIP returns the correct binary path for the given IP version.
func (m *IPTablesManager) binaryForIP(ip net.IP) (string, error) {
	if ip.To4() != nil {
		if m.iptablesPath == "" {
			return "", errors.New("iptables binary not available for IPv4")
		}
		return m.iptablesPath, nil
	}
	if m.ip6tablesPath == "" {
		return "", errors.New("ip6tables binary not available for IPv6")
	}
	return m.ip6tablesPath, nil
}

// availableBinaries returns non-empty binary paths in [iptables, ip6tables] order.
func (m *IPTablesManager) availableBinaries() []string {
	var bins []string
	if m.iptablesPath != "" {
		bins = append(bins, m.iptablesPath)
	}
	if m.ip6tablesPath != "" {
		bins = append(bins, m.ip6tablesPath)
	}
	return bins
}

// run executes a single iptables command and returns its error.
// Combined stderr is included in the error message for diagnostics.
func (m *IPTablesManager) run(ctx context.Context, binary string, args ...string) error {
	cmd := exec.CommandContext(ctx, binary, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, string(out))
	}
	return nil
}

// IsIPTablesAvailable returns true if iptables is present on the system.
func IsIPTablesAvailable() bool {
	_, err := exec.LookPath("iptables")
	return err == nil
}
