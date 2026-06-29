package enforcer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/zugolO/ebpf-guard/internal/bpf"
)

// XDPConfig holds XDP manager configuration.
type XDPConfig struct {
	// Interface is the network interface to attach the XDP program to (e.g. "eth0").
	// An empty string disables kernel-level enforcement (log-only / dry-run).
	Interface string
	// MaxEntries is the maximum number of blocked IPs / ports in each BPF map.
	// Defaults to 10 000.
	MaxEntries int
	// DryRun skips attachment and BPF map updates; actions are logged only.
	DryRun bool
}

// XDPManager manages the XDP-based packet filtering blocklist.
//
// When BPF programs are available (post `make generate`) and an Interface is
// configured, the manager loads the xdp_block_fn program, attaches it to the
// interface via generic XDP, and keeps the xdp_blocked_ips / xdp_blocked_ports
// BPF maps in sync.
//
// In stub mode (BPF not available) or dry-run mode, the manager maintains the
// blocklist in memory and logs what would be blocked — the enforcer remains
// fully testable without a real kernel.
type XDPManager struct {
	logger *slog.Logger
	cfg    XDPConfig

	mu           sync.RWMutex
	objs         *bpf.XDPObjects
	xdpLink      link.Link
	loaded       bool
	blockedIPs   map[string]struct{} // canonical IP string (net.IP.String())
	blockedPorts map[uint16]struct{}

	droppedTotal      prometheus.Counter
	blockedIPsGauge   prometheus.Gauge
	blockedPortsGauge prometheus.Gauge
}

// NewXDPManager creates and initialises an XDP manager.
// If BPF program loading or interface attachment fails, the manager degrades
// gracefully to in-memory + log-only mode.
func NewXDPManager(logger *slog.Logger, cfg XDPConfig) (*XDPManager, error) {
	if cfg.MaxEntries == 0 {
		cfg.MaxEntries = 10_000
	}
	m := &XDPManager{
		logger:       logger.With("component", "enforcer/xdp"),
		cfg:          cfg,
		blockedIPs:   make(map[string]struct{}),
		blockedPorts: make(map[uint16]struct{}),
		droppedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ebpf_guard_xdp_dropped_total",
			Help: "Total packets dropped by the XDP enforcement program.",
		}),
		blockedIPsGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ebpf_guard_xdp_blocked_ips",
			Help: "Current number of IPs in the XDP blocklist.",
		}),
		blockedPortsGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ebpf_guard_xdp_blocked_ports",
			Help: "Current number of ports in the XDP blocklist.",
		}),
	}

	if !cfg.DryRun && cfg.Interface != "" {
		m.loadBPF()
	}
	return m, nil
}

// loadBPF attempts to load the XDP BPF program and attach it to the interface.
// On any failure the manager remains functional in log-only mode.
func (m *XDPManager) loadBPF() {
	objs := &bpf.XDPObjects{}
	if err := bpf.LoadXDPObjects(objs, &ebpf.CollectionOptions{}); err != nil {
		m.logger.Warn("XDP: BPF program unavailable, using log-only mode",
			slog.String("reason", err.Error()))
		return
	}

	iface, err := net.InterfaceByName(m.cfg.Interface)
	if err != nil {
		m.logger.Warn("XDP: interface not found, using log-only mode",
			slog.String("interface", m.cfg.Interface),
			slog.Any("error", err))
		objs.Close()
		return
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Interface: iface.Index,
		Program:   objs.XdpBlockFn,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		m.logger.Warn("XDP: failed to attach program, using log-only mode",
			slog.String("interface", m.cfg.Interface),
			slog.Any("error", err))
		objs.Close()
		return
	}

	m.objs = objs
	m.xdpLink = l
	m.loaded = true
	m.logger.Info("XDP: program attached",
		slog.String("interface", m.cfg.Interface),
		slog.String("mode", "generic"))
}

// BlockIP adds an IP address to the XDP blocked-IPs map.
func (m *XDPManager) BlockIP(ctx context.Context, ip net.IP) error {
	canonical := ip.String()

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.blockedIPs[canonical]; exists {
		return nil
	}

	if m.loaded && m.objs != nil && m.objs.XdpBlockedIps != nil {
		key := ipToKey(ip)
		val := uint8(1)
		if err := m.objs.XdpBlockedIps.Put(key, val); err != nil {
			return fmt.Errorf("xdp: block IP %s in BPF map: %w", canonical, err)
		}
	} else {
		m.logger.Info("XDP (log-only): would block IP", slog.String("ip", canonical))
	}

	m.blockedIPs[canonical] = struct{}{}
	m.blockedIPsGauge.Set(float64(len(m.blockedIPs)))
	return nil
}

// UnblockIP removes an IP address from the XDP blocked-IPs map.
func (m *XDPManager) UnblockIP(ctx context.Context, ip net.IP) error {
	canonical := ip.String()

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.blockedIPs[canonical]; !exists {
		return nil
	}

	if m.loaded && m.objs != nil && m.objs.XdpBlockedIps != nil {
		key := ipToKey(ip)
		if err := m.objs.XdpBlockedIps.Delete(key); err != nil && !isMapKeyNotFound(err) {
			return fmt.Errorf("xdp: unblock IP %s in BPF map: %w", canonical, err)
		}
	}

	delete(m.blockedIPs, canonical)
	m.blockedIPsGauge.Set(float64(len(m.blockedIPs)))
	return nil
}

// BlockPort adds a destination port to the XDP blocked-ports map.
func (m *XDPManager) BlockPort(ctx context.Context, port uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.blockedPorts[port]; exists {
		return nil
	}

	if m.loaded && m.objs != nil && m.objs.XdpBlockedPorts != nil {
		val := uint8(1)
		if err := m.objs.XdpBlockedPorts.Put(port, val); err != nil {
			return fmt.Errorf("xdp: block port %d in BPF map: %w", port, err)
		}
	} else {
		m.logger.Info("XDP (log-only): would block port", slog.Int("port", int(port)))
	}

	m.blockedPorts[port] = struct{}{}
	m.blockedPortsGauge.Set(float64(len(m.blockedPorts)))
	return nil
}

// UnblockPort removes a port from the XDP blocked-ports map.
func (m *XDPManager) UnblockPort(ctx context.Context, port uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.blockedPorts[port]; !exists {
		return nil
	}

	if m.loaded && m.objs != nil && m.objs.XdpBlockedPorts != nil {
		if err := m.objs.XdpBlockedPorts.Delete(port); err != nil && !isMapKeyNotFound(err) {
			return fmt.Errorf("xdp: unblock port %d in BPF map: %w", port, err)
		}
	}

	delete(m.blockedPorts, port)
	m.blockedPortsGauge.Set(float64(len(m.blockedPorts)))
	return nil
}

// BlockTuple blocks traffic to the given destination IP and/or port.
// Either argument may be nil/0 to block only on the other dimension.
func (m *XDPManager) BlockTuple(ctx context.Context, daddr net.IP, dport uint16) error {
	if len(daddr) > 0 {
		if err := m.BlockIP(ctx, daddr); err != nil {
			return err
		}
	}
	if dport > 0 {
		if err := m.BlockPort(ctx, dport); err != nil {
			return err
		}
	}
	return nil
}

// GetBlockedIPs returns the current list of blocked IPs.
func (m *XDPManager) GetBlockedIPs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, 0, len(m.blockedIPs))
	for ip := range m.blockedIPs {
		out = append(out, ip)
	}
	return out
}

// GetBlockedPorts returns the current list of blocked ports.
func (m *XDPManager) GetBlockedPorts() []uint16 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]uint16, 0, len(m.blockedPorts))
	for port := range m.blockedPorts {
		out = append(out, port)
	}
	return out
}

// IsLoaded returns true if the XDP BPF program was successfully attached.
func (m *XDPManager) IsLoaded() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.loaded
}

// ReadStats returns the aggregated XDP packet drop/pass counters summed across
// all CPU cores.  Returns zero values when the BPF program is not loaded
// (dry-run mode or failed attachment).
func (m *XDPManager) ReadStats() (bpf.XDPAggregate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.loaded || m.objs == nil || m.objs.XdpStatsMap == nil {
		return bpf.XDPAggregate{}, nil
	}
	return bpf.ReadXDPStats(m.objs.XdpStatsMap)
}

// RegisterMetrics registers XDP Prometheus metrics with the given registerer.
func (m *XDPManager) RegisterMetrics(reg prometheus.Registerer) error {
	for _, c := range []prometheus.Collector{m.droppedTotal, m.blockedIPsGauge, m.blockedPortsGauge} {
		if c == nil {
			continue
		}
		if err := reg.Register(c); err != nil {
			return err
		}
	}
	return nil
}

// Close detaches the XDP program and releases all eBPF resources.
func (m *XDPManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.xdpLink != nil {
		if err := m.xdpLink.Close(); err != nil {
			m.logger.Warn("XDP: error closing link", slog.Any("error", err))
		}
		m.xdpLink = nil
	}
	if m.objs != nil {
		m.objs.Close()
		m.objs = nil
	}
	m.loaded = false
	return nil
}

// ipToKey converts a net.IP to a 16-byte BPF map key.
// IPv4 addresses are stored in the first 4 bytes (network byte order) so they
// match the C-side `*(__u32 *)daddr = iph->daddr` assignment.
// IPv6 addresses fill all 16 bytes.
func ipToKey(ip net.IP) [16]byte {
	var key [16]byte
	if v4 := ip.To4(); v4 != nil {
		copy(key[:4], v4)
	} else if v6 := ip.To16(); v6 != nil {
		copy(key[:], v6)
	}
	return key
}

// isMapKeyNotFound returns true for the cilium/ebpf "key does not exist" error.
func isMapKeyNotFound(err error) bool {
	return errors.Is(err, ebpf.ErrKeyNotExist)
}
