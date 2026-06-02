package gossip

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/zugolO/ebpf-guard/internal/util"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Config holds gossip sub-system configuration.
type Config struct {
	// Enabled toggles the gossip subsystem entirely.
	Enabled bool
	// NodeName is this node's identifier, included in every published IOC.
	// Defaults to the system hostname when empty.
	NodeName string
	// Secret is the shared authentication token used between peers.
	// Requests without a matching X-Gossip-Secret header are rejected.
	Secret string
	// Peers is the list of peer base URLs (e.g. "http://10.0.0.2:9090").
	Peers []string
	// IOCTTL is how long a published IOC remains valid. Default: 1 hour.
	IOCTTL time.Duration
	// MaxIOCs caps the in-memory IOC store size. Default: 100 000.
	MaxIOCs int
	// PushInterval controls how often the delta is flushed to peers. Default: 30 s.
	PushInterval time.Duration
}

// DefaultConfig returns a safe default configuration (gossip disabled).
func DefaultConfig() Config {
	return Config{
		Enabled:      false,
		IOCTTL:       time.Hour,
		MaxIOCs:      100_000,
		PushInterval: 30 * time.Second,
	}
}

// Manager runs the gossip sub-system.
// It implements correlator.IOCMatcher so it can be injected into the
// correlation engine without creating an import cycle.
type Manager struct {
	cfg       Config
	store     *IOCStore
	client    *gossipClient
	discovery PeerDiscovery
	logger    *slog.Logger

	// Accumulated IOCs since the last push to peers.
	deltaMu sync.Mutex
	delta   []IOC

	// Prometheus metrics (unregistered — callers call RegisterMetrics).
	iocReceived prometheus.Counter
	matchHits   prometheus.Counter
	pushTotal   prometheus.Counter
	pushErrors  prometheus.Counter
	storeSize   prometheus.Gauge
}

// NewManager creates a gossip Manager.
// Use Start to launch background goroutines.
func NewManager(cfg Config, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.IOCTTL <= 0 {
		cfg.IOCTTL = time.Hour
	}
	if cfg.MaxIOCs <= 0 {
		cfg.MaxIOCs = 100_000
	}
	if cfg.PushInterval <= 0 {
		cfg.PushInterval = 30 * time.Second
	}

	return &Manager{
		cfg:       cfg,
		store:     NewIOCStore(cfg.MaxIOCs, cfg.IOCTTL),
		client:    newGossipClient(cfg.Secret),
		discovery: NewStaticPeerDiscovery(cfg.Peers),
		logger:    logger,

		iocReceived: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ebpf_guard_gossip_iocs_received_total",
			Help: "Total IOCs received from peer agents.",
		}),
		matchHits: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ebpf_guard_gossip_match_hits_total",
			Help: "Events matched against gossip IOCs.",
		}),
		pushTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ebpf_guard_gossip_push_total",
			Help: "IOC batch pushes sent to peers.",
		}),
		pushErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ebpf_guard_gossip_push_errors_total",
			Help: "Failed IOC batch pushes.",
		}),
		storeSize: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ebpf_guard_gossip_store_size",
			Help: "Current IOC store entry count.",
		}),
	}
}

// RegisterMetrics registers all gossip Prometheus metrics with reg.
// Pass prometheus.DefaultRegisterer for the global registry.
func (m *Manager) RegisterMetrics(reg prometheus.Registerer) {
	for _, c := range []prometheus.Collector{
		m.iocReceived, m.matchHits, m.pushTotal, m.pushErrors, m.storeSize,
	} {
		// Ignore already-registered errors (safe for repeated test calls).
		_ = reg.Register(c)
	}
}

// Start launches the background cleanup and push goroutines.
// It is a no-op when gossip is disabled.
func (m *Manager) Start(ctx context.Context) {
	if !m.cfg.Enabled {
		return
	}
	go m.cleanupLoop(ctx)
	go m.pushLoop(ctx)
	m.logger.Info("gossip: started",
		slog.String("node", m.cfg.NodeName),
		slog.Int("peers", len(m.cfg.Peers)),
		slog.Duration("ioc_ttl", m.cfg.IOCTTL),
	)
}

// MatchIP satisfies correlator.IOCMatcher. Returns true when ip is a known IOC.
func (m *Manager) MatchIP(ip string) bool {
	if !m.cfg.Enabled {
		return false
	}
	if m.store.Match(IOCTypeIP, ip) {
		m.matchHits.Inc()
		return true
	}
	return false
}

// MatchDNS satisfies correlator.IOCMatcher. Returns true when domain is a known IOC.
func (m *Manager) MatchDNS(domain string) bool {
	if !m.cfg.Enabled {
		return false
	}
	if m.store.Match(IOCTypeDNS, domain) {
		m.matchHits.Inc()
		return true
	}
	return false
}

// MatchFingerprint satisfies correlator.IOCMatcher. Returns true when fp is a known IOC.
func (m *Manager) MatchFingerprint(fp string) bool {
	if !m.cfg.Enabled {
		return false
	}
	if m.store.Match(IOCTypeFingerprint, fp) {
		m.matchHits.Inc()
		return true
	}
	return false
}

// ExtractFromAlert extracts IOCs from a triggered alert and queues them for
// broadcast to peers. Only public (non-RFC1918) IPs are shared for IPs.
func (m *Manager) ExtractFromAlert(alert types.Alert) {
	if !m.cfg.Enabled {
		return
	}
	expires := time.Now().Add(m.cfg.IOCTTL)
	var batch []IOC

	switch alert.Event.Type {
	case types.EventTCPConnect:
		if alert.Event.Network != nil {
			ip := util.FormatIP16(alert.Event.Network.Daddr, alert.Event.Network.Family)
			if net.ParseIP(ip) != nil && !isPrivateIP(ip) {
				batch = append(batch, IOC{
					Type:      IOCTypeIP,
					Value:     ip,
					Source:    m.cfg.NodeName,
					RuleID:    alert.RuleID,
					Severity:  string(alert.Severity),
					ExpiresAt: expires,
				})
			}
		}
	case types.EventDNS:
		if alert.Event.DNS != nil && alert.Event.DNS.QName != "" {
			batch = append(batch, IOC{
				Type:      IOCTypeDNS,
				Value:     alert.Event.DNS.QName,
				Source:    m.cfg.NodeName,
				RuleID:    alert.RuleID,
				Severity:  string(alert.Severity),
				ExpiresAt: expires,
			})
		}
	}

	// Fingerprints apply regardless of event type.
	if alert.Fingerprint != "" {
		batch = append(batch, IOC{
			Type:      IOCTypeFingerprint,
			Value:     alert.Fingerprint,
			Source:    m.cfg.NodeName,
			RuleID:    alert.RuleID,
			Severity:  string(alert.Severity),
			ExpiresAt: expires,
		})
	}

	if len(batch) == 0 {
		return
	}
	for _, ioc := range batch {
		m.store.Add(ioc)
	}
	m.storeSize.Set(float64(m.store.Size()))

	m.deltaMu.Lock()
	m.delta = append(m.delta, batch...)
	m.deltaMu.Unlock()
}

// MergeFromPeer integrates IOCs received from a peer.
func (m *Manager) MergeFromPeer(iocs []IOC) {
	m.store.Merge(iocs)
	m.iocReceived.Add(float64(len(iocs)))
	m.storeSize.Set(float64(m.store.Size()))
}

// Snapshot returns all active IOCs (for pull-based peer sync via GET /gossip/iocs).
func (m *Manager) Snapshot() []IOC {
	return m.store.Snapshot()
}

// cleanupLoop periodically removes expired IOC entries.
func (m *Manager) cleanupLoop(ctx context.Context) {
	// Run cleanup at half the TTL so the store stays tidy between pushes.
	interval := m.cfg.IOCTTL / 2
	if interval < time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			removed := m.store.CleanExpired()
			m.storeSize.Set(float64(m.store.Size()))
			if removed > 0 {
				m.logger.Debug("gossip: expired IOCs removed", slog.Int("count", removed))
			}
		}
	}
}

// pushLoop drains the delta and broadcasts to all configured peers.
func (m *Manager) pushLoop(ctx context.Context) {
	ticker := time.NewTicker(m.cfg.PushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.flushDelta(ctx)
		}
	}
}

// flushDelta sends all pending IOCs to each peer concurrently.
func (m *Manager) flushDelta(ctx context.Context) {
	m.deltaMu.Lock()
	if len(m.delta) == 0 {
		m.deltaMu.Unlock()
		return
	}
	batch := m.delta
	m.delta = nil
	m.deltaMu.Unlock()

	peers := m.discovery.Peers()
	for _, peer := range peers {
		peer := peer
		go func() {
			if err := m.client.PushIOCs(ctx, peer, batch); err != nil {
				m.pushErrors.Inc()
				m.logger.Debug("gossip: push failed",
					slog.String("peer", peer),
					slog.Any("err", err),
				)
			} else {
				m.pushTotal.Inc()
			}
		}()
	}
}

// isPrivateIP returns true for addresses that should not be shared across nodes:
// RFC1918 ranges, loopback, and link-local.
func isPrivateIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return true
	}
	if parsed.IsLoopback() || parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast() {
		return true
	}
	for _, cidr := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/7",
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err == nil && block.Contains(parsed) {
			return true
		}
	}
	return false
}
