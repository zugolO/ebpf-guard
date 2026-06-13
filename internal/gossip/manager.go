package gossip

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"os"
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
	// SecretPrevious is the old shared secret accepted during a rotation window.
	// Peers still using the old secret are allowed to connect until
	// SecretRotationTTL elapses from the time this Manager was created.
	// Clear this field (and restart) once all nodes have adopted the new Secret.
	SecretPrevious string
	// SecretRotationTTL is how long SecretPrevious remains valid after startup.
	// Default: 5 minutes. Zero disables the rotation window.
	SecretRotationTTL time.Duration
	// Peers is the list of peer base URLs.
	// Use https:// URLs when TLSEnabled=true, e.g. "https://10.0.0.2:9090".
	Peers []string
	// IOCTTL is how long a published IOC remains valid. Default: 1 hour.
	IOCTTL time.Duration
	// MaxIOCs caps the in-memory IOC store size. Default: 100 000.
	MaxIOCs int
	// PushInterval controls how often the delta is flushed to peers. Default: 30 s.
	PushInterval time.Duration
	// TLSEnabled activates mTLS for all peer connections.
	// When true, TLSCertFile, TLSKeyFile, and TLSCAFile must be set.
	TLSEnabled bool
	// TLSCertFile is the path to the PEM-encoded client certificate.
	TLSCertFile string
	// TLSKeyFile is the path to the PEM-encoded private key.
	TLSKeyFile string
	// TLSCAFile is the path to the PEM-encoded CA bundle used to verify peers.
	TLSCAFile string
	// DeduplicationTTL is how long a fingerprint received from a peer suppresses
	// the same alert on the local node. Default: 5 minutes.
	DeduplicationTTL time.Duration
}

// DefaultConfig returns a safe default configuration (gossip disabled).
func DefaultConfig() Config {
	return Config{
		Enabled:           false,
		IOCTTL:            time.Hour,
		MaxIOCs:           100_000,
		PushInterval:      30 * time.Second,
		DeduplicationTTL:  deduplicationTTLDefault,
		SecretRotationTTL: 5 * time.Minute,
	}
}

// Manager runs the gossip sub-system.
// It implements correlator.IOCMatcher so it can be injected into the
// correlation engine without creating an import cycle.
// It also implements correlator.SensitivityAdjuster for cross-node alert
// amplification (attack on node A → lowered anomaly threshold on peers).
type Manager struct {
	cfg                    Config
	secretRotationDeadline time.Time // zero means no rotation window active
	store                  *IOCStore
	ampStore               *AmplificationStore
	client                 *gossipClient
	discovery              PeerDiscovery
	logger                 *slog.Logger

	// Accumulated IOCs since the last push to peers.
	deltaMu sync.Mutex
	delta   []IOC

	// Accumulated amplification signals since the last push to peers.
	ampDeltaMu sync.Mutex
	ampDelta   []AmplificationSignal

	// Prometheus metrics (unregistered — callers call RegisterMetrics).
	iocReceived        prometheus.Counter
	matchHits          prometheus.Counter
	pushTotal          prometheus.Counter
	pushErrors         prometheus.Counter
	storeSize          prometheus.Gauge
	ampReceived        prometheus.Counter
	ampActive          prometheus.Gauge
}

// NewManager creates a gossip Manager.
// Returns an error if TLS is enabled but cert/key/CA files cannot be loaded.
// Use Start to launch background goroutines.
func NewManager(cfg Config, logger *slog.Logger) (*Manager, error) {
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
	if cfg.DeduplicationTTL <= 0 {
		cfg.DeduplicationTTL = deduplicationTTLDefault
	}

	if cfg.Enabled && cfg.Secret == "" {
		return nil, fmt.Errorf("gossip: secret is required when enabled; configure a shared secret for cross-node authentication")
	}

	var tlsCfg *tls.Config
	if cfg.TLSEnabled {
		var err error
		tlsCfg, err = buildGossipTLSConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("gossip: %w", err)
		}
		logger.Info("gossip: mTLS configured for peer connections")
	}

	var rotationDeadline time.Time
	if cfg.SecretPrevious != "" && cfg.SecretRotationTTL > 0 {
		rotationDeadline = time.Now().Add(cfg.SecretRotationTTL)
		logger.Info("gossip: secret rotation window active",
			slog.Duration("ttl", cfg.SecretRotationTTL))
	}

	return &Manager{
		cfg:                    cfg,
		secretRotationDeadline: rotationDeadline,
		store:                  NewIOCStore(cfg.MaxIOCs, cfg.IOCTTL),
		ampStore:  newAmplificationStore(cfg.DeduplicationTTL),
		client:    newGossipClient(cfg.Secret, tlsCfg),
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
		ampReceived: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ebpf_guard_gossip_amplifications_received_total",
			Help: "Total cross-node alert amplification signals received from peers.",
		}),
		ampActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ebpf_guard_gossip_amplifications_active",
			Help: "Number of currently active cross-node alert amplification signals.",
		}),
	}, nil
}

// buildGossipTLSConfig creates an mTLS config for gossip peer connections.
func buildGossipTLSConfig(cfg Config) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load peer client cert: %w", err)
	}

	caCert, err := os.ReadFile(cfg.TLSCAFile)
	if err != nil {
		return nil, fmt.Errorf("read peer CA bundle: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("parse peer CA bundle: no valid certificates found")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// RegisterMetrics registers all gossip Prometheus metrics with reg.
// Pass prometheus.DefaultRegisterer for the global registry.
func (m *Manager) RegisterMetrics(reg prometheus.Registerer) {
	for _, c := range []prometheus.Collector{
		m.iocReceived, m.matchHits, m.pushTotal, m.pushErrors, m.storeSize,
		m.ampReceived, m.ampActive,
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

// BroadcastAlert inspects a triggered alert and, for critical alerts that
// carry a Kubernetes namespace, publishes an AmplificationSignal so peer nodes
// temporarily lower their anomaly detection threshold for that namespace.
// Call this for every alert the agent emits; it is a no-op for non-critical
// or non-K8s alerts.
func (m *Manager) BroadcastAlert(alert types.Alert) {
	if !m.cfg.Enabled {
		return
	}
	if alert.Severity != types.SeverityCritical {
		return
	}
	ns := alert.Enrichment.Namespace
	if ns == "" {
		return
	}
	sig := AmplificationSignal{
		Namespace:           ns,
		RuleID:              alert.RuleID,
		Severity:            string(alert.Severity),
		Source:              m.cfg.NodeName,
		ThresholdMultiplier: defaultThresholdMultiplier,
		ExpiresAt:           time.Now().Add(amplificationTTLDefault),
		Fingerprint:         alert.Fingerprint,
	}
	m.ampDeltaMu.Lock()
	m.ampDelta = append(m.ampDelta, sig)
	m.ampDeltaMu.Unlock()
}

// MergeAmplificationsFromPeer stores amplification signals received from a peer
// and records their fingerprints for cluster-level deduplication.
func (m *Manager) MergeAmplificationsFromPeer(sigs []AmplificationSignal) {
	now := time.Now()
	for _, sig := range sigs {
		if !now.Before(sig.ExpiresAt) {
			continue
		}
		m.ampStore.Add(sig)
		// Record the fingerprint so IsDuplicateAlert suppresses the same alert
		// if it fires locally on this node.
		m.ampStore.MarkSeen(sig.Fingerprint)
	}
	m.ampReceived.Add(float64(len(sigs)))
	m.ampActive.Set(float64(m.ampStore.ActiveCount()))
}

// IsDuplicateAlert returns true when the alert identified by fingerprint has
// already been seen from another cluster node via gossip. The correlator
// should suppress re-raising the alert in this case to avoid alert storms
// across a 100-node cluster all reporting the same container-escape event.
func (m *Manager) IsDuplicateAlert(fingerprint string) bool {
	if !m.cfg.Enabled || fingerprint == "" {
		return false
	}
	return m.ampStore.IsDuplicate(fingerprint)
}

// GetThresholdMultiplier implements correlator.SensitivityAdjuster.
// Returns the lowest threshold multiplier across all active signals for the
// given namespace. Returns 1.0 when no signal is active.
func (m *Manager) GetThresholdMultiplier(namespace string) float64 {
	if !m.cfg.Enabled {
		return 1.0
	}
	return m.ampStore.GetThresholdMultiplier(namespace)
}

// AmplificationSnapshot returns all active amplification signals for debugging.
func (m *Manager) AmplificationSnapshot() []AmplificationSignal {
	return m.ampStore.Snapshot()
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
			ampRemoved := m.ampStore.CleanExpired()
			m.ampActive.Set(float64(m.ampStore.ActiveCount()))
			if ampRemoved > 0 {
				m.logger.Debug("gossip: expired amplification signals removed", slog.Int("count", ampRemoved))
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

// flushDelta sends all pending IOCs and amplification signals to each peer concurrently.
func (m *Manager) flushDelta(ctx context.Context) {
	m.deltaMu.Lock()
	batch := m.delta
	m.delta = nil
	m.deltaMu.Unlock()

	m.ampDeltaMu.Lock()
	ampBatch := m.ampDelta
	m.ampDelta = nil
	m.ampDeltaMu.Unlock()

	if len(batch) == 0 && len(ampBatch) == 0 {
		return
	}

	peers := m.discovery.Peers()
	for _, peer := range peers {
		peer := peer
		if len(batch) > 0 {
			go func() {
				if err := m.client.PushIOCs(ctx, peer, batch); err != nil {
					m.pushErrors.Inc()
					m.logger.Debug("gossip: IOC push failed",
						slog.String("peer", peer),
						slog.Any("err", err),
					)
				} else {
					m.pushTotal.Inc()
				}
			}()
		}
		if len(ampBatch) > 0 {
			go func() {
				if err := m.client.PushAmplifications(ctx, peer, ampBatch); err != nil {
					m.logger.Debug("gossip: amplification push failed",
						slog.String("peer", peer),
						slog.Any("err", err),
					)
				}
			}()
		}
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
