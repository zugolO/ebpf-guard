package gossip

import (
	"net/url"
	"strings"
	"sync"
)

// PeerDiscovery resolves the set of peer base URLs to push IOCs to.
type PeerDiscovery interface {
	Peers() []string
}

// StaticPeerDiscovery serves a fixed, pre-validated list of peer URLs.
type StaticPeerDiscovery struct {
	mu    sync.RWMutex
	peers []string
}

// NewStaticPeerDiscovery creates a peer discovery from a list of raw URLs.
// Malformed or loopback URLs are silently dropped.
func NewStaticPeerDiscovery(rawURLs []string) *StaticPeerDiscovery {
	peers := make([]string, 0, len(rawURLs))
	for _, raw := range rawURLs {
		normalized := normalizePeerURL(raw)
		if normalized != "" {
			peers = append(peers, normalized)
		}
	}
	return &StaticPeerDiscovery{peers: peers}
}

// Peers returns the validated peer URL list.
func (s *StaticPeerDiscovery) Peers() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, len(s.peers))
	copy(out, s.peers)
	return out
}

// SetPeers atomically replaces the peer list (used by K8s-based discovery refresh).
func (s *StaticPeerDiscovery) SetPeers(rawURLs []string) {
	peers := make([]string, 0, len(rawURLs))
	for _, raw := range rawURLs {
		if normalized := normalizePeerURL(raw); normalized != "" {
			peers = append(peers, normalized)
		}
	}
	s.mu.Lock()
	s.peers = peers
	s.mu.Unlock()
}

// normalizePeerURL validates and normalizes a peer URL, returning "" for invalid entries.
func normalizePeerURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.TrimRight(raw, "/")
}
