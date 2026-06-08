package gossip

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	gossipPath             = "/gossip/iocs"
	gossipAmplPath         = "/gossip/amplifications"
	gossipSecretHeader     = "X-Gossip-Secret"
	clientTimeout          = 10 * time.Second
)

// gossipClient sends IOC batches to peer agents via HTTP POST.
type gossipClient struct {
	secret string
	http   *http.Client
}

func newGossipClient(secret string, tlsCfg *tls.Config) *gossipClient {
	transport := &http.Transport{
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     90 * time.Second,
	}
	if tlsCfg != nil {
		transport.TLSClientConfig = tlsCfg
	}
	return &gossipClient{
		secret: secret,
		http: &http.Client{
			Timeout:   clientTimeout,
			Transport: transport,
		},
	}
}

// PushAmplifications sends a batch of amplification signals to a peer.
func (c *gossipClient) PushAmplifications(ctx context.Context, peerBaseURL string, sigs []AmplificationSignal) error {
	if len(sigs) == 0 {
		return nil
	}
	body, err := json.Marshal(sigs)
	if err != nil {
		return fmt.Errorf("gossip: marshal amplifications: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, peerBaseURL+gossipAmplPath, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("gossip: build amplification request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.secret != "" {
		req.Header.Set(gossipSecretHeader, c.secret)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("gossip: amplification push to %s: %w", peerBaseURL, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("gossip: peer %s returned %d for amplifications", peerBaseURL, resp.StatusCode)
	}
	return nil
}

// PushIOCs sends a batch of IOCs to a single peer using POST /gossip/iocs.
func (c *gossipClient) PushIOCs(ctx context.Context, peerBaseURL string, iocs []IOC) error {
	if len(iocs) == 0 {
		return nil
	}
	body, err := json.Marshal(iocs)
	if err != nil {
		return fmt.Errorf("gossip: marshal IOCs: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, peerBaseURL+gossipPath, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("gossip: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.secret != "" {
		req.Header.Set(gossipSecretHeader, c.secret)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("gossip: push to %s: %w", peerBaseURL, err)
	}
	defer resp.Body.Close()
	// Drain body so the connection can be reused.
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("gossip: peer %s returned %d", peerBaseURL, resp.StatusCode)
	}
	return nil
}

// Handler returns an HTTP mux with the gossip endpoints mounted.
// The manager's secret is checked on each request when non-empty.
func Handler(mgr *Manager) http.Handler {
	mux := http.NewServeMux()

	authCheck := func(w http.ResponseWriter, r *http.Request) bool {
		if mgr.cfg.Secret != "" {
			got := r.Header.Get(gossipSecretHeader)
			// Use constant-time comparison to prevent timing-based secret leakage.
			if subtle.ConstantTimeCompare([]byte(got), []byte(mgr.cfg.Secret)) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return false
			}
		}
		return true
	}

	mux.HandleFunc(gossipPath, func(w http.ResponseWriter, r *http.Request) {
		if !authCheck(w, r) {
			return
		}
		switch r.Method {
		case http.MethodPost:
			handleReceiveIOCs(mgr, w, r)
		case http.MethodGet:
			handleSnapshotIOCs(mgr, w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc(gossipAmplPath, func(w http.ResponseWriter, r *http.Request) {
		if !authCheck(w, r) {
			return
		}
		switch r.Method {
		case http.MethodPost:
			handleReceiveAmplifications(mgr, w, r)
		case http.MethodGet:
			handleSnapshotAmplifications(mgr, w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	return mux
}

// handleReceiveIOCs processes a POST batch from a peer node.
func handleReceiveIOCs(mgr *Manager, w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20)) // 4 MiB cap
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	var iocs []IOC
	if err := json.Unmarshal(body, &iocs); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	mgr.MergeFromPeer(iocs)
	w.WriteHeader(http.StatusNoContent)
}

// handleSnapshotIOCs returns the full IOC store as JSON (for pull-based sync).
func handleSnapshotIOCs(mgr *Manager, w http.ResponseWriter, r *http.Request) {
	snapshot := mgr.Snapshot()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(snapshot)
}

// handleReceiveAmplifications processes a POST batch of amplification signals from a peer.
func handleReceiveAmplifications(mgr *Manager, w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MiB cap
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	var sigs []AmplificationSignal
	if err := json.Unmarshal(body, &sigs); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	mgr.MergeAmplificationsFromPeer(sigs)
	w.WriteHeader(http.StatusNoContent)
}

// handleSnapshotAmplifications returns all active amplification signals as JSON.
func handleSnapshotAmplifications(mgr *Manager, w http.ResponseWriter, r *http.Request) {
	snapshot := mgr.AmplificationSnapshot()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(snapshot)
}
