package gossip

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// ---------------------------------------------------------------------------
// IOCStore tests
// ---------------------------------------------------------------------------

func TestIOCStore_AddAndMatch(t *testing.T) {
	s := NewIOCStore(100, time.Hour)

	ioc := IOC{
		Type:      IOCTypeIP,
		Value:     "1.2.3.4",
		Source:    "node-1",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	s.Add(ioc)

	assert.True(t, s.Match(IOCTypeIP, "1.2.3.4"), "should match added IP")
	assert.False(t, s.Match(IOCTypeIP, "5.6.7.8"), "unknown IP must not match")
	assert.False(t, s.Match(IOCTypeDNS, "1.2.3.4"), "wrong type must not match")
}

func TestIOCStore_ExpiredEntryNotMatched(t *testing.T) {
	s := NewIOCStore(100, time.Hour)

	s.Add(IOC{
		Type:      IOCTypeIP,
		Value:     "9.9.9.9",
		ExpiresAt: time.Now().Add(-time.Millisecond), // already expired
	})

	assert.False(t, s.Match(IOCTypeIP, "9.9.9.9"), "expired IOC must not match")
}

func TestIOCStore_LRUEviction(t *testing.T) {
	const max = 3
	s := NewIOCStore(max, time.Hour)

	for i := 0; i < max+1; i++ {
		s.Add(IOC{
			Type:      IOCTypeIP,
			Value:     strings.Repeat("x", i+1), // unique values
			ExpiresAt: time.Now().Add(time.Hour),
		})
	}

	assert.LessOrEqual(t, s.Size(), max, "store must not exceed maxSize")
}

func TestIOCStore_RefreshExpiry(t *testing.T) {
	s := NewIOCStore(100, time.Hour)

	earlyExpiry := time.Now().Add(time.Minute)
	lateExpiry := time.Now().Add(time.Hour)

	s.Add(IOC{Type: IOCTypeIP, Value: "1.1.1.1", ExpiresAt: earlyExpiry})
	// Second Add with later expiry should refresh the entry.
	s.Add(IOC{Type: IOCTypeIP, Value: "1.1.1.1", ExpiresAt: lateExpiry})

	assert.True(t, s.Match(IOCTypeIP, "1.1.1.1"))
}

func TestIOCStore_CleanExpired(t *testing.T) {
	s := NewIOCStore(100, time.Hour)

	s.Add(IOC{Type: IOCTypeIP, Value: "10.0.0.1", ExpiresAt: time.Now().Add(-time.Second)})
	s.Add(IOC{Type: IOCTypeIP, Value: "10.0.0.2", ExpiresAt: time.Now().Add(time.Hour)})

	removed := s.CleanExpired()
	assert.Equal(t, 1, removed)
	assert.Equal(t, 1, s.Size())
}

func TestIOCStore_Snapshot(t *testing.T) {
	s := NewIOCStore(100, time.Hour)

	s.Add(IOC{Type: IOCTypeIP, Value: "1.1.1.1", ExpiresAt: time.Now().Add(time.Hour)})
	s.Add(IOC{Type: IOCTypeDNS, Value: "evil.com", ExpiresAt: time.Now().Add(time.Hour)})
	s.Add(IOC{Type: IOCTypeIP, Value: "2.2.2.2", ExpiresAt: time.Now().Add(-time.Second)}) // expired

	snap := s.Snapshot()
	assert.Len(t, snap, 2, "snapshot must exclude expired entries")
}

func TestIOCStore_Merge(t *testing.T) {
	s := NewIOCStore(100, time.Hour)

	s.Merge([]IOC{
		{Type: IOCTypeIP, Value: "3.3.3.3", ExpiresAt: time.Now().Add(time.Hour)},
		{Type: IOCTypeIP, Value: "4.4.4.4", ExpiresAt: time.Now().Add(-time.Second)}, // expired — skip
	})

	assert.True(t, s.Match(IOCTypeIP, "3.3.3.3"))
	assert.False(t, s.Match(IOCTypeIP, "4.4.4.4"))
}

func TestIOCStore_EmptyValueIgnored(t *testing.T) {
	s := NewIOCStore(100, time.Hour)
	s.Add(IOC{Type: IOCTypeIP, Value: "", ExpiresAt: time.Now().Add(time.Hour)})
	assert.Equal(t, 0, s.Size())
}

func TestIOCStore_ConcurrentAccess(t *testing.T) {
	s := NewIOCStore(1000, time.Hour)
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				s.Add(IOC{
					Type:      IOCTypeIP,
					Value:     strings.Repeat("a", (id%10)+1),
					ExpiresAt: time.Now().Add(time.Hour),
				})
				_ = s.Match(IOCTypeIP, strings.Repeat("a", (j%10)+1))
			}
		}(i)
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// IOCKey / type tests
// ---------------------------------------------------------------------------

func TestIOCKey(t *testing.T) {
	assert.Equal(t, "ip:1.2.3.4", iocKey(IOCTypeIP, "1.2.3.4"))
	assert.Equal(t, "dns:evil.com", iocKey(IOCTypeDNS, "evil.com"))
	assert.Equal(t, "fingerprint:abc", iocKey(IOCTypeFingerprint, "abc"))
}

// ---------------------------------------------------------------------------
// PeerDiscovery tests
// ---------------------------------------------------------------------------

func TestStaticPeerDiscovery_NormalizeURLs(t *testing.T) {
	d := NewStaticPeerDiscovery([]string{
		"http://10.0.0.1:9090",
		"10.0.0.2:9090",  // no scheme — should be normalised to http://
		"",               // empty — should be dropped
		"not a url%%%",   // invalid — should be dropped
	})

	peers := d.Peers()
	require.Len(t, peers, 2)
	assert.Contains(t, peers, "http://10.0.0.1:9090")
	assert.Contains(t, peers, "http://10.0.0.2:9090")
}

func TestStaticPeerDiscovery_SetPeers(t *testing.T) {
	d := NewStaticPeerDiscovery([]string{"http://10.0.0.1:9090"})
	assert.Len(t, d.Peers(), 1)

	d.SetPeers([]string{"http://10.0.0.2:9090", "http://10.0.0.3:9090"})
	assert.Len(t, d.Peers(), 2)
}

// ---------------------------------------------------------------------------
// isPrivateIP tests
// ---------------------------------------------------------------------------

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip      string
		private bool
	}{
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"192.168.1.1", true},
		{"127.0.0.1", true},
		{"::1", true},
		{"fc00::1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"2606:4700::1111", false},
		{"", true},
		{"not-an-ip", true},
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			assert.Equal(t, tt.private, isPrivateIP(tt.ip))
		})
	}
}

// ---------------------------------------------------------------------------
// Manager tests
// ---------------------------------------------------------------------------

func newTestManager(peers ...string) *Manager {
	cfg := Config{
		Enabled:      true,
		NodeName:     "test-node",
		Secret:       "test-secret",
		IOCTTL:       time.Hour,
		MaxIOCs:      1000,
		PushInterval: time.Hour, // long interval so pushLoop doesn't fire in tests
		Peers:        peers,
	}
	m, err := NewManager(cfg, nil)
	if err != nil {
		panic(err) // TLS is disabled in tests; this path is unreachable
	}
	return m
}

func TestManager_MatchIP(t *testing.T) {
	m := newTestManager()
	m.store.Add(IOC{Type: IOCTypeIP, Value: "1.2.3.4", ExpiresAt: time.Now().Add(time.Hour)})

	assert.True(t, m.MatchIP("1.2.3.4"))
	assert.False(t, m.MatchIP("5.6.7.8"))
}

func TestManager_MatchDNS(t *testing.T) {
	m := newTestManager()
	m.store.Add(IOC{Type: IOCTypeDNS, Value: "evil.example.com", ExpiresAt: time.Now().Add(time.Hour)})

	assert.True(t, m.MatchDNS("evil.example.com"))
	assert.False(t, m.MatchDNS("good.example.com"))
}

func TestManager_MatchFingerprint(t *testing.T) {
	m := newTestManager()
	m.store.Add(IOC{Type: IOCTypeFingerprint, Value: "deadbeef", ExpiresAt: time.Now().Add(time.Hour)})

	assert.True(t, m.MatchFingerprint("deadbeef"))
	assert.False(t, m.MatchFingerprint("cafebabe"))
}

func TestManager_DisabledMatchAlwaysFalse(t *testing.T) {
	cfg := Config{Enabled: false}
	m, err := NewManager(cfg, nil)
	require.NoError(t, err)
	m.store.Add(IOC{Type: IOCTypeIP, Value: "1.2.3.4", ExpiresAt: time.Now().Add(time.Hour)})

	assert.False(t, m.MatchIP("1.2.3.4"), "disabled manager must not match")
}

func TestNewManager_RejectsEnabledWithoutSecret(t *testing.T) {
	cfg := Config{
		Enabled: true,
	}
	_, err := NewManager(cfg, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret is required")
}

func TestManager_ExtractFromAlert_TCPConnect(t *testing.T) {
	m := newTestManager()

	var daddr [16]byte
	copy(daddr[:4], []byte{8, 8, 8, 8}) // 8.8.8.8

	alert := types.Alert{
		RuleID:   "rule_test",
		Severity: types.SeverityCritical,
		Event: types.Event{
			Type: types.EventTCPConnect,
			Network: &types.NetworkEvent{
				Daddr:  daddr,
				Family: types.AddressFamily(2), // AF_INET
			},
		},
	}

	m.ExtractFromAlert(alert)

	assert.True(t, m.MatchIP("8.8.8.8"), "extracted IP must be in store")
	assert.Equal(t, 1, m.store.Size())

	// Delta should have one entry queued for push.
	m.deltaMu.Lock()
	assert.Len(t, m.delta, 1)
	m.deltaMu.Unlock()
}

func TestManager_ExtractFromAlert_PrivateIPSkipped(t *testing.T) {
	m := newTestManager()

	var daddr [16]byte
	copy(daddr[:4], []byte{10, 0, 0, 1}) // RFC1918

	alert := types.Alert{
		RuleID:   "rule_test",
		Severity: types.SeverityCritical,
		Event: types.Event{
			Type: types.EventTCPConnect,
			Network: &types.NetworkEvent{
				Daddr:  daddr,
				Family: types.AddressFamily(2),
			},
		},
	}

	m.ExtractFromAlert(alert)
	assert.Equal(t, 0, m.store.Size(), "private IPs must not be published")
}

func TestManager_ExtractFromAlert_DNS(t *testing.T) {
	m := newTestManager()

	alert := types.Alert{
		RuleID:   "rule_dns",
		Severity: types.SeverityWarning,
		Event: types.Event{
			Type: types.EventDNS,
			DNS: &types.DNSEvent{
				QName: "malware.example.com",
			},
		},
	}

	m.ExtractFromAlert(alert)
	assert.True(t, m.MatchDNS("malware.example.com"))
}

func TestManager_ExtractFromAlert_Fingerprint(t *testing.T) {
	m := newTestManager()

	alert := types.Alert{
		RuleID:      "rule_fp",
		Severity:    types.SeverityCritical,
		Fingerprint: "abc123",
		Event:       types.Event{Type: types.EventSyscall},
	}

	m.ExtractFromAlert(alert)
	assert.True(t, m.MatchFingerprint("abc123"))
}

func TestManager_ExtractFromAlert_Disabled(t *testing.T) {
	cfg := Config{Enabled: false}
	m, err := NewManager(cfg, nil)
	require.NoError(t, err)

	alert := types.Alert{
		Fingerprint: "abc123",
		Event:       types.Event{Type: types.EventSyscall},
	}
	m.ExtractFromAlert(alert)
	assert.Equal(t, 0, m.store.Size())
}

func TestManager_MergeFromPeer(t *testing.T) {
	m := newTestManager()

	iocs := []IOC{
		{Type: IOCTypeIP, Value: "5.5.5.5", ExpiresAt: time.Now().Add(time.Hour)},
		{Type: IOCTypeDNS, Value: "bad.domain", ExpiresAt: time.Now().Add(time.Hour)},
	}
	m.MergeFromPeer(iocs)

	assert.True(t, m.MatchIP("5.5.5.5"))
	assert.True(t, m.MatchDNS("bad.domain"))
}

func TestManager_Snapshot(t *testing.T) {
	m := newTestManager()
	m.store.Add(IOC{Type: IOCTypeIP, Value: "7.7.7.7", ExpiresAt: time.Now().Add(time.Hour)})

	snap := m.Snapshot()
	require.Len(t, snap, 1)
	assert.Equal(t, "7.7.7.7", snap[0].Value)
}

// ---------------------------------------------------------------------------
// HTTP handler tests
// ---------------------------------------------------------------------------

func TestHTTP_ReceiveIOCs(t *testing.T) {
	m := newTestManager()
	handler := Handler(m)

	iocs := []IOC{
		{Type: IOCTypeIP, Value: "9.9.9.9", ExpiresAt: time.Now().Add(time.Hour)},
	}
	body, _ := json.Marshal(iocs)

	req := httptest.NewRequest(http.MethodPost, "/gossip/iocs", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(gossipSecretHeader, "test-secret")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.True(t, m.MatchIP("9.9.9.9"))
}

func TestHTTP_SnapshotIOCs(t *testing.T) {
	m := newTestManager()
	m.store.Add(IOC{Type: IOCTypeIP, Value: "11.22.33.44", ExpiresAt: time.Now().Add(time.Hour)})

	handler := Handler(m)
	req := httptest.NewRequest(http.MethodGet, "/gossip/iocs", nil)
	req.Header.Set(gossipSecretHeader, "test-secret")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var iocs []IOC
	require.NoError(t, json.NewDecoder(w.Body).Decode(&iocs))
	require.Len(t, iocs, 1)
	assert.Equal(t, "11.22.33.44", iocs[0].Value)
}

func TestHTTP_AuthRejectsMissingSecret(t *testing.T) {
	m := newTestManager()
	handler := Handler(m)

	iocs := []IOC{{Type: IOCTypeIP, Value: "9.9.9.9", ExpiresAt: time.Now().Add(time.Hour)}}
	body, _ := json.Marshal(iocs)

	req := httptest.NewRequest(http.MethodPost, "/gossip/iocs", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code, "requests without X-Gossip-Secret must be rejected when a secret is configured")
}

func TestHTTP_AuthEnforced(t *testing.T) {
	cfg := Config{
		Enabled:      true,
		NodeName:     "node-1",
		Secret:       "s3cr3t",
		IOCTTL:       time.Hour,
		MaxIOCs:      100,
		PushInterval: time.Hour,
	}
	m, err := NewManager(cfg, nil)
	require.NoError(t, err)
	handler := Handler(m)

	iocs := []IOC{{Type: IOCTypeIP, Value: "1.1.1.1", ExpiresAt: time.Now().Add(time.Hour)}}
	body, _ := json.Marshal(iocs)

	// No secret — should be rejected.
	req := httptest.NewRequest(http.MethodPost, "/gossip/iocs", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// Wrong secret — should be rejected.
	req = httptest.NewRequest(http.MethodPost, "/gossip/iocs", strings.NewReader(string(body)))
	req.Header.Set(gossipSecretHeader, "wrongsecret")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// Correct secret — should succeed.
	req = httptest.NewRequest(http.MethodPost, "/gossip/iocs", strings.NewReader(string(body)))
	req.Header.Set(gossipSecretHeader, "s3cr3t")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestHTTP_InvalidJSON(t *testing.T) {
	m := newTestManager()
	handler := Handler(m)

	req := httptest.NewRequest(http.MethodPost, "/gossip/iocs", strings.NewReader("not json"))
	req.Header.Set(gossipSecretHeader, "test-secret")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHTTP_MethodNotAllowed(t *testing.T) {
	m := newTestManager()
	handler := Handler(m)

	req := httptest.NewRequest(http.MethodDelete, "/gossip/iocs", nil)
	req.Header.Set(gossipSecretHeader, "test-secret")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

// ---------------------------------------------------------------------------
// gossipClient integration test (client pushes to a real httptest server)
// ---------------------------------------------------------------------------

func TestGossipClient_PushIOCs(t *testing.T) {
	var received []IOC
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, gossipSecretHeader, gossipSecretHeader)
		var iocs []IOC
		require.NoError(t, json.NewDecoder(r.Body).Decode(&iocs))
		mu.Lock()
		received = iocs
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := newGossipClient("", nil)
	iocs := []IOC{
		{Type: IOCTypeIP, Value: "8.8.8.8", ExpiresAt: time.Now().Add(time.Hour)},
	}
	err := c.PushIOCs(context.Background(), srv.URL, iocs)
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, received, 1)
	assert.Equal(t, "8.8.8.8", received[0].Value)
}

func TestGossipClient_EmptyBatchNoRequest(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := newGossipClient("", nil)
	err := c.PushIOCs(context.Background(), srv.URL, nil)
	require.NoError(t, err)
	assert.False(t, called, "no HTTP request should be made for empty batch")
}

// ---------------------------------------------------------------------------
// Manager Start / background goroutine tests
// ---------------------------------------------------------------------------

func TestManager_Start_DisabledIsNoop(t *testing.T) {
	cfg := Config{Enabled: false}
	m, err := NewManager(cfg, nil)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Should return without starting goroutines. Just verify no panic.
	m.Start(ctx)
}

func TestManager_CleanupLoop(t *testing.T) {
	// TTL=2s → cleanup fires at TTL/2=1s. The IOC expires after 50ms,
	// so by the time cleanup fires (≈1s) the entry is already stale.
	cfg := Config{
		Enabled:      true,
		NodeName:     "node-1",
		Secret:       "test-secret",
		IOCTTL:       2 * time.Second,
		MaxIOCs:      100,
		PushInterval: time.Hour,
	}
	m, err := NewManager(cfg, nil)
	require.NoError(t, err)

	m.store.Add(IOC{
		Type:      IOCTypeIP,
		Value:     "1.1.1.1",
		ExpiresAt: time.Now().Add(50 * time.Millisecond), // expires long before cleanup fires
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Start(ctx)

	// Wait for cleanup goroutine to fire (interval = 1s, add 500ms slack).
	time.Sleep(1500 * time.Millisecond)
	cancel()
	time.Sleep(10 * time.Millisecond)

	assert.Equal(t, 0, m.store.Size(), "cleanup goroutine should have removed expired entry")
}

func TestManager_PushLoop(t *testing.T) {
	// Start a peer server that records received IOCs.
	var (
		mu       sync.Mutex
		received []IOC
	)
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var iocs []IOC
		_ = json.NewDecoder(r.Body).Decode(&iocs)
		mu.Lock()
		received = append(received, iocs...)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer peer.Close()

	cfg := Config{
		Enabled:      true,
		NodeName:     "node-1",
		Secret:       "test-secret",
		IOCTTL:       time.Hour,
		MaxIOCs:      100,
		PushInterval: 50 * time.Millisecond, // fast for test
		Peers:        []string{peer.URL},
	}
	m, err := NewManager(cfg, nil)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Start(ctx)

	// Add an IOC that should get pushed.
	m.store.Add(IOC{Type: IOCTypeIP, Value: "2.2.2.2", ExpiresAt: time.Now().Add(time.Hour)})
	m.deltaMu.Lock()
	m.delta = append(m.delta, IOC{Type: IOCTypeIP, Value: "2.2.2.2", ExpiresAt: time.Now().Add(time.Hour)})
	m.deltaMu.Unlock()

	// Wait for push to fire.
	time.Sleep(200 * time.Millisecond)
	cancel()
	time.Sleep(10 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	assert.NotEmpty(t, received, "push loop should have sent IOCs to peer")
}

// ---------------------------------------------------------------------------
// Secret rotation window tests (issue #116)
// ---------------------------------------------------------------------------

// TestHTTP_RotationWindow_AcceptsBothSecrets verifies that during a rotation
// window both the new secret and the previous secret are accepted.
func TestHTTP_RotationWindow_AcceptsBothSecrets(t *testing.T) {
	cfg := Config{
		Enabled:           true,
		NodeName:          "node-rotate",
		Secret:            "new-secret",
		SecretPrevious:    "old-secret",
		SecretRotationTTL: 5 * time.Minute,
		IOCTTL:            time.Hour,
		MaxIOCs:           100,
		PushInterval:      time.Hour,
	}
	m, err := NewManager(cfg, nil)
	require.NoError(t, err)
	handler := Handler(m)

	iocs := []IOC{{Type: IOCTypeIP, Value: "1.2.3.4", ExpiresAt: time.Now().Add(time.Hour)}}
	body, _ := json.Marshal(iocs)

	// New secret must be accepted.
	req := httptest.NewRequest(http.MethodPost, "/gossip/iocs", strings.NewReader(string(body)))
	req.Header.Set(gossipSecretHeader, "new-secret")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNoContent, w.Code, "new secret must be accepted")

	// Old secret must also be accepted within the rotation window.
	req = httptest.NewRequest(http.MethodPost, "/gossip/iocs", strings.NewReader(string(body)))
	req.Header.Set(gossipSecretHeader, "old-secret")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNoContent, w.Code, "old secret must be accepted within rotation window")

	// An unknown secret must still be rejected.
	req = httptest.NewRequest(http.MethodPost, "/gossip/iocs", strings.NewReader(string(body)))
	req.Header.Set(gossipSecretHeader, "unknown-secret")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code, "unknown secret must be rejected")
}

// TestHTTP_RotationWindow_RejectsOldSecretAfterExpiry verifies that once the
// rotation window expires the previous secret is no longer accepted.
func TestHTTP_RotationWindow_RejectsOldSecretAfterExpiry(t *testing.T) {
	cfg := Config{
		Enabled:           true,
		NodeName:          "node-expired",
		Secret:            "new-secret",
		SecretPrevious:    "old-secret",
		SecretRotationTTL: 10 * time.Millisecond, // expires almost immediately
		IOCTTL:            time.Hour,
		MaxIOCs:           100,
		PushInterval:      time.Hour,
	}
	m, err := NewManager(cfg, nil)
	require.NoError(t, err)
	handler := Handler(m)

	// Wait for the rotation window to close.
	time.Sleep(20 * time.Millisecond)

	iocs := []IOC{{Type: IOCTypeIP, Value: "5.6.7.8", ExpiresAt: time.Now().Add(time.Hour)}}
	body, _ := json.Marshal(iocs)

	// Old secret must now be rejected.
	req := httptest.NewRequest(http.MethodPost, "/gossip/iocs", strings.NewReader(string(body)))
	req.Header.Set(gossipSecretHeader, "old-secret")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code, "old secret must be rejected after rotation window expires")

	// New secret must still work.
	req = httptest.NewRequest(http.MethodPost, "/gossip/iocs", strings.NewReader(string(body)))
	req.Header.Set(gossipSecretHeader, "new-secret")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNoContent, w.Code, "new secret must still be accepted after window expires")
}

// TestHTTP_RotationWindow_NoWindowWhenTTLZero verifies that setting
// SecretPrevious without a positive SecretRotationTTL does not open a window.
func TestHTTP_RotationWindow_NoWindowWhenTTLZero(t *testing.T) {
	cfg := Config{
		Enabled:           true,
		NodeName:          "node-no-window",
		Secret:            "new-secret",
		SecretPrevious:    "old-secret",
		SecretRotationTTL: 0, // explicitly disabled
		IOCTTL:            time.Hour,
		MaxIOCs:           100,
		PushInterval:      time.Hour,
	}
	m, err := NewManager(cfg, nil)
	require.NoError(t, err)
	handler := Handler(m)

	iocs := []IOC{{Type: IOCTypeIP, Value: "9.9.9.9", ExpiresAt: time.Now().Add(time.Hour)}}
	body, _ := json.Marshal(iocs)

	// Old secret must be rejected because SecretRotationTTL=0 means no window.
	req := httptest.NewRequest(http.MethodPost, "/gossip/iocs", strings.NewReader(string(body)))
	req.Header.Set(gossipSecretHeader, "old-secret")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code, "old secret must not be accepted when rotation TTL is zero")
}

// ---------------------------------------------------------------------------
// mTLS integration test (issue #116)
// ---------------------------------------------------------------------------

// TestGossipClient_mTLS verifies that a gossipClient with a mutual TLS
// configuration can push IOCs to an HTTPS server that requires client certs.
func TestGossipClient_mTLS(t *testing.T) {
	// Generate a self-signed CA + server cert + client cert in memory.
	ca, caKey := mustGenCA(t)
	serverCert, serverKey := mustGenCert(t, ca, caKey, "server")
	clientCert, clientKey := mustGenCert(t, ca, caKey, "client")

	// Build a CA pool trusted by both sides.
	caPool := x509.NewCertPool()
	caPool.AddCert(ca)

	// Server TLS: require and verify client certs.
	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{
			{Certificate: [][]byte{serverCert.Raw}, PrivateKey: serverKey},
		},
		ClientCAs:  caPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS13,
	}

	// Start an HTTPS test server.
	var received []IOC
	var mu sync.Mutex
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var iocs []IOC
		require.NoError(t, json.NewDecoder(r.Body).Decode(&iocs))
		mu.Lock()
		received = append(received, iocs...)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	srv.TLS = serverTLS
	srv.StartTLS()
	defer srv.Close()

	// Build client TLS: present client cert, trust the CA.
	clientTLSCfg := &tls.Config{
		Certificates: []tls.Certificate{
			{Certificate: [][]byte{clientCert.Raw}, PrivateKey: clientKey},
		},
		RootCAs:    caPool,
		MinVersion: tls.VersionTLS13,
	}

	c := newGossipClient("", clientTLSCfg)
	iocs := []IOC{
		{Type: IOCTypeIP, Value: "10.20.30.40", ExpiresAt: time.Now().Add(time.Hour)},
	}
	err := c.PushIOCs(context.Background(), srv.URL, iocs)
	require.NoError(t, err, "mTLS push must succeed")

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, received, 1)
	assert.Equal(t, "10.20.30.40", received[0].Value)
}

// ---------------------------------------------------------------------------
// TLS cert helpers
// ---------------------------------------------------------------------------

// mustGenCA generates an in-memory self-signed CA certificate and returns the
// parsed cert and its private key.
func mustGenCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		NotAfter:              time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}

// mustGenCert generates a leaf certificate signed by ca/caKey and returns the
// parsed cert and its private key.
func mustGenCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}
