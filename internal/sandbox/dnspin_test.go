package sandbox

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/internal/config"
)

// fakeResolver returns canned results per host, and can be flipped to fail.
type fakeResolver struct {
	byHost map[string][]net.IP
	fail   map[string]bool
}

func (f *fakeResolver) LookupIP(_ context.Context, _ string, host string) ([]net.IP, error) {
	if f.fail[host] {
		return nil, errors.New("simulated resolve failure")
	}
	ips, ok := f.byHost[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	return ips, nil
}

// recordingProgrammer captures the last IP set programmed per profile.
type recordingProgrammer struct {
	last map[string][]net.IP
}

func (r *recordingProgrammer) SetDomainEgress(profile string, ips []net.IP) error {
	if r.last == nil {
		r.last = map[string][]net.IP{}
	}
	r.last[profile] = ips
	return nil
}

func ipset(ss ...string) []net.IP {
	out := make([]net.IP, 0, len(ss))
	for _, s := range ss {
		out = append(out, net.ParseIP(s))
	}
	return out
}

func TestDNSPinner_ResolvesAndPrograms(t *testing.T) {
	cfg := config.AISandboxConfig{
		Enabled:            true,
		Mode:               "enforce",
		DNSRefreshInterval: time.Second,
		Profiles: []config.AISandboxProfile{{
			Name:           "agent",
			AllowedDomains: []string{"github.com", ".pypi.org"},
		}},
	}
	res := &fakeResolver{byHost: map[string][]net.IP{
		"github.com": ipset("140.82.112.3", "2606:50c0:8000::153"),
		"pypi.org":   ipset("151.101.0.223"),
	}}
	prog := &recordingProgrammer{}

	pinner, ok := NewDNSPinner(cfg, prog, res, nil)
	if !ok {
		t.Fatal("expected a pinner (profile has domains)")
	}
	n := pinner.RefreshOnce(context.Background())
	if n != 3 {
		t.Fatalf("pinned %d addresses, want 3", n)
	}
	got := prog.last["agent"]
	if len(got) != 3 {
		t.Fatalf("programmed %d IPs, want 3: %v", len(got), got)
	}
}

func TestDNSPinner_FailedLookupReusesCache(t *testing.T) {
	cfg := config.AISandboxConfig{
		DNSRefreshInterval: time.Second,
		Profiles: []config.AISandboxProfile{{
			Name:           "agent",
			AllowedDomains: []string{"github.com"},
		}},
	}
	res := &fakeResolver{
		byHost: map[string][]net.IP{"github.com": ipset("140.82.112.3")},
		fail:   map[string]bool{},
	}
	prog := &recordingProgrammer{}
	pinner, _ := NewDNSPinner(cfg, prog, res, nil)

	// First pass succeeds and caches.
	pinner.RefreshOnce(context.Background())
	if len(prog.last["agent"]) != 1 {
		t.Fatalf("first pass: want 1 IP, got %v", prog.last["agent"])
	}
	// Now DNS fails: the cached IP must be reused, not pruned.
	res.fail["github.com"] = true
	pinner.RefreshOnce(context.Background())
	if len(prog.last["agent"]) != 1 {
		t.Fatalf("failed-lookup pass: cache should keep 1 IP, got %v", prog.last["agent"])
	}
}

// rotatingResolver returns a different subset of a fixed record set on each
// call, mimicking a large domain that round-robins its A records per query.
type rotatingResolver struct {
	replies [][]net.IP
	n       int
}

func (r *rotatingResolver) LookupIP(_ context.Context, _, _ string) ([]net.IP, error) {
	idx := r.n
	if idx >= len(r.replies) {
		idx = len(r.replies) - 1 // clamp: keep returning the final reply
	}
	r.n++
	return r.replies[idx], nil
}

func TestDNSPinner_RoundRobinKeepsLiveIPsUntilTTL(t *testing.T) {
	cfg := config.AISandboxConfig{
		Mode:               "enforce",
		DNSRefreshInterval: time.Second,
		DNSPinTTL:          3 * time.Second,
		Profiles: []config.AISandboxProfile{{
			Name:           "agent",
			AllowedDomains: []string{"github.com"},
		}},
	}
	// Two replies each expose a rotating pair; A is only ever in the first.
	res := &rotatingResolver{replies: [][]net.IP{
		ipset("140.82.112.3", "140.82.113.4"), // {A, B}
		ipset("140.82.113.4", "140.82.114.5"), // {B, C} — A absent
	}}
	prog := &recordingProgrammer{}
	pinner, ok := NewDNSPinner(cfg, prog, res, nil)
	if !ok {
		t.Fatal("expected a pinner")
	}
	// Drive a deterministic clock so TTL expiry is exact.
	base := time.Unix(0, 0)
	clock := base
	pinner.now = func() time.Time { return clock }

	// Refresh 1 at t=0: pins {A, B}.
	pinner.RefreshOnce(context.Background())
	if got := mustIPStrings(prog.last["agent"]); len(got) != 2 {
		t.Fatalf("refresh 1: want 2 pins {A,B}, got %v", got)
	}

	// Refresh 2 at t=1s: reply is {B, C}; A dropped out of the reply but is still
	// within its TTL, so the union must stay {A, B, C} — no transient eviction.
	clock = base.Add(time.Second)
	pinner.RefreshOnce(context.Background())
	got := mustIPStrings(prog.last["agent"])
	if len(got) != 3 {
		t.Fatalf("refresh 2: round-robin must keep live A, want 3 pins {A,B,C}, got %v", got)
	}
	if !containsIP(got, "140.82.112.3") {
		t.Fatalf("refresh 2: still-live A (140.82.112.3) was wrongly evicted, got %v", got)
	}

	// Refresh 3 well past A's TTL (t=5s > 0+3s): A finally expires. B and C were
	// re-observed at t=1s so they remain live.
	clock = base.Add(5 * time.Second)
	pinner.RefreshOnce(context.Background())
	got = mustIPStrings(prog.last["agent"])
	if containsIP(got, "140.82.112.3") {
		t.Fatalf("refresh 3: A should have expired by TTL, got %v", got)
	}
	if !containsIP(got, "140.82.113.4") || !containsIP(got, "140.82.114.5") {
		t.Fatalf("refresh 3: re-observed B and C must stay live, got %v", got)
	}
}

func mustIPStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

func containsIP(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func TestNewDNSPinner_DisabledCases(t *testing.T) {
	withDomains := config.AISandboxProfile{Name: "a", AllowedDomains: []string{"x.com"}}

	// Interval 0 disables pinning.
	if _, ok := NewDNSPinner(config.AISandboxConfig{
		DNSRefreshInterval: 0,
		Profiles:           []config.AISandboxProfile{withDomains},
	}, &recordingProgrammer{}, &fakeResolver{}, nil); ok {
		t.Error("interval 0 should disable the pinner")
	}
	// No domains disables pinning.
	if _, ok := NewDNSPinner(config.AISandboxConfig{
		DNSRefreshInterval: time.Second,
		Profiles:           []config.AISandboxProfile{{Name: "a"}},
	}, &recordingProgrammer{}, &fakeResolver{}, nil); ok {
		t.Error("no domains should disable the pinner")
	}
}

func TestManager_SetDomainEgress_DiffAndPrune(t *testing.T) {
	mgr, err := New(aiCfg("enforce", config.AISandboxProfile{
		Name:           "agent",
		AllowedDomains: []string{"github.com"},
	}), nil)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	// Kernel maps present (fakes) so we exercise the add/delete paths.
	v4 := newFakeMap()
	v6 := newFakeMap()
	mgr.maps = &Maps{NetV4: v4, NetV6: v6}

	// Program two addresses.
	if err := mgr.SetDomainEgress("agent", ipset("140.82.112.3", "2606:50c0:8000::153")); err != nil {
		t.Fatalf("set 1: %v", err)
	}
	if got := mgr.DomainEgressIPs("agent"); len(got) != 2 {
		t.Fatalf("after set 1: want 2 pinned, got %v", got)
	}
	if len(v4.data) != 1 || len(v6.data) != 1 {
		t.Fatalf("want 1 v4 + 1 v6 row, got v4=%d v6=%d", len(v4.data), len(v6.data))
	}

	// Rotate: drop the v6, keep the v4, add a new v4. The stale v6 must be pruned.
	if err := mgr.SetDomainEgress("agent", ipset("140.82.112.3", "140.82.113.4")); err != nil {
		t.Fatalf("set 2: %v", err)
	}
	if got := mgr.DomainEgressIPs("agent"); len(got) != 2 {
		t.Fatalf("after set 2: want 2 pinned, got %v", got)
	}
	if len(v6.data) != 0 {
		t.Errorf("stale v6 row should be pruned, got %d", len(v6.data))
	}
	if len(v4.data) != 2 {
		t.Errorf("want 2 v4 rows after rotate, got %d", len(v4.data))
	}

	// Loopback is skipped (always allowed by the hook fast-path).
	if err := mgr.SetDomainEgress("agent", ipset("127.0.0.1")); err != nil {
		t.Fatalf("set 3: %v", err)
	}
	if got := mgr.DomainEgressIPs("agent"); len(got) != 0 {
		t.Errorf("loopback must not be pinned, got %v", got)
	}
}

func TestManager_SetDomainEgress_UnknownProfile(t *testing.T) {
	mgr, _ := New(aiCfg("enforce", config.AISandboxProfile{Name: "agent"}), nil)
	if err := mgr.SetDomainEgress("nope", ipset("1.2.3.4")); err == nil {
		t.Fatal("expected error for unknown profile")
	}
}
