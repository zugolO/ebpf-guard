package sandbox

import (
	"net"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/zugolO/ebpf-guard/internal/config"
)

func aiCfg(mode string, profiles ...config.AISandboxProfile) config.AISandboxConfig {
	return config.AISandboxConfig{
		Enabled:  true,
		Mode:     mode,
		Profiles: profiles,
	}
}

func TestCompile_ProfileIDsAndModes(t *testing.T) {
	pol, err := Compile(aiCfg("enforce",
		config.AISandboxProfile{Name: "a"},
		config.AISandboxProfile{Name: "b"},
	))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if pol.Mode != ModeEnforce {
		t.Fatalf("mode = %d, want enforce", pol.Mode)
	}
	if id, ok := pol.ProfileID("a"); !ok || id != 1 {
		t.Fatalf("profile a id = %d,%v; want 1,true", id, ok)
	}
	if id, ok := pol.ProfileID("b"); !ok || id != 2 {
		t.Fatalf("profile b id = %d,%v; want 2,true", id, ok)
	}
	if _, ok := pol.ProfileID("missing"); ok {
		t.Fatal("missing profile should not resolve")
	}
}

func TestNormalizePrefix(t *testing.T) {
	cases := map[string]string{
		"/usr/bin/":       "/usr/bin",
		"/usr/bin":        "/usr/bin",
		"/workspace//foo": "/workspace/foo",
		"/":               "/",
		"relative/path":   "",
		"":                "",
	}
	for in, want := range cases {
		if got := normalizePrefix(in); got != want {
			t.Errorf("normalizePrefix(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPathAllowed_PrefixSemantics(t *testing.T) {
	pol, err := Compile(aiCfg("enforce", config.AISandboxProfile{
		Name:             "agent",
		AllowedReadPaths: []string{"/workspace", "/etc/hosts"},
		AllowedExec:      []string{"/usr/bin"},
	}))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		path string
		want uint8
		ok   bool
	}{
		{"/workspace", accessRead, true},
		{"/workspace/src/main.go", accessRead, true},
		{"/workspaceX/secret", accessRead, false}, // must not prefix-match a sibling
		{"/etc/hosts", accessRead, true},
		{"/etc/hostsX", accessRead, false},
		{"/etc/shadow", accessRead, false},
		{"/usr/bin/python3", accessExec, true},
		{"/usr/bin/python3", accessRead, true}, // AllowedExec also grants read
		{"/tmp/evil", accessExec, false},
		{"relative", accessRead, false},
	}
	for _, tt := range tests {
		if got := pol.PathAllowed("agent", tt.path, tt.want); got != tt.ok {
			t.Errorf("PathAllowed(%q, %d) = %v, want %v", tt.path, tt.want, got, tt.ok)
		}
	}
}

func TestPathAllowed_DeniedOverridesAllow(t *testing.T) {
	pol, err := Compile(aiCfg("enforce", config.AISandboxProfile{
		Name:             "agent",
		AllowedReadPaths: []string{"/home/agent"},
		DeniedPaths:      []string{"/home/agent/.ssh"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !pol.PathAllowed("agent", "/home/agent/project/file", accessRead) {
		t.Error("allowed subtree should be readable")
	}
	if pol.PathAllowed("agent", "/home/agent/.ssh/id_rsa", accessRead) {
		t.Error("denied path must override the allow")
	}
}

func TestEgressAllowed(t *testing.T) {
	pol, err := Compile(aiCfg("enforce", config.AISandboxProfile{
		Name:               "agent",
		AllowedEgressCIDRs: []string{"140.82.112.0/20", "2606:50c0::/32"},
		AllowedEgressPorts: []uint16{443},
	}))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		ip   string
		port uint16
		ok   bool
	}{
		{"140.82.113.4", 443, true}, // github, allowed port
		{"140.82.113.4", 80, false}, // in CIDR, wrong port
		{"8.8.8.8", 443, false},     // outside CIDR
		{"127.0.0.1", 9999, true},   // loopback always allowed
		{"::1", 1234, true},         // ipv6 loopback
		{"2606:50c0::1", 443, true}, // ipv6 CIDR
		{"2001:4860:4860::8888", 443, false},
	}
	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if got := pol.EgressAllowed("agent", ip, tt.port); got != tt.ok {
			t.Errorf("EgressAllowed(%s:%d) = %v, want %v", tt.ip, tt.port, got, tt.ok)
		}
	}
}

func TestEgressAllowed_NoPortFilterAllowsAnyPort(t *testing.T) {
	pol, err := Compile(aiCfg("enforce", config.AISandboxProfile{
		Name:               "agent",
		AllowedEgressCIDRs: []string{"10.0.0.0/8"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !pol.EgressAllowed("agent", net.ParseIP("10.1.2.3"), 8080) {
		t.Error("no port filter should allow any port within an allowed CIDR")
	}
}

func TestFNV32aMatchesConstants(t *testing.T) {
	// Regression pin: fnv32a must match the FNV-1a of the BPF hook. These
	// values are the canonical FNV-1a 32-bit outputs and must never drift.
	cases := map[string]uint32{
		"":           2166136261,
		"a":          0xe40c292c,
		"/workspace": fnv32aReference("/workspace"),
	}
	for in, want := range cases {
		if got := fnv32a(in); got != want {
			t.Errorf("fnv32a(%q) = %#x, want %#x", in, got, want)
		}
	}
}

// fnv32aReference is an independent implementation used only to cross-check.
func fnv32aReference(s string) uint32 {
	h := uint32(2166136261)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}

// --- in-memory fake map to exercise writePolicy without a kernel ---

type fakeMap struct {
	data map[string][]byte
}

func newFakeMap() *fakeMap { return &fakeMap{data: map[string][]byte{}} }

func keyStr(k interface{}) string {
	switch v := k.(type) {
	case uint64:
		return string([]byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24),
			byte(v >> 32), byte(v >> 40), byte(v >> 48), byte(v >> 56)})
	case uint32:
		return string([]byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)})
	case CIDRv4Entry:
		return string(v.Data[:]) + string(rune(v.PrefixLen))
	case CIDRv6Entry:
		return string(v.Data[:]) + string(rune(v.PrefixLen))
	default:
		return ""
	}
}

func (f *fakeMap) Update(key, value interface{}, _ ebpf.MapUpdateFlags) error {
	f.data[keyStr(key)] = []byte{1}
	return nil
}
func (f *fakeMap) Delete(key interface{}) error {
	delete(f.data, keyStr(key))
	return nil
}

func TestWritePolicy_PopulatesAllMaps(t *testing.T) {
	pol, err := Compile(aiCfg("enforce", config.AISandboxProfile{
		Name:               "agent",
		AllowedReadPaths:   []string{"/workspace"},
		AllowedExec:        []string{"/usr/bin"},
		AllowedEgressCIDRs: []string{"10.0.0.0/8", "fd00::/8"},
		AllowedEgressPorts: []uint16{443, 53},
	}))
	if err != nil {
		t.Fatal(err)
	}
	maps := Maps{
		State:      newFakeMap(),
		Cgroups:    newFakeMap(),
		PathPolicy: newFakeMap(),
		NetV4:      newFakeMap(),
		NetV6:      newFakeMap(),
		Ports:      newFakeMap(),
	}
	if err := writePolicy(maps, pol); err != nil {
		t.Fatalf("writePolicy: %v", err)
	}
	if n := len(maps.PathPolicy.(*fakeMap).data); n != 2 {
		t.Errorf("path policy rows = %d, want 2", n)
	}
	if n := len(maps.NetV4.(*fakeMap).data); n != 1 {
		t.Errorf("v4 rows = %d, want 1", n)
	}
	if n := len(maps.NetV6.(*fakeMap).data); n != 1 {
		t.Errorf("v6 rows = %d, want 1", n)
	}
	if n := len(maps.Ports.(*fakeMap).data); n != 2 {
		t.Errorf("port rows = %d, want 2", n)
	}
}
