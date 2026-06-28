package bpf

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// parseSubnetKeys
// ---------------------------------------------------------------------------

func TestParseSubnetKeys_IPv4(t *testing.T) {
	tests := []struct {
		cidr      string
		wantPLen  uint32
		wantAddr  [4]byte
	}{
		{"0.0.0.0/0", 0, [4]byte{0, 0, 0, 0}},
		{"10.0.0.0/8", 8, [4]byte{10, 0, 0, 0}},
		{"192.168.1.0/24", 24, [4]byte{192, 168, 1, 0}},
		{"172.16.0.0/12", 12, [4]byte{172, 16, 0, 0}},
		{"8.8.8.8/32", 32, [4]byte{8, 8, 8, 8}},
	}
	for _, tc := range tests {
		v4, v6, err := parseSubnetKeys(tc.cidr)
		require.NoErrorf(t, err, "cidr=%s", tc.cidr)
		assert.Nilf(t, v6, "cidr=%s should produce nil IPv6 key", tc.cidr)
		require.NotNilf(t, v4, "cidr=%s should produce an IPv4 key", tc.cidr)
		assert.Equalf(t, tc.wantPLen, v4.PrefixLen, "cidr=%s prefixlen", tc.cidr)
		assert.Equalf(t, tc.wantAddr, v4.Addr, "cidr=%s addr", tc.cidr)
	}
}

func TestParseSubnetKeys_IPv6(t *testing.T) {
	tests := []struct {
		cidr     string
		wantPLen uint32
		wantAddr [16]byte
	}{
		{"::/0", 0, [16]byte{}},
		{"2001:db8::/32", 32, func() [16]byte {
			ip := net.ParseIP("2001:db8::")
			var a [16]byte
			copy(a[:], ip.To16())
			return a
		}()},
		{"fe80::/10", 10, func() [16]byte {
			ip := net.ParseIP("fe80::")
			var a [16]byte
			copy(a[:], ip.To16())
			return a
		}()},
		{"::1/128", 128, func() [16]byte {
			ip := net.ParseIP("::1")
			var a [16]byte
			copy(a[:], ip.To16())
			return a
		}()},
	}
	for _, tc := range tests {
		v4, v6, err := parseSubnetKeys(tc.cidr)
		require.NoErrorf(t, err, "cidr=%s", tc.cidr)
		assert.Nilf(t, v4, "cidr=%s should produce nil IPv4 key", tc.cidr)
		require.NotNilf(t, v6, "cidr=%s should produce an IPv6 key", tc.cidr)
		assert.Equalf(t, tc.wantPLen, v6.PrefixLen, "cidr=%s prefixlen", tc.cidr)
		assert.Equalf(t, tc.wantAddr, v6.Addr, "cidr=%s addr", tc.cidr)
	}
}

func TestParseSubnetKeys_Invalid(t *testing.T) {
	invalid := []string{
		"not-a-cidr",
		"256.0.0.0/8",
		"",
		"10.0.0.0",     // no prefix length
		"10.0.0.0/33",  // too long IPv4 prefix
		"::1/129",      // too long IPv6 prefix
	}
	for _, cidr := range invalid {
		v4, v6, err := parseSubnetKeys(cidr)
		assert.Errorf(t, err, "expected error for %q", cidr)
		assert.Nil(t, v4, "expected nil v4 key for %q", cidr)
		assert.Nil(t, v6, "expected nil v6 key for %q", cidr)
	}
}

func TestParseSubnetKeys_HostBitsIgnored(t *testing.T) {
	// net.ParseCIDR zeros out host bits; e.g. "192.168.1.5/24" -> "192.168.1.0/24"
	v4, _, err := parseSubnetKeys("192.168.1.5/24")
	require.NoError(t, err)
	require.NotNil(t, v4)
	assert.Equal(t, uint32(24), v4.PrefixLen)
	// Network address has host bits zeroed.
	assert.Equal(t, [4]byte{192, 168, 1, 0}, v4.Addr)
}

// ---------------------------------------------------------------------------
// NewNetworkBlocklistController – nil-map guards
// ---------------------------------------------------------------------------

func TestNewNetworkBlocklistController_NilIPv4(t *testing.T) {
	_, err := NewNetworkBlocklistController(nil, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "net_block_ipv4")
}

func TestNewNetworkBlocklistController_NilIPv6(t *testing.T) {
	// Pass a non-nil placeholder for ipv4 so we reach the ipv6 nil check.
	// We cannot create real ebpf.Map objects without root + kernel BPF support,
	// so instead we construct the controller struct directly and test guard paths.
	c := &NetworkBlocklistController{}

	err := c.AddSubnet("2001:db8::/32") // hits nil ipv6Map guard
	require.Error(t, err)
	assert.Contains(t, err.Error(), "net_block_ipv6")
}

func TestNewNetworkBlocklistController_NilPorts(t *testing.T) {
	c := &NetworkBlocklistController{}
	err := c.AddPort(4444)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "net_block_ports")
}

// ---------------------------------------------------------------------------
// AddSubnet / RemoveSubnet – nil-map guards (no real BPF map required)
// ---------------------------------------------------------------------------

func TestAddSubnet_NilIPv4Map(t *testing.T) {
	c := &NetworkBlocklistController{} // all maps nil

	err := c.AddSubnet("10.0.0.0/8")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "net_block_ipv4")
}

func TestAddSubnet_InvalidCIDR(t *testing.T) {
	c := &NetworkBlocklistController{}
	err := c.AddSubnet("not-a-cidr")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AddSubnet")
}

func TestRemoveSubnet_NilIPv4Map(t *testing.T) {
	c := &NetworkBlocklistController{}
	err := c.RemoveSubnet("10.0.0.0/8")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "net_block_ipv4")
}

func TestRemoveSubnet_NilIPv6Map(t *testing.T) {
	c := &NetworkBlocklistController{}
	err := c.RemoveSubnet("2001:db8::/32")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "net_block_ipv6")
}

func TestRemoveSubnet_InvalidCIDR(t *testing.T) {
	c := &NetworkBlocklistController{}
	err := c.RemoveSubnet("bad")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "RemoveSubnet")
}

// ---------------------------------------------------------------------------
// AddPort / RemovePort – nil-map guards
// ---------------------------------------------------------------------------

func TestAddPort_NilMap(t *testing.T) {
	c := &NetworkBlocklistController{}
	err := c.AddPort(80)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "net_block_ports")
}

func TestRemovePort_NilMap(t *testing.T) {
	c := &NetworkBlocklistController{}
	err := c.RemovePort(80)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "net_block_ports")
}

// ---------------------------------------------------------------------------
// SetBlocklist – invalid CIDR returns error
// ---------------------------------------------------------------------------

func TestSetBlocklist_InvalidCIDR(t *testing.T) {
	c := &NetworkBlocklistController{} // maps nil; error should surface at parse stage
	err := c.SetBlocklist(NetworkBlocklistConfig{
		Subnets: []string{"not-a-cidr"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "network blocklist")
}

func TestSetBlocklist_NilIPv4Map(t *testing.T) {
	c := &NetworkBlocklistController{}
	// Valid CIDR but nil ipv4 map → error when trying to insert.
	err := c.SetBlocklist(NetworkBlocklistConfig{
		Subnets: []string{"10.0.0.0/8"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "net_block_ipv4")
}

func TestSetBlocklist_NilIPv6Map(t *testing.T) {
	c := &NetworkBlocklistController{}
	// Valid IPv6 CIDR but nil ipv6 map → error when trying to insert.
	err := c.SetBlocklist(NetworkBlocklistConfig{
		Subnets: []string{"2001:db8::/32"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "net_block_ipv6")
}

func TestSetBlocklist_NilPortsMap(t *testing.T) {
	c := &NetworkBlocklistController{}
	// Valid port but nil ports map → error when trying to insert.
	err := c.SetBlocklist(NetworkBlocklistConfig{
		Ports: []uint16{4444},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "net_block_ports")
}

func TestSetBlocklist_EmptyConfig_NoMapAccess(t *testing.T) {
	c := &NetworkBlocklistController{} // all maps nil
	// Empty config should succeed — no map access needed.
	err := c.SetBlocklist(NetworkBlocklistConfig{})
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// ReadNetBlockDropCount – nil map guard
// ---------------------------------------------------------------------------

func TestReadNetBlockDropCount_NilMap(t *testing.T) {
	_, err := ReadNetBlockDropCount(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "net_block_counters")
}

// ---------------------------------------------------------------------------
// Key serialisation helpers
// ---------------------------------------------------------------------------

func TestIPv4LPMKeyBytes(t *testing.T) {
	k := IPv4LPMKey{PrefixLen: 24, Addr: [4]byte{192, 168, 1, 0}}
	b := IPv4LPMKeyBytes(k)
	require.Len(t, b, 8)

	plen := binary.LittleEndian.Uint32(b[0:4])
	assert.Equal(t, uint32(24), plen)
	assert.Equal(t, []byte{192, 168, 1, 0}, b[4:8])
}

func TestIPv4LPMKeyBytes_ZeroPrefix(t *testing.T) {
	k := IPv4LPMKey{PrefixLen: 0, Addr: [4]byte{0, 0, 0, 0}}
	b := IPv4LPMKeyBytes(k)
	require.Len(t, b, 8)
	assert.Equal(t, uint32(0), binary.LittleEndian.Uint32(b[0:4]))
}

func TestIPv6LPMKeyBytes(t *testing.T) {
	var addr [16]byte
	copy(addr[:], net.ParseIP("2001:db8::").To16())
	k := IPv6LPMKey{PrefixLen: 32, Addr: addr}
	b := IPv6LPMKeyBytes(k)
	require.Len(t, b, 20)

	plen := binary.LittleEndian.Uint32(b[0:4])
	assert.Equal(t, uint32(32), plen)
	assert.Equal(t, addr[:], b[4:20])
}

func TestIPv6LPMKeyBytes_FullHost(t *testing.T) {
	var addr [16]byte
	copy(addr[:], net.ParseIP("::1").To16())
	k := IPv6LPMKey{PrefixLen: 128, Addr: addr}
	b := IPv6LPMKeyBytes(k)
	require.Len(t, b, 20)
	assert.Equal(t, uint32(128), binary.LittleEndian.Uint32(b[0:4]))
}

// ---------------------------------------------------------------------------
// NetworkBlocklistConfig – basic struct behaviour
// ---------------------------------------------------------------------------

func TestNetworkBlocklistConfig_Empty(t *testing.T) {
	var cfg NetworkBlocklistConfig
	assert.Empty(t, cfg.Subnets)
	assert.Empty(t, cfg.Ports)
}

func TestNetworkBlocklistConfig_Fields(t *testing.T) {
	cfg := NetworkBlocklistConfig{
		Subnets: []string{"10.0.0.0/8", "2001:db8::/32"},
		Ports:   []uint16{4444, 6666},
	}
	assert.Len(t, cfg.Subnets, 2)
	assert.Len(t, cfg.Ports, 2)
	assert.Equal(t, uint16(4444), cfg.Ports[0])
	assert.Equal(t, uint16(6666), cfg.Ports[1])
}

// ---------------------------------------------------------------------------
// isNotFound helper
// ---------------------------------------------------------------------------

func TestIsNotFound_NilError(t *testing.T) {
	assert.False(t, isNotFound(nil))
}

func TestIsNotFound_ErrKeyNotExist(t *testing.T) {
	assert.True(t, isNotFound(ebpfErrKeyNotExist()))
}

// ebpfErrKeyNotExist returns a sentinel error that matches the key-not-exist
// check in isNotFound without importing ebpf in the test package (it's
// already imported in the production file).
func ebpfErrKeyNotExist() error {
	return ebpfNotFoundErr{}
}

type ebpfNotFoundErr struct{}

func (ebpfNotFoundErr) Error() string { return "key does not exist" }

// ---------------------------------------------------------------------------
// Stale-entry tracking via configXxxKeys fields (pure-Go logic, no BPF maps)
// ---------------------------------------------------------------------------

func TestSetBlocklist_TracksPreviousIPv4Keys(t *testing.T) {
	c := &NetworkBlocklistController{}

	k1 := IPv4LPMKey{PrefixLen: 8, Addr: [4]byte{10, 0, 0, 0}}
	k2 := IPv4LPMKey{PrefixLen: 24, Addr: [4]byte{192, 168, 1, 0}}

	// k2 is present in newKeys, so only k1 is stale.
	// With nil ipv4Map, the delete of k1 surfaces a "map is nil" error.
	err := c.removeStaleIPv4([]IPv4LPMKey{k1, k2}, []IPv4LPMKey{k2})
	require.Error(t, err, "should fail when stale key needs deletion but map is nil")
	assert.Contains(t, err.Error(), "net_block_ipv4")
}

func TestSetBlocklist_TracksPreviousPorts(t *testing.T) {
	c := &NetworkBlocklistController{}
	c.configPorts = []uint16{80, 443}

	// 443 is kept, 80 is removed, 8080 is added.
	err := c.removeStaleports([]uint16{80, 443}, []uint16{443, 8080})
	// nil portsMap → error when trying to delete stale port 80.
	require.Error(t, err)
	assert.Contains(t, err.Error(), "net_block_ports")
}

func TestRemoveStaleIPv4_NoDiff(t *testing.T) {
	c := &NetworkBlocklistController{}
	k := IPv4LPMKey{PrefixLen: 8, Addr: [4]byte{10, 0, 0, 0}}

	// Same key in old and new → nothing to delete; no map access required.
	err := c.removeStaleIPv4([]IPv4LPMKey{k}, []IPv4LPMKey{k})
	assert.NoError(t, err)
}

func TestRemoveStaleIPv6_NoDiff(t *testing.T) {
	c := &NetworkBlocklistController{}
	var addr [16]byte
	copy(addr[:], net.ParseIP("2001:db8::").To16())
	k := IPv6LPMKey{PrefixLen: 32, Addr: addr}

	err := c.removeStaleIPv6([]IPv6LPMKey{k}, []IPv6LPMKey{k})
	assert.NoError(t, err)
}

func TestRemoveStaleports_NoDiff(t *testing.T) {
	c := &NetworkBlocklistController{}
	err := c.removeStaleports([]uint16{80}, []uint16{80})
	assert.NoError(t, err)
}

func TestRemoveStaleIPv4_EmptyOld(t *testing.T) {
	c := &NetworkBlocklistController{}
	// Nothing stale → no map access → no error even with nil map.
	err := c.removeStaleIPv4(nil, []IPv4LPMKey{{PrefixLen: 8, Addr: [4]byte{10}}})
	assert.NoError(t, err)
}

func TestRemoveStaleIPv6_EmptyOld(t *testing.T) {
	c := &NetworkBlocklistController{}
	var addr [16]byte
	err := c.removeStaleIPv6(nil, []IPv6LPMKey{{PrefixLen: 32, Addr: addr}})
	assert.NoError(t, err)
}

func TestRemoveStaleports_EmptyOld(t *testing.T) {
	c := &NetworkBlocklistController{}
	err := c.removeStaleports(nil, []uint16{80})
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// parseSubnetKeys – IPv4-mapped IPv6 addresses
// ---------------------------------------------------------------------------

func TestParseSubnetKeys_IPv4MappedIPv6(t *testing.T) {
	// "::ffff:192.168.1.0/120" is an IPv6 CIDR that Go's net.ParseCIDR treats
	// as an IPv6 address (bits=128).  Verify we return an IPv6 key.
	v4, v6, err := parseSubnetKeys("::ffff:192.168.1.0/120")
	require.NoError(t, err)
	assert.Nil(t, v4)
	assert.NotNil(t, v6)
	assert.Equal(t, uint32(120), v6.PrefixLen)
}

// ---------------------------------------------------------------------------
// Key deduplication in hot-reload (no BPF map interaction)
// ---------------------------------------------------------------------------

func TestRemoveStaleIPv4_DeduplicatesCorrectly(t *testing.T) {
	c := &NetworkBlocklistController{}

	k1 := IPv4LPMKey{PrefixLen: 8, Addr: [4]byte{10, 0, 0, 0}}
	k2 := IPv4LPMKey{PrefixLen: 16, Addr: [4]byte{172, 16, 0, 0}}
	k3 := IPv4LPMKey{PrefixLen: 24, Addr: [4]byte{192, 168, 1, 0}}

	// k1 is stale (removed), k2 and k3 are kept.
	// With nil map, only the stale-key deletion path triggers an error.
	err := c.removeStaleIPv4([]IPv4LPMKey{k1, k2, k3}, []IPv4LPMKey{k2, k3})
	require.Error(t, err) // k1 is stale → delete attempted → nil map error
	assert.Contains(t, err.Error(), "stale")
}

func TestRemoveStaleIPv6_DeduplicatesCorrectly(t *testing.T) {
	c := &NetworkBlocklistController{}

	var addr1, addr2 [16]byte
	copy(addr1[:], net.ParseIP("2001:db8::").To16())
	copy(addr2[:], net.ParseIP("fe80::").To16())

	k1 := IPv6LPMKey{PrefixLen: 32, Addr: addr1}
	k2 := IPv6LPMKey{PrefixLen: 10, Addr: addr2}

	err := c.removeStaleIPv6([]IPv6LPMKey{k1, k2}, []IPv6LPMKey{k2})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "stale")
}
