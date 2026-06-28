package bpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
)

// bpfMap is the subset of *ebpf.Map operations used here.
// Extracted as an interface so unit tests can inject in-memory fakes.
type bpfMap interface {
	Update(key, value interface{}, flags ebpf.MapUpdateFlags) error
	Delete(key interface{}) error
	Lookup(key, valueOut interface{}) error
}

// IPv4LPMKey is the BPF key for net_block_ipv4 (BPF_MAP_TYPE_LPM_TRIE).
// Layout must match C struct lpm_key_v4 in bpf/common.h exactly.
type IPv4LPMKey struct {
	PrefixLen uint32
	Addr      [4]byte
}

// IPv6LPMKey is the BPF key for net_block_ipv6 (BPF_MAP_TYPE_LPM_TRIE).
// Layout must match C struct lpm_key_v6 in bpf/common.h exactly.
type IPv6LPMKey struct {
	PrefixLen uint32
	Addr      [16]byte
}

// NetworkBlocklistConfig holds the user-supplied blocklist entries loaded at
// startup and on hot-reload.
type NetworkBlocklistConfig struct {
	// Subnets is a list of CIDR notation subnets to block (IPv4 and IPv6).
	// Examples: "10.0.0.0/8", "192.168.1.0/24", "2001:db8::/32"
	Subnets []string
	// Ports is a list of destination TCP ports (in host byte order) to block.
	// Examples: 4444, 6666, 1337
	Ports []uint16
}

// NetworkBlocklistController manages the three BPF maps that implement
// in-kernel network blocking:
//
//   - net_block_ipv4  (BPF_MAP_TYPE_LPM_TRIE) — IPv4 subnet blocklist
//   - net_block_ipv6  (BPF_MAP_TYPE_LPM_TRIE) — IPv6 subnet blocklist
//   - net_block_ports (BPF_MAP_TYPE_HASH)      — destination port blocklist
//
// SetBlocklist replaces the current config-driven entries atomically,
// enabling hot-reload on config change.
type NetworkBlocklistController struct {
	ipv4Map  bpfMap
	ipv6Map  bpfMap
	portsMap bpfMap

	// Track config-loaded keys so hot-reload can remove stale entries.
	configIPv4Keys []IPv4LPMKey
	configIPv6Keys []IPv6LPMKey
	configPorts    []uint16
}

// NewNetworkBlocklistController creates a controller backed by the three BPF
// maps. All three maps must be non-nil.
func NewNetworkBlocklistController(ipv4, ipv6, ports *ebpf.Map) (*NetworkBlocklistController, error) {
	if ipv4 == nil {
		return nil, fmt.Errorf("bpf: net_block_ipv4 map is nil")
	}
	if ipv6 == nil {
		return nil, fmt.Errorf("bpf: net_block_ipv6 map is nil")
	}
	if ports == nil {
		return nil, fmt.Errorf("bpf: net_block_ports map is nil")
	}
	return &NetworkBlocklistController{
		ipv4Map:  ipv4,
		ipv6Map:  ipv6,
		portsMap: ports,
	}, nil
}

// SetBlocklist atomically replaces all config-driven blocklist entries with
// the contents of cfg. It removes entries that were added by a previous call
// to SetBlocklist but are absent from the new config, and inserts new entries.
// This is safe to call on hot-reload.
func (n *NetworkBlocklistController) SetBlocklist(cfg NetworkBlocklistConfig) error {
	// Parse new subnets.
	var newIPv4 []IPv4LPMKey
	var newIPv6 []IPv6LPMKey
	for _, cidr := range cfg.Subnets {
		v4, v6, err := parseSubnetKeys(cidr)
		if err != nil {
			return fmt.Errorf("bpf: network blocklist: %w", err)
		}
		if v4 != nil {
			newIPv4 = append(newIPv4, *v4)
		}
		if v6 != nil {
			newIPv6 = append(newIPv6, *v6)
		}
	}

	val := uint8(1)

	// Remove stale IPv4 entries from previous config.
	if err := n.removeStaleIPv4(n.configIPv4Keys, newIPv4); err != nil {
		return err
	}
	// Insert new IPv4 entries.
	if len(newIPv4) > 0 {
		if n.ipv4Map == nil {
			return fmt.Errorf("bpf: net_block_ipv4 map is nil")
		}
		for _, k := range newIPv4 {
			if err := n.ipv4Map.Update(k, val, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("bpf: net_block_ipv4 update %v/%d: %w", k.Addr, k.PrefixLen, err)
			}
		}
	}
	n.configIPv4Keys = newIPv4

	// Remove stale IPv6 entries.
	if err := n.removeStaleIPv6(n.configIPv6Keys, newIPv6); err != nil {
		return err
	}
	// Insert new IPv6 entries.
	if len(newIPv6) > 0 {
		if n.ipv6Map == nil {
			return fmt.Errorf("bpf: net_block_ipv6 map is nil")
		}
		for _, k := range newIPv6 {
			if err := n.ipv6Map.Update(k, val, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("bpf: net_block_ipv6 update %v/%d: %w", k.Addr, k.PrefixLen, err)
			}
		}
	}
	n.configIPv6Keys = newIPv6

	// Remove stale port entries.
	if err := n.removeStaleports(n.configPorts, cfg.Ports); err != nil {
		return err
	}
	// Insert new port entries.
	if len(cfg.Ports) > 0 {
		if n.portsMap == nil {
			return fmt.Errorf("bpf: net_block_ports map is nil")
		}
		for _, p := range cfg.Ports {
			if err := n.portsMap.Update(p, val, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("bpf: net_block_ports update port %d: %w", p, err)
			}
		}
	}
	n.configPorts = cfg.Ports

	return nil
}

// AddSubnet inserts a single CIDR subnet into the appropriate BPF LPM trie.
// The entry is not tracked for hot-reload (use SetBlocklist for that).
func (n *NetworkBlocklistController) AddSubnet(cidr string) error {
	v4, v6, err := parseSubnetKeys(cidr)
	if err != nil {
		return fmt.Errorf("bpf: AddSubnet: %w", err)
	}
	val := uint8(1)
	if v4 != nil {
		if n.ipv4Map == nil {
			return fmt.Errorf("bpf: net_block_ipv4 map is nil")
		}
		if err := n.ipv4Map.Update(*v4, val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("bpf: net_block_ipv4 add %s: %w", cidr, err)
		}
	}
	if v6 != nil {
		if n.ipv6Map == nil {
			return fmt.Errorf("bpf: net_block_ipv6 map is nil")
		}
		if err := n.ipv6Map.Update(*v6, val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("bpf: net_block_ipv6 add %s: %w", cidr, err)
		}
	}
	return nil
}

// RemoveSubnet removes a single CIDR subnet from the BPF LPM trie.
func (n *NetworkBlocklistController) RemoveSubnet(cidr string) error {
	v4, v6, err := parseSubnetKeys(cidr)
	if err != nil {
		return fmt.Errorf("bpf: RemoveSubnet: %w", err)
	}
	if v4 != nil {
		if n.ipv4Map == nil {
			return fmt.Errorf("bpf: net_block_ipv4 map is nil")
		}
		if err := n.ipv4Map.Delete(*v4); err != nil && !isNotFound(err) {
			return fmt.Errorf("bpf: net_block_ipv4 remove %s: %w", cidr, err)
		}
	}
	if v6 != nil {
		if n.ipv6Map == nil {
			return fmt.Errorf("bpf: net_block_ipv6 map is nil")
		}
		if err := n.ipv6Map.Delete(*v6); err != nil && !isNotFound(err) {
			return fmt.Errorf("bpf: net_block_ipv6 remove %s: %w", cidr, err)
		}
	}
	return nil
}

// AddPort inserts a single destination port into the BPF port hash map.
func (n *NetworkBlocklistController) AddPort(port uint16) error {
	if n.portsMap == nil {
		return fmt.Errorf("bpf: net_block_ports map is nil")
	}
	val := uint8(1)
	if err := n.portsMap.Update(port, val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("bpf: net_block_ports add port %d: %w", port, err)
	}
	return nil
}

// RemovePort removes a single destination port from the BPF port hash map.
func (n *NetworkBlocklistController) RemovePort(port uint16) error {
	if n.portsMap == nil {
		return fmt.Errorf("bpf: net_block_ports map is nil")
	}
	if err := n.portsMap.Delete(port); err != nil && !isNotFound(err) {
		return fmt.Errorf("bpf: net_block_ports remove port %d: %w", port, err)
	}
	return nil
}

// ReadNetBlockDropCount reads and sums the per-CPU drop counter from the
// net_block_counters BPF PERCPU_ARRAY map. Returns the total number of
// connections dropped in-kernel since agent start (or last reset).
func ReadNetBlockDropCount(countersMap bpfMap) (uint64, error) {
	if countersMap == nil {
		return 0, fmt.Errorf("bpf: net_block_counters map is nil")
	}
	key := uint32(0)
	var perCPU []uint64
	if err := countersMap.Lookup(key, &perCPU); err != nil {
		return 0, fmt.Errorf("bpf: read net_block_counters: %w", err)
	}
	var total uint64
	for _, v := range perCPU {
		total += v
	}
	return total, nil
}

// parseSubnetKeys parses a CIDR notation string and returns the corresponding
// IPv4LPMKey or IPv6LPMKey (the other is nil). Returns an error for invalid
// or unsupported CIDR formats.
func parseSubnetKeys(cidr string) (*IPv4LPMKey, *IPv6LPMKey, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	ones, bits := ipnet.Mask.Size()
	switch bits {
	case 32:
		if ones < 0 || ones > 32 {
			return nil, nil, fmt.Errorf("CIDR %q: prefix length %d out of range for IPv4", cidr, ones)
		}
		ip4 := ipnet.IP.To4()
		if ip4 == nil {
			return nil, nil, fmt.Errorf("CIDR %q: failed to convert to IPv4", cidr)
		}
		k := &IPv4LPMKey{PrefixLen: uint32(ones)} //nolint:gosec
		copy(k.Addr[:], ip4)
		return k, nil, nil
	case 128:
		if ones < 0 || ones > 128 {
			return nil, nil, fmt.Errorf("CIDR %q: prefix length %d out of range for IPv6", cidr, ones)
		}
		ip6 := ipnet.IP.To16()
		if ip6 == nil {
			return nil, nil, fmt.Errorf("CIDR %q: failed to convert to IPv6", cidr)
		}
		k := &IPv6LPMKey{PrefixLen: uint32(ones)} //nolint:gosec
		copy(k.Addr[:], ip6)
		return nil, k, nil
	default:
		return nil, nil, fmt.Errorf("CIDR %q: unsupported address family (bits=%d)", cidr, bits)
	}
}

// removeStaleIPv4 deletes old IPv4 LPM keys that are absent from newKeys.
func (n *NetworkBlocklistController) removeStaleIPv4(old, newKeys []IPv4LPMKey) error {
	newSet := make(map[IPv4LPMKey]struct{}, len(newKeys))
	for _, k := range newKeys {
		newSet[k] = struct{}{}
	}
	for _, k := range old {
		if _, keep := newSet[k]; !keep {
			if n.ipv4Map == nil {
				return fmt.Errorf("bpf: net_block_ipv4 remove stale %v/%d: map is nil", k.Addr, k.PrefixLen)
			}
			if err := n.ipv4Map.Delete(k); err != nil && !isNotFound(err) {
				return fmt.Errorf("bpf: net_block_ipv4 remove stale %v/%d: %w", k.Addr, k.PrefixLen, err)
			}
		}
	}
	return nil
}

// removeStaleIPv6 deletes old IPv6 LPM keys that are absent from newKeys.
func (n *NetworkBlocklistController) removeStaleIPv6(old, newKeys []IPv6LPMKey) error {
	type key6 struct {
		p uint32
		a [16]byte
	}
	newSet := make(map[key6]struct{}, len(newKeys))
	for _, k := range newKeys {
		newSet[key6{k.PrefixLen, k.Addr}] = struct{}{}
	}
	for _, k := range old {
		if _, keep := newSet[key6{k.PrefixLen, k.Addr}]; !keep {
			if n.ipv6Map == nil {
				return fmt.Errorf("bpf: net_block_ipv6 remove stale %v/%d: map is nil", k.Addr, k.PrefixLen)
			}
			if err := n.ipv6Map.Delete(k); err != nil && !isNotFound(err) {
				return fmt.Errorf("bpf: net_block_ipv6 remove stale %v/%d: %w", k.Addr, k.PrefixLen, err)
			}
		}
	}
	return nil
}

// removeStaleports deletes old port entries that are absent from newPorts.
func (n *NetworkBlocklistController) removeStaleports(old, newPorts []uint16) error {
	newSet := make(map[uint16]struct{}, len(newPorts))
	for _, p := range newPorts {
		newSet[p] = struct{}{}
	}
	for _, p := range old {
		if _, keep := newSet[p]; !keep {
			if n.portsMap == nil {
				return fmt.Errorf("bpf: net_block_ports remove stale port %d: map is nil", p)
			}
			if err := n.portsMap.Delete(p); err != nil && !isNotFound(err) {
				return fmt.Errorf("bpf: net_block_ports remove stale port %d: %w", p, err)
			}
		}
	}
	return nil
}

// isNotFound reports whether err indicates a BPF map key-not-found condition.
func isNotFound(err error) bool {
	return err != nil && (errors.Is(err, ebpf.ErrKeyNotExist) ||
		err.Error() == "key does not exist")
}

// IPv4LPMKeyBytes serialises an IPv4LPMKey to a byte slice in the same layout
// that the cilium/ebpf library uses when writing to a BPF map (little-endian
// host byte order for the scalar PrefixLen field; raw bytes for Addr).
// Useful for unit tests that compare serialised keys.
func IPv4LPMKeyBytes(k IPv4LPMKey) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint32(b[0:4], k.PrefixLen)
	copy(b[4:8], k.Addr[:])
	return b
}

// IPv6LPMKeyBytes serialises an IPv6LPMKey the same way.
func IPv6LPMKeyBytes(k IPv6LPMKey) []byte {
	b := make([]byte, 20)
	binary.LittleEndian.PutUint32(b[0:4], k.PrefixLen)
	copy(b[4:20], k.Addr[:])
	return b
}
