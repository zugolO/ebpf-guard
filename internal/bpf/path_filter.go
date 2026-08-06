package bpf

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// PathFilterPrefixLen is the fixed key width of path_filter_map, matching
// PATH_FILTER_PREFIX_LEN in bpf/common.h. Prefixes longer than this are
// truncated when loaded — a truncated prefix still matches everything the
// full prefix would have matched, plus a few unintended siblings, which is
// the safe direction for a denylist (see P1-18b risk note: denylist errors
// are cheaper than allowlist errors).
const PathFilterPrefixLen = 128

// PathLPMKey is the BPF key for path_filter_map (BPF_MAP_TYPE_LPM_TRIE).
// Layout must match C struct path_filter_key in bpf/common.h exactly:
// a little-endian uint32 prefix length in BITS, followed by the raw path
// bytes NUL-padded to PathFilterPrefixLen.
type PathLPMKey struct {
	PrefixLen uint32
	Path      [PathFilterPrefixLen]byte
}

// PathFilterController manages the in-kernel path-prefix denylist
// (path_filter_map) and its drop counter (path_filter_drop_counters).
//
// Unlike KernelFilterController's comm/syscall filters, this is deliberately
// its own type: it is only consulted by fileaccess.bpf.c, and per P1-18b it
// carries materially higher risk (a bad prefix silently blinds a whole class
// of file events), so its entries are tracked separately for hot-reload
// rather than folded into the general kernel filter surface.
type PathFilterController struct {
	pathMap  bpfMap
	countMap bpfMap

	// configPrefixes tracks prefixes inserted by the last SetDenylist call,
	// so a subsequent call can remove stale entries (hot-reload support).
	configPrefixes []string
}

// NewPathFilterController creates a controller backed by path_filter_map.
// countersMap may be nil — ReadPathFilterDropCount then returns 0 instead of
// erroring, since the map is diagnostic and its absence should not block
// filtering itself from working.
//
// Parameters are typed *ebpf.Map (not the internal bpfMap interface) so the
// nil check below is meaningful: a nil *ebpf.Map assigned to an interface
// field produces a non-nil interface holding a nil pointer, which would
// silently defeat "pathMap == nil". Callers needing to inject a fake for
// tests construct the struct literal directly, as network_blocklist_test.go
// does for NetworkBlocklistController.
func NewPathFilterController(pathMap, countersMap *ebpf.Map) (*PathFilterController, error) {
	if pathMap == nil {
		return nil, fmt.Errorf("bpf: path_filter_map is nil")
	}
	c := &PathFilterController{pathMap: pathMap}
	if countersMap != nil {
		c.countMap = countersMap
	}
	return c, nil
}

// pathLPMKey builds the LPM key for a prefix string: prefixlen in bits
// (always a whole number of bytes, i.e. a multiple of 8) and the prefix
// bytes copied into a zero-padded fixed buffer. Prefixes longer than
// PathFilterPrefixLen are truncated to fit — see the PathFilterPrefixLen
// doc comment for why that is the safe failure direction.
func pathLPMKey(prefix string) PathLPMKey {
	if len(prefix) > PathFilterPrefixLen {
		prefix = prefix[:PathFilterPrefixLen]
	}
	k := PathLPMKey{PrefixLen: uint32(len(prefix)) * 8} //nolint:gosec
	copy(k.Path[:], prefix)
	return k
}

// SetDenylist atomically replaces the path-prefix denylist with prefixes.
// Entries present in a previous call but absent from this one are removed,
// so this is safe to call on every hot-reload (mirrors
// NetworkBlocklistController.SetBlocklist).
//
// An empty prefix ("") is rejected: it would match every path (prefixlen 0),
// silently blinding the fileaccess collector entirely — exactly the failure
// mode P1-18b's risk note warns about.
func (p *PathFilterController) SetDenylist(prefixes []string) error {
	for _, prefix := range prefixes {
		if prefix == "" {
			return fmt.Errorf("bpf: path filter: empty prefix would deny all paths, refusing")
		}
	}

	newSet := make(map[string]struct{}, len(prefixes))
	for _, p := range prefixes {
		newSet[p] = struct{}{}
	}

	// Remove stale entries from the previous config.
	for _, old := range p.configPrefixes {
		if _, keep := newSet[old]; !keep {
			if err := p.pathMap.Delete(pathLPMKey(old)); err != nil && !isNotFound(err) {
				return fmt.Errorf("bpf: path_filter_map remove stale %q: %w", old, err)
			}
		}
	}

	// Insert new entries.
	val := uint8(1)
	for _, prefix := range prefixes {
		if err := p.pathMap.Update(pathLPMKey(prefix), val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("bpf: path_filter_map update %q: %w", prefix, err)
		}
	}

	p.configPrefixes = append([]string(nil), prefixes...)
	return nil
}

// AddPrefix inserts a single path prefix into the denylist. Not tracked for
// hot-reload (use SetDenylist for that).
func (p *PathFilterController) AddPrefix(prefix string) error {
	if prefix == "" {
		return fmt.Errorf("bpf: path filter: empty prefix would deny all paths, refusing")
	}
	if err := p.pathMap.Update(pathLPMKey(prefix), uint8(1), ebpf.UpdateAny); err != nil {
		return fmt.Errorf("bpf: path_filter_map add %q: %w", prefix, err)
	}
	return nil
}

// RemovePrefix removes a single path prefix from the denylist.
func (p *PathFilterController) RemovePrefix(prefix string) error {
	if err := p.pathMap.Delete(pathLPMKey(prefix)); err != nil && !isNotFound(err) {
		return fmt.Errorf("bpf: path_filter_map remove %q: %w", prefix, err)
	}
	return nil
}

// ReadPathFilterDropCount reads and sums the per-CPU drop counter from
// path_filter_drop_counters. Returns 0, nil if no counters map was supplied
// (diagnostic-only, absence must not be treated as an error by callers that
// just want a best-effort metric).
func (p *PathFilterController) ReadPathFilterDropCount() (uint64, error) {
	if p.countMap == nil {
		return 0, nil
	}
	key := uint32(0)
	var perCPU []uint64
	if err := p.countMap.Lookup(key, &perCPU); err != nil {
		return 0, fmt.Errorf("bpf: read path_filter_drop_counters: %w", err)
	}
	var total uint64
	for _, v := range perCPU {
		total += v
	}
	return total, nil
}
