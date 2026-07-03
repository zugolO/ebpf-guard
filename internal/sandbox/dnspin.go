package sandbox

import (
	"context"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zugolO/ebpf-guard/internal/config"
)

// DNS-pinned egress (issue #255, item 6).
//
// A sandbox profile's allowed_egress_cidrs are static: they cannot express
// "let the agent reach github.com" when that name resolves to a rotating,
// CDN-fronted address set. The DNSPinner closes the gap: it periodically
// resolves each profile's allowed_domains and programs the current A/AAAA
// records as single-host (/32, /128) egress allow entries scoped to that
// profile, pruning addresses that have dropped out of DNS.
//
// This is deny-by-default preserved: only names the operator listed are
// resolved, and only their resolved addresses are opened — never a wildcard.
// It is a convenience/allow-list layer, not a security boundary against an
// attacker who controls DNS; see docs/ai-agent-sandbox.md for the caveats.

// egressProgrammer is the subset of *Manager the pinner drives. Declared as an
// interface so the refresh logic is unit-testable without a kernel.
type egressProgrammer interface {
	SetDomainEgress(profile string, ips []net.IP) error
}

// Resolver resolves a hostname to IPs. *net.Resolver satisfies it; tests supply
// a deterministic fake.
type Resolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

// profileDomains pairs a profile name with the domains it allows.
type profileDomains struct {
	profile string
	domains []string
}

// DNSPinner resolves allowed_domains and keeps each profile's egress allow-list
// in sync with their current records.
type DNSPinner struct {
	prog     egressProgrammer
	resolver Resolver
	interval time.Duration
	targets  []profileDomains
	logger   *slog.Logger

	mu sync.Mutex
	// lastIPs caches the most recent successful resolution per domain so a
	// transient lookup failure reuses the last-known addresses instead of
	// tearing a working allow-list down (fail-safe).
	lastIPs map[string][]net.IP
}

// NewDNSPinner builds a pinner from the ai_sandbox config. It returns (nil,
// false) when no profile lists any domain or the refresh interval is disabled
// (0), so callers can skip starting a goroutine that would have nothing to do.
func NewDNSPinner(cfg config.AISandboxConfig, prog egressProgrammer, resolver Resolver, logger *slog.Logger) (*DNSPinner, bool) {
	if logger == nil {
		logger = slog.Default()
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	if cfg.DNSRefreshInterval <= 0 {
		return nil, false
	}
	var targets []profileDomains
	for _, p := range cfg.Profiles {
		domains := normalizeDomains(p.AllowedDomains)
		if len(domains) == 0 {
			continue
		}
		targets = append(targets, profileDomains{profile: p.Name, domains: domains})
	}
	if len(targets) == 0 {
		return nil, false
	}
	return &DNSPinner{
		prog:     prog,
		resolver: resolver,
		interval: cfg.DNSRefreshInterval,
		targets:  targets,
		logger:   logger.With("component", "ai_sandbox_dnspin"),
		lastIPs:  make(map[string][]net.IP),
	}, true
}

// normalizeDomains lowercases, trims, strips a leading dot, and dedupes the
// configured domain list. Empty entries are dropped.
func normalizeDomains(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	var out []string
	for _, d := range in {
		d = strings.ToLower(strings.TrimSpace(d))
		d = strings.TrimPrefix(d, ".")
		if d == "" {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// Run programs the initial set immediately, then refreshes every interval until
// ctx is cancelled. Blocking; run it in its own goroutine.
func (d *DNSPinner) Run(ctx context.Context) {
	d.RefreshOnce(ctx)
	t := time.NewTicker(d.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.RefreshOnce(ctx)
		}
	}
}

// RefreshOnce resolves every target profile's domains and reprograms its egress
// allow-list. A resolution failure for one domain is logged and skipped: the
// previously pinned addresses for that profile stay in place (fail-safe — a
// transient DNS blip must not tear down a working allow-list), and other
// domains/profiles still update. Returns the total number of addresses pinned.
func (d *DNSPinner) RefreshOnce(ctx context.Context) int {
	total := 0
	for _, t := range d.targets {
		ips := d.resolveAll(ctx, t)
		if err := d.prog.SetDomainEgress(t.profile, ips); err != nil {
			d.logger.Warn("ai_sandbox: program DNS-pinned egress", "profile", t.profile, "error", err)
			continue
		}
		total += len(ips)
	}
	return total
}

// resolveAll resolves all of a profile's domains into a deduped IP slice.
// Domains are cached per name (keyed by "profile\x00domain"): a successful
// lookup refreshes the cache, a failed one reuses the last-known addresses so a
// transient DNS blip does not prune a working allow-list.
func (d *DNSPinner) resolveAll(ctx context.Context, t profileDomains) []net.IP {
	seen := make(map[string]struct{})
	var ips []net.IP
	add := func(list []net.IP) {
		for _, ip := range list {
			k := ip.String()
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			ips = append(ips, ip)
		}
	}
	for _, name := range t.domains {
		cacheKey := t.profile + "\x00" + name
		got, err := d.resolver.LookupIP(ctx, "ip", name)
		if err != nil {
			d.mu.Lock()
			cached := d.lastIPs[cacheKey]
			d.mu.Unlock()
			d.logger.Warn("ai_sandbox: resolve allowed domain failed; reusing last-known pins",
				"profile", t.profile, "domain", name, "cached", len(cached), "error", err)
			add(cached)
			continue
		}
		d.mu.Lock()
		d.lastIPs[cacheKey] = got
		d.mu.Unlock()
		add(got)
	}
	return ips
}
