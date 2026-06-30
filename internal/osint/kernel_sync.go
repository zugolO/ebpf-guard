package osint

import (
	"fmt"
	"log/slog"
	"net"
	"sort"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

const defaultMaxKernelEntries = 100_000

// BlocklistUpdater is the interface required by KernelSyncer for loading IoCs
// into kernel BPF maps. Satisfied by *bpf.NetworkBlocklistController (wrapped
// in main.go to avoid an import cycle).
type BlocklistUpdater interface {
	// AddSubnet inserts a CIDR subnet (e.g. "1.2.3.4/32" or "10.0.0.0/8")
	// into the kernel blocklist map.
	AddSubnet(cidr string) error
	// RemoveSubnet deletes a CIDR subnet from the kernel blocklist map.
	RemoveSubnet(cidr string) error
}

// KernelSyncer loads IP/CIDR IoCs from OSINT feeds directly into kernel BPF
// blocklist maps. Domain and URL IoCs continue through the YAML/rule path.
//
// It tracks which subnets it has inserted so that stale entries are removed
// when the feed is refreshed.
type KernelSyncer struct {
	mu          sync.Mutex
	updater     BlocklistUpdater
	maxEntries  int
	activeCIDRs map[string]struct{} // CIDRs currently in the kernel map

	syncTotal     prometheus.Counter
	syncErrors    prometheus.Counter
	activeEntries prometheus.Gauge
	lastSyncTime  prometheus.Gauge
}

// KernelSyncerConfig holds configuration for the KernelSyncer.
type KernelSyncerConfig struct {
	// Updater is the kernel map writer. May be nil for a no-op (graceful
	// degradation when kernel maps are not available).
	Updater BlocklistUpdater
	// MaxEntries caps the total number of CIDRs loaded into kernel maps.
	// 0 means use the default (100 000). The highest-scored IoCs are
	// preferred when the feed exceeds the cap.
	MaxEntries int
	// Registerer is the Prometheus registry; defaults to the default registry.
	Registerer prometheus.Registerer
}

// NewKernelSyncer creates a KernelSyncer with the given config. If
// cfg.Updater is nil the syncer is a no-op (graceful degradation).
func NewKernelSyncer(cfg KernelSyncerConfig) (*KernelSyncer, error) {
	max := cfg.MaxEntries
	if max <= 0 {
		max = defaultMaxKernelEntries
	}

	reg := cfg.Registerer
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}

	syncTotal := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "osint_kernel_sync_total",
		Help: "Total number of OSINT kernel map sync operations.",
	})
	syncErrors := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "osint_kernel_sync_errors_total",
		Help: "Total number of errors during OSINT kernel map sync.",
	})
	activeEntries := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "osint_kernel_active_entries",
		Help: "Current number of IoC entries loaded into kernel blocklist maps.",
	})
	lastSyncTime := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "osint_kernel_last_sync_timestamp_seconds",
		Help: "Unix timestamp of the last successful OSINT kernel map sync.",
	})

	for _, c := range []prometheus.Collector{syncTotal, syncErrors, activeEntries, lastSyncTime} {
		if err := reg.Register(c); err != nil {
			// Already registered is fine (e.g. multiple test runs).
			if _, ok := err.(prometheus.AlreadyRegisteredError); !ok {
				return nil, fmt.Errorf("osint kernel_sync: register metric: %w", err)
			}
		}
	}

	return &KernelSyncer{
		updater:       cfg.Updater,
		maxEntries:    max,
		activeCIDRs:   make(map[string]struct{}),
		syncTotal:     syncTotal,
		syncErrors:    syncErrors,
		activeEntries: activeEntries,
		lastSyncTime:  lastSyncTime,
	}, nil
}

// SyncToKernel translates IP and CIDR IoCs from results into kernel BPF map
// entries. Domain and URL IoCs are skipped (they go through the YAML rule
// path). Returns the number of entries now active in the kernel map.
//
// The call is idempotent: it computes the desired set from all results, caps
// it to MaxEntries (highest ThreatScore first), removes stale entries from
// the previous sync, and inserts new ones.
func (ks *KernelSyncer) SyncToKernel(results []FeedResult) (int, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if ks.updater == nil {
		return 0, nil
	}

	desired, err := ks.buildDesiredSet(results)
	if err != nil {
		ks.syncErrors.Inc()
		return len(ks.activeCIDRs), fmt.Errorf("osint kernel_sync: build desired set: %w", err)
	}

	ks.syncTotal.Inc()
	var syncErr error

	// Remove stale entries (present in active but not in desired).
	for cidr := range ks.activeCIDRs {
		if _, keep := desired[cidr]; !keep {
			if err := ks.updater.RemoveSubnet(cidr); err != nil {
				slog.Warn("osint: kernel sync: remove stale entry",
					slog.String("cidr", cidr), slog.Any("error", err))
				syncErr = err
				ks.syncErrors.Inc()
				// Keep going — partial sync is better than no sync.
			} else {
				delete(ks.activeCIDRs, cidr)
			}
		}
	}

	// Add new entries (present in desired but not yet active).
	for cidr := range desired {
		if _, exists := ks.activeCIDRs[cidr]; !exists {
			if err := ks.updater.AddSubnet(cidr); err != nil {
				slog.Warn("osint: kernel sync: add entry",
					slog.String("cidr", cidr), slog.Any("error", err))
				syncErr = err
				ks.syncErrors.Inc()
			} else {
				ks.activeCIDRs[cidr] = struct{}{}
			}
		}
	}

	n := len(ks.activeCIDRs)
	ks.activeEntries.Set(float64(n))
	if syncErr == nil {
		ks.lastSyncTime.SetToCurrentTime()
	}

	return n, syncErr
}

// ActiveCount returns the number of CIDRs currently in the kernel map.
func (ks *KernelSyncer) ActiveCount() int {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	return len(ks.activeCIDRs)
}

// buildDesiredSet collects all unique IP/CIDR IoCs from results, sorts by
// ThreatScore descending, and returns up to ks.maxEntries as a CIDR set.
// IPs are converted to host-route CIDRs (/32 or /128).
func (ks *KernelSyncer) buildDesiredSet(results []FeedResult) (map[string]struct{}, error) {
	type scored struct {
		cidr  string
		score float64
	}
	seen := make(map[string]float64)

	for _, r := range results {
		for _, ioc := range r.IoCs {
			var cidr string
			switch ioc.Type {
			case IoCTypeCIDR:
				// Normalise: parse and re-format to canonical form.
				_, ipNet, err := net.ParseCIDR(ioc.Value)
				if err != nil {
					slog.Debug("osint: kernel_sync: skip invalid CIDR",
						slog.String("value", ioc.Value), slog.Any("error", err))
					continue
				}
				cidr = ipNet.String()
			case IoCTypeIP:
				ip := net.ParseIP(ioc.Value)
				if ip == nil {
					slog.Debug("osint: kernel_sync: skip invalid IP",
						slog.String("value", ioc.Value))
					continue
				}
				if ip.To4() != nil {
					cidr = ip.String() + "/32"
				} else {
					cidr = ip.String() + "/128"
				}
			case IoCTypeDomain, IoCTypeURL:
				continue // domain / URL handled by YAML rules
			}

			// Keep the highest threat score across duplicate IoCs.
			if prev, ok := seen[cidr]; !ok || ioc.ThreatScore > prev {
				seen[cidr] = ioc.ThreatScore
			}
		}
	}

	// Sort by score descending for deterministic capping.
	candidates := make([]scored, 0, len(seen))
	for cidr, score := range seen {
		candidates = append(candidates, scored{cidr, score})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		return candidates[i].cidr < candidates[j].cidr
	})

	if len(candidates) > ks.maxEntries {
		candidates = candidates[:ks.maxEntries]
	}

	desired := make(map[string]struct{}, len(candidates))
	for _, c := range candidates {
		desired[c.cidr] = struct{}{}
	}
	return desired, nil
}
