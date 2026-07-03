//go:build tui

package tui

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/zugolO/ebpf-guard/internal/apiclient"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// AgentStatus reports the last known health of one fleet member.
type AgentStatus struct {
	Endpoint   string
	NodeName   string // best-effort: derived from endpoint host until an alert reveals the real node
	Healthy    bool
	LastSeen   time.Time // time of the last *successful* poll (zero until first success)
	LastError  string
	AlertCount int64
}

const (
	// fleetSeenLimit bounds the per-agent dedup set so long-running sessions
	// don't grow memory unboundedly; oldest entries are evicted once exceeded.
	fleetSeenLimit = 5000
	// fleetPageLimit is how many alerts are requested per API page.
	fleetPageLimit = 200
	// fleetMaxPages caps pagination per poll so a huge backlog can't make one
	// poll unbounded; fleetMaxPages*fleetPageLimit alerts are fetched at most.
	fleetMaxPages = 10
	// fleetMaxWindow caps the "since" window so a long outage doesn't ask an
	// agent for an enormous history in a single request.
	fleetMaxWindow = time.Hour
)

// agentPoller polls a single agent's REST API on an interval and forwards
// newly observed alerts into the shared Feed. All of its mutable state is
// touched only from its own polling goroutine, so it needs no locking.
type agentPoller struct {
	endpoint string
	label    string // short host:port label used as a NodeName fallback
	client   *apiclient.Client

	// dedup state (single-goroutine access).
	seen    map[string]struct{}
	ring    []string // FIFO eviction ring; grows to fleetSeenLimit then wraps
	ringIdx int

	discoveredNode string    // real node name once an alert reveals it; persisted across polls
	totalSeen      int64     // monotonic count of distinct alerts ever seen (never plateaus)
	lastSuccess    time.Time // time of the last successful poll, for dynamic windowing
}

func newAgentPoller(endpoint, token string) *agentPoller {
	label := endpoint
	if u, err := url.Parse(endpoint); err == nil && u.Host != "" {
		label = u.Host
	}
	client := apiclient.New(endpoint, token)
	return &agentPoller{
		endpoint: client.BaseURL(),
		label:    label,
		client:   client,
		seen:     make(map[string]struct{}),
		ring:     make([]string, 0, fleetSeenLimit),
	}
}

// dedupKey returns a stable identity for an alert. It prefers the server-assigned
// ID but falls back to a content hash so that alerts with an empty ID are not all
// collapsed into a single entry (and are still deduplicated across polls).
func dedupKey(a types.Alert) string {
	if a.ID != "" {
		return a.ID
	}
	return fmt.Sprintf("%s|%d|%d|%s", a.RuleID, a.PID, a.Timestamp.UnixNano(), a.Comm)
}

// markSeen records key as seen and returns true if it was new. Eviction is O(1)
// via a fixed-size FIFO ring, so the backing array never grows past
// fleetSeenLimit and old entries are not retained.
func (p *agentPoller) markSeen(key string) bool {
	if _, ok := p.seen[key]; ok {
		return false
	}
	if len(p.ring) < fleetSeenLimit {
		p.ring = append(p.ring, key)
	} else {
		delete(p.seen, p.ring[p.ringIdx])
		p.ring[p.ringIdx] = key
		p.ringIdx = (p.ringIdx + 1) % fleetSeenLimit
	}
	p.seen[key] = struct{}{}
	p.totalSeen++
	return true
}

// window returns how far back to ask the agent for alerts. On the steady state
// it is baseWindow; after a gap (a failed or delayed poll) it stretches to cover
// the whole time since the last successful poll so no alert window is skipped.
func (p *agentPoller) window(baseWindow time.Duration) time.Duration {
	if p.lastSuccess.IsZero() {
		return baseWindow
	}
	w := time.Since(p.lastSuccess) + baseWindow
	if w > fleetMaxWindow {
		w = fleetMaxWindow
	}
	return w
}

// poll fetches recent alerts and health from the agent once, pushing new alerts
// into feed and updating the shared status map. It paginates so that bursts
// larger than one page are not silently truncated, and it preserves the agent's
// discovered node name and monotonic alert count even when a poll fails.
func (p *agentPoller) poll(ctx context.Context, feed *Feed, baseWindow time.Duration) {
	win := p.window(baseWindow)

	var fetchErr error
	for page := 0; page < fleetMaxPages; page++ {
		alerts, err := p.client.FetchAlerts(ctx, apiclient.AlertQuery{
			Since:  win,
			Limit:  fleetPageLimit,
			Offset: page * fleetPageLimit,
		})
		if err != nil {
			fetchErr = err
			break
		}

		pageNew := 0
		for _, a := range alerts {
			if !p.markSeen(dedupKey(a)) {
				continue
			}
			pageNew++
			// Attribute the alert to a node even when the remote agent has no
			// Kubernetes enrichment (bare-metal/VM fleets): fall back to the
			// endpoint's host:port so the merged view always has a node column.
			if a.Enrichment.NodeName == "" {
				a.Enrichment.NodeName = p.label
			} else {
				p.discoveredNode = a.Enrichment.NodeName
			}
			feed.PushAlert(a)
		}

		// Stop once the agent returns a short page (no more in-window alerts) or
		// a page that is entirely already-seen (we've caught up to prior polls).
		if len(alerts) < fleetPageLimit || pageNew == 0 {
			break
		}
	}

	node := p.label
	if p.discoveredNode != "" {
		node = p.discoveredNode
	}
	status := AgentStatus{
		Endpoint:   p.endpoint,
		NodeName:   node,
		AlertCount: p.totalSeen,
		LastSeen:   p.lastSuccess,
	}
	if fetchErr != nil {
		status.Healthy = false
		status.LastError = fetchErr.Error()
	} else {
		status.Healthy = true
		p.lastSuccess = time.Now()
		status.LastSeen = p.lastSuccess
	}
	feed.SetAgentStatus(status)
}

// RunFleet starts one polling goroutine per configured endpoint and blocks
// running the bubbletea dashboard until the user quits or ctx is canceled.
func RunFleet(ctx context.Context, feed *Feed, cfg FleetConfig) error {
	if len(cfg.Endpoints) == 0 {
		return fmt.Errorf("fleet: no endpoints configured")
	}
	interval := cfg.PollInterval
	if interval <= 0 {
		interval = 3 * time.Second
	}
	// baseWindow must comfortably cover one poll interval plus scheduling jitter
	// so no alert window is missed between consecutive polls; the poller widens
	// it automatically after any gap, and duplicates are filtered client-side.
	baseWindow := interval*3 + time.Second

	for _, ep := range cfg.Endpoints {
		poller := newAgentPoller(ep, cfg.Token)
		go func(p *agentPoller) {
			// Poll immediately so the dashboard isn't empty for a full interval.
			p.poll(ctx, feed, baseWindow)
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					p.poll(ctx, feed, baseWindow)
				}
			}
		}(poller)
	}

	return Run(ctx, feed)
}
