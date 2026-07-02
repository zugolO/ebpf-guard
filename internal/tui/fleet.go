//go:build tui

package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// FleetConfig configures client-side fan-out polling of multiple agent REST
// APIs, merging their alert streams into a single Feed. This is the "client-
// side fan-out" design for fleet-wide observability: no central aggregation
// service is required, each agent is queried directly over its existing
// /api/v1 HTTP API.
type FleetConfig struct {
	// Endpoints are agent base URLs, e.g. "http://node-a:9090".
	Endpoints []string
	// Token is the bearer token sent to every endpoint (agents are expected
	// to share credentials in fleet mode; per-agent tokens are not supported).
	Token string
	// PollInterval controls how often each agent is polled for new alerts
	// and health. Defaults to 3s when zero.
	PollInterval time.Duration
}

// AgentStatus reports the last known health of one fleet member.
type AgentStatus struct {
	Endpoint   string
	NodeName   string // best-effort: derived from endpoint host until an alert reveals the real node
	Healthy    bool
	LastSeen   time.Time
	LastError  string
	AlertCount int64
}

// fleetSeenLimit bounds the per-agent dedup set so long-running sessions
// don't grow memory unboundedly; oldest entries are dropped once exceeded.
const fleetSeenLimit = 5000

// agentPoller polls a single agent's REST API on an interval and forwards
// newly observed alerts into the shared Feed.
type agentPoller struct {
	endpoint string
	label    string // short host:port label used as a NodeName fallback
	client   *http.Client
	token    string

	mu   sync.Mutex
	seen map[string]struct{}
	// seenOrder preserves insertion order for eviction once fleetSeenLimit is hit.
	seenOrder []string
}

func newAgentPoller(endpoint, token string) *agentPoller {
	label := endpoint
	if u, err := url.Parse(endpoint); err == nil && u.Host != "" {
		label = u.Host
	}
	return &agentPoller{
		endpoint: strings.TrimRight(endpoint, "/"),
		label:    label,
		token:    token,
		client:   &http.Client{Timeout: 10 * time.Second},
		seen:     make(map[string]struct{}),
	}
}

func (p *agentPoller) markSeen(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.seen[id]; ok {
		return false
	}
	p.seen[id] = struct{}{}
	p.seenOrder = append(p.seenOrder, id)
	if len(p.seenOrder) > fleetSeenLimit {
		drop := p.seenOrder[0]
		p.seenOrder = p.seenOrder[1:]
		delete(p.seen, drop)
	}
	return true
}

func (p *agentPoller) seenCount() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return int64(len(p.seenOrder))
}

func (p *agentPoller) doGet(ctx context.Context, path string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.endpoint+path, nil)
	if err != nil {
		return err
	}
	if p.token != "" {
		req.Header.Set("Authorization", "Bearer "+p.token)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// poll fetches recent alerts and health from the agent once, pushing new
// alerts into feed and updating the shared status map.
func (p *agentPoller) poll(ctx context.Context, feed *Feed, since string) {
	status := AgentStatus{Endpoint: p.endpoint, NodeName: p.label, LastSeen: time.Now()}

	var alerts []types.Alert
	err := p.doGet(ctx, "/api/v1/alerts?since="+since+"&limit=200", &alerts)
	if err != nil {
		status.Healthy = false
		status.LastError = err.Error()
		feed.SetAgentStatus(status)
		return
	}

	status.Healthy = true
	for _, a := range alerts {
		if !p.markSeen(a.ID) {
			continue
		}
		// Attribute the alert to a node even when the remote agent has no
		// Kubernetes enrichment (bare-metal/VM fleets): fall back to the
		// endpoint's host:port so the merged view always has a node column.
		if a.Enrichment.NodeName == "" {
			a.Enrichment.NodeName = p.label
			status.NodeName = p.label
		} else {
			status.NodeName = a.Enrichment.NodeName
		}
		feed.PushAlert(a)
	}
	status.AlertCount = p.seenCount()
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
	// since must comfortably cover one poll interval plus scheduling jitter
	// so no alert window is missed between polls; duplicates are filtered
	// client-side via agentPoller.seen.
	since := (interval*3 + time.Second).String()

	for _, ep := range cfg.Endpoints {
		poller := newAgentPoller(ep, cfg.Token)
		go func(p *agentPoller) {
			// Poll immediately so the dashboard isn't empty for a full interval.
			p.poll(ctx, feed, since)
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					p.poll(ctx, feed, since)
				}
			}
		}(poller)
	}

	return Run(ctx, feed)
}
