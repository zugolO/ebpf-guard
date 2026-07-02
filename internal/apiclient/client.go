// Package apiclient is a small REST client for an ebpf-guard agent's /api/v1
// HTTP API. It is shared by every in-tree consumer that fans out to a running
// agent (the attack-verify runner and the fleet-mode TUI) so the API contract
// — path, auth header, the duration-style "since" filter, and the bare JSON
// array response — lives in exactly one place instead of being copy-pasted.
package apiclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// maxAlertBody bounds how much of a response body is read to avoid unbounded
// memory use if an agent returns a pathologically large payload.
const maxAlertBody = 8 << 20 // 8 MB

// Client talks to a single agent's /api/v1 API.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// New returns a Client for the given agent base URL (e.g. "http://node-a:9090")
// with a default 10s request timeout.
func New(baseURL, token string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		http:    &http.Client{Timeout: 10 * time.Second},
	}
}

// NewWithClient is like New but uses the caller-supplied *http.Client (for
// custom timeouts, transports, or mTLS). A nil hc falls back to the default.
func NewWithClient(baseURL, token string, hc *http.Client) *Client {
	c := New(baseURL, token)
	if hc != nil {
		c.http = hc
	}
	return c
}

// BaseURL returns the normalized agent base URL (trailing slash trimmed).
func (c *Client) BaseURL() string { return c.baseURL }

// AlertQuery holds the filters for FetchAlerts. Zero-valued fields are omitted.
type AlertQuery struct {
	// Since is a relative window: the agent returns alerts newer than now-Since.
	Since time.Duration
	// Limit caps the number of alerts returned (newest first).
	Limit int
	// Offset skips the newest Offset alerts, enabling pagination past Limit.
	Offset int
}

// FetchAlerts GETs /api/v1/alerts with the given filters and decodes the bare
// JSON array of alerts the agent returns.
func (c *Client) FetchAlerts(ctx context.Context, q AlertQuery) ([]types.Alert, error) {
	params := url.Values{}
	if q.Since > 0 {
		params.Set("since", q.Since.String())
	}
	if q.Limit > 0 {
		params.Set("limit", strconv.Itoa(q.Limit))
	}
	if q.Offset > 0 {
		params.Set("offset", strconv.Itoa(q.Offset))
	}

	endpoint := c.baseURL + "/api/v1/alerts"
	if encoded := params.Encode(); encoded != "" {
		endpoint += "?" + encoded
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("alerts API returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAlertBody))
	if err != nil {
		return nil, err
	}
	var alerts []types.Alert
	if err := json.Unmarshal(body, &alerts); err != nil {
		return nil, fmt.Errorf("decode alerts: %w", err)
	}
	return alerts, nil
}
