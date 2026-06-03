package osint

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

const vtBaseURL = "https://www.virustotal.com/api/v3"

// VirusTotalClient fetches IoCs from VirusTotal threat intelligence feeds.
// Enterprise feeds require a VT Intelligence subscription.
// The free tier supports only single-object lookups; set EnterpriseFeeds=false
// for community-only mode (no automated bulk feed download).
type VirusTotalClient struct {
	apiKey          string
	enterpriseFeeds bool
	httpClient      *http.Client
}

// NewVirusTotalClient creates a VirusTotal API v3 client.
func NewVirusTotalClient(apiKey string, enterpriseFeeds bool) *VirusTotalClient {
	return &VirusTotalClient{
		apiKey:          apiKey,
		enterpriseFeeds: enterpriseFeeds,
		httpClient:      &http.Client{Timeout: 120 * time.Second},
	}
}

func (c *VirusTotalClient) Source() Source { return SourceVirusTotal }

// Fetch downloads IoCs from VirusTotal feeds.
// Enterprise mode: downloads hourly IP and domain feed files.
// Community mode: returns an empty result (bulk feeds require a paid tier).
func (c *VirusTotalClient) Fetch(since time.Time) (FeedResult, error) {
	now := time.Now().UTC()
	if !c.enterpriseFeeds {
		return FeedResult{Source: SourceVirusTotal, FetchedAt: now}, nil
	}
	return c.fetchEnterprise(since, now)
}

// vtFeedHour returns the VT feed time token for the hour containing t.
// Format: YYYYMMDDThh00 (aligned to the hour, minutes always 00).
func vtFeedHour(t time.Time) string {
	return t.UTC().Format("20060102T15") + "00"
}

// vtIPEntry is one line of the VirusTotal IP feed JSONL.
type vtIPEntry struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Attributes struct {
		ASOwner        string `json:"as_owner"`
		Network        string `json:"network"`
		LastAnalysisStats struct {
			Malicious int `json:"malicious"`
			Total     int `json:"total"`
		} `json:"last_analysis_stats"`
	} `json:"attributes"`
}

// vtDomainEntry is one line of the VirusTotal domain feed JSONL.
type vtDomainEntry struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Attributes struct {
		LastAnalysisStats struct {
			Malicious int `json:"malicious"`
			Total     int `json:"total"`
		} `json:"last_analysis_stats"`
	} `json:"attributes"`
}

func (c *VirusTotalClient) fetchEnterprise(since, now time.Time) (FeedResult, error) {
	// Collect all hours from since..now (up to 24 hours to avoid runaway requests).
	start := since.UTC().Truncate(time.Hour)
	if now.UTC().Sub(start) > 24*time.Hour {
		start = now.UTC().Add(-24 * time.Hour).Truncate(time.Hour)
	}

	var iocs []IoC
	for t := start; t.Before(now); t = t.Add(time.Hour) {
		token := vtFeedHour(t)
		ipIoCs, err := c.fetchIPFeed(token)
		if err != nil {
			return FeedResult{}, fmt.Errorf("virustotal: ip feed %s: %w", token, err)
		}
		iocs = append(iocs, ipIoCs...)

		domainIoCs, err := c.fetchDomainFeed(token)
		if err != nil {
			return FeedResult{}, fmt.Errorf("virustotal: domain feed %s: %w", token, err)
		}
		iocs = append(iocs, domainIoCs...)
	}

	return FeedResult{Source: SourceVirusTotal, IoCs: iocs, FetchedAt: now}, nil
}

func (c *VirusTotalClient) fetchIPFeed(token string) ([]IoC, error) {
	url := fmt.Sprintf("%s/feeds/ips/%s", vtBaseURL, token)
	resp, err := c.vtGet(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // Feed not yet available for this hour
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var iocs []IoC
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var entry vtIPEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		ioc, ok := vtIPToIoC(entry)
		if ok {
			iocs = append(iocs, ioc)
		}
	}
	return iocs, scanner.Err()
}

func (c *VirusTotalClient) fetchDomainFeed(token string) ([]IoC, error) {
	url := fmt.Sprintf("%s/feeds/domains/%s", vtBaseURL, token)
	resp, err := c.vtGet(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var iocs []IoC
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var entry vtDomainEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		ioc, ok := vtDomainToIoC(entry)
		if ok {
			iocs = append(iocs, ioc)
		}
	}
	return iocs, scanner.Err()
}

func (c *VirusTotalClient) vtGet(url string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-apikey", c.apiKey)
	return c.httpClient.Do(req)
}

func vtIPToIoC(e vtIPEntry) (IoC, bool) {
	raw := e.ID
	now := time.Now().UTC()

	iocType := IoCTypeIP
	if strings.Contains(raw, "/") {
		if _, _, err := net.ParseCIDR(raw); err != nil {
			return IoC{}, false
		}
		iocType = IoCTypeCIDR
	} else if net.ParseIP(raw) == nil {
		return IoC{}, false
	}

	total := e.Attributes.LastAnalysisStats.Total
	malicious := e.Attributes.LastAnalysisStats.Malicious
	score := 0.0
	if total > 0 {
		score = float64(malicious) / float64(total)
	}

	return IoC{
		Value:       raw,
		Type:        iocType,
		Source:      SourceVirusTotal,
		ThreatScore: score,
		Tags:        []string{"osint", "virustotal"},
		FirstSeen:   now,
		Description: e.Attributes.ASOwner,
	}, true
}

func vtDomainToIoC(e vtDomainEntry) (IoC, bool) {
	domain := strings.ToLower(e.ID)
	if domain == "" {
		return IoC{}, false
	}
	now := time.Now().UTC()

	total := e.Attributes.LastAnalysisStats.Total
	malicious := e.Attributes.LastAnalysisStats.Malicious
	score := 0.0
	if total > 0 {
		score = float64(malicious) / float64(total)
	}

	return IoC{
		Value:       domain,
		Type:        IoCTypeDomain,
		Source:      SourceVirusTotal,
		ThreatScore: score,
		Tags:        []string{"osint", "virustotal"},
		FirstSeen:   now,
	}, true
}
