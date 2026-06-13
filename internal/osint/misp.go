package osint

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// MISPClient fetches IoCs from a MISP instance via the restSearch REST API.
type MISPClient struct {
	url            string
	apiKey         string
	attributeTypes []string
	minThreatLevel int // 1=high…4=undefined (MISP convention)
	tags           []string
	httpClient     *http.Client
}

// mispRestSearchRequest is the JSON body sent to /attributes/restSearch.
type mispRestSearchRequest struct {
	ReturnFormat   string            `json:"returnFormat"`
	Type           mispORFilter      `json:"type"`
	ToIDs          int               `json:"to_ids,omitempty"`
	Tags           *mispORFilter     `json:"tags,omitempty"`
	ThreatLevelID  *mispORFilter     `json:"threat_level_id,omitempty"`
	Limit          int               `json:"limit"`
	Page           int               `json:"page"`
}

type mispORFilter struct {
	OR []string `json:"OR"`
}

type mispSearchResponse struct {
	Response struct {
		Attribute []mispAttribute `json:"Attribute"`
	} `json:"response"`
}

type mispAttribute struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Value     string `json:"value"`
	ToIDs     bool   `json:"to_ids"`
	Timestamp string `json:"timestamp"`
	Comment   string `json:"comment"`
}

// NewMISPClient creates a MISP REST API client.
func NewMISPClient(url, apiKey string, attributeTypes []string, minThreatLevel int, tags []string, insecureSkipVerify bool) *MISPClient {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkipVerify}, //nolint:gosec
	}
	return &MISPClient{
		url:            strings.TrimRight(url, "/"),
		apiKey:         apiKey,
		attributeTypes: attributeTypes,
		minThreatLevel: minThreatLevel,
		tags:           tags,
		httpClient:     &http.Client{Transport: transport, Timeout: 60 * time.Second},
	}
}

func (c *MISPClient) Source() Source { return SourceMISP }

// Fetch retrieves attributes from MISP using restSearch, paginating until exhausted.
func (c *MISPClient) Fetch(since time.Time) (FeedResult, error) {
	const pageSize = 5000
	var allAttrs []mispAttribute

	for page := 1; ; page++ {
		req := mispRestSearchRequest{
			ReturnFormat:  "json",
			Type:          mispORFilter{OR: c.attributeTypes},
			ToIDs:         1,
			Limit:         pageSize,
			Page:          page,
		}
		if len(c.tags) > 0 {
			f := mispORFilter{OR: c.tags}
			req.Tags = &f
		}

		attrs, err := c.fetchPage(req)
		if err != nil {
			return FeedResult{}, fmt.Errorf("misp: page %d: %w", page, err)
		}
		allAttrs = append(allAttrs, attrs...)
		if len(attrs) < pageSize {
			break
		}
	}

	iocs := make([]IoC, 0, len(allAttrs))
	now := time.Now().UTC()
	for _, a := range allAttrs {
		ioc, ok := mispAttrToIoC(a, now)
		if !ok {
			continue
		}
		iocs = append(iocs, ioc)
	}

	return FeedResult{Source: SourceMISP, IoCs: iocs, FetchedAt: now}, nil
}

func (c *MISPClient) fetchPage(req mispRestSearchRequest) ([]mispAttribute, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequest(http.MethodPost, c.url+"/attributes/restSearch", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", c.apiKey)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from MISP", resp.StatusCode)
	}

	var result mispSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return result.Response.Attribute, nil
}

func mispAttrToIoC(a mispAttribute, defaultTime time.Time) (IoC, bool) {
	ioc := IoC{
		Source:      SourceMISP,
		ThreatScore: 0.8,
		Description: a.Comment,
		FirstSeen:   defaultTime,
		Tags:        []string{"osint", "misp"},
	}

	switch a.Type {
	case "ip-dst", "ip-src", "ip-dst|port":
		raw := strings.SplitN(a.Value, "|", 2)[0] // strip port suffix
		if _, _, err := net.ParseCIDR(raw); err == nil {
			ioc.Type = IoCTypeCIDR
		} else if net.ParseIP(raw) != nil {
			ioc.Type = IoCTypeIP
		} else {
			return IoC{}, false
		}
		ioc.Value = raw
	case "domain", "hostname":
		ioc.Type = IoCTypeDomain
		ioc.Value = strings.ToLower(a.Value)
	case "url":
		ioc.Type = IoCTypeURL
		ioc.Value = a.Value
	default:
		return IoC{}, false
	}

	return ioc, true
}
