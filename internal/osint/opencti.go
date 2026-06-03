package osint

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// OpenCTIClient fetches indicators from an OpenCTI instance via its GraphQL API.
type OpenCTIClient struct {
	url           string
	apiKey        string
	confidenceMin int    // Minimum indicator confidence score (0–100)
	tlpMarkings   []string
	httpClient    *http.Client
}

// NewOpenCTIClient creates an OpenCTI GraphQL API client.
func NewOpenCTIClient(url, apiKey string, confidenceMin int, tlpMarkings []string, verifyTLS bool) *OpenCTIClient {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !verifyTLS}, //nolint:gosec
	}
	return &OpenCTIClient{
		url:           strings.TrimRight(url, "/") + "/graphql",
		apiKey:        apiKey,
		confidenceMin: confidenceMin,
		tlpMarkings:   tlpMarkings,
		httpClient:    &http.Client{Transport: transport, Timeout: 60 * time.Second},
	}
}

func (c *OpenCTIClient) Source() Source { return SourceOpenCTI }

const openCTIIndicatorsQuery = `
query GetIndicators($first: Int!, $after: ID) {
  indicators(first: $first, after: $after) {
    pageInfo { hasNextPage endCursor }
    edges {
      node {
        id
        name
        pattern_type
        pattern
        confidence
        x_opencti_score
        valid_until
        objectMarking { edges { node { definition_type definition } } }
      }
    }
  }
}`

type openCTIGraphQLRequest struct {
	Query     string                 `json:"query"`
	Variables map[string]interface{} `json:"variables"`
}

type openCTIGraphQLResponse struct {
	Data struct {
		Indicators struct {
			PageInfo struct {
				HasNextPage bool   `json:"hasNextPage"`
				EndCursor   string `json:"endCursor"`
			} `json:"pageInfo"`
			Edges []struct {
				Node openCTIIndicator `json:"node"`
			} `json:"edges"`
		} `json:"indicators"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors,omitempty"`
}

type openCTIIndicator struct {
	ID           string  `json:"id"`
	Name         string  `json:"name"`
	PatternType  string  `json:"pattern_type"`
	Pattern      string  `json:"pattern"`
	Confidence   int     `json:"confidence"`
	Score        int     `json:"x_opencti_score"`
	ValidUntil   string  `json:"valid_until"`
	ObjectMarking struct {
		Edges []struct {
			Node struct {
				DefinitionType string `json:"definition_type"`
				Definition     string `json:"definition"`
			} `json:"node"`
		} `json:"edges"`
	} `json:"objectMarking"`
}

// Fetch retrieves indicators from OpenCTI using paginated GraphQL queries.
func (c *OpenCTIClient) Fetch(since time.Time) (FeedResult, error) {
	const pageSize = 500
	var allIndicators []openCTIIndicator
	var cursor *string

	for {
		vars := map[string]interface{}{"first": pageSize}
		if cursor != nil {
			vars["after"] = *cursor
		}

		indicators, hasNext, nextCursor, err := c.fetchPage(vars)
		if err != nil {
			return FeedResult{}, fmt.Errorf("opencti: %w", err)
		}
		allIndicators = append(allIndicators, indicators...)
		if !hasNext {
			break
		}
		cursor = &nextCursor
	}

	now := time.Now().UTC()
	iocs := make([]IoC, 0, len(allIndicators))
	for _, ind := range allIndicators {
		if ind.Confidence < c.confidenceMin {
			continue
		}
		if !c.matchesTLP(ind) {
			continue
		}
		ioc, ok := parseSTIXPattern(ind.Pattern, now)
		if !ok {
			continue
		}
		ioc.Source = SourceOpenCTI
		ioc.ThreatScore = float64(ind.Score) / 100.0
		ioc.Description = ind.Name
		ioc.Tags = []string{"osint", "opencti"}
		iocs = append(iocs, ioc)
	}

	return FeedResult{Source: SourceOpenCTI, IoCs: iocs, FetchedAt: now}, nil
}

func (c *OpenCTIClient) fetchPage(vars map[string]interface{}) ([]openCTIIndicator, bool, string, error) {
	payload := openCTIGraphQLRequest{Query: openCTIIndicatorsQuery, Variables: vars}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, false, "", err
	}

	req, err := http.NewRequest(http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return nil, false, "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, false, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, false, "", fmt.Errorf("HTTP %d from OpenCTI", resp.StatusCode)
	}

	var result openCTIGraphQLResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, false, "", fmt.Errorf("decode response: %w", err)
	}
	if len(result.Errors) > 0 {
		return nil, false, "", fmt.Errorf("GraphQL error: %s", result.Errors[0].Message)
	}

	page := result.Data.Indicators
	edges := make([]openCTIIndicator, 0, len(page.Edges))
	for _, e := range page.Edges {
		edges = append(edges, e.Node)
	}
	return edges, page.PageInfo.HasNextPage, page.PageInfo.EndCursor, nil
}

func (c *OpenCTIClient) matchesTLP(ind openCTIIndicator) bool {
	if len(c.tlpMarkings) == 0 {
		return true
	}
	for _, edge := range ind.ObjectMarking.Edges {
		for _, allowed := range c.tlpMarkings {
			if strings.EqualFold(edge.Node.Definition, allowed) {
				return true
			}
		}
	}
	return false
}

// reSTIXIPv4 matches STIX 2 IPv4 patterns: [ipv4-addr:value = '1.2.3.4']
var reSTIXIPv4 = regexp.MustCompile(`\[ipv4-addr:value\s*=\s*'([^']+)'\]`)

// reSTIXDomain matches STIX 2 domain patterns: [domain-name:value = 'evil.com']
var reSTIXDomain = regexp.MustCompile(`\[domain-name:value\s*=\s*'([^']+)'\]`)

// reSTIXURL matches STIX 2 URL patterns: [url:value = 'http://evil.com/path']
var reSTIXURL = regexp.MustCompile(`\[url:value\s*=\s*'([^']+)'\]`)

func parseSTIXPattern(pattern string, now time.Time) (IoC, bool) {
	if m := reSTIXIPv4.FindStringSubmatch(pattern); len(m) == 2 {
		raw := m[1]
		iocType := IoCTypeIP
		if strings.Contains(raw, "/") {
			if _, _, err := net.ParseCIDR(raw); err != nil {
				return IoC{}, false
			}
			iocType = IoCTypeCIDR
		} else if net.ParseIP(raw) == nil {
			return IoC{}, false
		}
		return IoC{Value: raw, Type: iocType, FirstSeen: now}, true
	}
	if m := reSTIXDomain.FindStringSubmatch(pattern); len(m) == 2 {
		return IoC{Value: strings.ToLower(m[1]), Type: IoCTypeDomain, FirstSeen: now}, true
	}
	if m := reSTIXURL.FindStringSubmatch(pattern); len(m) == 2 {
		return IoC{Value: m[1], Type: IoCTypeURL, FirstSeen: now}, true
	}
	return IoC{}, false
}
