package osint

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// --- VirusTotal client tests ---

func TestVTClient_Constructor(t *testing.T) {
	c := NewVirusTotalClient("mykey", false)
	if c == nil {
		t.Fatal("expected non-nil client")
	}
	if c.Source() != SourceVirusTotal {
		t.Errorf("Source: want %q, got %q", SourceVirusTotal, c.Source())
	}
	if c.apiKey != "mykey" {
		t.Errorf("apiKey: got %q", c.apiKey)
	}
}

func TestVTClient_FetchCommunityMode_ReturnsEmpty(t *testing.T) {
	c := NewVirusTotalClient("key", false)
	result, err := c.Fetch(time.Now())
	if err != nil {
		t.Fatalf("expected no error in community mode, got: %v", err)
	}
	if result.Source != SourceVirusTotal {
		t.Errorf("source: want %q, got %q", SourceVirusTotal, result.Source)
	}
	if len(result.IoCs) != 0 {
		t.Errorf("expected 0 IoCs in community mode, got %d", len(result.IoCs))
	}
}

func TestVTIPToIoC_ValidIP(t *testing.T) {
	e := vtIPEntry{ID: "8.8.8.8"}
	e.Attributes.LastAnalysisStats.Malicious = 10
	e.Attributes.LastAnalysisStats.Total = 100
	e.Attributes.ASOwner = "Google LLC"

	ioc, ok := vtIPToIoC(e)
	if !ok {
		t.Fatal("expected ok=true for valid IP")
	}
	if ioc.Type != IoCTypeIP {
		t.Errorf("type: want IP, got %q", ioc.Type)
	}
	if ioc.Value != "8.8.8.8" {
		t.Errorf("value: want 8.8.8.8, got %q", ioc.Value)
	}
	if ioc.ThreatScore != 0.1 {
		t.Errorf("threat score: want 0.1, got %f", ioc.ThreatScore)
	}
	if ioc.Source != SourceVirusTotal {
		t.Errorf("source: want virustotal, got %q", ioc.Source)
	}
	if ioc.Description != "Google LLC" {
		t.Errorf("description: want 'Google LLC', got %q", ioc.Description)
	}
}

func TestVTIPToIoC_ValidCIDR(t *testing.T) {
	e := vtIPEntry{ID: "192.168.0.0/16"}
	ioc, ok := vtIPToIoC(e)
	if !ok {
		t.Fatal("expected ok=true for valid CIDR")
	}
	if ioc.Type != IoCTypeCIDR {
		t.Errorf("type: want CIDR, got %q", ioc.Type)
	}
	if ioc.Value != "192.168.0.0/16" {
		t.Errorf("value: want 192.168.0.0/16, got %q", ioc.Value)
	}
}

func TestVTIPToIoC_InvalidCIDR(t *testing.T) {
	e := vtIPEntry{ID: "not/a/cidr"}
	_, ok := vtIPToIoC(e)
	if ok {
		t.Error("expected ok=false for invalid CIDR")
	}
}

func TestVTIPToIoC_InvalidIP(t *testing.T) {
	e := vtIPEntry{ID: "not-an-ip"}
	_, ok := vtIPToIoC(e)
	if ok {
		t.Error("expected ok=false for non-IP string")
	}
}

func TestVTIPToIoC_ZeroTotalAnalysis(t *testing.T) {
	e := vtIPEntry{ID: "1.1.1.1"}
	e.Attributes.LastAnalysisStats.Total = 0
	ioc, ok := vtIPToIoC(e)
	if !ok {
		t.Fatal("expected ok=true even with zero total")
	}
	if ioc.ThreatScore != 0.0 {
		t.Errorf("expected 0 threat score with zero total, got %f", ioc.ThreatScore)
	}
}

func TestVTDomainToIoC_ValidDomain(t *testing.T) {
	e := vtDomainEntry{ID: "Evil.COM"}
	e.Attributes.LastAnalysisStats.Malicious = 50
	e.Attributes.LastAnalysisStats.Total = 100

	ioc, ok := vtDomainToIoC(e)
	if !ok {
		t.Fatal("expected ok=true for valid domain")
	}
	if ioc.Type != IoCTypeDomain {
		t.Errorf("type: want domain, got %q", ioc.Type)
	}
	if ioc.Value != "evil.com" {
		t.Errorf("value: want evil.com (lowercase), got %q", ioc.Value)
	}
	if ioc.ThreatScore != 0.5 {
		t.Errorf("threat score: want 0.5, got %f", ioc.ThreatScore)
	}
}

func TestVTDomainToIoC_EmptyID(t *testing.T) {
	e := vtDomainEntry{ID: ""}
	_, ok := vtDomainToIoC(e)
	if ok {
		t.Error("expected ok=false for empty ID")
	}
}

func TestVTFeedHour_FormatsCorrectly(t *testing.T) {
	ts := time.Date(2026, 6, 10, 9, 45, 0, 0, time.UTC)
	got := vtFeedHour(ts)
	if got != "20260610T0900" {
		t.Errorf("vtFeedHour: got %q, want 20260610T0900", got)
	}
}

func TestVTClient_FetchEnterpriseMode_MockServer(t *testing.T) {
	// Enterprise feed server: serve JSONL for IP feed, 404 for domain feed.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if apiKey := r.Header.Get("x-apikey"); apiKey != "testkey" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		// Return a single IP entry for any IP feed URL; 404 for domain feeds.
		if containsStrProviders(r.URL.Path, "ips") {
			entry := `{"id":"10.0.0.1","type":"ip_address","attributes":{"as_owner":"TestAS","network":"10.0.0.0/8","last_analysis_stats":{"malicious":5,"total":10}}}` + "\n"
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(entry))
		} else {
			// Domain feed not available.
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := NewVirusTotalClient("testkey", true)
	// Override the base URL by replacing the http client to point at our server.
	// Since vtBaseURL is a package-level const we use a redirecting transport instead.
	c.httpClient = &http.Client{
		Transport: &rewriteTransport{target: srv.URL, orig: "https://www.virustotal.com/api/v3"},
	}

	// Use a 30-minute window so only one hour token is generated.
	since := time.Now().UTC().Add(-30 * time.Minute)
	result, err := c.fetchEnterprise(since, time.Now().UTC())
	if err != nil {
		t.Fatalf("fetchEnterprise: %v", err)
	}
	if result.Source != SourceVirusTotal {
		t.Errorf("source: want virustotal, got %q", result.Source)
	}
	// Should have received the single IP IoC.
	if len(result.IoCs) == 0 {
		t.Error("expected at least 1 IoC from mock IP feed")
	}
	if result.IoCs[0].Type != IoCTypeIP && result.IoCs[0].Type != IoCTypeCIDR {
		t.Errorf("expected IP or CIDR IoC type, got %q", result.IoCs[0].Type)
	}
}

// --- MISP client tests ---

func TestMISPClient_Constructor(t *testing.T) {
	c := NewMISPClient("https://misp.test", "apikey", []string{"ip-dst"}, 2, nil, false)
	if c == nil {
		t.Fatal("expected non-nil client")
	}
	if c.Source() != SourceMISP {
		t.Errorf("Source: want misp, got %q", c.Source())
	}
}

func TestMISPClient_URLTrailingSlashStripped(t *testing.T) {
	c := NewMISPClient("https://misp.test/", "key", nil, 0, nil, true)
	if c.url != "https://misp.test" {
		t.Errorf("expected trailing slash stripped, got %q", c.url)
	}
}

func TestMISPClient_Fetch_MockServer(t *testing.T) {
	attrs := mispSearchResponse{}
	attrs.Response.Attribute = []mispAttribute{
		{ID: "1", Type: "ip-dst", Value: "1.2.3.4", ToIDs: true},
		{ID: "2", Type: "domain", Value: "evil.com", ToIDs: true},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "testkey" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/attributes/restSearch" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(attrs)
	}))
	defer srv.Close()

	c := NewMISPClient(srv.URL, "testkey", []string{"ip-dst", "domain"}, 0, nil, true)
	result, err := c.Fetch(time.Time{})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if result.Source != SourceMISP {
		t.Errorf("source: want misp, got %q", result.Source)
	}
	if len(result.IoCs) != 2 {
		t.Errorf("expected 2 IoCs, got %d", len(result.IoCs))
	}
}

func TestMISPClient_Fetch_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewMISPClient(srv.URL, "key", nil, 0, nil, true)
	_, err := c.Fetch(time.Time{})
	if err == nil {
		t.Error("expected error on HTTP 500")
	}
}

func TestMISPClient_Fetch_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	c := NewMISPClient(srv.URL, "key", nil, 0, nil, true)
	_, err := c.Fetch(time.Time{})
	if err == nil {
		t.Error("expected error on invalid JSON response")
	}
}

func TestMISPClient_Fetch_EmptyResult(t *testing.T) {
	resp := mispSearchResponse{}
	resp.Response.Attribute = []mispAttribute{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c := NewMISPClient(srv.URL, "key", nil, 0, nil, true)
	result, err := c.Fetch(time.Time{})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(result.IoCs) != 0 {
		t.Errorf("expected 0 IoCs for empty result, got %d", len(result.IoCs))
	}
}

// --- OpenCTI client tests ---

func TestOpenCTIClient_Constructor(t *testing.T) {
	c := NewOpenCTIClient("https://opencti.test", "apikey", 50, []string{"TLP:GREEN"}, false)
	if c == nil {
		t.Fatal("expected non-nil client")
	}
	if c.Source() != SourceOpenCTI {
		t.Errorf("Source: want opencti, got %q", c.Source())
	}
}

func TestOpenCTIClient_URLHasGraphQLSuffix(t *testing.T) {
	c := NewOpenCTIClient("https://opencti.test", "key", 0, nil, true)
	if c.url != "https://opencti.test/graphql" {
		t.Errorf("expected /graphql suffix, got %q", c.url)
	}
}

func TestOpenCTIClient_URLTrailingSlashStripped(t *testing.T) {
	c := NewOpenCTIClient("https://opencti.test/", "key", 0, nil, true)
	if c.url != "https://opencti.test/graphql" {
		t.Errorf("expected trailing slash + /graphql, got %q", c.url)
	}
}

func TestOpenCTIClient_MatchesTLP_NoMarkings_AllowsAll(t *testing.T) {
	c := NewOpenCTIClient("https://x", "k", 0, nil, true)
	ind := openCTIIndicator{}
	if !c.matchesTLP(ind) {
		t.Error("expected matchesTLP=true when no TLP filter configured")
	}
}

func TestOpenCTIClient_MatchesTLP_Matching(t *testing.T) {
	c := NewOpenCTIClient("https://x", "k", 0, []string{"TLP:GREEN", "TLP:WHITE"}, true)
	var ind openCTIIndicator
	ind.ObjectMarking.Edges = []struct {
		Node struct {
			DefinitionType string `json:"definition_type"`
			Definition     string `json:"definition"`
		} `json:"node"`
	}{
		{Node: struct {
			DefinitionType string `json:"definition_type"`
			Definition     string `json:"definition"`
		}{DefinitionType: "TLP", Definition: "TLP:GREEN"}},
	}
	if !c.matchesTLP(ind) {
		t.Error("expected matchesTLP=true for matching TLP marking")
	}
}

func TestOpenCTIClient_MatchesTLP_NotMatching(t *testing.T) {
	c := NewOpenCTIClient("https://x", "k", 0, []string{"TLP:GREEN"}, true)
	var ind openCTIIndicator
	ind.ObjectMarking.Edges = []struct {
		Node struct {
			DefinitionType string `json:"definition_type"`
			Definition     string `json:"definition"`
		} `json:"node"`
	}{
		{Node: struct {
			DefinitionType string `json:"definition_type"`
			Definition     string `json:"definition"`
		}{DefinitionType: "TLP", Definition: "TLP:RED"}},
	}
	if c.matchesTLP(ind) {
		t.Error("expected matchesTLP=false for non-matching TLP marking")
	}
}

func TestOpenCTIClient_MatchesTLP_CaseInsensitive(t *testing.T) {
	c := NewOpenCTIClient("https://x", "k", 0, []string{"tlp:green"}, true)
	var ind openCTIIndicator
	ind.ObjectMarking.Edges = []struct {
		Node struct {
			DefinitionType string `json:"definition_type"`
			Definition     string `json:"definition"`
		} `json:"node"`
	}{
		{Node: struct {
			DefinitionType string `json:"definition_type"`
			Definition     string `json:"definition"`
		}{DefinitionType: "TLP", Definition: "TLP:GREEN"}},
	}
	if !c.matchesTLP(ind) {
		t.Error("expected matchesTLP=true for case-insensitive TLP match")
	}
}

func TestOpenCTIClient_Fetch_MockServer(t *testing.T) {
	response := openCTIGraphQLResponse{}
	response.Data.Indicators.PageInfo.HasNextPage = false
	response.Data.Indicators.Edges = []struct {
		Node openCTIIndicator `json:"node"`
	}{
		{Node: openCTIIndicator{
			ID:          "ind-1",
			Name:        "Malicious IP",
			Pattern:     "[ipv4-addr:value = '5.5.5.5']",
			PatternType: "stix",
			Confidence:  80,
			Score:       90,
		}},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer srv.Close()

	// Manually set the URL to bypass NewOpenCTIClient's /graphql suffix logic.
	c := &OpenCTIClient{
		url:           srv.URL,
		apiKey:        "testkey",
		confidenceMin: 0,
		httpClient:    &http.Client{},
	}

	result, err := c.Fetch(time.Time{})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if result.Source != SourceOpenCTI {
		t.Errorf("source: want opencti, got %q", result.Source)
	}
	if len(result.IoCs) != 1 {
		t.Errorf("expected 1 IoC, got %d", len(result.IoCs))
	}
	if result.IoCs[0].Value != "5.5.5.5" {
		t.Errorf("IoC value: want 5.5.5.5, got %q", result.IoCs[0].Value)
	}
}

func TestOpenCTIClient_Fetch_ConfidenceFilter(t *testing.T) {
	response := openCTIGraphQLResponse{}
	response.Data.Indicators.PageInfo.HasNextPage = false
	response.Data.Indicators.Edges = []struct {
		Node openCTIIndicator `json:"node"`
	}{
		{Node: openCTIIndicator{
			ID:          "low-conf",
			Pattern:     "[ipv4-addr:value = '1.1.1.1']",
			PatternType: "stix",
			Confidence:  10, // below minimum
		}},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer srv.Close()

	c := &OpenCTIClient{
		url:           srv.URL,
		apiKey:        "key",
		confidenceMin: 50, // filter out low-confidence
		httpClient:    &http.Client{},
	}

	result, err := c.Fetch(time.Time{})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(result.IoCs) != 0 {
		t.Errorf("expected 0 IoCs after confidence filter, got %d", len(result.IoCs))
	}
}

func TestOpenCTIClient_Fetch_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := &OpenCTIClient{url: srv.URL, apiKey: "key", httpClient: &http.Client{}}
	_, err := c.Fetch(time.Time{})
	if err == nil {
		t.Error("expected error on HTTP 503")
	}
}

// --- helpers ---

// containsStr is a simple string containment check (avoids importing strings in _test files
// where strings is already imported via another test file in same package).
func containsStrProviders(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// rewriteTransport rewrites requests whose URL starts with `orig` to `target`.
type rewriteTransport struct {
	orig   string
	target string
}

func (rt *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	url := req.URL.String()
	if len(url) >= len(rt.orig) && url[:len(rt.orig)] == rt.orig {
		newURL := rt.target + url[len(rt.orig):]
		newReq := req.Clone(req.Context())
		parsed, err := http.NewRequest(req.Method, newURL, req.Body)
		if err != nil {
			return nil, err
		}
		parsed.Header = newReq.Header
		u, _ := parsed.URL.Parse(newURL)
		parsed.URL = u
		parsed.Host = u.Host
		// Ensure we connect to HTTP not HTTPS for tests.
		conn, err := net.Dial("tcp", u.Host)
		if err != nil {
			return nil, err
		}
		conn.Close()
		return http.DefaultTransport.RoundTrip(parsed)
	}
	return http.DefaultTransport.RoundTrip(req)
}
