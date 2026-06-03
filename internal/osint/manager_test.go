package osint

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// --- Generator tests ---

func TestGeneratorIPRules(t *testing.T) {
	dir := t.TempDir()
	g := NewGenerator(dir, 3) // small batch to test multi-file output

	ips := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"}
	result := FeedResult{
		Source:    SourceMISP,
		FetchedAt: time.Now().UTC(),
		IoCs:      makeIoCs(ips, IoCTypeIP, SourceMISP),
	}

	written, err := g.GenerateRules(result)
	if err != nil {
		t.Fatalf("GenerateRules: %v", err)
	}

	// 5 IPs / 3 per rule = 2 files.
	if len(written) != 2 {
		t.Fatalf("expected 2 files, got %d: %v", len(written), keys(written))
	}
	for name := range written {
		if !strings.HasPrefix(name, "osint_misp_ip_") {
			t.Errorf("unexpected filename %q", name)
		}
	}
}

func TestGeneratorDomainRules(t *testing.T) {
	dir := t.TempDir()
	g := NewGenerator(dir, 500)

	domains := []string{"evil.com", "malware.net", "phish.io"}
	result := FeedResult{
		Source:    SourceOpenCTI,
		FetchedAt: time.Now().UTC(),
		IoCs:      makeIoCs(domains, IoCTypeDomain, SourceOpenCTI),
	}

	written, err := g.GenerateRules(result)
	if err != nil {
		t.Fatalf("GenerateRules: %v", err)
	}
	if len(written) != 1 {
		t.Fatalf("expected 1 file, got %d", len(written))
	}

	// Verify the YAML is valid and has the correct structure.
	var name string
	for k := range written {
		name = k
	}
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	var rf ruleFile
	if err := yaml.Unmarshal(stripHeader(data), &rf); err != nil {
		t.Fatalf("YAML parse: %v", err)
	}
	if len(rf.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rf.Rules))
	}
	rule := rf.Rules[0]
	if rule.EventType != "dns" {
		t.Errorf("event_type: want dns, got %q", rule.EventType)
	}
	if rule.Condition == nil {
		t.Fatal("condition is nil")
	}
	if rule.Condition.Op != "suffix" {
		t.Errorf("op: want suffix, got %q", rule.Condition.Op)
	}
	if len(rule.Condition.Values) != 3 {
		t.Errorf("values: want 3, got %d", len(rule.Condition.Values))
	}
}

func TestGeneratorCIDRRules(t *testing.T) {
	dir := t.TempDir()
	g := NewGenerator(dir, 500)

	cidrs := []string{"10.0.0.0/8", "192.168.1.0/24"}
	result := FeedResult{
		Source:    SourceVirusTotal,
		FetchedAt: time.Now().UTC(),
		IoCs:      makeIoCs(cidrs, IoCTypeCIDR, SourceVirusTotal),
	}

	written, err := g.GenerateRules(result)
	if err != nil {
		t.Fatalf("GenerateRules: %v", err)
	}
	if len(written) != 1 {
		t.Fatalf("expected 1 file, got %d", len(written))
	}

	var name string
	for k := range written {
		name = k
	}
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	var rf ruleFile
	if err := yaml.Unmarshal(stripHeader(data), &rf); err != nil {
		t.Fatalf("YAML parse: %v", err)
	}
	rule := rf.Rules[0]
	if rule.ConditionGroup == nil {
		t.Fatal("condition_group is nil for CIDR rule")
	}
	if rule.ConditionGroup.Operator != "or" {
		t.Errorf("operator: want or, got %q", rule.ConditionGroup.Operator)
	}
	if len(rule.ConditionGroup.Conditions) != 2 {
		t.Errorf("conditions: want 2, got %d", len(rule.ConditionGroup.Conditions))
	}
	for _, c := range rule.ConditionGroup.Conditions {
		if c.Op != "in_cidr" {
			t.Errorf("cidr condition op: want in_cidr, got %q", c.Op)
		}
	}
}

func TestGeneratorIdempotent(t *testing.T) {
	dir := t.TempDir()
	g := NewGenerator(dir, 500)

	result := FeedResult{
		Source:    SourceMISP,
		FetchedAt: time.Now().UTC(),
		IoCs:      makeIoCs([]string{"1.1.1.1", "2.2.2.2"}, IoCTypeIP, SourceMISP),
	}

	written1, err := g.GenerateRules(result)
	if err != nil {
		t.Fatal(err)
	}
	written2, err := g.GenerateRules(result)
	if err != nil {
		t.Fatal(err)
	}

	for k, v := range written1 {
		if written2[k] != v {
			t.Errorf("file %s: sha256 changed between identical runs", k)
		}
	}
}

func TestGeneratorEmptyFeed(t *testing.T) {
	dir := t.TempDir()
	g := NewGenerator(dir, 500)

	result := FeedResult{Source: SourceVirusTotal, FetchedAt: time.Now().UTC()}
	written, err := g.GenerateRules(result)
	if err != nil {
		t.Fatal(err)
	}
	if len(written) != 0 {
		t.Errorf("expected no files for empty feed, got %d", len(written))
	}
}

// --- MISP client helper tests ---

func TestMISPAttrToIoC(t *testing.T) {
	now := time.Now().UTC()
	tests := []struct {
		attr     mispAttribute
		wantType IoCType
		wantVal  string
		wantOK   bool
	}{
		{mispAttribute{Type: "ip-dst", Value: "1.2.3.4"}, IoCTypeIP, "1.2.3.4", true},
		{mispAttribute{Type: "ip-dst|port", Value: "5.6.7.8|443"}, IoCTypeIP, "5.6.7.8", true},
		{mispAttribute{Type: "ip-dst", Value: "10.0.0.0/8"}, IoCTypeCIDR, "10.0.0.0/8", true},
		{mispAttribute{Type: "domain", Value: "Evil.COM"}, IoCTypeDomain, "evil.com", true},
		{mispAttribute{Type: "hostname", Value: "c2.example.org"}, IoCTypeDomain, "c2.example.org", true},
		{mispAttribute{Type: "url", Value: "http://evil.com/payload"}, IoCTypeURL, "http://evil.com/payload", true},
		{mispAttribute{Type: "md5", Value: "aabbcc"}, "", "", false},
	}

	for _, tt := range tests {
		ioc, ok := mispAttrToIoC(tt.attr, now)
		if ok != tt.wantOK {
			t.Errorf("attr %q: ok=%v want %v", tt.attr.Value, ok, tt.wantOK)
			continue
		}
		if !ok {
			continue
		}
		if ioc.Type != tt.wantType {
			t.Errorf("attr %q: type=%q want %q", tt.attr.Value, ioc.Type, tt.wantType)
		}
		if ioc.Value != tt.wantVal {
			t.Errorf("attr %q: value=%q want %q", tt.attr.Value, ioc.Value, tt.wantVal)
		}
	}
}

// --- OpenCTI STIX pattern parser tests ---

func TestParseSTIXPattern(t *testing.T) {
	now := time.Now().UTC()
	tests := []struct {
		pattern  string
		wantType IoCType
		wantVal  string
		wantOK   bool
	}{
		{"[ipv4-addr:value = '1.2.3.4']", IoCTypeIP, "1.2.3.4", true},
		{"[ipv4-addr:value = '10.0.0.0/8']", IoCTypeCIDR, "10.0.0.0/8", true},
		{"[domain-name:value = 'Evil.COM']", IoCTypeDomain, "evil.com", true},
		{"[url:value = 'http://phish.io/page']", IoCTypeURL, "http://phish.io/page", true},
		{"[file:hashes.MD5 = 'abc123']", "", "", false},
	}
	for _, tt := range tests {
		ioc, ok := parseSTIXPattern(tt.pattern, now)
		if ok != tt.wantOK {
			t.Errorf("pattern %q: ok=%v want %v", tt.pattern, ok, tt.wantOK)
			continue
		}
		if !ok {
			continue
		}
		if ioc.Type != tt.wantType {
			t.Errorf("pattern %q: type=%q want %q", tt.pattern, ioc.Type, tt.wantType)
		}
		if ioc.Value != tt.wantVal {
			t.Errorf("pattern %q: value=%q want %q", tt.pattern, ioc.Value, tt.wantVal)
		}
	}
}

// --- VT feed time token test ---

func TestVTFeedHour(t *testing.T) {
	ts := time.Date(2026, 6, 3, 14, 37, 0, 0, time.UTC)
	got := vtFeedHour(ts)
	want := "20260603T1400"
	if got != want {
		t.Errorf("vtFeedHour: got %q want %q", got, want)
	}
}

// --- domainFromValue tests ---

func TestDomainFromValue(t *testing.T) {
	tests := []struct{ input, want string }{
		{"http://evil.com/path?q=1", "evil.com"},
		{"https://Evil.ORG:8443/x", "evil.org"},
		{"ftp://files.evil.net/pub", "files.evil.net"},
		{"just-a-domain.com", "just-a-domain.com"},
	}
	for _, tt := range tests {
		got := domainFromValue(tt.input)
		if got != tt.want {
			t.Errorf("domainFromValue(%q): got %q want %q", tt.input, got, tt.want)
		}
	}
}

// --- batch helper tests ---

func TestBatch(t *testing.T) {
	items := []string{"a", "b", "c", "d", "e"}
	got := batch(items, 2)
	if len(got) != 3 {
		t.Fatalf("expected 3 batches, got %d", len(got))
	}
	if len(got[0]) != 2 || len(got[1]) != 2 || len(got[2]) != 1 {
		t.Errorf("unexpected batch sizes: %v", got)
	}
}

func TestBatchEmpty(t *testing.T) {
	if got := batch(nil, 10); got != nil {
		t.Errorf("expected nil for empty input, got %v", got)
	}
}

// --- helpers ---

func makeIoCs(values []string, typ IoCType, src Source) []IoC {
	iocs := make([]IoC, len(values))
	for i, v := range values {
		iocs[i] = IoC{Value: v, Type: typ, Source: src, Tags: []string{"osint", string(src)}}
	}
	return iocs
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// stripHeader removes the leading comment lines so yaml.Unmarshal sees clean YAML.
func stripHeader(data []byte) []byte {
	lines := strings.Split(string(data), "\n")
	var out []string
	for _, l := range lines {
		if !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return []byte(strings.Join(out, "\n"))
}
