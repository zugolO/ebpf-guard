// Package osint provides automated rule generation from OSINT threat feeds.
// It fetches IoC (Indicator of Compromise) data from MISP, OpenCTI, and
// VirusTotal and converts IP/domain blocklists into ebpf-guard YAML rules.
package osint

import "time"

// IoCType identifies the kind of indicator.
type IoCType string

const (
	IoCTypeIP     IoCType = "ip"
	IoCTypeCIDR   IoCType = "cidr"
	IoCTypeDomain IoCType = "domain"
	IoCTypeURL    IoCType = "url"
)

// Source identifies which OSINT provider supplied the IoC.
type Source string

const (
	SourceMISP       Source = "misp"
	SourceOpenCTI    Source = "opencti"
	SourceVirusTotal Source = "virustotal"
)

// IoC represents a single indicator of compromise.
type IoC struct {
	Value       string    // IP address, CIDR, domain name, or URL value
	Type        IoCType
	Source      Source
	ThreatScore float64  // 0.0–1.0; higher = more malicious
	Tags        []string // Source-specific labels (e.g., TLP markings, MITRE tags)
	FirstSeen   time.Time
	Description string
}

// FeedResult is the output of a single client Fetch call.
type FeedResult struct {
	Source Source
	IoCs   []IoC
	// FetchedAt is when the feed was retrieved.
	FetchedAt time.Time
}

// SyncState persists per-source sync metadata between runs.
type SyncState struct {
	LastSync  map[Source]time.Time  `json:"last_sync"`
	RuleFiles map[string]string     `json:"rule_files"` // filename → sha256
}

// Client is implemented by each OSINT provider.
type Client interface {
	// Source returns the provider identifier.
	Source() Source
	// Fetch retrieves IoCs from the provider feed.
	// since is a hint for incremental fetches; providers may ignore it.
	Fetch(since time.Time) (FeedResult, error)
}
