package osint

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ruleFile is the top-level YAML structure matching the ebpf-guard rule schema.
type ruleFile struct {
	Rules []generatedRule `yaml:"rules"`
}

// generatedRule mirrors correlator.Rule for YAML serialization.
// We avoid importing the correlator package to keep this package dependency-free.
type generatedRule struct {
	ID             string              `yaml:"id"`
	Name           string              `yaml:"name"`
	Description    string              `yaml:"description"`
	EventType      string              `yaml:"event_type"`
	Condition      *ruleCondition      `yaml:"condition,omitempty"`
	ConditionGroup *ruleConditionGroup `yaml:"condition_group,omitempty"`
	Severity       string              `yaml:"severity"`
	Action         string              `yaml:"action"`
	Tags           []string            `yaml:"tags,omitempty"`
}

type ruleCondition struct {
	Field  string   `yaml:"field"`
	Op     string   `yaml:"op"`
	Values []string `yaml:"values"`
}

type ruleConditionGroup struct {
	Operator   string           `yaml:"operator"`
	Conditions []ruleCondition  `yaml:"conditions"`
}

// Generator converts IoC lists into ebpf-guard YAML rule files.
type Generator struct {
	outputDir      string
	maxIoCsPerRule int
}

// NewGenerator creates a rule generator that writes to outputDir.
// maxIoCsPerRule limits how many values appear in a single rule's condition
// to keep YAML files manageable and evaluation fast.
func NewGenerator(outputDir string, maxIoCsPerRule int) *Generator {
	if maxIoCsPerRule <= 0 {
		maxIoCsPerRule = 500
	}
	return &Generator{outputDir: outputDir, maxIoCsPerRule: maxIoCsPerRule}
}

// GenerateRules converts IoCs from a FeedResult into YAML rule files.
// It returns a map of filename → sha256 of written content.
func (g *Generator) GenerateRules(result FeedResult) (map[string]string, error) {
	if err := os.MkdirAll(g.outputDir, 0o750); err != nil {
		return nil, fmt.Errorf("osint: mkdir %s: %w", g.outputDir, err)
	}

	// Partition IoCs by type.
	var (
		ips     []string
		cidrs   []string
		domains []string
	)
	for _, ioc := range result.IoCs {
		switch ioc.Type {
		case IoCTypeIP:
			ips = append(ips, ioc.Value)
		case IoCTypeCIDR:
			cidrs = append(cidrs, ioc.Value)
		case IoCTypeDomain, IoCTypeURL:
			// URLs are matched as domain suffixes in DNS rules.
			domains = append(domains, domainFromValue(ioc.Value))
		}
	}

	// Deduplicate and sort for stable output.
	ips = dedup(ips)
	cidrs = dedup(cidrs)
	domains = dedup(domains)

	written := make(map[string]string)
	srcStr := string(result.Source)
	ts := result.FetchedAt.UTC().Format(time.RFC3339)

	if err := g.writeIPRules(srcStr, ts, ips, written); err != nil {
		return nil, err
	}
	if err := g.writeCIDRRules(srcStr, ts, cidrs, written); err != nil {
		return nil, err
	}
	if err := g.writeDomainRules(srcStr, ts, domains, written); err != nil {
		return nil, err
	}

	return written, nil
}

func (g *Generator) writeIPRules(src, ts string, ips []string, written map[string]string) error {
	batches := batch(ips, g.maxIoCsPerRule)
	for i, b := range batches {
		id := fmt.Sprintf("osint_%s_ip_%03d", src, i+1)
		rule := generatedRule{
			ID:          id,
			Name:        fmt.Sprintf("OSINT %s: Malicious IP Blocklist (batch %d/%d)", strings.ToUpper(src), i+1, len(batches)),
			Description: fmt.Sprintf("Auto-generated from %s threat intelligence feed. Updated: %s", strings.ToUpper(src), ts),
			EventType:   "network",
			Condition: &ruleCondition{
				Field:  "daddr",
				Op:     "in",
				Values: b,
			},
			Severity: "critical",
			Action:   "alert",
			Tags:     []string{"osint", src, "auto-generated", "ioc", "network"},
		}
		filename := fmt.Sprintf("osint_%s_ip_%03d.yaml", src, i+1)
		if err := g.writeRule(filename, rule, written); err != nil {
			return err
		}
	}
	return nil
}

func (g *Generator) writeCIDRRules(src, ts string, cidrs []string, written map[string]string) error {
	batches := batch(cidrs, g.maxIoCsPerRule)
	for i, b := range batches {
		id := fmt.Sprintf("osint_%s_cidr_%03d", src, i+1)

		conditions := make([]ruleCondition, len(b))
		for j, cidr := range b {
			conditions[j] = ruleCondition{Field: "daddr", Op: "in_cidr", Values: []string{cidr}}
		}

		rule := generatedRule{
			ID:          id,
			Name:        fmt.Sprintf("OSINT %s: Malicious CIDR Blocklist (batch %d/%d)", strings.ToUpper(src), i+1, len(batches)),
			Description: fmt.Sprintf("Auto-generated from %s threat intelligence feed. Updated: %s", strings.ToUpper(src), ts),
			EventType:   "network",
			ConditionGroup: &ruleConditionGroup{
				Operator:   "or",
				Conditions: conditions,
			},
			Severity: "critical",
			Action:   "alert",
			Tags:     []string{"osint", src, "auto-generated", "ioc", "network", "cidr"},
		}
		filename := fmt.Sprintf("osint_%s_cidr_%03d.yaml", src, i+1)
		if err := g.writeRule(filename, rule, written); err != nil {
			return err
		}
	}
	return nil
}

func (g *Generator) writeDomainRules(src, ts string, domains []string, written map[string]string) error {
	batches := batch(domains, g.maxIoCsPerRule)
	for i, b := range batches {
		id := fmt.Sprintf("osint_%s_domain_%03d", src, i+1)
		rule := generatedRule{
			ID:          id,
			Name:        fmt.Sprintf("OSINT %s: Malicious Domain Blocklist (batch %d/%d)", strings.ToUpper(src), i+1, len(batches)),
			Description: fmt.Sprintf("Auto-generated from %s threat intelligence feed. Updated: %s", strings.ToUpper(src), ts),
			EventType:   "dns",
			Condition: &ruleCondition{
				Field:  "qname",
				Op:     "suffix",
				Values: b,
			},
			Severity: "critical",
			Action:   "alert",
			Tags:     []string{"osint", src, "auto-generated", "ioc", "dns"},
		}
		filename := fmt.Sprintf("osint_%s_domain_%03d.yaml", src, i+1)
		if err := g.writeRule(filename, rule, written); err != nil {
			return err
		}
	}
	return nil
}

func (g *Generator) writeRule(filename string, rule generatedRule, written map[string]string) error {
	rf := ruleFile{Rules: []generatedRule{rule}}
	data, err := yaml.Marshal(rf)
	if err != nil {
		return fmt.Errorf("osint: marshal rule %s: %w", rule.ID, err)
	}

	// Prepend a header comment.
	header := fmt.Sprintf("# Auto-generated by ebpf-guard OSINT engine — do not edit manually.\n# Source: %s | Rule: %s\n\n", rule.Tags[1], rule.ID)
	content := []byte(header + string(data))

	path := filepath.Join(g.outputDir, filename)

	// Skip writing if content is identical to what's already on disk.
	existing, _ := os.ReadFile(path)
	if string(existing) == string(content) {
		sum := sha256hex(content)
		written[filename] = sum
		return nil
	}

	if err := os.WriteFile(path, content, 0o640); err != nil {
		return fmt.Errorf("osint: write %s: %w", path, err)
	}
	written[filename] = sha256hex(content)
	return nil
}

func sha256hex(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h)
}

func batch(items []string, size int) [][]string {
	if len(items) == 0 {
		return nil
	}
	var batches [][]string
	for i := 0; i < len(items); i += size {
		end := i + size
		if end > len(items) {
			end = len(items)
		}
		cp := make([]string, end-i)
		copy(cp, items[i:end])
		batches = append(batches, cp)
	}
	return batches
}

func dedup(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	out := items[:0]
	for _, v := range items {
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// domainFromValue extracts the hostname from a URL or returns the value as-is.
func domainFromValue(v string) string {
	// Strip scheme prefix if present.
	for _, prefix := range []string{"https://", "http://", "ftp://"} {
		if strings.HasPrefix(v, prefix) {
			v = v[len(prefix):]
			break
		}
	}
	// Strip path.
	if idx := strings.IndexByte(v, '/'); idx >= 0 {
		v = v[:idx]
	}
	// Strip port.
	if host, _, found := strings.Cut(v, ":"); found {
		v = host
	}
	return strings.ToLower(v)
}
