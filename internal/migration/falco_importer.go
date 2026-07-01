// Package migration provides tools for migrating from other runtime security tools.
package migration

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// FalcoRule represents a single rule from a Falco rules YAML file.
type FalcoRule struct {
	Rule      string   `yaml:"rule"`
	Desc      string   `yaml:"desc"`
	Condition string   `yaml:"condition"`
	Output    string   `yaml:"output"`
	Priority  string   `yaml:"priority"`
	Tags      []string `yaml:"tags"`
	Enabled   *bool    `yaml:"enabled"`
}

// FalcoDocument represents the top-level structure of a Falco rules file.
// Falco files are lists of heterogeneous items (rules, macros, lists).
type FalcoDocument []map[string]interface{}

// FalcoCondition is a single field condition in an ebpf-guard rule.
type FalcoCondition struct {
	Field  string   `yaml:"field"`
	Op     string   `yaml:"op"`
	Values []string `yaml:"values"`
}

// FalcoConditionGroup combines multiple conditions with AND/OR logic.
type FalcoConditionGroup struct {
	Operator   string                `yaml:"operator"`
	Conditions []FalcoCondition      `yaml:"conditions,omitempty"`
	SubGroups  []FalcoConditionGroup `yaml:"subgroups,omitempty"`
}

// ConvertedRule is an ebpf-guard rule produced by conversion.
type ConvertedRule struct {
	ID             string               `yaml:"id"`
	Name           string               `yaml:"name"`
	Description    string               `yaml:"description,omitempty"`
	EventType      string               `yaml:"event_type"`
	Condition      *FalcoCondition      `yaml:"condition,omitempty"`
	ConditionGroup *FalcoConditionGroup `yaml:"condition_group,omitempty"`
	Severity       string               `yaml:"severity"`
	Action         string               `yaml:"action"`
	Tags           []string             `yaml:"tags,omitempty"`
}

// ConversionResult holds the result of converting one Falco rule.
type ConversionResult struct {
	SourceRule         string
	Converted          *ConvertedRule
	Status             string // "converted" | "unsupported" | "disabled"
	UnsupportedReasons []string
}

// ImportResult is the full result of importing a Falco rules file.
type ImportResult struct {
	Results     []ConversionResult
	Converted   int
	Unsupported int
	Disabled    int
}

// FalcoImporter converts Falco rules YAML to ebpf-guard correlator YAML.
//
// It supports the boolean-expression subset of the Falco condition language
// (and/or/not, parentheses), expands macro: blocks referenced as bare
// identifiers, resolves list: blocks referenced inside in (...) clauses, and
// maps Falco field names to the exact field names accepted by
// internal/correlator/rule_loader.go for each ebpf-guard event type. Fields
// or expressions with no ebpf-guard equivalent are dropped with a WARN log
// and recorded in UnsupportedReasons; a rule only becomes "unsupported" when
// none of its clauses could be converted.
type FalcoImporter struct {
	logger *slog.Logger
}

// NewFalcoImporter creates a new FalcoImporter.
func NewFalcoImporter() *FalcoImporter {
	return &FalcoImporter{logger: slog.Default()}
}

// ImportFile reads a Falco rules file and converts all rules.
func (f *FalcoImporter) ImportFile(path string) (*ImportResult, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is supplied directly by the CLI operator
	if err != nil {
		return nil, fmt.Errorf("read falco rules file: %w", err)
	}
	idx := 0
	return f.importWithIdx(data, &idx)
}

// ImportDir converts all .yml/.yaml Falco files found directly in dir.
func (f *FalcoImporter) ImportDir(dir string) (*ImportResult, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read falco rules directory: %w", err)
	}

	combined := &ImportResult{}
	idx := 0

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path) // #nosec G304 -- dir is supplied directly by the CLI operator; entry.Name() comes from ReadDir on that same dir
		if err != nil {
			f.logger.Warn("falco: skipping unreadable file",
				slog.String("path", path), slog.Any("error", err))
			continue
		}
		result, err := f.importWithIdx(data, &idx)
		if err != nil {
			f.logger.Warn("falco: skipping unparseable file",
				slog.String("path", path), slog.Any("error", err))
			continue
		}
		combined.Results = append(combined.Results, result.Results...)
		combined.Converted += result.Converted
		combined.Unsupported += result.Unsupported
		combined.Disabled += result.Disabled
	}
	return combined, nil
}

// Import converts Falco rules YAML bytes to ebpf-guard rules.
func (f *FalcoImporter) Import(data []byte) (*ImportResult, error) {
	idx := 0
	return f.importWithIdx(data, &idx)
}

func (f *FalcoImporter) importWithIdx(data []byte, idx *int) (*ImportResult, error) {
	var doc FalcoDocument
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse falco rules YAML: %w", err)
	}

	macros, lists := collectMacrosAndLists(doc)

	result := &ImportResult{}

	for _, item := range doc {
		// Only process items that have a "rule" key.
		ruleName, ok := item["rule"].(string)
		if !ok || ruleName == "" {
			continue
		}

		fr := FalcoRule{
			Rule:      ruleName,
			Desc:      stringField(item, "desc"),
			Condition: stringField(item, "condition"),
			Output:    stringField(item, "output"),
			Priority:  stringField(item, "priority"),
		}

		if tags, ok := item["tags"].([]interface{}); ok {
			for _, t := range tags {
				if s, ok := t.(string); ok {
					fr.Tags = append(fr.Tags, s)
				}
			}
		}

		if enabled, ok := item["enabled"].(bool); ok {
			fr.Enabled = &enabled
		}

		*idx++
		cr := f.convertRule(*idx, fr, macros, lists)
		switch cr.Status {
		case "converted":
			result.Converted++
		case "unsupported":
			result.Unsupported++
		case "disabled":
			result.Disabled++
		}
		result.Results = append(result.Results, cr)
	}

	return result, nil
}

// WriteOutput serializes the converted rules to ebpf-guard YAML format.
func (f *FalcoImporter) WriteOutput(result *ImportResult) ([]byte, error) {
	type rulesFile struct {
		Rules []*ConvertedRule `yaml:"rules"`
	}

	var converted []*ConvertedRule
	for _, r := range result.Results {
		if r.Status == "converted" && r.Converted != nil {
			converted = append(converted, r.Converted)
		}
	}

	out := rulesFile{Rules: converted}
	return yaml.Marshal(out)
}

// collectMacrosAndLists separates macro: and list: items out of a parsed
// Falco document. Macro bodies are kept as raw (unexpanded) condition
// strings; expandMacros resolves nested macro references recursively.
func collectMacrosAndLists(doc FalcoDocument) (macros map[string]string, lists map[string][]string) {
	macros = make(map[string]string)
	lists = make(map[string][]string)

	for _, item := range doc {
		if name, ok := item["macro"].(string); ok && name != "" {
			macros[name] = stringField(item, "condition")
			continue
		}
		if name, ok := item["list"].(string); ok && name != "" {
			var items []string
			if raw, ok := item["items"].([]interface{}); ok {
				for _, v := range raw {
					switch s := v.(type) {
					case string:
						items = append(items, s)
					case int:
						items = append(items, fmt.Sprintf("%d", s))
					}
				}
			}
			lists[name] = items
		}
	}
	return macros, lists
}

// convertRule converts a single Falco rule to an ebpf-guard rule.
func (f *FalcoImporter) convertRule(idx int, fr FalcoRule, macros map[string]string, lists map[string][]string) ConversionResult {
	cr := ConversionResult{SourceRule: fr.Rule}

	// Handle disabled rules.
	if fr.Enabled != nil && !*fr.Enabled {
		cr.Status = "disabled"
		return cr
	}

	if strings.TrimSpace(fr.Condition) == "" {
		cr.Status = "unsupported"
		cr.UnsupportedReasons = []string{"empty condition"}
		return cr
	}

	expanded := expandMacros(fr.Condition, macros)
	eventType := detectEventType(expanded)

	node, reasons := parseExpr(expanded, eventType, lists)

	rule := &ConvertedRule{
		ID:          fmt.Sprintf("falco_imported_%03d", idx),
		Name:        fr.Rule,
		Description: fr.Desc,
		EventType:   eventType,
		Severity:    mapPriority(fr.Priority),
		Action:      "alert",
		Tags:        fr.Tags,
	}

	if node == nil {
		if len(reasons) == 0 {
			reasons = []string{"could not parse condition: " + fr.Condition}
		}
		cr.Status = "unsupported"
		cr.UnsupportedReasons = reasons
		return cr
	}

	for _, r := range reasons {
		f.logger.Warn("falco-import: " + r)
	}

	if node.single != nil {
		rule.Condition = node.single
	} else {
		rule.ConditionGroup = node.group
	}

	cr.Converted = rule
	cr.Status = "converted"
	cr.UnsupportedReasons = reasons
	return cr
}

// mapPriority converts Falco priority to ebpf-guard severity.
func mapPriority(priority string) string {
	switch strings.ToUpper(priority) {
	case "CRITICAL", "EMERGENCY", "ALERT", "ERROR":
		return "critical"
	default:
		return "warning"
	}
}

func stringField(m map[string]interface{}, key string) string {
	v, _ := m[key].(string)
	return v
}
