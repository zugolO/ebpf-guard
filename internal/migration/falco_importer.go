// Package migration provides tools for migrating from other runtime security tools.
package migration

import (
	"fmt"
	"os"
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

// ConvertedRule is an ebpf-guard rule produced by conversion.
type ConvertedRule struct {
	ID          string                 `yaml:"id"`
	Name        string                 `yaml:"name"`
	Description string                 `yaml:"description,omitempty"`
	EventType   string                 `yaml:"event_type"`
	Condition   map[string]interface{} `yaml:"condition,omitempty"`
	Severity    string                 `yaml:"severity"`
	Action      string                 `yaml:"action"`
	Tags        []string               `yaml:"tags,omitempty"`
}

// ConversionResult holds the result of converting one Falco rule.
type ConversionResult struct {
	SourceRule  string
	Converted   *ConvertedRule
	Status      string // "converted" | "unsupported" | "disabled"
	UnsupportedReasons []string
}

// ImportResult is the full result of importing a Falco rules file.
type ImportResult struct {
	Results   []ConversionResult
	Converted int
	Unsupported int
	Disabled  int
}

// FalcoImporter converts Falco rules YAML to ebpf-guard correlator YAML.
type FalcoImporter struct{}

// NewFalcoImporter creates a new FalcoImporter.
func NewFalcoImporter() *FalcoImporter {
	return &FalcoImporter{}
}

// ImportFile reads a Falco rules file and converts all rules.
func (f *FalcoImporter) ImportFile(path string) (*ImportResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read falco rules file: %w", err)
	}
	return f.Import(data)
}

// Import converts Falco rules YAML bytes to ebpf-guard rules.
func (f *FalcoImporter) Import(data []byte) (*ImportResult, error) {
	var doc FalcoDocument
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse falco rules YAML: %w", err)
	}

	result := &ImportResult{}
	ruleIdx := 0

	for _, item := range doc {
		// Only process items that have a "rule" key
		ruleName, ok := item["rule"].(string)
		if !ok || ruleName == "" {
			continue
		}

		fr := FalcoRule{
			Rule:     ruleName,
			Desc:     stringField(item, "desc"),
			Condition: stringField(item, "condition"),
			Output:   stringField(item, "output"),
			Priority: stringField(item, "priority"),
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

		ruleIdx++
		cr := f.convertRule(ruleIdx, fr)
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

// convertRule converts a single Falco rule to an ebpf-guard rule.
func (f *FalcoImporter) convertRule(idx int, fr FalcoRule) ConversionResult {
	cr := ConversionResult{SourceRule: fr.Rule}

	// Handle disabled rules
	if fr.Enabled != nil && !*fr.Enabled {
		cr.Status = "disabled"
		return cr
	}

	rule := &ConvertedRule{
		ID:          fmt.Sprintf("falco_imported_%03d", idx),
		Name:        fr.Rule,
		Description: fr.Desc,
		Severity:    mapPriority(fr.Priority),
		Action:      "alert",
		Tags:        fr.Tags,
	}

	// Parse condition to determine event type and conditions
	eventType, condition, unsupported := parseCondition(fr.Condition)
	if len(unsupported) > 0 {
		cr.Status = "unsupported"
		cr.UnsupportedReasons = unsupported
		cr.SourceRule = fr.Rule
		// Still attach partial result for documentation
		rule.EventType = eventType
		rule.Condition = condition
		cr.Converted = rule
		return cr
	}

	rule.EventType = eventType
	rule.Condition = condition
	cr.Converted = rule
	cr.Status = "converted"
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

// parseCondition converts a Falco condition string into an ebpf-guard condition map.
// Returns (eventType, condition, unsupportedReasons).
func parseCondition(condition string) (string, map[string]interface{}, []string) {
	if condition == "" {
		return "syscall", nil, []string{"empty condition"}
	}

	cond := strings.TrimSpace(condition)
	var unsupported []string

	// Detect event type from condition tokens
	eventType := detectEventType(cond)

	// Build condition map by parsing well-known Falco filter expressions.
	// We parse a flat AND-list of known atoms; complex boolean logic is unsupported.
	atoms := splitTopLevelAnd(cond)
	if len(atoms) == 0 {
		return eventType, nil, []string{"could not parse condition: " + condition}
	}

	var conditions []map[string]interface{}
	for _, atom := range atoms {
		mapped, reason := mapAtom(strings.TrimSpace(atom))
		if reason != "" {
			unsupported = append(unsupported, reason)
		} else if mapped != nil {
			conditions = append(conditions, mapped)
		}
	}

	if len(unsupported) > 0 {
		return eventType, nil, unsupported
	}

	var result map[string]interface{}
	if len(conditions) == 1 {
		result = conditions[0]
	} else if len(conditions) > 1 {
		result = map[string]interface{}{
			"operator":   "AND",
			"conditions": conditions,
		}
	}

	return eventType, result, nil
}

// detectEventType guesses the ebpf-guard event_type from Falco condition tokens.
func detectEventType(cond string) string {
	lower := strings.ToLower(cond)
	switch {
	case strings.Contains(lower, "fd.") || strings.Contains(lower, "open") ||
		strings.Contains(lower, "read") || strings.Contains(lower, "write") ||
		strings.Contains(lower, "fd.name"):
		return "file"
	case strings.Contains(lower, "inbound") || strings.Contains(lower, "outbound") ||
		strings.Contains(lower, "fd.sip") || strings.Contains(lower, "fd.dip") ||
		strings.Contains(lower, "fd.sport") || strings.Contains(lower, "fd.dport") ||
		strings.Contains(lower, "connection"):
		return "network"
	case strings.Contains(lower, "evt.type = execve") || strings.Contains(lower, "evt.type=execve"):
		return "syscall"
	default:
		return "syscall"
	}
}

// mapAtom converts a single Falco filter atom to an ebpf-guard condition map.
func mapAtom(atom string) (map[string]interface{}, string) {
	atom = strings.TrimSpace(atom)

	// Skip macro references (no '=' or 'contains')
	if !strings.Contains(atom, "=") && !strings.Contains(atom, " contains ") &&
		!strings.Contains(atom, " in ") && !strings.Contains(atom, " startswith ") {
		return nil, fmt.Sprintf("unsupported atom (macro reference or complex expr): %q", atom)
	}

	// evt.type = execve / evt.type in (...)
	if strings.HasPrefix(atom, "evt.type") {
		return mapEvtType(atom)
	}

	// fd.name contains "..."
	if strings.Contains(atom, "fd.name contains") {
		val := extractQuoted(atom)
		if val == "" {
			return nil, fmt.Sprintf("could not extract value from: %q", atom)
		}
		return map[string]interface{}{"field": "file_path", "op": "contains", "values": []string{val}}, ""
	}

	// fd.name startswith "..."
	if strings.Contains(atom, "fd.name startswith") {
		val := extractQuoted(atom)
		if val == "" {
			return nil, fmt.Sprintf("could not extract value from: %q", atom)
		}
		return map[string]interface{}{"field": "file_path", "op": "prefix", "values": []string{val}}, ""
	}

	// proc.name = "..." or proc.name in (...)
	if strings.HasPrefix(atom, "proc.name") {
		return mapProcName(atom)
	}

	// container.id != host
	if strings.Contains(atom, "container.id") {
		if strings.Contains(atom, "!= host") || strings.Contains(atom, "!=host") {
			return map[string]interface{}{"field": "in_container", "op": "eq", "values": []string{"true"}}, ""
		}
		return nil, fmt.Sprintf("unsupported container.id expression: %q", atom)
	}

	// fd.sport / fd.dport
	if strings.Contains(atom, "fd.sport") || strings.Contains(atom, "fd.dport") {
		return mapPort(atom)
	}

	// fd.sip / fd.dip
	if strings.Contains(atom, "fd.sip") || strings.Contains(atom, "fd.dip") {
		val := extractQuoted(atom)
		if val == "" {
			return nil, fmt.Sprintf("could not extract IP from: %q", atom)
		}
		return map[string]interface{}{"field": "remote_ip", "op": "in_cidr", "values": []string{val}}, ""
	}

	// user.name
	if strings.Contains(atom, "user.name") {
		val := extractQuoted(atom)
		if val == "" {
			vals := extractInList(atom)
			if len(vals) == 0 {
				return nil, fmt.Sprintf("could not extract user from: %q", atom)
			}
			return map[string]interface{}{"field": "username", "op": "in", "values": vals}, ""
		}
		return map[string]interface{}{"field": "username", "op": "eq", "values": []string{val}}, ""
	}

	return nil, fmt.Sprintf("unsupported Falco filter expression: %q", atom)
}

func mapEvtType(atom string) (map[string]interface{}, string) {
	// evt.type in (open, openat, ...)
	if strings.Contains(atom, " in ") {
		vals := extractInList(atom)
		if len(vals) > 0 {
			return map[string]interface{}{"field": "syscall_name", "op": "in", "values": vals}, ""
		}
	}
	// evt.type = open / evt.type = execve  (single equality)
	if strings.Contains(atom, "=") {
		parts := strings.SplitN(atom, "=", 2)
		if len(parts) == 2 {
			val := strings.TrimSpace(parts[1])
			val = strings.Trim(val, `"' `)
			if val != "" {
				return map[string]interface{}{"field": "syscall_name", "op": "eq", "values": []string{val}}, ""
			}
		}
	}
	return nil, fmt.Sprintf("unsupported evt.type expression: %q", atom)
}

func mapProcName(atom string) (map[string]interface{}, string) {
	// proc.name in (nginx, apache2)
	if strings.Contains(atom, " in ") {
		vals := extractInList(atom)
		if len(vals) == 0 {
			return nil, fmt.Sprintf("could not extract proc list from: %q", atom)
		}
		op := "in"
		if strings.Contains(atom, "not in") {
			op = "not_in"
		}
		return map[string]interface{}{"field": "comm", "op": op, "values": vals}, ""
	}
	// proc.name = "nginx"
	if strings.Contains(atom, "=") {
		val := extractQuoted(atom)
		if val == "" {
			// unquoted value
			parts := strings.SplitN(atom, "=", 2)
			if len(parts) == 2 {
				val = strings.TrimSpace(parts[1])
			}
		}
		if val == "" {
			return nil, fmt.Sprintf("could not extract proc.name value from: %q", atom)
		}
		op := "eq"
		if strings.Contains(atom, "!=") {
			op = "neq"
		}
		return map[string]interface{}{"field": "comm", "op": op, "values": []string{val}}, ""
	}
	return nil, fmt.Sprintf("unsupported proc.name expression: %q", atom)
}

func mapPort(atom string) (map[string]interface{}, string) {
	vals := extractInList(atom)
	if len(vals) > 0 {
		return map[string]interface{}{"field": "dst_port", "op": "in", "values": vals}, ""
	}
	// single value
	parts := strings.SplitN(atom, "=", 2)
	if len(parts) == 2 {
		val := strings.TrimSpace(parts[1])
		val = strings.Trim(val, `"'`)
		return map[string]interface{}{"field": "dst_port", "op": "eq", "values": []string{val}}, ""
	}
	return nil, fmt.Sprintf("unsupported port expression: %q", atom)
}

// splitTopLevelAnd splits a Falco condition on top-level " and " tokens,
// not splitting inside parentheses.
func splitTopLevelAnd(cond string) []string {
	var parts []string
	depth := 0
	start := 0

	lower := strings.ToLower(cond)
	for i := 0; i < len(lower); i++ {
		switch lower[i] {
		case '(':
			depth++
		case ')':
			depth--
		}
		if depth == 0 && i+5 <= len(lower) && lower[i:i+5] == " and " {
			parts = append(parts, strings.TrimSpace(cond[start:i]))
			start = i + 5
			i += 4
		}
	}
	if start < len(cond) {
		parts = append(parts, strings.TrimSpace(cond[start:]))
	}
	return parts
}

// extractQuoted extracts the first double-quoted string value from an expression.
func extractQuoted(s string) string {
	start := strings.Index(s, `"`)
	if start == -1 {
		return ""
	}
	end := strings.Index(s[start+1:], `"`)
	if end == -1 {
		return ""
	}
	return s[start+1 : start+1+end]
}

// extractInList extracts values from a Falco "in (a, b, c)" expression.
func extractInList(s string) []string {
	start := strings.Index(s, "(")
	end := strings.LastIndex(s, ")")
	if start == -1 || end == -1 || end <= start {
		return nil
	}
	inner := s[start+1 : end]
	var vals []string
	for _, v := range strings.Split(inner, ",") {
		v = strings.TrimSpace(v)
		v = strings.Trim(v, `"'`)
		if v != "" {
			vals = append(vals, v)
		}
	}
	return vals
}

func stringField(m map[string]interface{}, key string) string {
	v, _ := m[key].(string)
	return v
}
