package migration

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// SigmaRule represents a parsed Sigma rule YAML document.
type SigmaRule struct {
	Title       string                 `yaml:"title"`
	ID          string                 `yaml:"id"`
	Status      string                 `yaml:"status"`
	Description string                 `yaml:"description"`
	LogSource   SigmaLogSource         `yaml:"logsource"`
	Detection   map[string]interface{} `yaml:"detection"`
	Level       string                 `yaml:"level"`
	Tags        []string               `yaml:"tags"`
}

// SigmaLogSource identifies the event category a Sigma rule applies to.
type SigmaLogSource struct {
	Category string `yaml:"category"`
	Product  string `yaml:"product"`
	Service  string `yaml:"service"`
}

// SigmaCondition is a single field condition in an ebpf-guard rule.
type SigmaCondition struct {
	Field  string   `yaml:"field"`
	Op     string   `yaml:"op"`
	Values []string `yaml:"values"`
}

// SigmaConditionGroup combines multiple conditions with AND/OR logic.
type SigmaConditionGroup struct {
	Operator   string                `yaml:"operator"`
	Conditions []SigmaCondition      `yaml:"conditions,omitempty"`
	SubGroups  []SigmaConditionGroup `yaml:"subgroups,omitempty"`
}

// SigmaConvertedRule is the ebpf-guard YAML rule produced by the Sigma converter.
type SigmaConvertedRule struct {
	ID             string               `yaml:"id"`
	Name           string               `yaml:"name"`
	Description    string               `yaml:"description,omitempty"`
	EventType      string               `yaml:"event_type"`
	Condition      *SigmaCondition      `yaml:"condition,omitempty"`
	ConditionGroup *SigmaConditionGroup `yaml:"condition_group,omitempty"`
	Severity       string               `yaml:"severity"`
	Action         string               `yaml:"action"`
	Tags           []string             `yaml:"tags,omitempty"`
}

// SigmaConversionResult holds the outcome of converting one Sigma rule.
type SigmaConversionResult struct {
	SourceRule         string
	Converted          *SigmaConvertedRule
	Status             string // "converted" | "unsupported" | "disabled"
	UnsupportedReasons []string
}

// SigmaImportResult is the aggregate result of importing Sigma rules.
type SigmaImportResult struct {
	Results     []SigmaConversionResult
	Converted   int
	Unsupported int
	Disabled    int
}

// SigmaImporter converts Sigma YAML rules to ebpf-guard correlator rules.
type SigmaImporter struct {
	logger *slog.Logger
}

// NewSigmaImporter creates a new SigmaImporter.
func NewSigmaImporter() *SigmaImporter {
	return &SigmaImporter{logger: slog.Default()}
}

// sigmaLogsourceMap maps Sigma logsource.category to ebpf-guard event_type strings.
var sigmaLogsourceMap = map[string]string{
	"process_creation":  "syscall",
	"network_connection": "network",
	"file_event":        "file",
	"file_access":       "file",
	"dns_query":         "dns",
	"dns":               "dns",
}

// sigmaFieldMap maps Sigma field names to ebpf-guard field names, keyed by event type.
// Fields that map to "" are explicitly unsupported (emit WARN, skip).
var sigmaFieldMap = map[string]map[string]string{
	"syscall": {
		"Image":       "comm",
		"ProcessName": "comm",
		"Exe":         "comm",
		"User":        "uid",
		"SubjectUserName": "uid",
		"EventID":     "nr",
		// Intentionally omitted (no mapping yet): CommandLine, ParentImage, ProcessId
	},
	"network": {
		"DestinationIp":   "daddr",
		"DestinationPort": "dport",
		"SourceIp":        "saddr",
		"SourcePort":      "sport",
		"dst_ip":          "daddr",
		"dst_port":        "dport",
		"src_ip":          "saddr",
		"src_port":        "sport",
		"Protocol":        "proto",
	},
	"file": {
		"TargetFilename": "filename",
		"TargetObject":   "filename",
		"FileName":       "filename",
		"Path":           "filename",
	},
	"dns": {
		"QueryName":          "qname",
		"dns.question.name":  "qname",
		"query":              "qname",
		"QueryType":          "qtype",
	},
}

// ImportFile reads a single Sigma rule file and converts it.
func (s *SigmaImporter) ImportFile(path string) (*SigmaImportResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read sigma rules file: %w", err)
	}
	idx := 0
	return s.importWithIdx(data, &idx)
}

// ImportDir converts all .yml/.yaml Sigma files found directly in dir.
func (s *SigmaImporter) ImportDir(dir string) (*SigmaImportResult, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read sigma rules directory: %w", err)
	}

	combined := &SigmaImportResult{}
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
		data, err := os.ReadFile(path)
		if err != nil {
			s.logger.Warn("sigma: skipping unreadable file",
				slog.String("path", path), slog.Any("error", err))
			continue
		}
		result, err := s.importWithIdx(data, &idx)
		if err != nil {
			s.logger.Warn("sigma: skipping unparseable file",
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

// Import converts a single Sigma YAML document.
func (s *SigmaImporter) Import(data []byte) (*SigmaImportResult, error) {
	idx := 0
	return s.importWithIdx(data, &idx)
}

func (s *SigmaImporter) importWithIdx(data []byte, idx *int) (*SigmaImportResult, error) {
	var sr SigmaRule
	if err := yaml.Unmarshal(data, &sr); err != nil {
		return nil, fmt.Errorf("parse sigma YAML: %w", err)
	}
	if sr.Title == "" && sr.Detection == nil {
		return &SigmaImportResult{}, nil
	}

	*idx++
	cr := s.convertRule(*idx, sr)
	result := &SigmaImportResult{}
	switch cr.Status {
	case "converted":
		result.Converted++
	case "unsupported":
		result.Unsupported++
	case "disabled":
		result.Disabled++
	}
	result.Results = append(result.Results, cr)
	return result, nil
}

// WriteOutput serializes converted rules to ebpf-guard YAML.
func (s *SigmaImporter) WriteOutput(result *SigmaImportResult) ([]byte, error) {
	type rulesFile struct {
		Rules []*SigmaConvertedRule `yaml:"rules"`
	}
	var rules []*SigmaConvertedRule
	for _, r := range result.Results {
		if r.Status == "converted" && r.Converted != nil {
			rules = append(rules, r.Converted)
		}
	}
	return yaml.Marshal(rulesFile{Rules: rules})
}

// convertRule converts a single parsed Sigma rule to an ebpf-guard rule.
func (s *SigmaImporter) convertRule(idx int, sr SigmaRule) SigmaConversionResult {
	cr := SigmaConversionResult{SourceRule: sr.Title}

	if strings.EqualFold(sr.Status, "deprecated") {
		cr.Status = "disabled"
		return cr
	}

	// Map logsource category to ebpf-guard event type.
	eventType, ok := sigmaLogsourceMap[strings.ToLower(sr.LogSource.Category)]
	if !ok {
		cr.Status = "unsupported"
		cr.UnsupportedReasons = []string{
			fmt.Sprintf("unsupported logsource.category %q (supported: process_creation, network_connection, file_event, dns_query)",
				sr.LogSource.Category),
		}
		return cr
	}

	if sr.Detection == nil {
		cr.Status = "unsupported"
		cr.UnsupportedReasons = []string{"rule has no detection section"}
		return cr
	}

	condExpr, _ := sr.Detection["condition"].(string)
	if condExpr == "" {
		cr.Status = "unsupported"
		cr.UnsupportedReasons = []string{"detection.condition is missing or empty"}
		return cr
	}

	// Collect named selection groups (skip reserved keys).
	groups := make(map[string]map[string]interface{})
	for k, v := range sr.Detection {
		if k == "condition" || k == "timeframe" {
			continue
		}
		if m, ok := v.(map[string]interface{}); ok {
			groups[k] = m
		}
	}

	node, unsupported := s.parseConditionExpr(condExpr, groups, eventType)
	if len(unsupported) > 0 {
		cr.Status = "unsupported"
		cr.UnsupportedReasons = unsupported
		return cr
	}
	if node == nil {
		cr.Status = "unsupported"
		cr.UnsupportedReasons = []string{"detection produced no usable conditions"}
		return cr
	}

	// Derive a stable rule ID.
	id := buildRuleID(sr.ID, idx)

	rule := &SigmaConvertedRule{
		ID:          id,
		Name:        sr.Title,
		Description: sr.Description,
		EventType:   eventType,
		Severity:    mapSigmaLevel(sr.Level),
		Action:      "alert",
		Tags:        normalizeSigmaTags(sr.Tags),
	}
	if node.single != nil {
		rule.Condition = node.single
	} else {
		rule.ConditionGroup = node.group
	}

	cr.Status = "converted"
	cr.Converted = rule
	return cr
}

// buildRuleID produces a deterministic rule ID from a Sigma UUID or fallback index.
func buildRuleID(sigmaID string, idx int) string {
	if sigmaID == "" {
		return fmt.Sprintf("sigma_imported_%03d", idx)
	}
	// Use the first 8 hex chars (before first '-') as a stable short ID.
	short := strings.ReplaceAll(sigmaID, "-", "")
	if len(short) > 8 {
		short = short[:8]
	}
	return "sigma_" + short
}

// mapSigmaLevel converts a Sigma level string to an ebpf-guard severity.
func mapSigmaLevel(level string) string {
	switch strings.ToLower(level) {
	case "critical", "high":
		return "critical"
	default:
		return "warning"
	}
}

// normalizeSigmaTags converts Sigma ATT&CK tags (attack.tXXXX) to mitre: prefixed tags.
func normalizeSigmaTags(tags []string) []string {
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		lower := strings.ToLower(t)
		switch {
		case strings.HasPrefix(lower, "attack.t"):
			// attack.t1059 → mitre:T1059
			out = append(out, "mitre:"+strings.ToUpper(lower[7:]))
		case strings.HasPrefix(lower, "attack."):
			out = append(out, strings.TrimPrefix(lower, "attack."))
		default:
			out = append(out, lower)
		}
	}
	return out
}

// ── Condition expression parsing ─────────────────────────────────────────────

// sigmaConditionNode is the internal union of a single condition or a group.
type sigmaConditionNode struct {
	single *SigmaCondition
	group  *SigmaConditionGroup
}

// parseConditionExpr parses a Sigma condition expression (e.g. "sel and not filter")
// and converts it to an ebpf-guard condition node. Fatal errors are returned as strings.
func (s *SigmaImporter) parseConditionExpr(expr string, groups map[string]map[string]interface{}, eventType string) (*sigmaConditionNode, []string) {
	expr = strings.TrimSpace(expr)
	lower := strings.ToLower(expr)

	// "1 of ..." / "all of ..."
	if strings.HasPrefix(lower, "1 of ") || strings.HasPrefix(lower, "all of ") {
		return s.parseQuantifiedExpr(expr, groups, eventType)
	}

	// NOT is unsupported.
	if strings.HasPrefix(lower, "not ") {
		return nil, []string{"NOT conditions are not supported: " + expr}
	}

	// Split on top-level " and " before trying " or " so mixed logic is stable.
	if parts := splitTopLevelOp(expr, " and "); len(parts) > 1 {
		return s.combineNodes(parts, groups, eventType, "and")
	}
	if parts := splitTopLevelOp(expr, " or "); len(parts) > 1 {
		return s.combineNodes(parts, groups, eventType, "or")
	}

	// Plain group reference.
	name := strings.TrimSpace(expr)
	g, ok := groups[name]
	if !ok {
		return nil, []string{fmt.Sprintf("unknown detection group %q in condition", name)}
	}
	return s.convertSelectionGroup(g, eventType)
}

// parseQuantifiedExpr handles "1 of X*" and "all of X*" / "them".
func (s *SigmaImporter) parseQuantifiedExpr(expr string, groups map[string]map[string]interface{}, eventType string) (*sigmaConditionNode, []string) {
	lower := strings.ToLower(expr)
	var op, rest string
	if strings.HasPrefix(lower, "1 of ") {
		op = "or"
		rest = strings.TrimSpace(expr[5:])
	} else {
		op = "and"
		rest = strings.TrimSpace(expr[7:]) // "all of "
	}

	var matched []map[string]interface{}
	if strings.EqualFold(rest, "them") {
		for _, g := range groups {
			matched = append(matched, g)
		}
	} else {
		isWild := strings.HasSuffix(rest, "*")
		prefix := strings.ToLower(strings.TrimSuffix(rest, "*"))
		for name, g := range groups {
			if isWild {
				if strings.HasPrefix(strings.ToLower(name), prefix) {
					matched = append(matched, g)
				}
			} else if strings.EqualFold(name, rest) {
				matched = append(matched, g)
			}
		}
	}

	if len(matched) == 0 {
		return nil, []string{fmt.Sprintf("no groups matched by: %s", expr)}
	}
	if len(matched) == 1 {
		return s.convertSelectionGroup(matched[0], eventType)
	}

	var nodes []*sigmaConditionNode
	for _, g := range matched {
		n, unsup := s.convertSelectionGroup(g, eventType)
		if len(unsup) > 0 {
			return nil, unsup
		}
		if n != nil {
			nodes = append(nodes, n)
		}
	}
	return mergeNodes(nodes, op), nil
}

// combineNodes converts multiple sub-expressions and merges them with op.
func (s *SigmaImporter) combineNodes(parts []string, groups map[string]map[string]interface{}, eventType, op string) (*sigmaConditionNode, []string) {
	var nodes []*sigmaConditionNode
	for _, p := range parts {
		n, unsup := s.parseConditionExpr(strings.TrimSpace(p), groups, eventType)
		if len(unsup) > 0 {
			return nil, unsup
		}
		if n != nil {
			nodes = append(nodes, n)
		}
	}
	return mergeNodes(nodes, op), nil
}

// mergeNodes flattens/combines multiple condition nodes into a single group node.
func mergeNodes(nodes []*sigmaConditionNode, op string) *sigmaConditionNode {
	if len(nodes) == 0 {
		return nil
	}
	if len(nodes) == 1 {
		return nodes[0]
	}

	var conds []SigmaCondition
	var subs []SigmaConditionGroup
	for _, n := range nodes {
		if n.single != nil {
			conds = append(conds, *n.single)
		} else if n.group != nil {
			subs = append(subs, *n.group)
		}
	}
	return &sigmaConditionNode{
		group: &SigmaConditionGroup{
			Operator:   op,
			Conditions: conds,
			SubGroups:  subs,
		},
	}
}

// convertSelectionGroup turns a Sigma selection map into a condition node.
// Fields that have no ebpf-guard mapping emit a WARN log and are skipped;
// this is non-fatal per the acceptance criteria.
func (s *SigmaImporter) convertSelectionGroup(group map[string]interface{}, eventType string) (*sigmaConditionNode, []string) {
	var conds []SigmaCondition

	for fieldKey, rawVal := range group {
		parts := strings.SplitN(fieldKey, "|", -1)
		sigmaField := parts[0]
		modifiers := parts[1:]

		ebpfField, ok := mapSigmaField(sigmaField, eventType)
		if !ok {
			s.logger.Warn("sigma: skipping unsupported field",
				slog.String("field", sigmaField),
				slog.String("event_type", eventType))
			continue
		}

		values := extractValues(rawVal)
		if len(values) == 0 {
			s.logger.Warn("sigma: skipping field with no usable values",
				slog.String("field", sigmaField))
			continue
		}

		newConds, warn := applyModifiers(ebpfField, modifiers, values)
		if warn != "" {
			s.logger.Warn(warn)
			continue
		}
		conds = append(conds, newConds...)
	}

	if len(conds) == 0 {
		return nil, []string{"selection group produced no supported conditions"}
	}
	if len(conds) == 1 {
		return &sigmaConditionNode{single: &conds[0]}, nil
	}
	return &sigmaConditionNode{
		group: &SigmaConditionGroup{Operator: "and", Conditions: conds},
	}, nil
}

// extractValues coerces a YAML value (string, []interface{}, int, etc.) to []string.
func extractValues(v interface{}) []string {
	switch val := v.(type) {
	case string:
		if val != "" {
			return []string{val}
		}
	case int:
		return []string{fmt.Sprintf("%d", val)}
	case int64:
		return []string{fmt.Sprintf("%d", val)}
	case float64:
		return []string{fmt.Sprintf("%g", val)}
	case []interface{}:
		var out []string
		for _, item := range val {
			switch iv := item.(type) {
			case string:
				if iv != "" {
					out = append(out, iv)
				}
			case int:
				out = append(out, fmt.Sprintf("%d", iv))
			case int64:
				out = append(out, fmt.Sprintf("%d", iv))
			case float64:
				out = append(out, fmt.Sprintf("%g", iv))
			}
		}
		return out
	}
	return nil
}

// applyModifiers maps a Sigma field + modifier list + values to ebpf-guard conditions.
// Returns a non-empty warning string if the modifier is unsupported (skip the field).
func applyModifiers(ebpfField string, modifiers []string, values []string) ([]SigmaCondition, string) {
	mods := make(map[string]bool, len(modifiers))
	for _, m := range modifiers {
		mods[strings.ToLower(m)] = true
	}

	// Reject modifiers we cannot translate.
	unsupportedMods := []string{"base64", "windash", "utf16le", "utf16be", "utf16", "wide"}
	for _, m := range unsupportedMods {
		if mods[m] {
			return nil, fmt.Sprintf("WARN: skipping field %q: unsupported modifier %q", ebpfField, m)
		}
	}

	hasAll := mods["all"]

	switch {
	case mods["cidr"]:
		if ebpfField != "daddr" && ebpfField != "saddr" {
			return nil, fmt.Sprintf("WARN: cidr modifier requires an IP field, not %q", ebpfField)
		}
		return []SigmaCondition{{Field: ebpfField, Op: "in_cidr", Values: values}}, ""

	case mods["re"]:
		return []SigmaCondition{{Field: ebpfField, Op: "regex", Values: values}}, ""

	case mods["startswith"]:
		return []SigmaCondition{{Field: ebpfField, Op: "prefix", Values: values}}, ""

	case mods["endswith"]:
		return []SigmaCondition{{Field: ebpfField, Op: "suffix", Values: values}}, ""

	case mods["contains"]:
		if hasAll {
			// contains|all → one regex condition per value, all must match (caller ANDs them)
			conds := make([]SigmaCondition, 0, len(values))
			for _, v := range values {
				conds = append(conds, SigmaCondition{
					Field:  ebpfField,
					Op:     "regex",
					Values: []string{regexp.QuoteMeta(v)},
				})
			}
			return conds, ""
		}
		// contains → regex OR across all values (multiple patterns = any-match)
		escaped := make([]string, 0, len(values))
		for _, v := range values {
			escaped = append(escaped, regexp.QuoteMeta(v))
		}
		return []SigmaCondition{{Field: ebpfField, Op: "regex", Values: escaped}}, ""

	default:
		// No modifier (or only the consumed "all"): equality / in.
		if len(values) == 1 {
			return []SigmaCondition{{Field: ebpfField, Op: "equals", Values: values}}, ""
		}
		return []SigmaCondition{{Field: ebpfField, Op: "in", Values: values}}, ""
	}
}

// mapSigmaField resolves a Sigma field name to an ebpf-guard field for the given event type.
// Returns ("", false) when the field has no mapping.
func mapSigmaField(sigmaField, eventType string) (string, bool) {
	m, ok := sigmaFieldMap[eventType]
	if !ok {
		return "", false
	}
	f, ok := m[sigmaField]
	if !ok || f == "" {
		return "", false
	}
	return f, true
}

// splitTopLevelOp splits expr on op only at depth 0 (not inside parentheses).
func splitTopLevelOp(expr, op string) []string {
	lowerExpr := strings.ToLower(expr)
	lowerOp := strings.ToLower(op)
	opLen := len(op)

	var parts []string
	depth, start := 0, 0
	for i := 0; i < len(lowerExpr); i++ {
		switch lowerExpr[i] {
		case '(':
			depth++
		case ')':
			depth--
		}
		if depth == 0 && i+opLen <= len(lowerExpr) && lowerExpr[i:i+opLen] == lowerOp {
			parts = append(parts, strings.TrimSpace(expr[start:i]))
			start = i + opLen
			i += opLen - 1
		}
	}
	if start < len(expr) {
		parts = append(parts, strings.TrimSpace(expr[start:]))
	}
	return parts
}
