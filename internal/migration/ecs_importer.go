// Package migration provides ECS rule importer for converting Elastic Common Schema rules.
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

// ECSRule represents a parsed Elastic Security detection rule.
type ECSRule struct {
	Name        string                 `yaml:"name"`
	ID          string                 `yaml:"id"`
	Description string                 `yaml:"description"`
	Type        string                 `yaml:"type"`
	Language    string                 `yaml:"language"`
	Query       string                 `yaml:"query"`
	Severity    string                 `yaml:"severity"`
	RiskScore   int                    `yaml:"risk_score"`
	Tags        []string               `yaml:"tags"`
	// Structured detection format (alternative to query)
	Detection map[string]interface{} `yaml:"detection"`
}

// ECSConvertedRule is the ebpf-guard YAML rule produced by the ECS converter.
type ECSConvertedRule struct {
	ID             string            `yaml:"id"`
	Name           string            `yaml:"name"`
	Description    string            `yaml:"description,omitempty"`
	EventType      string            `yaml:"event_type"`
	ConditionGroup *ECSConvCondGroup `yaml:"condition_group,omitempty"`
	Severity       string            `yaml:"severity"`
	Action         string            `yaml:"action"`
	Tags           []string          `yaml:"tags,omitempty"`
}

// ECSConvCond is a single field condition.
type ECSConvCond struct {
	Field  string   `yaml:"field"`
	Op     string   `yaml:"op"`
	Values []string `yaml:"values"`
}

// ECSConvCondGroup combines multiple conditions with AND/OR logic.
type ECSConvCondGroup struct {
	Operator   string          `yaml:"operator"`
	Conditions []ECSConvCond   `yaml:"conditions,omitempty"`
	SubGroups  []ECSConvCondGroup `yaml:"subgroups,omitempty"`
}

// ECSConversionResult holds the outcome of converting one ECS rule.
type ECSConversionResult struct {
	SourceRule         string
	Converted          *ECSConvertedRule
	Status             string // "converted" | "unsupported" | "disabled"
	UnsupportedReasons []string
}

// ECSImportResult is the aggregate result of importing ECS rules.
type ECSImportResult struct {
	Results     []ECSConversionResult
	Converted   int
	Unsupported int
	Disabled    int
}

// ECSImporter converts Elastic ECS-based detection rules to ebpf-guard YAML.
type ECSImporter struct {
	logger *slog.Logger
}

// NewECSImporter creates a new ECSImporter.
func NewECSImporter() *ECSImporter {
	return &ECSImporter{logger: slog.Default()}
}

// ecsEventCategoryMap maps ECS event categories to ebpf-guard event types.
var ecsEventCategoryMap = map[string]string{
	"process": "syscall",
	"network": "network",
	"file":    "file",
	"dns":     "dns",
}

// ecsFieldMap maps ECS field names to ebpf-guard field names.
// Fields that map to "" are explicitly unsupported.
var ecsFieldMap = map[string]string{
	// Process
	"process.name":        "comm",
	"process.executable":  "comm",
	"process.args":        "args",
	"process.pid":         "pid",
	"process.ppid":        "ppid",
	"process.parent.name": "parent_comm",
	"user.id":             "uid",
	"user.name":           "uid",
	// Network
	"destination.ip":   "daddr",
	"destination.port": "dport",
	"source.ip":        "saddr",
	"source.port":      "sport",
	"network.transport": "proto",
	"network.protocol":  "proto",
	"network.direction": "evt_dir",
	// File
	"file.path": "filename",
	"file.name": "filename",
	"file.directory": "dir",
	// DNS
	"dns.question.name": "qname",
	"dns.question.type": "qtype",
}

// ImportFile reads a single ECS rule file and converts it.
func (e *ECSImporter) ImportFile(path string) (*ECSImportResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read ecs rules file: %w", err)
	}
	idx := 0
	return e.importWithIdx(data, &idx)
}

// ImportDir converts all .yaml/.yml ECS rule files found in dir.
func (e *ECSImporter) ImportDir(dir string) (*ECSImportResult, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read ecs rules directory: %w", err)
	}

	combined := &ECSImportResult{}
	idx := 0

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext != ".yaml" && ext != ".yml" && ext != ".ndjson" {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			e.logger.Warn("ecs: skipping unreadable file",
				slog.String("path", path), slog.Any("error", err))
			continue
		}
		result, err := e.importWithIdx(data, &idx)
		if err != nil {
			e.logger.Warn("ecs: skipping unparseable file",
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

// Import converts a single ECS YAML document.
func (e *ECSImporter) Import(data []byte) (*ECSImportResult, error) {
	idx := 0
	return e.importWithIdx(data, &idx)
}

func (e *ECSImporter) importWithIdx(data []byte, idx *int) (*ECSImportResult, error) {
	var er ECSRule
	if err := yaml.Unmarshal(data, &er); err != nil {
		return nil, fmt.Errorf("parse ecs YAML: %w", err)
	}
	if er.Name == "" {
		return &ECSImportResult{}, nil
	}

	*idx++
	cr := e.convertRule(*idx, er)
	result := &ECSImportResult{}
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
func (e *ECSImporter) WriteOutput(result *ECSImportResult) ([]byte, error) {
	type rulesFile struct {
		Rules []*ECSConvertedRule `yaml:"rules"`
	}
	var rules []*ECSConvertedRule
	for _, r := range result.Results {
		if r.Status == "converted" && r.Converted != nil {
			rules = append(rules, r.Converted)
		}
	}
	return yaml.Marshal(rulesFile{Rules: rules})
}

// convertRule converts a single parsed ECS rule to an ebpf-guard rule.
func (e *ECSImporter) convertRule(idx int, er ECSRule) ECSConversionResult {
	cr := ECSConversionResult{SourceRule: er.Name}

	// Derive event type from query or detection context.
	eventType := e.detectEventType(er)
	if eventType == "" {
		cr.Status = "unsupported"
		cr.UnsupportedReasons = []string{"could not determine event type — no recognised ECS fields in query"}
		return cr
	}

	// Parse conditions from query or detection block.
	var group *ECSConvCondGroup
	var reasons []string

	if er.Detection != nil && len(er.Detection) > 0 {
		group, reasons = e.parseDetectionBlock(er.Detection, eventType)
	} else if er.Query != "" {
		group, reasons = e.parseQuery(er.Query, eventType)
	} else {
		reasons = []string{"no query or detection block found"}
	}

	if len(reasons) > 0 {
		cr.Status = "unsupported"
		cr.UnsupportedReasons = reasons
		return cr
	}
	if group == nil {
		cr.Status = "unsupported"
		cr.UnsupportedReasons = []string{"no usable conditions extracted"}
		return cr
	}

	// Derive rule ID.
	id := fmt.Sprintf("ecs_imported_%03d", idx)
	if er.ID != "" {
		if strings.Contains(er.ID, "-") {
			id = "ecs_" + strings.ReplaceAll(er.ID, "-", "")[:min(8, len(strings.ReplaceAll(er.ID, "-", "")))]
		} else {
			id = "ecs_" + er.ID
		}
	}

	rule := &ECSConvertedRule{
		ID:             id,
		Name:           er.Name,
		Description:    er.Description,
		EventType:      eventType,
		ConditionGroup: group,
		Severity:       mapECSSeverity(er.Severity, er.RiskScore),
		Action:         "alert",
		Tags:           normalizeECSTags(er.Tags),
	}

	cr.Status = "converted"
	cr.Converted = rule
	return cr
}

// detectEventType heuristically determines the ebpf-guard event type from the rule content.
func (e *ECSImporter) detectEventType(er ECSRule) string {
	searchText := strings.ToLower(er.Query)
	if er.Name != "" {
		searchText += " " + strings.ToLower(er.Name)
	}
	for _, t := range er.Tags {
		searchText += " " + strings.ToLower(t)
	}

	// Check detection block field names.
	if er.Detection != nil {
		for k := range er.Detection {
			searchText += " " + strings.ToLower(k)
		}
	}

	// Check for process-related fields.
	processIndicators := []string{"process.", "process_name", "processname", "executable"}
	for _, ind := range processIndicators {
		if strings.Contains(searchText, ind) {
			return "syscall"
		}
	}

	// Check for network-related fields.
	networkIndicators := []string{"destination.ip", "destination.port", "source.ip", "source.port",
		"network.", "dst_ip", "src_ip", "dport", "sport", "connection", "outbound", "inbound"}
	for _, ind := range networkIndicators {
		if strings.Contains(searchText, ind) {
			return "network"
		}
	}

	// Check for file-related fields.
	fileIndicators := []string{"file.path", "file.name", "filename", "file_event",
		"fileaccess", "file access", "open", "read(", "write("}
	for _, ind := range fileIndicators {
		if strings.Contains(searchText, ind) {
			return "file"
		}
	}

	// Check for DNS-related fields.
	dnsIndicators := []string{"dns.", "question.name", "question.type", "dns_query", "dns query"}
	for _, ind := range dnsIndicators {
		if strings.Contains(searchText, ind) {
			return "dns"
		}
	}

	// Check detection block categories.
	if er.Detection != nil {
		for k := range er.Detection {
			if cat, ok := ecsEventCategoryMap[strings.ToLower(k)]; ok {
				return cat
			}
		}
	}

	return ""
}

// parseDetectionBlock converts a structured detection map to conditions.
func (e *ECSImporter) parseDetectionBlock(detection map[string]interface{}, eventType string) (*ECSConvCondGroup, []string) {
	var conds []ECSConvCond
	var reasons []string

	for field, rawVal := range detection {
		field = e.normalizeFieldName(field)

		ebpfField, ok := ecsFieldMap[field]
		if !ok || ebpfField == "" {
			e.logger.Warn("ecs: skipping unsupported detection field",
				slog.String("field", field), slog.String("event_type", eventType))
			continue
		}

		values := extractECSValues(rawVal)
		if len(values) == 0 {
			continue
		}

		op := "equals"
		if len(values) > 1 {
			op = "in"
		}

		conds = append(conds, ECSConvCond{Field: ebpfField, Op: op, Values: values})
	}

	if len(conds) == 0 {
		return nil, []string{"detection block produced no supported conditions"}
	}

	return &ECSConvCondGroup{Operator: "and", Conditions: conds}, reasons
}

// parseQuery converts an ECS query string (Lucene/EQL-like) to conditions.
func (e *ECSImporter) parseQuery(query string, eventType string) (*ECSConvCondGroup, []string) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, []string{"empty query"}
	}

	// Default to "and" for single-condition queries.
	var operator string = "and"
	var atoms []string

	if parts := splitECSQueryOp(query, " and "); len(parts) > 1 {
		operator = "and"
		atoms = parts
	} else if parts := splitECSQueryOp(query, " or "); len(parts) > 1 {
		operator = "or"
		atoms = parts
	} else if parts := splitECSQueryOp(query, " AND "); len(parts) > 1 {
		operator = "and"
		atoms = parts
	} else if parts := splitECSQueryOp(query, " OR "); len(parts) > 1 {
		operator = "or"
		atoms = parts
	} else if parts := splitECSQueryOp(query, " && "); len(parts) > 1 {
		operator = "and"
		atoms = parts
	} else if parts := splitECSQueryOp(query, " || "); len(parts) > 1 {
		operator = "or"
		atoms = parts
	}

	if len(atoms) == 0 {
		atoms = []string{query}
	}

	var conds []ECSConvCond
	for _, atom := range atoms {
		cond, reason := e.parseECSAtom(strings.TrimSpace(atom), eventType)
		if reason != "" {
			e.logger.Warn("ecs: skipping atom", slog.String("atom", atom), slog.String("reason", reason))
			continue
		}
		if cond != nil {
			conds = append(conds, *cond)
		}
	}

	if len(conds) == 0 {
		return nil, []string{"query produced no supported conditions: " + query}
	}

	return &ECSConvCondGroup{Operator: operator, Conditions: conds}, nil
}

// parseECSAtom parses a single query atom like "process.name:bash" or "destination.port:443".
func (e *ECSImporter) parseECSAtom(atom string, eventType string) (*ECSConvCond, string) {
	// EQL "where" syntax: process where process.name == "bash"
	if strings.Contains(atom, " where ") {
		parts := strings.SplitN(atom, " where ", 2)
		if len(parts) == 2 {
			return e.parseEQLCondition(strings.TrimSpace(parts[1]))
		}
	}

	// Field:value syntax (Lucene).
	if strings.Contains(atom, ":") {
		return e.parseLucenePair(atom)
	}

	// Field operator value (EQL).
	for _, op := range []string{"==", "!=", ">=", "<=", ">", "<"} {
		if strings.Contains(atom, " "+op+" ") {
			return e.parseEQLCondition(atom)
		}
	}

	return nil, fmt.Sprintf("could not parse query atom: %q", atom)
}

// parseLucenePair parses "field:value" Lucene syntax.
func (e *ECSImporter) parseLucenePair(atom string) (*ECSConvCond, string) {
	idx := strings.Index(atom, ":")
	if idx <= 0 {
		return nil, fmt.Sprintf("invalid lucene pair: %q", atom)
	}

	field := strings.TrimSpace(atom[:idx])
	value := strings.TrimSpace(atom[idx+1:])
	value = strings.Trim(value, `"'`)

	if value == "" {
		return nil, fmt.Sprintf("empty value in: %q", atom)
	}

	field = e.normalizeFieldName(field)

	ebpfField, ok := ecsFieldMap[field]
	if !ok || ebpfField == "" {
		return nil, fmt.Sprintf("no ebpf-guard mapping for ECS field %q", field)
	}

	// Handle wildcards.
	if strings.Contains(value, "*") {
		pattern := "^" + strings.ReplaceAll(regexp.QuoteMeta(value), `\*`, ".*") + "$"
		return &ECSConvCond{Field: ebpfField, Op: "regex", Values: []string{pattern}}, ""
	}

	return &ECSConvCond{Field: ebpfField, Op: "equals", Values: []string{value}}, ""
}

// parseEQLCondition parses a simple EQL condition like "process.name == \"bash\"".
func (e *ECSImporter) parseEQLCondition(cond string) (*ECSConvCond, string) {
	var field, operator, value string

	for _, op := range []string{"==", "!=", ">=", "<=", ">", "<"} {
		if idx := strings.Index(cond, " "+op+" "); idx > 0 {
			field = strings.TrimSpace(cond[:idx])
			operator = op
			value = strings.TrimSpace(cond[idx+len(op)+2:])
			break
		}
	}

	if field == "" {
		return nil, fmt.Sprintf("could not parse EQL condition: %q", cond)
	}

	value = strings.Trim(value, `"'`)

	field = e.normalizeFieldName(field)

	ebpfField, ok := ecsFieldMap[field]
	if !ok || ebpfField == "" {
		return nil, fmt.Sprintf("no ebpf-guard mapping for ECS field %q", field)
	}

	ebpfOp := "equals"
	switch operator {
	case "!=":
		ebpfOp = "not_equals"
	case ">", ">=":
		ebpfOp = "gte"
	case "<", "<=":
		ebpfOp = "lte"
	}

	return &ECSConvCond{Field: ebpfField, Op: ebpfOp, Values: []string{value}}, ""
}

// normalizeFieldName lowercases and trims the ECS field name for consistent lookup.
func (e *ECSImporter) normalizeFieldName(field string) string {
	return strings.TrimSpace(strings.ToLower(field))
}

// splitECSQueryOp splits query on op at top level (outside of quotes).
func splitECSQueryOp(query, op string) []string {
	lowerQuery := strings.ToLower(query)
	lowerOp := strings.ToLower(op)
	opLen := len(op)

	var parts []string
	inQuote := false
	start := 0

	for i := 0; i < len(lowerQuery); i++ {
		if lowerQuery[i] == '"' {
			if inQuote {
				inQuote = false
			} else {
				inQuote = true
			}
			continue
		}
		if inQuote {
			continue
		}
		if i+opLen <= len(lowerQuery) && lowerQuery[i:i+opLen] == lowerOp {
			parts = append(parts, strings.TrimSpace(query[start:i]))
			start = i + opLen
			i += opLen - 1
		}
	}
	if start < len(query) {
		parts = append(parts, strings.TrimSpace(query[start:]))
	}
	return parts
}

// extractECSValues coerces a YAML value to []string.
func extractECSValues(v interface{}) []string {
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
	case bool:
		return []string{fmt.Sprintf("%v", val)}
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

// mapECSSeverity converts ECS severity/risk_score to ebpf-guard severity.
func mapECSSeverity(severity string, riskScore int) string {
	s := strings.ToLower(severity)
	switch {
	case s == "critical" || riskScore >= 73:
		return "critical"
	case s == "high" || riskScore >= 47:
		return "critical"
	case s == "medium" || riskScore >= 21:
		return "warning"
	default:
		return "warning"
	}
}

// normalizeECSTags converts Elastic-style tags to ebpf-guard format.
func normalizeECSTags(tags []string) []string {
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		lower := strings.ToLower(t)
		switch {
		case strings.HasPrefix(lower, "attack.t"):
			out = append(out, "mitre:"+strings.ToUpper(lower[7:]))
		case strings.HasPrefix(lower, "attack."):
			out = append(out, strings.TrimPrefix(lower, "attack."))
		default:
			out = append(out, lower)
		}
	}
	return out
}
