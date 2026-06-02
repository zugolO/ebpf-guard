// Package explainer provides human-readable explanations for security alerts.
// It uses Go templates to generate contextual explanations with MITRE ATT&CK mappings.
package explainer

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"gopkg.in/yaml.v3"
)

// Explanation contains a human-readable explanation of an alert.
type Explanation struct {
	Summary     string    `json:"summary" yaml:"summary"`
	Detail      string    `json:"detail" yaml:"detail"`
	Severity    string    `json:"severity" yaml:"severity"`
	SeverityWhy string    `json:"severity_why" yaml:"severity_why"`
	Mitigations []string  `json:"mitigations" yaml:"mitigations"`
	References  []string  `json:"references" yaml:"references"`
	MITRE       MITREInfo `json:"mitre" yaml:"mitre"`
}

// MITREInfo contains MITRE ATT&CK mapping information.
type MITREInfo struct {
	Tactic      string `json:"tactic" yaml:"tactic"`
	TechniqueID string `json:"technique_id" yaml:"technique_id"`
	Technique   string `json:"technique" yaml:"technique"`
	URL         string `json:"url" yaml:"url"`
}

// TemplateData contains the data available for template rendering.
type TemplateData struct {
	RuleID      string
	RuleName    string
	Severity    string
	PID         uint32
	Comm        string
	PPID        uint32
	ParentComm  string
	Pod         string
	Namespace   string
	Message     string
	Details     map[string]interface{}
	Fingerprint string
}

// TemplateDefinition defines a single explanation template.
type TemplateDefinition struct {
	ID          string    `yaml:"id"`
	Name        string    `yaml:"name"`
	Category    string    `yaml:"category"`
	Summary     string    `yaml:"summary"`
	Detail      string    `yaml:"detail"`
	Severity    string    `yaml:"severity"`
	SeverityWhy string    `yaml:"severity_why"`
	Mitigations []string  `yaml:"mitigations"`
	References  []string  `yaml:"references"`
	MITRE       MITREInfo `yaml:"mitre"`
}

// TemplateFile represents a YAML file containing multiple templates.
type TemplateFile struct {
	Templates []TemplateDefinition `yaml:"templates"`
}

// Explainer generates human-readable explanations for alerts.
type Explainer struct {
	templates map[string]*TemplateDefinition
	funcs     template.FuncMap
}

// New creates a new Explainer with templates loaded from the given directory.
func New(templatesDir string) (*Explainer, error) {
	e := &Explainer{
		templates: make(map[string]*TemplateDefinition),
		funcs:     make(template.FuncMap),
	}

	// Register template functions
	e.funcs["upper"] = strings.ToUpper
	e.funcs["lower"] = strings.ToLower
	e.funcs["title"] = cases.Title(language.English).String
	e.funcs["trim"] = strings.TrimSpace
	e.funcs["join"] = strings.Join

	// Load templates from directory
	if err := e.loadTemplates(templatesDir); err != nil {
		return nil, fmt.Errorf("load templates: %w", err)
	}

	return e, nil
}

// NewWithDefaults creates an Explainer with embedded default templates.
func NewWithDefaults() (*Explainer, error) {
	e := &Explainer{
		templates: make(map[string]*TemplateDefinition),
		funcs:     make(template.FuncMap),
	}

	e.funcs["upper"] = strings.ToUpper
	e.funcs["lower"] = strings.ToLower
	e.funcs["title"] = cases.Title(language.English).String
	e.funcs["trim"] = strings.TrimSpace
	e.funcs["join"] = strings.Join

	// Load default templates
	if err := e.loadDefaultTemplates(); err != nil {
		return nil, fmt.Errorf("load default templates: %w", err)
	}

	return e, nil
}

// loadTemplates loads all YAML template files from the given directory.
func (e *Explainer) loadTemplates(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			// Directory doesn't exist, use defaults
			return e.loadDefaultTemplates()
		}
		return fmt.Errorf("read templates directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		if err := e.loadTemplateFile(path); err != nil {
			return fmt.Errorf("load template file %s: %w", entry.Name(), err)
		}
	}

	return nil
}

// loadTemplateFile loads a single YAML template file.
func (e *Explainer) loadTemplateFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	var tf TemplateFile
	if err := yaml.Unmarshal(data, &tf); err != nil {
		return fmt.Errorf("unmarshal yaml: %w", err)
	}

	for _, tmpl := range tf.Templates {
		tmplCopy := tmpl // Copy to avoid pointer to loop variable
		e.templates[tmpl.ID] = &tmplCopy
	}

	return nil
}

// loadDefaultTemplates loads the embedded default templates.
func (e *Explainer) loadDefaultTemplates() error {
	// These are fallback templates used when no template files exist
	defaults := []TemplateDefinition{
		{
			ID:          "default",
			Name:        "Default Alert",
			Category:    "general",
			Summary:     "Security alert: {{.RuleName}} detected for process {{.Comm}} (PID {{.PID}})",
			Detail:      "The process {{.Comm}} (PID {{.PID}}) triggered rule '{{.RuleID}}'. {{.Message}}",
			Severity:    "{{.Severity}}",
			SeverityWhy: "This alert was assigned severity based on the rule configuration.",
			Mitigations: []string{
				"Investigate the process {{.Comm}} (PID {{.PID}})",
				"Review system logs for related activity",
				"Consider isolating the affected pod {{.Pod}} if in Kubernetes",
			},
			References: []string{
				"https://ebpf-guard.io/docs/alerts",
			},
			MITRE: MITREInfo{
				Tactic:      "Initial Access",
				TechniqueID: "T1190",
				Technique:   "Exploit Public-Facing Application",
				URL:         "https://attack.mitre.org/techniques/T1190/",
			},
		},
	}

	for _, tmpl := range defaults {
		tmplCopy := tmpl
		e.templates[tmpl.ID] = &tmplCopy
	}

	return nil
}

// Explain generates an explanation for the given alert.
func (e *Explainer) Explain(alert types.Alert) (*Explanation, error) {
	// Find template by rule ID, fallback to default
	tmpl := e.findTemplate(alert.RuleID)
	if tmpl == nil {
		tmpl = e.templates["default"]
	}
	if tmpl == nil {
		return nil, fmt.Errorf("no template found for rule %s and no default template", alert.RuleID)
	}

	// Prepare template data
	data := TemplateData{
		RuleID:      alert.RuleID,
		RuleName:    alert.RuleName,
		Severity:    string(alert.Severity),
		PID:         alert.PID,
		Comm:        alert.Comm,
		Message:     alert.Message,
		Details:     alert.Details,
		Fingerprint: alert.Fingerprint,
	}

	// Extract PPID and ParentComm from event if available
	data.PPID = alert.Event.PPID
	data.ParentComm = string(bytes.Trim(alert.Event.ParentComm[:], "\x00"))

	// Extract pod/namespace from enrichment
	data.Pod = alert.Enrichment.PodName
	data.Namespace = alert.Enrichment.Namespace

	// Render templates
	explanation := &Explanation{
		MITRE: tmpl.MITRE,
	}

	var err error
	explanation.Summary, err = e.render(tmpl.Summary, data)
	if err != nil {
		return nil, fmt.Errorf("render summary: %w", err)
	}

	explanation.Detail, err = e.render(tmpl.Detail, data)
	if err != nil {
		return nil, fmt.Errorf("render detail: %w", err)
	}

	explanation.Severity, err = e.render(tmpl.Severity, data)
	if err != nil {
		return nil, fmt.Errorf("render severity: %w", err)
	}

	explanation.SeverityWhy, err = e.render(tmpl.SeverityWhy, data)
	if err != nil {
		return nil, fmt.Errorf("render severity_why: %w", err)
	}

	// Render mitigations
	explanation.Mitigations = make([]string, len(tmpl.Mitigations))
	for i, m := range tmpl.Mitigations {
		explanation.Mitigations[i], err = e.render(m, data)
		if err != nil {
			return nil, fmt.Errorf("render mitigation %d: %w", i, err)
		}
	}

	// Render references
	explanation.References = make([]string, len(tmpl.References))
	for i, r := range tmpl.References {
		explanation.References[i], err = e.render(r, data)
		if err != nil {
			return nil, fmt.Errorf("render reference %d: %w", i, err)
		}
	}

	return explanation, nil
}

// findTemplate finds the best matching template for a rule ID.
func (e *Explainer) findTemplate(ruleID string) *TemplateDefinition {
	// Direct match
	if tmpl, ok := e.templates[ruleID]; ok {
		return tmpl
	}

	// Try category prefix match (e.g., "lineage_" -> lineage templates)
	parts := strings.Split(ruleID, "_")
	if len(parts) > 0 {
		category := parts[0]
		for id, tmpl := range e.templates {
			if strings.HasPrefix(id, category) {
				return tmpl
			}
		}
	}

	return nil
}

// render executes a template string with the given data.
func (e *Explainer) render(tmplStr string, data TemplateData) (string, error) {
	tmpl, err := template.New("explanation").Funcs(e.funcs).Parse(tmplStr)
	if err != nil {
		return "", fmt.Errorf("parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("execute template: %w", err)
	}

	return buf.String(), nil
}

// GetTemplate returns a template by ID (for testing and inspection).
func (e *Explainer) GetTemplate(id string) (*TemplateDefinition, bool) {
	tmpl, ok := e.templates[id]
	return tmpl, ok
}

// ListTemplates returns all available template IDs.
func (e *Explainer) ListTemplates() []string {
	ids := make([]string, 0, len(e.templates))
	for id := range e.templates {
		ids = append(ids, id)
	}
	return ids
}

// ListTemplatesByCategory returns templates filtered by category.
func (e *Explainer) ListTemplatesByCategory(category string) []string {
	var ids []string
	for id, tmpl := range e.templates {
		if strings.EqualFold(tmpl.Category, category) {
			ids = append(ids, id)
		}
	}
	return ids
}

// GetMITRECoverage returns all unique MITRE tactics and techniques covered by templates.
func (e *Explainer) GetMITRECoverage() map[string][]MITREInfo {
	coverage := make(map[string][]MITREInfo)

	for _, tmpl := range e.templates {
		if tmpl.MITRE.TechniqueID != "" {
			tactic := tmpl.MITRE.Tactic
			// Check for duplicates
			found := false
			for _, existing := range coverage[tactic] {
				if existing.TechniqueID == tmpl.MITRE.TechniqueID {
					found = true
					break
				}
			}
			if !found {
				coverage[tactic] = append(coverage[tactic], tmpl.MITRE)
			}
		}
	}

	return coverage
}
