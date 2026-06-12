// Package explainer provides human-readable explanations for security alerts.
// It uses Go templates to generate contextual explanations with MITRE ATT&CK mappings.
package explainer

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
	// Plain provides a non-technical explanation designed for developers without
	// security backgrounds. Populated when Style is StylePlain or StyleFull.
	Plain *PlainExplanation `json:"plain,omitempty" yaml:"plain,omitempty"`
	// Style indicates which explanation style was requested.
	Style ExplanationStyle `json:"style" yaml:"style"`
}

// ExplanationStyle selects between plain (non-technical) and technical explanation modes.
type ExplanationStyle string

const (
	// StylePlain returns a non-technical, phone-readable explanation with three
	// sections: what happened, why it matters, and what to do now.
	StylePlain ExplanationStyle = "plain"
	// StyleTechnical returns the traditional SOC-oriented explanation with
	// MITRE ATT&CK references, forensic commands, and tactical mitigations.
	StyleTechnical ExplanationStyle = "technical"
	// StyleFull returns both plain and technical explanations combined.
	StyleFull ExplanationStyle = "full"
)

// PlainExplanation provides a non-technical explanation designed for developers
// without security backgrounds. Each section is a complete, self-contained message
// suitable for reading on a phone.
type PlainExplanation struct {
	// WhatHappened describes the incident in plain language (e.g. "Someone started
	// an interactive shell from your Node web process.").
	WhatHappened string `json:"what_happened" yaml:"what_happened"`
	// WhyItMatters explains why this is a security concern in terms a non-expert
	// can understand (e.g. "This usually means your app was exploited...").
	WhyItMatters string `json:"why_it_matters" yaml:"why_it_matters"`
	// WhatToDo provides concrete, actionable steps the user can take
	// (e.g. "Restart the container and check for an unpatched dependency.").
	WhatToDo string `json:"what_to_do" yaml:"what_to_do"`
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
	// Plain contains the non-technical explanation sections for indie-developer UX.
	Plain *PlainTemplateDefinition `yaml:"plain,omitempty"`
}

// PlainTemplateDefinition holds the three-section plain-language explanation.
type PlainTemplateDefinition struct {
	WhatHappened string `yaml:"what_happened"`
	WhyItMatters string `yaml:"why_it_matters"`
	WhatToDo     string `yaml:"what_to_do"`
}

// TemplateFile represents a YAML file containing multiple templates.
type TemplateFile struct {
	Templates []TemplateDefinition `yaml:"templates"`
}

// Explainer generates human-readable explanations for alerts.
type Explainer struct {
	templates    map[string]*TemplateDefinition
	funcs        template.FuncMap
	defaultStyle ExplanationStyle
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

	e.defaultStyle = StyleTechnical
	return nil
}

// SetDefaultStyle sets the default explanation style.
// Valid styles are "plain", "technical", or "full".
// When an explanation is generated via Explain(), this style is used.
// In simple mode, the caller should set this to StylePlain.
func (e *Explainer) SetDefaultStyle(style ExplanationStyle) {
	switch style {
	case StylePlain, StyleTechnical, StyleFull:
		e.defaultStyle = style
	default:
		// Invalid style — silently keep current
	}
}

// DefaultStyle returns the current default explanation style.
func (e *Explainer) DefaultStyle() ExplanationStyle {
	return e.defaultStyle
}

// Explain generates an explanation for the given alert using the default style.
// Falls back to StyleTechnical when no default style has been explicitly set.
func (e *Explainer) Explain(alert types.Alert) (*Explanation, error) {
	style := e.defaultStyle
	if style == "" {
		style = StyleTechnical
	}
	return e.ExplainWithStyle(alert, style)
}

// ExplainWithStyle generates an explanation in the requested style.
// An empty style defaults to StyleTechnical for backward compatibility.
func (e *Explainer) ExplainWithStyle(alert types.Alert, style ExplanationStyle) (*Explanation, error) {
	if style == "" {
		style = StyleTechnical
	}
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

	explanation := &Explanation{
		MITRE: tmpl.MITRE,
		Style: style,
	}

	var err error

	// Always fill technical fields (needed for StyleTechnical, StyleFull, and details).
	// StylePlain also populates these so consumers can access technical context via the
	// Detail/Mitigations/References fields even when the primary display is plain-language.
	if style == StyleTechnical || style == StyleFull || style == StylePlain {
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

		explanation.Mitigations = make([]string, len(tmpl.Mitigations))
		for i, m := range tmpl.Mitigations {
			explanation.Mitigations[i], err = e.render(m, data)
			if err != nil {
				return nil, fmt.Errorf("render mitigation %d: %w", i, err)
			}
		}

		explanation.References = make([]string, len(tmpl.References))
		for i, r := range tmpl.References {
			explanation.References[i], err = e.render(r, data)
			if err != nil {
				return nil, fmt.Errorf("render reference %d: %w", i, err)
			}
		}
	}

	// Fill plain explanation if requested and template has plain fields
	if (style == StylePlain || style == StyleFull) && tmpl.Plain != nil {
		explanation.Plain = &PlainExplanation{}

		explanation.Plain.WhatHappened, err = e.render(tmpl.Plain.WhatHappened, data)
		if err != nil {
			return nil, fmt.Errorf("render what_happened: %w", err)
		}
		explanation.Plain.WhyItMatters, err = e.render(tmpl.Plain.WhyItMatters, data)
		if err != nil {
			return nil, fmt.Errorf("render why_it_matters: %w", err)
		}
		explanation.Plain.WhatToDo, err = e.render(tmpl.Plain.WhatToDo, data)
		if err != nil {
			return nil, fmt.Errorf("render what_to_do: %w", err)
		}
	} else if style == StylePlain && tmpl.Plain == nil {
		explanation.Plain = e.buildDefaultPlain(data, tmpl)
	}

	return explanation, nil
}

// buildDefaultPlain creates a fallback plain explanation from technical template data
// when no explicit plain template exists.
func (e *Explainer) buildDefaultPlain(data TemplateData, tmpl *TemplateDefinition) *PlainExplanation {
	return &PlainExplanation{
		WhatHappened: fmt.Sprintf("A security alert was triggered for process %s (PID %d) matching rule \"%s\". %s",
			data.Comm, data.PID, data.RuleName, data.Message),
		WhyItMatters: "This activity was flagged as potentially malicious by ebpf-guard's detection rules. " +
			"Unexpected process behaviour often indicates an application exploit, malware, or unauthorized access.",
		WhatToDo: fmt.Sprintf("1. Restart the affected container or process.\n"+
			"2. Check logs for %s around the time of the alert.\n"+
			"3. If this is a false positive, add \"%s\" to the allowlist.",
			data.Comm, data.Comm),
	}
}

// findTemplate finds the best matching template for a rule ID.
func (e *Explainer) findTemplate(ruleID string) *TemplateDefinition {
	// Direct match
	if tmpl, ok := e.templates[ruleID]; ok {
		return tmpl
	}

	// Try category prefix match (e.g., "lineage_" -> lineage templates).
	// Iterate template IDs in sorted order so the fallback choice is
	// deterministic when several templates share a category prefix (map
	// iteration order would otherwise be random).
	parts := strings.Split(ruleID, "_")
	if len(parts) > 0 {
		category := parts[0]
		ids := make([]string, 0, len(e.templates))
		for id := range e.templates {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			if strings.HasPrefix(id, category) {
				return e.templates[id]
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
