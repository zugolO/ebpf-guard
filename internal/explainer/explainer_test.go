package explainer

import (
	"strings"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

func TestNewWithDefaults(t *testing.T) {
	e, err := NewWithDefaults()
	if err != nil {
		t.Fatalf("NewWithDefaults() error = %v", err)
	}

	// Check that default template exists
	if tmpl, ok := e.GetTemplate("default"); !ok {
		t.Error("Expected default template to exist")
	} else if tmpl.ID != "default" {
		t.Errorf("Expected template ID 'default', got %s", tmpl.ID)
	}
}

func TestExplain_DefaultTemplate(t *testing.T) {
	e, err := NewWithDefaults()
	if err != nil {
		t.Fatalf("NewWithDefaults() error = %v", err)
	}

	alert := types.Alert{
		ID:          "alert-123",
		Timestamp:   time.Now(),
		RuleID:      "unknown_rule",
		RuleName:    "Test Rule",
		Severity:    types.SeverityCritical,
		PID:         1234,
		Comm:        "test-process",
		Message:     "Test alert message",
		Fingerprint: "sha256:abc123",
		Event: types.Event{
			PID:  1234,
			PPID: 5678,
		},
		Enrichment: types.EnrichmentInfo{
			PodName:   "test-pod",
			Namespace: "test-ns",
		},
	}

	explanation, err := e.Explain(alert)
	if err != nil {
		t.Fatalf("Explain() error = %v", err)
	}

	// Check that explanation was generated
	if explanation.Summary == "" {
		t.Error("Expected non-empty summary")
	}
	if explanation.Detail == "" {
		t.Error("Expected non-empty detail")
	}
	if explanation.Severity == "" {
		t.Error("Expected non-empty severity")
	}
	if len(explanation.Mitigations) == 0 {
		t.Error("Expected non-empty mitigations")
	}

	// Check that template variables were substituted
	if !strings.Contains(explanation.Summary, "test-process") {
		t.Errorf("Summary should contain process name, got: %s", explanation.Summary)
	}
	if !strings.Contains(explanation.Summary, "1234") {
		t.Errorf("Summary should contain PID, got: %s", explanation.Summary)
	}

	// Check MITRE mapping
	if explanation.MITRE.TechniqueID == "" {
		t.Error("Expected MITRE technique ID")
	}
	if explanation.MITRE.Tactic == "" {
		t.Error("Expected MITRE tactic")
	}
}

func TestExplain_TemplateRendering(t *testing.T) {
	e := &Explainer{
		templates: map[string]*TemplateDefinition{
			"test_rule": {
				ID:          "test_rule",
				Name:        "Test Rule",
				Category:    "test",
				Summary:     "Process {{.Comm}} triggered {{.RuleID}}",
				Detail:      "PID {{.PID}} in namespace {{.Namespace}}: {{.Message}}",
				Severity:    "{{.Severity}}",
				SeverityWhy: "Test severity reason",
				Mitigations: []string{
					"Check process {{.Comm}}",
					"Review pod {{.Pod}}",
				},
				References: []string{
					"https://example.com/{{.RuleID}}",
				},
				MITRE: MITREInfo{
					Tactic:      "Execution",
					TechniqueID: "T1059",
					Technique:   "Command and Scripting Interpreter",
					URL:         "https://attack.mitre.org/techniques/T1059/",
				},
			},
		},
		funcs: templateFuncs(),
	}

	alert := types.Alert{
		ID:       "alert-456",
		RuleID:   "test_rule",
		RuleName: "Test Rule",
		Severity: types.SeverityWarning,
		PID:      5678,
		Comm:     "nginx",
		Message:  "Suspicious activity detected",
		Event: types.Event{
			PID:  5678,
			PPID: 1,
		},
		Enrichment: types.EnrichmentInfo{
			PodName:   "web-pod",
			Namespace: "production",
		},
	}

	explanation, err := e.Explain(alert)
	if err != nil {
		t.Fatalf("Explain() error = %v", err)
	}

	// Verify template substitution
	expectedSummary := "Process nginx triggered test_rule"
	if explanation.Summary != expectedSummary {
		t.Errorf("Summary = %q, want %q", explanation.Summary, expectedSummary)
	}

	expectedDetail := "PID 5678 in namespace production: Suspicious activity detected"
	if explanation.Detail != expectedDetail {
		t.Errorf("Detail = %q, want %q", explanation.Detail, expectedDetail)
	}

	// Check mitigations
	if len(explanation.Mitigations) != 2 {
		t.Errorf("Expected 2 mitigations, got %d", len(explanation.Mitigations))
	}
	if !strings.Contains(explanation.Mitigations[0], "nginx") {
		t.Errorf("First mitigation should contain 'nginx', got: %s", explanation.Mitigations[0])
	}

	// Check references
	if len(explanation.References) != 1 {
		t.Errorf("Expected 1 reference, got %d", len(explanation.References))
	}
	if !strings.Contains(explanation.References[0], "test_rule") {
		t.Errorf("Reference should contain rule ID, got: %s", explanation.References[0])
	}
}

func TestListTemplates(t *testing.T) {
	e := &Explainer{
		templates: map[string]*TemplateDefinition{
			"rule1": {ID: "rule1", Category: "test"},
			"rule2": {ID: "rule2", Category: "test"},
			"rule3": {ID: "rule3", Category: "other"},
		},
	}

	ids := e.ListTemplates()
	if len(ids) != 3 {
		t.Errorf("Expected 3 templates, got %d", len(ids))
	}

	// Test filter by category
	testIds := e.ListTemplatesByCategory("test")
	if len(testIds) != 2 {
		t.Errorf("Expected 2 test templates, got %d", len(testIds))
	}
}

func TestGetMITRECoverage(t *testing.T) {
	e := &Explainer{
		templates: map[string]*TemplateDefinition{
			"rule1": {
				ID:       "rule1",
				Category: "execution",
				MITRE: MITREInfo{
					Tactic:      "Execution",
					TechniqueID: "T1059",
					Technique:   "Command and Scripting Interpreter",
				},
			},
			"rule2": {
				ID:       "rule2",
				Category: "execution",
				MITRE: MITREInfo{
					Tactic:      "Execution",
					TechniqueID: "T1053",
					Technique:   "Scheduled Task/Job",
				},
			},
			"rule3": {
				ID:       "rule3",
				Category: "persistence",
				MITRE: MITREInfo{
					Tactic:      "Persistence",
					TechniqueID: "T1543",
					Technique:   "Create or Modify System Process",
				},
			},
		},
	}

	coverage := e.GetMITRECoverage()

	// Should have 2 tactics
	if len(coverage) != 2 {
		t.Errorf("Expected 2 tactics, got %d", len(coverage))
	}

	// Execution tactic should have 2 techniques
	if len(coverage["Execution"]) != 2 {
		t.Errorf("Expected 2 execution techniques, got %d", len(coverage["Execution"]))
	}

	// Persistence tactic should have 1 technique
	if len(coverage["Persistence"]) != 1 {
		t.Errorf("Expected 1 persistence technique, got %d", len(coverage["Persistence"]))
	}
}

func TestFindTemplate(t *testing.T) {
	e := &Explainer{
		templates: map[string]*TemplateDefinition{
			"lineage_web_shell": {ID: "lineage_web_shell", Category: "lineage"},
			"lineage_shell_net": {ID: "lineage_shell_net", Category: "lineage"},
			"file_sensitive":    {ID: "file_sensitive", Category: "file"},
		},
	}

	tests := []struct {
		ruleID       string
		expectedTmpl string
	}{
		{"lineage_web_shell", "lineage_web_shell"}, // Direct match
		// Category prefix fallback: deterministically returns the
		// lexicographically-first matching "lineage" template.
		{"lineage_unknown", "lineage_shell_net"},
		{"file_sensitive", "file_sensitive"}, // Direct match
		{"unknown_rule", ""},                 // No match
	}

	for _, tt := range tests {
		t.Run(tt.ruleID, func(t *testing.T) {
			tmpl := e.findTemplate(tt.ruleID)
			if tt.expectedTmpl == "" {
				if tmpl != nil {
					t.Errorf("Expected no template, got %s", tmpl.ID)
				}
			} else {
				if tmpl == nil {
					t.Errorf("Expected template %s, got nil", tt.expectedTmpl)
				} else if tmpl.ID != tt.expectedTmpl {
					t.Errorf("Expected template %s, got %s", tt.expectedTmpl, tmpl.ID)
				}
			}
		})
	}
}

func TestRender_TemplateFunctions(t *testing.T) {
	e := &Explainer{
		funcs: templateFuncs(),
	}

	data := TemplateData{
		Comm:   "TestProcess",
		RuleID: "test_rule",
	}

	tests := []struct {
		template string
		expected string
	}{
		{"{{.Comm | upper}}", "TESTPROCESS"},
		{"{{.Comm | lower}}", "testprocess"},
		{"{{.Comm | title}}", "Testprocess"},
		{"{{.RuleID | upper}}", "TEST_RULE"},
	}

	for _, tt := range tests {
		t.Run(tt.template, func(t *testing.T) {
			result, err := e.render(tt.template, data)
			if err != nil {
				t.Fatalf("render() error = %v", err)
			}
			if result != tt.expected {
				t.Errorf("render() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestExplain_AllMITRETemplates(t *testing.T) {
	// Test that all templates have valid MITRE mappings
	e := &Explainer{
		templates: map[string]*TemplateDefinition{
			"rule_with_mitre": {
				ID:       "rule_with_mitre",
				Category: "test",
				Summary:  "Test",
				Detail:   "Test",
				MITRE: MITREInfo{
					Tactic:      "Initial Access",
					TechniqueID: "T1190",
					Technique:   "Exploit Public-Facing Application",
					URL:         "https://attack.mitre.org/techniques/T1190/",
				},
			},
			"rule_without_mitre": {
				ID:       "rule_without_mitre",
				Category: "test",
				Summary:  "Test",
				Detail:   "Test",
				// No MITRE info
			},
		},
		funcs: templateFuncs(),
	}

	coverage := e.GetMITRECoverage()

	// Only rule_with_mitre should be in coverage
	if len(coverage) != 1 {
		t.Errorf("Expected 1 tactic in coverage, got %d", len(coverage))
	}

	if len(coverage["Initial Access"]) != 1 {
		t.Errorf("Expected 1 technique for Initial Access, got %d", len(coverage["Initial Access"]))
	}
}

// Helper function to create template function map
func templateFuncs() map[string]interface{} {
	return map[string]interface{}{
		"upper": strings.ToUpper,
		"lower": strings.ToLower,
		"title": cases.Title(language.English).String,
		"trim":  strings.TrimSpace,
		"join":  strings.Join,
	}
}

// BenchmarkExplain measures the performance of explanation generation
func BenchmarkExplain(b *testing.B) {
	e := &Explainer{
		templates: map[string]*TemplateDefinition{
			"benchmark_rule": {
				ID:          "benchmark_rule",
				Category:    "benchmark",
				Summary:     "Process {{.Comm}} (PID {{.PID}}) triggered {{.RuleID}}",
				Detail:      "In namespace {{.Namespace}}, pod {{.Pod}}: {{.Message}}",
				Severity:    "{{.Severity}}",
				SeverityWhy: "This is a {{.Severity}} severity alert because of suspicious activity",
				Mitigations: []string{
					"Investigate process {{.Comm}}",
					"Check pod {{.Pod}} in namespace {{.Namespace}}",
					"Review logs for PID {{.PID}}",
				},
				References: []string{
					"https://example.com/docs/{{.RuleID}}",
					"https://mitre.org/techniques/T1059",
				},
				MITRE: MITREInfo{
					Tactic:      "Execution",
					TechniqueID: "T1059",
					Technique:   "Command and Scripting Interpreter",
					URL:         "https://attack.mitre.org/techniques/T1059/",
				},
			},
		},
		funcs: templateFuncs(),
	}

	alert := types.Alert{
		ID:       "bench-alert",
		RuleID:   "benchmark_rule",
		RuleName: "Benchmark Rule",
		Severity: types.SeverityCritical,
		PID:      12345,
		Comm:     "benchmark-process",
		Message:  "Benchmark test message with details",
		Event: types.Event{
			PID:  12345,
			PPID: 1,
		},
		Enrichment: types.EnrichmentInfo{
			PodName:   "bench-pod",
			Namespace: "benchmark",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := e.Explain(alert)
		if err != nil {
			b.Fatalf("Explain() error = %v", err)
		}
	}
}

func TestExplainPlain_StylePlain(t *testing.T) {
	e := &Explainer{
		templates: map[string]*TemplateDefinition{
			"test_rule": {
				ID:          "test_rule",
				Name:        "Test Plain Rule",
				Category:    "test",
				Summary:     "Technical summary for {{.Comm}}",
				Detail:      "Technical detail for PID {{.PID}}",
				Severity:    "{{.Severity}}",
				SeverityWhy: "Because it's serious",
				Mitigations: []string{"Mitigation 1", "Mitigation 2"},
				References:  []string{"https://ref.example.com"},
				MITRE: MITREInfo{
					Tactic:      "Execution",
					TechniqueID: "T1059",
					Technique:   "Command and Scripting Interpreter",
					URL:         "https://attack.mitre.org/techniques/T1059/",
				},
				Plain: &PlainTemplateDefinition{
					WhatHappened: "Someone ran {{.Comm}} (PID {{.PID}}) on your server.",
					WhyItMatters: "This could mean your {{.Pod}} pod was exploited.",
					WhatToDo:     "Restart pod {{.Pod}} and check logs for {{.Comm}}.",
				},
			},
		},
		funcs:        templateFuncs(),
		defaultStyle: StylePlain,
	}

	alert := types.Alert{
		ID:       "alert-789",
		RuleID:   "test_rule",
		RuleName: "Test Plain Rule",
		Severity: types.SeverityCritical,
		PID:      9999,
		Comm:     "bash",
		Message:  "Suspicious shell detected",
		Enrichment: types.EnrichmentInfo{
			PodName:   "web-app",
			Namespace: "prod",
		},
	}

	explanation, err := e.Explain(alert)
	if err != nil {
		t.Fatalf("Explain() error = %v", err)
	}

	if explanation.Style != StylePlain {
		t.Errorf("Style = %q, want %q", explanation.Style, StylePlain)
	}
	if explanation.Plain == nil {
		t.Fatal("Plain explanation should be populated")
	}

	if explanation.Plain.WhatHappened != "Someone ran bash (PID 9999) on your server." {
		t.Errorf("WhatHappened = %q", explanation.Plain.WhatHappened)
	}
	if explanation.Plain.WhyItMatters != "This could mean your web-app pod was exploited." {
		t.Errorf("WhyItMatters = %q", explanation.Plain.WhyItMatters)
	}
	if explanation.Plain.WhatToDo != "Restart pod web-app and check logs for bash." {
		t.Errorf("WhatToDo = %q", explanation.Plain.WhatToDo)
	}

	// Technical fields should be empty in StylePlain
	if explanation.Summary != "" {
		t.Errorf("Summary should be empty in plain mode, got %q", explanation.Summary)
	}
	if explanation.Detail != "" {
		t.Errorf("Detail should be empty in plain mode, got %q", explanation.Detail)
	}

	// MITRE should still be available as details
	if explanation.MITRE.TechniqueID != "T1059" {
		t.Errorf("MITRE TechniqueID = %q, want T1059", explanation.MITRE.TechniqueID)
	}
}

func TestExplainPlain_StyleTechnical(t *testing.T) {
	e := &Explainer{
		templates: map[string]*TemplateDefinition{
			"test_rule": {
				ID:          "test_rule",
				Name:        "Test Rule",
				Category:    "test",
				Summary:     "Process {{.Comm}} triggered {{.RuleID}}",
				Detail:      "PID {{.PID}}: {{.Message}}",
				Severity:    "{{.Severity}}",
				SeverityWhy: "Test severity",
				Plain: &PlainTemplateDefinition{
					WhatHappened: "Plain what: {{.Comm}}",
					WhyItMatters: "Plain why: {{.Comm}}",
					WhatToDo:     "Plain todo: {{.Comm}}",
				},
			},
		},
		funcs:        templateFuncs(),
		defaultStyle: StyleTechnical,
	}

	alert := types.Alert{
		RuleID:   "test_rule",
		RuleName: "Test Rule",
		Severity: types.SeverityWarning,
		PID:      1234,
		Comm:     "nginx",
		Message:  "Test message",
	}

	explanation, err := e.Explain(alert)
	if err != nil {
		t.Fatalf("Explain() error = %v", err)
	}

	if explanation.Style != StyleTechnical {
		t.Errorf("Style = %q, want %q", explanation.Style, StyleTechnical)
	}
	if explanation.Plain != nil {
		t.Errorf("Plain explanation should be nil in technical mode")
	}
	if explanation.Summary != "Process nginx triggered test_rule" {
		t.Errorf("Summary = %q", explanation.Summary)
	}
	if !strings.Contains(explanation.Detail, "Test message") {
		t.Errorf("Detail should contain 'Test message', got %q", explanation.Detail)
	}
}

func TestExplainPlain_StyleFull(t *testing.T) {
	e := &Explainer{
		templates: map[string]*TemplateDefinition{
			"test_rule": {
				ID:          "test_rule",
				Name:        "Full Rule",
				Category:    "test",
				Summary:     "Technical: {{.Comm}} PID {{.PID}}",
				Detail:      "Technical detail: {{.Message}}",
				Severity:    "{{.Severity}}",
				SeverityWhy: "Because reasons",
				Plain: &PlainTemplateDefinition{
					WhatHappened: "Plain: {{.Comm}} (PID {{.PID}}) did something.",
					WhyItMatters: "Plain: This is important for {{.Comm}}.",
					WhatToDo:     "Plain: Restart {{.Pod}} and check {{.Comm}}.",
				},
			},
		},
		funcs:        templateFuncs(),
		defaultStyle: StyleFull,
	}

	alert := types.Alert{
		RuleID:   "test_rule",
		RuleName: "Full Rule",
		Severity: types.SeverityCritical,
		PID:      4321,
		Comm:     "python",
		Message:  "Full test message",
		Enrichment: types.EnrichmentInfo{
			PodName:   "ml-worker",
			Namespace: "default",
		},
	}

	explanation, err := e.Explain(alert)
	if err != nil {
		t.Fatalf("Explain() error = %v", err)
	}

	if explanation.Style != StyleFull {
		t.Errorf("Style = %q, want %q", explanation.Style, StyleFull)
	}

	// Both styles should be populated
	if explanation.Summary != "Technical: python PID 4321" {
		t.Errorf("Summary = %q", explanation.Summary)
	}
	if explanation.Plain == nil {
		t.Fatal("Plain should be populated in full mode")
	}
	if explanation.Plain.WhatHappened != "Plain: python (PID 4321) did something." {
		t.Errorf("WhatHappened = %q", explanation.Plain.WhatHappened)
	}
	if explanation.Plain.WhatToDo != "Plain: Restart ml-worker and check python." {
		t.Errorf("WhatToDo = %q", explanation.Plain.WhatToDo)
	}
}

func TestExplainPlain_DefaultStyle(t *testing.T) {
	e := &Explainer{
		templates: map[string]*TemplateDefinition{
			"test_rule": {
				ID:          "test_rule",
				Name:        "Test",
				Category:    "test",
				Summary:     "Sum: {{.Comm}}",
				Detail:      "Det: {{.Comm}}",
				Severity:    "{{.Severity}}",
				SeverityWhy: "Reason",
			},
		},
		funcs: templateFuncs(),
	}
	e.SetDefaultStyle(StylePlain)

	if e.DefaultStyle() != StylePlain {
		t.Errorf("DefaultStyle = %q, want %q", e.DefaultStyle(), StylePlain)
	}
	e.SetDefaultStyle(StyleTechnical)
	if e.DefaultStyle() != StyleTechnical {
		t.Errorf("DefaultStyle = %q, want %q", e.DefaultStyle(), StyleTechnical)
	}

	alert := types.Alert{
		RuleID:   "test_rule",
		RuleName: "Test",
		Severity: types.SeverityWarning,
		Comm:     "curl",
	}

	explanation, err := e.Explain(alert)
	if err != nil {
		t.Fatalf("Explain() error = %v", err)
	}
	if explanation.Style != StyleTechnical {
		t.Errorf("Style = %q, want %q", explanation.Style, StyleTechnical)
	}
	if explanation.Summary == "" {
		t.Error("Summary should not be empty")
	}
}

func TestExplainPlain_NoPlainTemplate(t *testing.T) {
	e := &Explainer{
		templates: map[string]*TemplateDefinition{
			"test_rule": {
				ID:          "test_rule",
				Name:        "No Plain Rule",
				Category:    "test",
				Summary:     "Sum: {{.Comm}}",
				Detail:      "Det: PID {{.PID}}",
				Severity:    "{{.Severity}}",
				SeverityWhy: "Because",
				MITRE: MITREInfo{
					Tactic:      "Discovery",
					TechniqueID: "T1083",
				},
			},
		},
		funcs:        templateFuncs(),
		defaultStyle: StylePlain,
	}

	alert := types.Alert{
		RuleID:   "test_rule",
		RuleName: "No Plain Rule",
		Severity: types.SeverityWarning,
		PID:      5555,
		Comm:     "myapp",
		Message:  "Alert message here",
	}

	explanation, err := e.Explain(alert)
	if err != nil {
		t.Fatalf("Explain() error = %v", err)
	}

	if explanation.Plain == nil {
		t.Fatal("Should generate fallback plain explanation")
	}
	if !strings.Contains(explanation.Plain.WhatHappened, "myapp") {
		t.Errorf("WhatHappened should contain 'myapp', got %q", explanation.Plain.WhatHappened)
	}
	if !strings.Contains(explanation.Plain.WhatHappened, "5555") {
		t.Errorf("WhatHappened should contain '5555', got %q", explanation.Plain.WhatHappened)
	}
	if !strings.Contains(explanation.Plain.WhyItMatters, "malicious") {
		t.Errorf("WhyItMatters should mention malicious, got %q", explanation.Plain.WhyItMatters)
	}
	if !strings.Contains(explanation.Plain.WhatToDo, "allowlist") {
		t.Errorf("WhatToDo should mention allowlist, got %q", explanation.Plain.WhatToDo)
	}
}

func TestSetDefaultStyle_Invalid(t *testing.T) {
	e := &Explainer{
		templates:    map[string]*TemplateDefinition{},
		funcs:        templateFuncs(),
		defaultStyle: StyleTechnical,
	}

	e.SetDefaultStyle("invalid-style")
	if e.DefaultStyle() != StyleTechnical {
		t.Errorf("Invalid style should not change default, got %q", e.DefaultStyle())
	}

	e.SetDefaultStyle("plain")
	if e.DefaultStyle() != StylePlain {
		t.Errorf("Expected plain, got %q", e.DefaultStyle())
	}

	e.SetDefaultStyle("full")
	if e.DefaultStyle() != StyleFull {
		t.Errorf("Expected full, got %q", e.DefaultStyle())
	}
}

func TestBuildDefaultPlain(t *testing.T) {
	e := &Explainer{funcs: templateFuncs()}

	data := TemplateData{
		RuleName: "Test Rule Alert",
		PID:      7777,
		Comm:     "suspicious-binary",
		Message:  "Critical security event detected",
	}

	plain := e.buildDefaultPlain(data, &TemplateDefinition{})

	if !strings.Contains(plain.WhatHappened, "suspicious-binary") {
		t.Errorf("WhatHappened should contain 'suspicious-binary', got %q", plain.WhatHappened)
	}
	if !strings.Contains(plain.WhatHappened, "7777") {
		t.Errorf("WhatHappened should contain '7777', got %q", plain.WhatHappened)
	}
	if !strings.Contains(plain.WhatHappened, "Test Rule Alert") {
		t.Errorf("WhatHappened should contain rule name, got %q", plain.WhatHappened)
	}
	if !strings.Contains(plain.WhatHappened, "Critical security event detected") {
		t.Errorf("WhatHappened should contain message, got %q", plain.WhatHappened)
	}
	if plain.WhyItMatters == "" {
		t.Error("WhyItMatters should not be empty")
	}
	if !strings.Contains(plain.WhatToDo, "allowlist") {
		t.Errorf("WhatToDo should mention allowlist, got %q", plain.WhatToDo)
	}
}

