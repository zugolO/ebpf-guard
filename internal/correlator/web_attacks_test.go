package correlator

import (
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// TestWebAttacksEnhancedRules tests the new web attack detection rules from web-attacks-enhanced.yaml
func TestWebAttacksEnhancedRules(t *testing.T) {
	// Load the enhanced web attack rules
	rules, err := LoadRulesFromFile("../../rules/web-attacks-enhanced.yaml")
	require.NoError(t, err, "Failed to load web-attacks-enhanced.yaml")
	require.NotEmpty(t, rules, "Rules file should not be empty")

	// Create rule engine
	engine := NewRuleEngine(rules)

	// Test SQL injection file patterns
	t.Run("SQL Injection File Patterns", func(t *testing.T) {
		sqliTestCases := []struct {
			name     string
			filename string
			expected bool
		}{
			{"UNION SELECT payload", "/tmp/log?union+select+users", true},
			{"Boolean SQLi", "/var/www/upload.php?or 1=1", true},
			{"DROP TABLE", "/app/upload.sql?drop table users", true},
			{"Quote escaping", "/var/www/test'%27", true},
			{"Normal file", "/var/www/index.html", false},
			// 5.9.9.F.1c (finding #114): this row used to read
			// {"Comment marker", "/tmp/file--", true} — a test that demanded
			// the defect. The bare markers "--", "#" and ";" were matched
			// against a FILENAME, so one character raised a critical "SQL
			// injection": замер №2.9.9.F produced 10 such criticals, zero of
			// them true (systemd-logind session temp files, a git man page).
			// The expectation is inverted, not deleted — a deleted row would
			// let the pattern come back unnoticed, which is how it survived
			// this long.
			{"Bare comment marker in a filename is not an injection", "/tmp/file--", false},
			{"Bare hash in a filename is not an injection", "/run/systemd/sessions/.#114376ChHzY", false},
			{"Bare semicolon in a filename is not an injection", "/tmp/report;final.csv", false},
			{"Double dash inside a package name is not an injection", "git-mergetool--lib.1.gz", false},
		}

		for _, tc := range sqliTestCases {
			t.Run(tc.name, func(t *testing.T) {
				event := types.Event{
					Type: types.EventFileAccess,
					File: &types.FileEvent{
						Filename: [256]byte{},
					},
				}
				copy(event.File.Filename[:], tc.filename)

				alerts := engine.Evaluate(event)
				hasSQLiAlert := false
				for _, alert := range alerts {
					if alert.RuleID == "web_sql_injection_files" {
						hasSQLiAlert = true
						break
					}
				}

				if tc.expected {
					assert.True(t, hasSQLiAlert, "Expected SQL injection alert for: %s", tc.filename)
				} else {
					assert.False(t, hasSQLiAlert, "Did not expect SQL injection alert for: %s", tc.filename)
				}
			})
		}
	})

	// Test XSS patterns
	t.Run("XSS File Patterns", func(t *testing.T) {
		xssTestCases := []struct {
			name     string
			filename string
			expected bool
		}{
			{"Script tag", "/uploads/<script>alert(1)</script>.txt", true},
			{"JavaScript protocol", "/tmp/file?javascript:alert(1)", true},
			{"Event handler", "/var/www/onerror=prompt(1)", true},
			{"Document cookie", "/uploads/document.cookie.txt", true},
			{"innerHTML", "/tmp/innerHTMLpayload", true},
			{"URL-encoded script", "/upload/%3Cscript%3E", true},
			{"Normal file", "/var/www/style.css", false},
		}

		for _, tc := range xssTestCases {
			t.Run(tc.name, func(t *testing.T) {
				event := types.Event{
					Type: types.EventFileAccess,
					File: &types.FileEvent{
						Filename: [256]byte{},
					},
				}
				copy(event.File.Filename[:], tc.filename)

				alerts := engine.Evaluate(event)
				hasXSSAlert := false
				for _, alert := range alerts {
					if alert.RuleID == "web_xss_file_pattern" {
						hasXSSAlert = true
						break
					}
				}

				if tc.expected {
					assert.True(t, hasXSSAlert, "Expected XSS alert for: %s", tc.filename)
				} else {
					assert.False(t, hasXSSAlert, "Did not expect XSS alert for: %s", tc.filename)
				}
			})
		}
	})

	// Test extended path traversal patterns.
	// 5.9.9.F.4d (finding #144): the rule is no longer "any process that opened
	// a path containing ../" — it is scoped to the web-worker comm list, the same
	// one owasp_web_sensitive_file_read uses. Fixtures therefore carry a comm, and
	// the last case pins the narrowing itself: the same traversal path read by a
	// non-web process (grep — one of the 50 uptime criticals the finding counted)
	// must NOT alert. Without that case a re-widening of the rule would go unnoticed.
	t.Run("Extended Path Traversal Patterns", func(t *testing.T) {
		traversalTestCases := []struct {
			name     string
			comm     string
			filename string
			expected bool
		}{
			{"Basic traversal", "nginx", "/etc/passwd/../../", true},
			{"Backslash traversal", "nginx", "\\windows\\system32\\..\\..", true},
			{"URL-encoded", "apache2", "/var/www/%2e%2e%2f", true},
			{"Double-encoded", "php-fpm", "/tmp/%252e%252e%252f", true},
			{"Unicode evasion", "tomcat", "/uploads/%c0%ae", true},
			{"Repeated traversal", "node", "/var/www/../../../../etc/passwd", true},
			{"Normal file", "nginx", "/var/www/images/logo.png", false},
			{"Traversal by non-web process (5.9.9.F.4d)", "grep", "/var/www/../../../../etc/passwd", false},
			{"Traversal without comm (5.9.9.F.4d)", "", "/var/www/../../../../etc/passwd", false},
		}

		for _, tc := range traversalTestCases {
			t.Run(tc.name, func(t *testing.T) {
				event := types.Event{
					Type: types.EventFileAccess,
					File: &types.FileEvent{
						Filename: [256]byte{},
					},
				}
				copy(event.Comm[:], tc.comm)
				copy(event.File.Filename[:], tc.filename)

				alerts := engine.Evaluate(event)
				hasTraversalAlert := false
				for _, alert := range alerts {
					if alert.RuleID == "web_path_traversal_extended" {
						hasTraversalAlert = true
						break
					}
				}

				if tc.expected {
					assert.True(t, hasTraversalAlert, "Expected path traversal alert for: %s", tc.filename)
				} else {
					assert.False(t, hasTraversalAlert, "Did not expect path traversal alert for: %s", tc.filename)
				}
			})
		}
	})

	// Test file inclusion attacks
	t.Run("File Inclusion Attacks", func(t *testing.T) {
		inclusionTestCases := []struct {
			name     string
			filename string
			expected bool
		}{
			{"PHP input wrapper", "/uploads/php://input", true},
			{"PHP file wrapper", "/tmp/php://file/etc/passwd", true},
			{"Expect wrapper", "/var/www/expect://id", true},
			{"Data wrapper", "/uploads/data://text/plain,test", true},
			{"ZIP wrapper", "/tmp/zip://file.zip", true},
			{"Java file URL", "/app/file:///etc/passwd", true},
			{"Normal file", "/var/www/config.php", false},
		}

		for _, tc := range inclusionTestCases {
			t.Run(tc.name, func(t *testing.T) {
				event := types.Event{
					Type: types.EventFileAccess,
					File: &types.FileEvent{
						Filename: [256]byte{},
					},
				}
				copy(event.File.Filename[:], tc.filename)

				alerts := engine.Evaluate(event)
				hasInclusionAlert := false
				for _, alert := range alerts {
					if alert.RuleID == "web_file_inclusion_attack" {
						hasInclusionAlert = true
						break
					}
				}

				if tc.expected {
					assert.True(t, hasInclusionAlert, "Expected file inclusion alert for: %s", tc.filename)
				} else {
					assert.False(t, hasInclusionAlert, "Did not expect file inclusion alert for: %s", tc.filename)
				}
			})
		}
	})

	// Test template injection patterns
	t.Run("Template Injection Patterns", func(t *testing.T) {
		templateTestCases := []struct {
			name     string
			filename string
			expected bool
		}{
			{"Jinja2 syntax", "/uploads/{{config.items()}}", true},
			{"Twig syntax", "/tmp/{{_self.env}}", true},
			{"FreeMarker", "/var/www/<#assign x=1>", true},
			{"Velocity", "/app/${7*7}", true},
			{"Ruby ERB", "/uploads/<%=system('id')%>", true},
			{"Handlebars", "/tmp/{{{{constructor}}}}", true},
			{"Normal template", "/var/www/template.html", false},
		}

		for _, tc := range templateTestCases {
			t.Run(tc.name, func(t *testing.T) {
				event := types.Event{
					Type: types.EventFileAccess,
					File: &types.FileEvent{
						Filename: [256]byte{},
					},
				}
				copy(event.File.Filename[:], tc.filename)

				alerts := engine.Evaluate(event)
				hasTemplateAlert := false
				for _, alert := range alerts {
					if alert.RuleID == "web_template_injection" {
						hasTemplateAlert = true
						break
					}
				}

				if tc.expected {
					assert.True(t, hasTemplateAlert, "Expected template injection alert for: %s", tc.filename)
				} else {
					assert.False(t, hasTemplateAlert, "Did not expect template injection alert for: %s", tc.filename)
				}
			})
		}
	})

	// Test internal network reconnaissance
	t.Run("Internal Network Reconnaissance", func(t *testing.T) {
		internalReconTestCases := []struct {
			name     string
			daddr    string
			expected bool
		}{
			{"RFC1918 Class A", "10.0.0.5", true},
			{"RFC1918 Class B", "172.16.0.10", true},
			{"RFC1918 Class C", "192.168.1.50", true},
			{"Public IP", "8.8.8.8", false},
			{"Cloud metadata", "169.254.169.254", false},
		}

		for _, tc := range internalReconTestCases {
			t.Run(tc.name, func(t *testing.T) {
				event := types.Event{
					Type: types.EventTCPConnect,
					Network: &types.NetworkEvent{
						Daddr: [16]byte{},
						Dport: 0,
					},
				}

				// Convert IP string to bytes (proper IPv4 format)
				ipParts := strings.Split(tc.daddr, ".")
				if len(ipParts) == 4 {
					for i, part := range ipParts {
						val, _ := strconv.Atoi(part)
						event.Network.Daddr[i] = byte(val)
					}
				}

				alerts := engine.Evaluate(event)
				hasInternalReconAlert := false
				for _, alert := range alerts {
					if alert.RuleID == "web_internal_recon" {
						hasInternalReconAlert = true
						break
					}
				}

				if tc.expected {
					assert.True(t, hasInternalReconAlert, "Expected internal recon alert for: %s", tc.daddr)
				} else {
					assert.False(t, hasInternalReconAlert, "Did not expect internal recon alert for: %s", tc.daddr)
				}
			})
		}
	})

	// Test combined attack patterns
	t.Run("Combined Attack Patterns", func(t *testing.T) {
		combinedTestCases := []struct {
			name     string
			filename string
			expected bool
		}{
			{"SQLi + traversal", "/tmp/union select*../../../etc/passwd", true},
			{"XSS + file inclusion", "/uploads/<script>php://input", true},
			{"SSTI + traversal", "/app/{{config}}%2e%2e%2f", true},
			{"Normal attack pattern", "/var/www/upload.php", false},
		}

		for _, tc := range combinedTestCases {
			t.Run(tc.name, func(t *testing.T) {
				event := types.Event{
					Type: types.EventFileAccess,
					File: &types.FileEvent{
						Filename: [256]byte{},
					},
				}
				copy(event.File.Filename[:], tc.filename)

				alerts := engine.Evaluate(event)
				hasCombinedAlert := false
				for _, alert := range alerts {
					if alert.RuleID == "web_combined_attack" {
						hasCombinedAlert = true
						break
					}
				}

				if tc.expected {
					assert.True(t, hasCombinedAlert, "Expected combined attack alert for: %s", tc.filename)
				} else {
					assert.False(t, hasCombinedAlert, "Did not expect combined attack alert for: %s", tc.filename)
				}
			})
		}
	})
}