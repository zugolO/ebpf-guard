package correlator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// TestWebAttacksNetworkRules tests the network-payload (http_plaintext) rules
// from rules/web-attacks-network.yaml — the Phase B follow-up to issue #281 that
// closes the gap Phase A (web-attacks-enhanced.yaml, file-based only) could not:
// real SQLi/XSS/path-traversal detection against captured HTTP payload bytes.
func TestWebAttacksNetworkRules(t *testing.T) {
	rules, err := LoadRulesFromFile("../../rules/web-attacks-network.yaml")
	require.NoError(t, err, "Failed to load web-attacks-network.yaml")
	require.NotEmpty(t, rules, "Rules file should not be empty")

	engine := NewRuleEngine(rules)

	makeHTTPEvent := func(payload string) types.Event {
		var data [256]byte
		n := copy(data[:], payload)
		return types.Event{
			Type: types.EventHTTPPlaintext,
			HTTPPlaintext: &types.HTTPEvent{
				Direction: types.HTTPDirectionRequest,
				DataLen:   uint32(n),
				Data:      data,
			},
		}
	}

	t.Run("SQL Injection Network Patterns", func(t *testing.T) {
		cases := []struct {
			name     string
			payload  string
			expected bool
		}{
			{"UNION SELECT in query string", "GET /products?id=1 union select username,password from users HTTP/1.1", true},
			{"Boolean SQLi", "GET /login?user=admin' or 1=1-- HTTP/1.1", true},
			{"DROP TABLE", "POST /api/exec HTTP/1.1\r\n\r\ndrop table users", true},
			{"Normal request", "GET /index.html HTTP/1.1", false},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				alerts := engine.Evaluate(makeHTTPEvent(tc.payload))
				found := false
				for _, alert := range alerts {
					if alert.RuleID == "web_sql_injection_network" {
						found = true
						break
					}
				}
				if tc.expected {
					assert.True(t, found, "Expected SQLi network alert for: %s", tc.payload)
				} else {
					assert.False(t, found, "Did not expect SQLi network alert for: %s", tc.payload)
				}
			})
		}
	})

	t.Run("XSS Network Patterns", func(t *testing.T) {
		cases := []struct {
			name     string
			payload  string
			expected bool
		}{
			{"Script tag in query", "GET /search?q=<script>alert(1)</script> HTTP/1.1", true},
			{"Event handler payload", "POST /comment HTTP/1.1\r\n\r\nname=onerror=alert(1)", true},
			{"Normal request", "GET /style.css HTTP/1.1", false},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				alerts := engine.Evaluate(makeHTTPEvent(tc.payload))
				found := false
				for _, alert := range alerts {
					if alert.RuleID == "web_xss_network_pattern" {
						found = true
						break
					}
				}
				if tc.expected {
					assert.True(t, found, "Expected XSS network alert for: %s", tc.payload)
				} else {
					assert.False(t, found, "Did not expect XSS network alert for: %s", tc.payload)
				}
			})
		}
	})

	t.Run("Path Traversal Network Patterns", func(t *testing.T) {
		cases := []struct {
			name     string
			payload  string
			expected bool
		}{
			{"Basic traversal", "GET /files/../../etc/passwd HTTP/1.1", true},
			{"URL-encoded traversal", "GET /files/%2e%2e%2f%2e%2e%2fetc%2fpasswd HTTP/1.1", true},
			{"Normal request", "GET /files/report.pdf HTTP/1.1", false},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				alerts := engine.Evaluate(makeHTTPEvent(tc.payload))
				found := false
				for _, alert := range alerts {
					if alert.RuleID == "web_path_traversal_network" {
						found = true
						break
					}
				}
				if tc.expected {
					assert.True(t, found, "Expected path traversal network alert for: %s", tc.payload)
				} else {
					assert.False(t, found, "Did not expect path traversal network alert for: %s", tc.payload)
				}
			})
		}
	})
}
