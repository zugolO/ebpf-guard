package correlator_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// TestWave6_1ContainerAxis is the positive/negative control for wave 6.1
// (plan.md, "Контейнерная идентификация", criterion 6.1): a Q9 rule must fire
// on a containerized web workload even when its comm does not appear in the
// fixed comm allowlist (a Node app's actual file-syscall comm is a libuv
// worker thread name, e.g. "libuv-worker", not "node" — the allowlist can
// never be extended to cover every runtime's thread names), and must still
// stay silent for the same file read by a host process with no container
// identity (sshd). This is the result sentinel plan.md's rule В requires:
// it asserts the alert fired AND that it fired via the container.id axis,
// not a coincidental comm match.
func TestWave6_1ContainerAxis(t *testing.T) {
	const opOpen = 0

	fileEvent := func(comm, path, containerID string) types.Event {
		e := types.Event{
			Type: types.EventFileAccess,
			PID:  4242,
			File: &types.FileEvent{Op: opOpen},
		}
		copy(e.Comm[:], comm)
		copy(e.File.Filename[:], path)
		if containerID != "" {
			e.Enrichment = &types.EnrichmentInfo{ContainerID: containerID}
		}
		return e
	}

	const juiceShopContainerID = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85"

	cases := []struct {
		ruleID string
		file   string
		path   string
	}{
		{"owasp_path_traversal", "../../rules/owasp-web.yaml", "/var/www/../../../../etc/passwd"},
		{"owasp_web_sensitive_file_read", "../../rules/owasp-web.yaml", "/etc/passwd"},
		{"appexploit_lfi_passwd_access", "../../rules/application-exploits.yaml", "/etc/passwd"},
		{"appexploit_xxe_file_read", "../../rules/application-exploits.yaml", "/etc/passwd"},
		{"webshell_sensitive_file_read", "../../rules/webshell-detection.yaml", "/etc/passwd"},
	}

	for _, tc := range cases {
		t.Run(tc.ruleID, func(t *testing.T) {
			rules, err := correlator.LoadRulesFromFile(tc.file)
			require.NoError(t, err)

			var target *correlator.Rule
			for i := range rules {
				if rules[i].ID == tc.ruleID {
					target = &rules[i]
					break
				}
			}
			require.NotNil(t, target, "rule %s not found in %s", tc.ruleID, tc.file)
			engine := correlator.NewRuleEngine([]correlator.Rule{*target})

			// Juice Shop's actual file-syscall comm ("libuv-worker") is not in
			// the web-worker comm allowlist. Without container.id enrichment
			// this must stay silent — pins the defect the fix addresses.
			assert.Empty(t, engine.Evaluate(fileEvent("libuv-worker", tc.path, "")),
				"rule %s: a libuv-worker comm with no container enrichment must not "+
					"alert on its own — the container axis, not the comm coincidence, "+
					"is what should raise this", tc.ruleID)

			// Same comm, but now with container enrichment (Juice Shop's cgroup
			// resolved to a container ID by wave 6.1's enricher fix) — must fire.
			assert.NotEmpty(t, engine.Evaluate(fileEvent("libuv-worker", tc.path, juiceShopContainerID)),
				"rule %s: a containerized web workload must be detected via "+
					"container.id even when its comm ('libuv-worker') isn't in the "+
					"web-worker allowlist (criterion 6.1)", tc.ruleID)

			// Negative control: the same file read by sshd on the host (no
			// container identity) must not raise a "web server" rule — this is
			// the other half of criterion 6.1 ("тот же файл, читаемый sshd, —
			// не поднимает").
			assert.Empty(t, engine.Evaluate(fileEvent("sshd", tc.path, "")),
				"rule %s: sshd reading %s on the host (no container, no web-worker "+
					"comm) must not alert", tc.ruleID, tc.path)
		})
	}
}
