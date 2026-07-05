// Package tests exercises repository-wide consistency checks that don't
// belong in the main source tree (so `go test ./tests/...` stays free of any
// BPF/kernel-specific imports).
package tests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestHelmAiAgentContentMatchesCanonicalRuleset guards against the Helm chart
// drift flagged in issue #271: deploy/helm/ebpf-guard/values.yaml embeds
// `rules.aiAgentContent` as a verbatim copy of rules/ai-agent/ai-agent.yaml so
// the DaemonSet can mount it as a ConfigMap. Because it is a second, hand-kept
// copy rather than something generated from the canonical file, a detection
// fix landed in one can silently fail to reach the other — a cluster mounts
// whatever the chart embeds, not the file under rules/. This test fails CI the
// moment the two diverge, so a change to one is caught if the other is not
// updated to match (until the values.yaml copy is replaced with real
// generation at package time).
func TestHelmAiAgentContentMatchesCanonicalRuleset(t *testing.T) {
	repoRoot := repoRootFromTests(t)

	canonicalPath := filepath.Join(repoRoot, "rules", "ai-agent", "ai-agent.yaml")
	canonical, err := os.ReadFile(canonicalPath) // #nosec G304 -- fixed repo-relative test path
	if err != nil {
		t.Fatalf("reading canonical ruleset %s: %v", canonicalPath, err)
	}

	valuesPath := filepath.Join(repoRoot, "deploy", "helm", "ebpf-guard", "values.yaml")
	valuesRaw, err := os.ReadFile(valuesPath) // #nosec G304 -- fixed repo-relative test path
	if err != nil {
		t.Fatalf("reading Helm values %s: %v", valuesPath, err)
	}

	var values struct {
		Rules struct {
			AiAgentContent string `yaml:"aiAgentContent"`
		} `yaml:"rules"`
	}
	if err := yaml.Unmarshal(valuesRaw, &values); err != nil {
		t.Fatalf("parsing %s: %v", valuesPath, err)
	}
	if strings.TrimSpace(values.Rules.AiAgentContent) == "" {
		t.Fatalf("%s: rules.aiAgentContent is empty — expected the embedded copy of %s", valuesPath, canonicalPath)
	}

	embedded := strings.TrimRight(values.Rules.AiAgentContent, "\n")
	canon := strings.TrimRight(string(canonical), "\n")
	if embedded != canon {
		t.Errorf(
			"deploy/helm/ebpf-guard/values.yaml rules.aiAgentContent has drifted from rules/ai-agent/ai-agent.yaml.\n" +
				"Update the embedded copy in values.yaml to match the canonical file (or generate it at package time) — " +
				"see issue #271.",
		)
	}
}

// repoRootFromTests locates the repository root from this test file's
// directory (tests/), so the test works regardless of the working directory
// `go test` is invoked from.
func repoRootFromTests(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return filepath.Dir(wd) // tests/ -> repo root
}
