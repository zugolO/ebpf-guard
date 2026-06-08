// Package tests exercises all YAML rule fixture files under tests/rules/ as
// Go sub-tests.  This file intentionally lives outside the main source tree so
// that `go test ./tests/...` runs the rule fixtures without importing any BPF
// or kernel-specific packages that would break on CI runners.
package tests

import (
	"testing"

	ruletesting "github.com/zugolO/ebpf-guard/internal/testing"
)

func TestRuleFixtures(t *testing.T) {
	// Each fixture file specifies its own rules_path; no global fallback needed.
	ruletesting.RunDir(t, "rules", "")
}
