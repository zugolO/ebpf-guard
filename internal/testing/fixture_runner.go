// Package ruletesting provides a Go testing.T-integrated runner for
// ebpf-guard declarative rule fixture files (*_test.yaml).
//
// It wraps the [ruletest] package so that YAML-driven rule unit tests
// surface as first-class Go sub-tests in `go test` output and CI reports.
//
// Typical usage in a _test.go file:
//
//	func TestRuleFixtures(t *testing.T) {
//		ruletesting.RunDir(t, "testdata/rules", "../../rules")
//	}
package ruletesting

import (
	"testing"

	"github.com/zugolO/ebpf-guard/internal/ruletest"
)

// RunDir discovers all *_test.yaml files under fixtureDir and runs each
// test case as a named Go sub-test under t.  rulesDir is passed to the
// Runner as the fallback rules directory for suites that do not embed a
// rules_path.  Pass an empty string when every suite provides its own path.
func RunDir(t *testing.T, fixtureDir, rulesDir string) {
	t.Helper()

	files, err := ruletest.Discover(fixtureDir)
	if err != nil {
		t.Fatalf("fixture discovery failed for %s: %v", fixtureDir, err)
	}
	if len(files) == 0 {
		t.Skipf("no *_test.yaml fixtures found under %s", fixtureDir)
		return
	}

	runner := &ruletest.Runner{RulesDir: rulesDir}

	for _, f := range files {
		f := f
		suite, rulesPath, loadErr := ruletest.LoadSuite(f)
		if loadErr != nil {
			t.Errorf("load fixture %s: %v", f, loadErr)
			continue
		}

		eng, engErr := runner.BuildEngine(rulesPath)
		if engErr != nil {
			t.Errorf("build rule engine for %s: %v", f, engErr)
			continue
		}

		results := ruletest.RunSuite(suite, eng)
		for _, res := range results {
			res := res
			t.Run(suite.Suite+"/"+res.Name, func(t *testing.T) {
				t.Parallel()
				if res.Passed {
					return
				}
				if res.Error != "" {
					t.Errorf("event build error: %s", res.Error)
					return
				}
				if len(res.MatchedIDs) > 0 {
					t.Errorf("expected %s, got %s (fired rules: %v)",
						res.Expected, res.Got, res.MatchedIDs)
				} else {
					t.Errorf("expected %s, got %s (no rules fired)",
						res.Expected, res.Got)
				}
			})
		}
	}
}

// RunFile runs a single fixture file as Go sub-tests under t.
// rulesDir is the fallback rules directory (may be empty).
func RunFile(t *testing.T, fixturePath, rulesDir string) {
	t.Helper()

	suite, rulesPath, err := ruletest.LoadSuite(fixturePath)
	if err != nil {
		t.Fatalf("load fixture %s: %v", fixturePath, err)
	}

	runner := &ruletest.Runner{RulesDir: rulesDir}
	eng, err := runner.BuildEngine(rulesPath)
	if err != nil {
		t.Fatalf("build rule engine for %s: %v", fixturePath, err)
	}

	results := ruletest.RunSuite(suite, eng)
	for _, res := range results {
		res := res
		t.Run(suite.Suite+"/"+res.Name, func(t *testing.T) {
			t.Parallel()
			if res.Passed {
				return
			}
			if res.Error != "" {
				t.Errorf("event build error: %s", res.Error)
				return
			}
			if len(res.MatchedIDs) > 0 {
				t.Errorf("expected %s, got %s (fired rules: %v)",
					res.Expected, res.Got, res.MatchedIDs)
			} else {
				t.Errorf("expected %s, got %s (no rules fired)",
					res.Expected, res.Got)
			}
		})
	}
}
