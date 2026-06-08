package ruletest

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Result holds the outcome of a single test case execution.
type Result struct {
	Suite      string
	Name       string
	Passed     bool
	Expected   Expectation
	Got        Expectation
	MatchedIDs []string // rule IDs that fired
	Error      string   // set when event spec parsing failed
}

// Summary aggregates test outcomes across one or more suites.
type Summary struct {
	Total  int
	Passed int
	Failed int
}

// Evaluator is satisfied by *correlator.RuleEngine.
type Evaluator interface {
	Evaluate(e types.Event) []types.Alert
}

// RunSuite executes all test cases in s against eng and returns results.
func RunSuite(s Suite, eng Evaluator) []Result {
	results := make([]Result, 0, len(s.Tests))
	for _, tc := range s.Tests {
		results = append(results, runCase(s.Suite, tc, eng))
	}
	return results
}

func runCase(suiteName string, tc TestCase, eng Evaluator) Result {
	res := Result{
		Suite:    suiteName,
		Name:     tc.Name,
		Expected: tc.Expect,
	}

	event, err := tc.Event.Build()
	if err != nil {
		res.Error = fmt.Sprintf("build event: %v", err)
		res.Got = ExpectNoAlert
		res.Passed = tc.Expect == ExpectNoAlert
		return res
	}

	alerts := eng.Evaluate(event)

	// Classify actual outcome.
	var got Expectation
	switch {
	case len(alerts) == 0:
		got = ExpectNoAlert
	default:
		// Check whether any alert is a "drop" action.
		allDrop := true
		for _, a := range alerts {
			if a.Action != "drop" {
				allDrop = false
				break
			}
		}
		if allDrop {
			got = ExpectDrop
		} else {
			got = ExpectAlert
		}
	}
	res.Got = got

	for _, a := range alerts {
		res.MatchedIDs = append(res.MatchedIDs, a.RuleID)
	}

	// Evaluate pass/fail.
	res.Passed = checkExpectation(tc, alerts, got)
	return res
}

// checkExpectation returns true when the actual outcome satisfies the test case.
func checkExpectation(tc TestCase, alerts []types.Alert, got Expectation) bool {
	if got != tc.Expect {
		return false
	}
	// For alert expectations, check optional assertions.
	if tc.Expect == ExpectAlert {
		if id := tc.effectiveExpectRuleID(); id != "" {
			if !containsRuleID(alerts, id) {
				return false
			}
		}
		if tc.ExpectSeverity != "" {
			if !containsSeverity(alerts, tc.ExpectSeverity) {
				return false
			}
		}
	}
	return true
}

func containsRuleID(alerts []types.Alert, id string) bool {
	for _, a := range alerts {
		if a.RuleID == id {
			return true
		}
	}
	return false
}

func containsSeverity(alerts []types.Alert, sev string) bool {
	for _, a := range alerts {
		if string(a.Severity) == sev {
			return true
		}
	}
	return false
}

// ─────────────────────────────────────────────────────────────────────────────
// File discovery
// ─────────────────────────────────────────────────────────────────────────────

// Discover returns all *_test.yaml files under path (recursive).
func Discover(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("ruletest: stat %s: %w", path, err)
	}
	if !info.IsDir() {
		// Single file: accept it regardless of naming convention.
		return []string{path}, nil
	}

	var files []string
	err = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		if strings.HasSuffix(name, "_test.yaml") || strings.HasSuffix(name, "_test.yml") {
			files = append(files, p)
		}
		return nil
	})
	return files, err
}

// ─────────────────────────────────────────────────────────────────────────────
// Runner — loads rules and executes suites
// ─────────────────────────────────────────────────────────────────────────────

// Runner discovers, loads, and executes rule test suites.
type Runner struct {
	// RulesDir is the fallback directory for loading rule files when a suite
	// does not specify its own rules_path.
	RulesDir string
}

// RunPath discovers all *_test.yaml files under testPath, loads their rules,
// and executes them. The results are written to w in TAP format.
// Returns the number of failed tests, or -1 on a fatal error.
func (r *Runner) RunPath(testPath string, w *TAPWriter) (Summary, error) {
	files, err := Discover(testPath)
	if err != nil {
		return Summary{}, err
	}
	if len(files) == 0 {
		return Summary{}, fmt.Errorf("ruletest: no *_test.yaml files found under %s", testPath)
	}

	// Count total tests for TAP plan.
	total := 0
	suites := make([]Suite, 0, len(files))
	engines := make([]Evaluator, 0, len(files))

	for _, f := range files {
		suite, rulesPath, err := LoadSuite(f)
		if err != nil {
			return Summary{}, err
		}
		eng, err := r.BuildEngine(rulesPath)
		if err != nil {
			return Summary{}, fmt.Errorf("ruletest: load rules for %s: %w", f, err)
		}
		suites = append(suites, suite)
		engines = append(engines, eng)
		total += len(suite.Tests)
	}

	w.Plan(total)

	var sum Summary
	sum.Total = total

	for i, suite := range suites {
		results := RunSuite(suite, engines[i])
		for _, res := range results {
			if res.Passed {
				sum.Passed++
			} else {
				sum.Failed++
			}
			w.WriteResult(res)
		}
	}
	return sum, nil
}

// BuildEngine loads rules from rulesPath (if set) or r.RulesDir and returns
// a configured RuleEngine.
func (r *Runner) BuildEngine(rulesPath string) (Evaluator, error) {
	var rules []correlator.Rule

	// Load rules from the suite's rules_path (specific file or directory).
	if rulesPath != "" {
		info, err := os.Stat(rulesPath)
		if err != nil {
			return nil, fmt.Errorf("stat rules_path %s: %w", rulesPath, err)
		}
		if info.IsDir() {
			rules, err = correlator.LoadRulesFromDir(rulesPath)
		} else {
			rules, err = correlator.LoadRulesFromFile(rulesPath)
		}
		if err != nil {
			return nil, err
		}
	}

	// Supplement (or replace) with global --rules directory if configured.
	if r.RulesDir != "" && r.RulesDir != rulesPath {
		extra, err := correlator.LoadRulesFromDir(r.RulesDir)
		if err != nil {
			return nil, fmt.Errorf("load rules dir %s: %w", r.RulesDir, err)
		}
		// Merge: prefer suite-specific rules, add extras that are not already present.
		seen := make(map[string]struct{}, len(rules))
		for _, ru := range rules {
			seen[ru.ID] = struct{}{}
		}
		for _, ru := range extra {
			if _, ok := seen[ru.ID]; !ok {
				rules = append(rules, ru)
			}
		}
	}

	if len(rules) == 0 {
		return nil, fmt.Errorf("no rules loaded (set rules_path in the suite YAML or --rules flag)")
	}
	return correlator.NewRuleEngine(rules), nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Watch mode
// ─────────────────────────────────────────────────────────────────────────────

// Watch re-runs all tests whenever any .yaml file under watchDirs changes.
// It blocks until ctx's done channel is closed. run is called on each cycle.
func Watch(watchDirs []string, run func()) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("ruletest: create watcher: %w", err)
	}
	defer watcher.Close()

	for _, dir := range watchDirs {
		if err := watcher.Add(dir); err != nil {
			return fmt.Errorf("ruletest: watch %s: %w", dir, err)
		}
	}

	// Debounce: coalesce rapid filesystem events (editors save multiple times).
	const debounce = 300 * time.Millisecond
	var timer *time.Timer
	schedule := func() {
		if timer != nil {
			timer.Stop()
		}
		timer = time.AfterFunc(debounce, func() {
			fmt.Println("\n── file changed — re-running tests ──")
			run()
		})
	}

	for {
		select {
		case ev, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			if strings.HasSuffix(ev.Name, ".yaml") || strings.HasSuffix(ev.Name, ".yml") {
				schedule()
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			fmt.Fprintf(os.Stderr, "ruletest: watcher error: %v\n", err)
		}
	}
}
