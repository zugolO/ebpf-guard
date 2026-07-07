package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zugolO/ebpf-guard/internal/store"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

func TestNewRulesTestCmd_ReplaysMatchingEvent(t *testing.T) {
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "rule.yaml")
	writeFile(t, rulePath, minimalRuleYAML("rulestest_matching_rule"))

	logPath := filepath.Join(dir, "events.jsonl")
	el, err := store.NewEventLog(store.EventLogConfig{Path: logPath})
	if err != nil {
		t.Fatalf("NewEventLog: %v", err)
	}
	if err := el.Write(types.Event{
		Type:    types.EventTCPConnect,
		PID:     42,
		Network: &types.NetworkEvent{Dport: 4444, Family: types.AFInet},
	}); err != nil {
		t.Fatalf("write event: %v", err)
	}
	el.Close()

	cfgPath := writeMinimalConfig(t, dir, "memory", "")
	cmd := newRulesTestCmd(&cfgPath)
	cmd.SetArgs([]string{"--rule", rulePath, "--events-log", logPath, "--replay", "24h"})
	out := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Errorf("rules test error = %v", err)
		}
	})
	if !strings.Contains(out, "Loaded 1 rule(s)") {
		t.Errorf("rules test output = %q, want it to report loading 1 rule", out)
	}
	if !strings.Contains(out, "rulestest_matching_rule") {
		t.Errorf("rules test output = %q, want the matching rule ID mentioned in the summary", out)
	}
}

func TestNewRulesTestCmd_MissingRuleFlag(t *testing.T) {
	cfgPath := writeMinimalConfig(t, t.TempDir(), "memory", "")
	cmd := newRulesTestCmd(&cfgPath)
	cmd.SetArgs([]string{"--replay", "1h"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("rules test without --rule error = nil, want error")
	}
}

func TestNewRulesTestCmd_InvalidReplayDuration(t *testing.T) {
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "rule.yaml")
	writeFile(t, rulePath, minimalRuleYAML("rulestest_bad_replay"))

	cfgPath := writeMinimalConfig(t, dir, "memory", "")
	cmd := newRulesTestCmd(&cfgPath)
	cmd.SetArgs([]string{"--rule", rulePath, "--replay", "not-a-duration"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("rules test with invalid --replay error = nil, want error")
	}
}

func TestNewRulesTestCmd_MissingRuleFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeMinimalConfig(t, dir, "memory", "")
	cmd := newRulesTestCmd(&cfgPath)
	cmd.SetArgs([]string{"--rule", filepath.Join(dir, "no-such-rule.yaml")})
	if err := cmd.Execute(); err == nil {
		t.Fatal("rules test with missing rule file error = nil, want error")
	}
}

func TestNewRulesCheckCmd_PassingSuite(t *testing.T) {
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "rule.yaml")
	writeFile(t, rulePath, minimalRuleYAML("ruleschk_pass_rule"))

	suitePath := filepath.Join(dir, "suite_test.yaml")
	writeFile(t, suitePath, `suite: check_cmd_pass
rules_path: `+rulePath+`
tests:
  - name: "dport 4444 fires the rule"
    rule_id: ruleschk_pass_rule
    event:
      type: network
      network:
        dport: 4444
    expect: alert
    expect_severity: critical
  - name: "dport 80 does not fire"
    event:
      type: network
      network:
        dport: 80
    expect: no_alert
`)

	cmd := newRulesCheckCmd()
	cmd.SetArgs([]string{suitePath})
	out := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Errorf("rules check (passing suite) error = %v", err)
		}
	})
	if !strings.Contains(out, "2/2 passed") {
		t.Errorf("rules check output = %q, want 2/2 passed", out)
	}
	if !strings.Contains(out, "ok 1") || !strings.Contains(out, "ok 2") {
		t.Errorf("rules check output = %q, want TAP ok lines for both tests", out)
	}
}

func TestNewRulesCheckCmd_FailingSuiteReturnsError(t *testing.T) {
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "rule.yaml")
	writeFile(t, rulePath, minimalRuleYAML("ruleschk_fail_rule"))

	suitePath := filepath.Join(dir, "suite_test.yaml")
	writeFile(t, suitePath, `suite: check_cmd_fail
rules_path: `+rulePath+`
tests:
  - name: "wrongly expects no_alert on a matching event"
    event:
      type: network
      network:
        dport: 4444
    expect: no_alert
`)

	cmd := newRulesCheckCmd()
	cmd.SetArgs([]string{suitePath})
	out := captureStdout(t, func() {
		if err := cmd.Execute(); err == nil {
			t.Error("rules check (failing suite) error = nil, want error")
		}
	})
	if !strings.Contains(out, "not ok 1") {
		t.Errorf("rules check output = %q, want a TAP 'not ok' line", out)
	}
}

func TestNewRulesCheckCmd_GlobalRulesFlag(t *testing.T) {
	rulesDir := t.TempDir()
	writeFile(t, filepath.Join(rulesDir, "rule.yaml"), minimalRuleYAML("ruleschk_global_rule"))

	// The suite intentionally omits rules_path, relying on --rules instead.
	suitePath := filepath.Join(t.TempDir(), "suite_test.yaml")
	writeFile(t, suitePath, `suite: check_cmd_global_rules
tests:
  - name: "dport 4444 fires the rule"
    rule_id: ruleschk_global_rule
    event:
      type: network
      network:
        dport: 4444
    expect: alert
`)

	cmd := newRulesCheckCmd()
	cmd.SetArgs([]string{suitePath, "--rules", rulesDir})
	out := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Errorf("rules check --rules error = %v", err)
		}
	})
	if !strings.Contains(out, "1/1 passed") {
		t.Errorf("rules check --rules output = %q, want 1/1 passed", out)
	}
}

func TestNewRulesCheckCmd_JUnitOutput(t *testing.T) {
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "rule.yaml")
	writeFile(t, rulePath, minimalRuleYAML("ruleschk_junit_rule"))

	suitePath := filepath.Join(dir, "suite_test.yaml")
	writeFile(t, suitePath, `suite: check_cmd_junit
rules_path: `+rulePath+`
tests:
  - name: "dport 4444 fires the rule"
    rule_id: ruleschk_junit_rule
    event:
      type: network
      network:
        dport: 4444
    expect: alert
`)
	junitPath := filepath.Join(dir, "results.xml")

	cmd := newRulesCheckCmd()
	cmd.SetArgs([]string{suitePath, "--junit", junitPath})
	captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Errorf("rules check --junit error = %v", err)
		}
	})

	content, err := os.ReadFile(junitPath)
	if err != nil {
		t.Fatalf("read junit output: %v", err)
	}
	if !strings.Contains(string(content), "<testsuite") {
		t.Errorf("junit output = %q, want a <testsuite> element", content)
	}
}
