package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/internal/config"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// captureStdout redirects os.Stdout for the duration of fn and returns
// everything written to it. Commands under test print via fmt.Printf
// directly to os.Stdout rather than an injected io.Writer, so tests capture
// at the file-descriptor level instead.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()

	fn()
	_ = w.Close()
	out := <-done
	return out
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = orig }()

	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()

	fn()
	_ = w.Close()
	out := <-done
	return out
}

func TestGenerateToken(t *testing.T) {
	tok, err := generateToken()
	if err != nil {
		t.Fatalf("generateToken() error = %v", err)
	}
	if len(tok) != 64 {
		t.Errorf("generateToken() len = %d, want 64 (32 bytes hex-encoded)", len(tok))
	}
	tok2, err := generateToken()
	if err != nil {
		t.Fatalf("generateToken() second call error = %v", err)
	}
	if tok == tok2 {
		t.Errorf("generateToken() returned the same token twice: %q", tok)
	}
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		name       string
		s          string
		defaultDur time.Duration
		want       time.Duration
	}{
		{"empty string returns zero", "", time.Hour, 0},
		{"zero string returns zero", "0", time.Hour, 0},
		{"valid duration parsed", "5m", time.Hour, 5 * time.Minute},
		{"invalid duration falls back to default", "not-a-duration", 42 * time.Second, 42 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseDuration(tt.s, tt.defaultDur)
			if got != tt.want {
				t.Errorf("parseDuration(%q, %v) = %v, want %v", tt.s, tt.defaultDur, got, tt.want)
			}
		})
	}
}

func TestRuleIDsFrom(t *testing.T) {
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "rule.yaml")
	writeFile(t, rulePath, minimalRuleYAML("ruleids_from_rule"))

	rules, err := loadRules(rulePath)
	if err != nil {
		t.Fatalf("loadRules error = %v", err)
	}
	ids := ruleIDsFrom(rules)
	if len(ids) != 1 || ids[0] != "ruleids_from_rule" {
		t.Errorf("ruleIDsFrom() = %v, want [ruleids_from_rule]", ids)
	}

	if empty := ruleIDsFrom(nil); len(empty) != 0 {
		t.Errorf("ruleIDsFrom(nil) = %v, want empty slice", empty)
	}
}

func TestLoadRules_File(t *testing.T) {
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "rule.yaml")
	writeFile(t, rulePath, minimalRuleYAML("loadrules_file_rule"))

	rules, err := loadRules(rulePath)
	if err != nil {
		t.Fatalf("loadRules(file) error = %v", err)
	}
	if len(rules) != 1 || rules[0].ID != "loadrules_file_rule" {
		t.Errorf("loadRules(file) = %+v, want single rule with ID loadrules_file_rule", rules)
	}
}

func TestLoadRules_Dir(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.yaml"), minimalRuleYAML("loadrules_dir_rule_a"))
	writeFile(t, filepath.Join(dir, "b.yaml"), minimalRuleYAML("loadrules_dir_rule_b"))

	rules, err := loadRules(dir)
	if err != nil {
		t.Fatalf("loadRules(dir) error = %v", err)
	}
	if len(rules) != 2 {
		t.Errorf("loadRules(dir) returned %d rules, want 2", len(rules))
	}
}

func TestLoadRules_MissingPath(t *testing.T) {
	_, err := loadRules(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err == nil {
		t.Fatal("loadRules(missing path) error = nil, want error")
	}
}

func TestLoadRulesWithTuning_MissingTuningFileIsNoOp(t *testing.T) {
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "rule.yaml")
	writeFile(t, rulePath, minimalRuleYAML("tuning_missing_file_rule"))

	rules, err := loadRulesWithTuning(rulePath, filepath.Join(dir, "does-not-exist-tuning.yaml"))
	if err != nil {
		t.Fatalf("loadRulesWithTuning error = %v", err)
	}
	if len(rules) != 1 || len(rules[0].Exceptions) != 0 {
		t.Errorf("loadRulesWithTuning() = %+v, want single rule with no exceptions", rules)
	}
}

func TestLoadRulesWithTuning_MergesExceptions(t *testing.T) {
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "rule.yaml")
	writeFile(t, rulePath, minimalRuleYAML("tuning_merge_rule"))

	tuningPath := filepath.Join(dir, "local-tuning.yaml")
	writeFile(t, tuningPath, `
overlays:
  - rule_id: tuning_merge_rule
    exceptions:
      - name: allow-lo
        condition:
          field: dport
          op: eq
          values: [4444]
`)

	rules, err := loadRulesWithTuning(rulePath, tuningPath)
	if err != nil {
		t.Fatalf("loadRulesWithTuning error = %v", err)
	}
	if len(rules) != 1 || len(rules[0].Exceptions) != 1 || rules[0].Exceptions[0].Name != "allow-lo" {
		t.Errorf("loadRulesWithTuning() = %+v, want single rule with 1 merged exception", rules)
	}
}

func TestLoadRulesWithTuning_BaseRulesErrorPropagates(t *testing.T) {
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "rule.yaml")
	writeFile(t, rulePath, "not: [valid yaml")

	if _, err := loadRulesWithTuning(rulePath, ""); err == nil {
		t.Fatal("loadRulesWithTuning(invalid rules) error = nil, want error")
	}
}

func TestLoadRulesWithTuning_InvalidTuningFileErrors(t *testing.T) {
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "rule.yaml")
	writeFile(t, rulePath, minimalRuleYAML("tuning_invalid_overlay_rule"))

	tuningPath := filepath.Join(dir, "local-tuning.yaml")
	writeFile(t, tuningPath, "overlays: [this is not valid yaml")

	if _, err := loadRulesWithTuning(rulePath, tuningPath); err == nil {
		t.Fatal("loadRulesWithTuning(invalid tuning file) error = nil, want error")
	}
}

func TestLoadRulesWithTuning_InvalidOverlayFieldErrors(t *testing.T) {
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "rule.yaml")
	writeFile(t, rulePath, minimalRuleYAML("tuning_bad_field_rule"))

	tuningPath := filepath.Join(dir, "local-tuning.yaml")
	writeFile(t, tuningPath, `
overlays:
  - rule_id: tuning_bad_field_rule
    exceptions:
      - name: bad
        condition:
          field: not_a_real_field
          op: eq
          values: [x]
`)

	if _, err := loadRulesWithTuning(rulePath, tuningPath); err == nil {
		t.Fatal("loadRulesWithTuning(invalid overlay field) error = nil, want error")
	}
}

func TestLoadRulesWithTuning_UnknownRuleIDIsWarnedNotErrored(t *testing.T) {
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "rule.yaml")
	writeFile(t, rulePath, minimalRuleYAML("tuning_known_rule"))

	tuningPath := filepath.Join(dir, "local-tuning.yaml")
	writeFile(t, tuningPath, `
overlays:
  - rule_id: rule_that_does_not_exist
    exceptions:
      - name: x
        condition:
          field: dport
          op: eq
          values: [4444]
`)

	rules, err := loadRulesWithTuning(rulePath, tuningPath)
	if err != nil {
		t.Fatalf("loadRulesWithTuning error = %v", err)
	}
	if len(rules) != 1 || len(rules[0].Exceptions) != 0 {
		t.Errorf("loadRulesWithTuning() = %+v, want unmodified rule (unknown rule_id skipped)", rules)
	}
}

func TestBuildSyntheticEvents(t *testing.T) {
	events := buildSyntheticEvents(0)
	if len(events) != 6 {
		t.Errorf("buildSyntheticEvents(0) len = %d, want 6 (treats <=0 as 1)", len(events))
	}

	events2 := buildSyntheticEvents(3)
	if len(events2) != 18 {
		t.Errorf("buildSyntheticEvents(3) len = %d, want 18", len(events2))
	}

	seenTypes := make(map[types.EventType]bool)
	for _, e := range events {
		seenTypes[e.Type] = true
	}
	for _, want := range []types.EventType{
		types.EventSyscall, types.EventTCPConnect, types.EventFileAccess,
		types.EventDNS, types.EventPrivesc, types.EventKmodLoad,
	} {
		if !seenTypes[want] {
			t.Errorf("buildSyntheticEvents: missing event type %v", want)
		}
	}
}

func TestSetupLogger(t *testing.T) {
	// setupLogger just needs to not panic for any known/unknown level, and
	// must default unknown levels to info rather than erroring.
	for _, level := range []string{"debug", "info", "warn", "error", "bogus", ""} {
		setupLogger(level)
	}
}

func TestPrintZeroConfigBanner(t *testing.T) {
	cfg := config.NewZeroConfigManager().Get()
	out := captureStderr(t, func() {
		printZeroConfigBanner(cfg)
	})
	if !strings.Contains(out, "ebpf-guard") {
		t.Errorf("printZeroConfigBanner output missing version banner: %q", out)
	}
	if !strings.Contains(out, "Zero-config mode") {
		t.Errorf("printZeroConfigBanner output missing zero-config note: %q", out)
	}
}

func TestPrintZeroConfigBanner_WithAdminToken(t *testing.T) {
	cfg := config.NewZeroConfigManager().Get()
	cfg.Auth.AdminToken = "deadbeefdeadbeefdeadbeef"
	out := captureStderr(t, func() {
		printZeroConfigBanner(cfg)
	})
	if !strings.Contains(out, "Auth token (admin): deadbeefdead...") {
		t.Errorf("printZeroConfigBanner output = %q, want the truncated admin token", out)
	}
}

func TestResolveMetricsNodeName(t *testing.T) {
	origNode := os.Getenv("NODE_NAME")
	origK8s := os.Getenv("KUBERNETES_SERVICE_HOST")
	defer func() {
		_ = os.Setenv("NODE_NAME", origNode)
		_ = os.Setenv("KUBERNETES_SERVICE_HOST", origK8s)
	}()

	_ = os.Setenv("NODE_NAME", "node-a")
	_ = os.Unsetenv("KUBERNETES_SERVICE_HOST")
	if got := resolveMetricsNodeName(); got != "node-a" {
		t.Errorf("resolveMetricsNodeName() with NODE_NAME set = %q, want node-a", got)
	}

	_ = os.Unsetenv("NODE_NAME")
	_ = os.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	if got := resolveMetricsNodeName(); got != "" {
		t.Errorf("resolveMetricsNodeName() in-cluster without NODE_NAME = %q, want empty string", got)
	}

	_ = os.Unsetenv("NODE_NAME")
	_ = os.Unsetenv("KUBERNETES_SERVICE_HOST")
	want, _ := os.Hostname()
	if got := resolveMetricsNodeName(); got != want {
		t.Errorf("resolveMetricsNodeName() off-cluster = %q, want hostname %q", got, want)
	}
}

func TestWriteTokenFile_NoOpWhenBothEmpty(t *testing.T) {
	dir := t.TempDir()
	origDir := tokenFileDir
	tokenFileDir = filepath.Join(dir, "should-not-be-created")
	defer func() { tokenFileDir = origDir }()

	if err := writeTokenFile("", ""); err != nil {
		t.Fatalf("writeTokenFile(\"\", \"\") error = %v", err)
	}
	if _, err := os.Stat(tokenFileDir); !os.IsNotExist(err) {
		t.Errorf("writeTokenFile(\"\", \"\") should not create %s", tokenFileDir)
	}
}

func TestWriteTokenFile_WritesBothTokens(t *testing.T) {
	dir := t.TempDir()
	origDir := tokenFileDir
	tokenFileDir = filepath.Join(dir, "ebpf-guard")
	defer func() { tokenFileDir = origDir }()

	if err := writeTokenFile("admin-tok", "viewer-tok"); err != nil {
		t.Fatalf("writeTokenFile error = %v", err)
	}
	content, err := os.ReadFile(filepath.Join(tokenFileDir, "token"))
	if err != nil {
		t.Fatalf("read token file: %v", err)
	}
	if !strings.Contains(string(content), "admin=admin-tok") || !strings.Contains(string(content), "viewer=viewer-tok") {
		t.Errorf("token file content = %q, want both admin and viewer tokens", content)
	}
}

func TestWriteTokenFile_AdminOnly(t *testing.T) {
	dir := t.TempDir()
	origDir := tokenFileDir
	tokenFileDir = filepath.Join(dir, "ebpf-guard")
	defer func() { tokenFileDir = origDir }()

	if err := writeTokenFile("admin-tok", ""); err != nil {
		t.Fatalf("writeTokenFile error = %v", err)
	}
	content, err := os.ReadFile(filepath.Join(tokenFileDir, "token"))
	if err != nil {
		t.Fatalf("read token file: %v", err)
	}
	if !strings.Contains(string(content), "admin=admin-tok") || strings.Contains(string(content), "viewer=") {
		t.Errorf("token file content = %q, want only admin token", content)
	}
}

// writeFile is a small test helper for creating fixture files.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture %s: %v", path, err)
	}
}

// minimalRuleYAML returns a syntactically valid single-rule YAML document
// with the given rule ID, suitable for loadRules/rules-cmd fixtures.
func minimalRuleYAML(id string) string {
	return `rules:
  - id: ` + id + `
    name: "test rule"
    event_type: network
    condition:
      field: dport
      op: eq
      values: [4444]
    severity: critical
    action: alert
`
}
