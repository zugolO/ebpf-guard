package canary

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

func TestNew_DefaultFiles(t *testing.T) {
	m := New(Config{Enabled: true})
	if len(m.Paths()) == 0 {
		t.Fatal("expected default canary paths, got none")
	}
}

func TestNew_CustomFiles(t *testing.T) {
	files := []string{"/tmp/a.canary", "/tmp/b.canary"}
	m := New(Config{Enabled: true, Files: files})
	if len(m.Paths()) != 2 {
		t.Fatalf("expected 2 paths, got %d", len(m.Paths()))
	}
}

func TestSetup_AutoCreate(t *testing.T) {
	dir := t.TempDir()
	files := []string{
		filepath.Join(dir, "shadow.canary"),
		filepath.Join(dir, "secret.key"),
	}
	m := New(Config{Enabled: true, AutoCreate: true, Files: files})
	m.Setup()

	for _, f := range files {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("canary file not created: %s: %v", f, err)
		}
	}
}

func TestSetup_NoAutoCreate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shadow.canary")
	m := New(Config{Enabled: true, AutoCreate: false, Files: []string{path}})
	m.Setup()
	if _, err := os.Stat(path); err == nil {
		t.Error("expected no file when auto_create=false")
	}
}

func TestSetup_IdempotentCreate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trap")
	m := New(Config{Enabled: true, AutoCreate: true, Files: []string{path}})
	m.Setup()
	m.Setup() // second call should not panic or error
	if _, err := os.Stat(path); err != nil {
		t.Errorf("file missing after second Setup call: %v", err)
	}
}

func TestRules_Count(t *testing.T) {
	files := []string{"/a", "/b", "/c"}
	m := New(Config{Enabled: true, Files: files})
	rules := m.Rules()
	if len(rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(rules))
	}
}

func TestRules_Fields(t *testing.T) {
	m := New(Config{
		Enabled:       true,
		Files:         []string{"/etc/shadow.canary"},
		AlertSeverity: "critical",
	})
	rules := m.Rules()
	if len(rules) == 0 {
		t.Fatal("expected at least one rule")
	}
	r := rules[0]
	if r.EventType != types.EventFileAccess {
		t.Errorf("expected EventFileAccess, got %d", r.EventType)
	}
	if r.Condition.Op != correlator.OpEquals {
		t.Errorf("expected equals operator, got %s", r.Condition.Op)
	}
	if len(r.Condition.Values) == 0 || r.Condition.Values[0] != "/etc/shadow.canary" {
		t.Errorf("unexpected condition values: %v", r.Condition.Values)
	}
	if r.Severity != "critical" {
		t.Errorf("expected critical severity, got %s", r.Severity)
	}
	if r.Action != correlator.ActionAlert {
		t.Errorf("expected alert action, got %s", r.Action)
	}
}

func TestRules_DefaultSeverity(t *testing.T) {
	m := New(Config{Enabled: true, Files: []string{"/tmp/trap"}})
	rules := m.Rules()
	if rules[0].Severity != "critical" {
		t.Errorf("expected default severity critical, got %s", rules[0].Severity)
	}
}

func TestRules_Tags(t *testing.T) {
	m := New(Config{Enabled: true, Files: []string{"/tmp/trap"}})
	rules := m.Rules()
	tags := rules[0].Tags
	found := false
	for _, tag := range tags {
		if tag == "canary" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'canary' tag, got %v", tags)
	}
}
