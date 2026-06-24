package canary

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

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

// TestVerify_DetectsDeletedFile verifies that deleting a canary file causes
// an alert to be emitted within 2× the verify interval.
func TestVerify_DetectsDeletedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trap.canary")

	interval := 50 * time.Millisecond
	m := New(Config{
		Enabled:        true,
		AutoCreate:     true,
		Files:          []string{path},
		AlertSeverity:  "critical",
		VerifyInterval: interval,
		AlertOnTamper:  true,
	})
	m.Setup()

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("canary file not created: %v", err)
	}

	var mu sync.Mutex
	var alerts []types.Alert
	alertFn := func(a types.Alert) {
		mu.Lock()
		alerts = append(alerts, a)
		mu.Unlock()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := m.Start(ctx, alertFn); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Delete the canary file to trigger tampering detection.
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}

	deadline := time.Now().Add(2 * interval * 2)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(alerts)
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(alerts) == 0 {
		t.Fatal("expected alert for deleted canary file, got none within 2× interval")
	}
	a := alerts[0]
	if a.RuleID != "canary_tampered" {
		t.Errorf("expected rule_id canary_tampered, got %q", a.RuleID)
	}
	if string(a.Severity) != "critical" {
		t.Errorf("expected severity critical, got %q", a.Severity)
	}
}

// TestVerify_DetectsModifiedFile verifies that modifying a canary file's
// content causes an alert within 2× the verify interval.
func TestVerify_DetectsModifiedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.canary")

	interval := 50 * time.Millisecond
	m := New(Config{
		Enabled:        true,
		AutoCreate:     true,
		Files:          []string{path},
		AlertSeverity:  "critical",
		VerifyInterval: interval,
		AlertOnTamper:  true,
	})
	m.Setup()

	var mu sync.Mutex
	var alerts []types.Alert
	alertFn := func(a types.Alert) {
		mu.Lock()
		alerts = append(alerts, a)
		mu.Unlock()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := m.Start(ctx, alertFn); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Overwrite content to trigger hash mismatch. The trap installs the canary
	// read-only, so flip the write bit first — otherwise the overwrite fails
	// with EACCES when the test runs as a non-root user (e.g. on CI runners);
	// root ignores the mode, which is why this only surfaced outside of root.
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if err := os.WriteFile(path, []byte("attacker was here\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	deadline := time.Now().Add(2 * interval * 2)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(alerts)
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(alerts) == 0 {
		t.Fatal("expected alert for modified canary file, got none within 2× interval")
	}
}

// TestVerify_NoAlertWhenIntact verifies that an unmodified canary file
// produces no tamper alerts.
func TestVerify_NoAlertWhenIntact(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "intact.canary")

	interval := 30 * time.Millisecond
	m := New(Config{
		Enabled:        true,
		AutoCreate:     true,
		Files:          []string{path},
		AlertSeverity:  "critical",
		VerifyInterval: interval,
		AlertOnTamper:  true,
	})
	m.Setup()

	var mu sync.Mutex
	var alerts []types.Alert
	alertFn := func(a types.Alert) {
		mu.Lock()
		alerts = append(alerts, a)
		mu.Unlock()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := m.Start(ctx, alertFn); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Wait for 3 verification cycles with no modification.
	time.Sleep(interval * 3)

	mu.Lock()
	defer mu.Unlock()
	if len(alerts) != 0 {
		t.Errorf("expected no tamper alerts for intact file, got %d", len(alerts))
	}
}

// TestVerify_AlertOnTamperFalse verifies that no alert callback is invoked
// when AlertOnTamper is false, even if the file is deleted.
func TestVerify_AlertOnTamperFalse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "noalert.canary")

	interval := 30 * time.Millisecond
	m := New(Config{
		Enabled:        true,
		AutoCreate:     true,
		Files:          []string{path},
		AlertSeverity:  "critical",
		VerifyInterval: interval,
		AlertOnTamper:  false,
	})
	m.Setup()

	var called bool
	alertFn := func(_ types.Alert) { called = true }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = m.Start(ctx, alertFn)

	// Delete the file — should NOT trigger alert callback.
	_ = os.Remove(path)
	time.Sleep(interval * 3)

	if called {
		t.Error("expected no alert when AlertOnTamper=false, but alertFn was called")
	}
}
