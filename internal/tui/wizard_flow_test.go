//go:build tui

package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// wizStep applies one message to a WizardModel and returns the concrete model.
func wizStep(m WizardModel, msg tea.Msg) WizardModel {
	nm, _ := m.Update(msg)
	return nm.(WizardModel)
}

func TestWizardInitNil(t *testing.T) {
	if NewWizardModel().Init() != nil {
		t.Error("wizard Init should return nil cmd")
	}
}

// TestWizardFullFlow drives the wizard end to end via Update, exercising
// advance(), dynamic field population, choice selection, and text entry.
func TestWizardFullFlow(t *testing.T) {
	m := NewWizardModel()

	// Step 0: event type. Move cursor down then back up to cover navigation,
	// then select "network" (index 1).
	m = wizStep(m, keyType(tea.KeyDown)) // cursor 0 -> 1 (network)
	m = wizStep(m, keyType(tea.KeyUp))   // 1 -> 0
	m = wizStep(m, keyType(tea.KeyDown)) // 0 -> 1 (network)
	if m.cursor != 1 {
		t.Fatalf("cursor after down/up/down = %d, want 1", m.cursor)
	}
	m = wizStep(m, keyType(tea.KeyEnter)) // select network, advance to step 1
	if m.stepIdx != 1 {
		t.Fatalf("stepIdx after first select = %d, want 1", m.stepIdx)
	}
	// Step 1 choices must have been populated from the network event type.
	if len(m.steps[1].choices) == 0 || m.steps[1].choices[0].value != "dport" {
		t.Fatalf("field choices not populated for network: %+v", m.steps[1].choices)
	}

	// Step 1: field — select first (dport) via space.
	m = wizStep(m, keyRunes(" "))
	if m.stepIdx != 2 {
		t.Fatalf("stepIdx after field select = %d, want 2", m.stepIdx)
	}

	// Step 2: operator — select first (eq).
	m = wizStep(m, keyType(tea.KeyEnter))

	// Step 3: values (text). Type, backspace, retype.
	m = wizStep(m, keyRunes("4"))
	m = wizStep(m, keyRunes("4"))
	m = wizStep(m, keyRunes("5"))
	m = wizStep(m, keyType(tea.KeyBackspace)) // remove the erroneous 5
	m = wizStep(m, keyRunes("4"))
	m = wizStep(m, keyRunes("4"))
	if m.steps[3].input != "4444" {
		t.Fatalf("value input = %q, want 4444", m.steps[3].input)
	}
	m = wizStep(m, keyType(tea.KeyEnter))

	// Step 4: severity — select first (warning).
	m = wizStep(m, keyType(tea.KeyEnter))
	// Step 5: action — select first (alert).
	m = wizStep(m, keyType(tea.KeyEnter))

	// Step 6: name (text).
	for _, r := range "my rule" {
		m = wizStep(m, keyRunes(string(r)))
	}
	m = wizStep(m, keyType(tea.KeyEnter))

	// Step 7: description (blank) — Enter completes the wizard.
	if m.done {
		t.Fatal("wizard should not be done before the last step")
	}
	m = wizStep(m, keyType(tea.KeyEnter))
	if !m.done {
		t.Fatal("wizard should be done after the final step")
	}

	yaml := m.yaml
	for _, want := range []string{
		"event_type: network",
		`field: "dport"`,
		"op: eq",
		`"4444"`,
		"severity: warning",
		"action: alert",
		`name: "my rule"`,
		"custom_my_rule",
	} {
		if !strings.Contains(yaml, want) {
			t.Errorf("final YAML missing %q:\n%s", want, yaml)
		}
	}
}

// TestWizardDoneStateQuits verifies that once done, q/enter/ctrl+c quit.
func TestWizardDoneStateQuits(t *testing.T) {
	m := NewWizardModel()
	m.done = true
	for _, k := range []tea.KeyMsg{keyRunes("q"), keyType(tea.KeyEnter), keyType(tea.KeyCtrlC)} {
		_, cmd := m.Update(k)
		if !isQuitCmd(cmd) {
			t.Errorf("done wizard should quit on %v", k)
		}
	}
	// A non-quit key in done state is a harmless no-op.
	_, cmd := m.Update(keyRunes("x"))
	if cmd != nil {
		t.Error("unexpected cmd from stray key in done state")
	}
}

// TestWizardQuitKeys verifies ctrl+c / q quit mid-flow for both step kinds.
func TestWizardQuitKeys(t *testing.T) {
	// stepChoose: q quits.
	m := NewWizardModel()
	if _, cmd := m.Update(keyRunes("q")); !isQuitCmd(cmd) {
		t.Error("q on a choose step should quit")
	}
	// stepText: ctrl+c quits.
	m2 := NewWizardModel()
	m2.stepIdx = 3 // values (text) step
	if _, cmd := m2.Update(keyType(tea.KeyCtrlC)); !isQuitCmd(cmd) {
		t.Error("ctrl+c on a text step should quit")
	}
}

// TestWizardBuildYAMLDefaultName covers the auto-generated name/description branch.
func TestWizardBuildYAMLDefaults(t *testing.T) {
	m := NewWizardModel()
	m.steps[0].answer = "file"
	m.steps[1].answer = "filename"
	m.steps[2].answer = "prefix"
	m.steps[3].answer = "/etc/, /root/" // comma-separated, with blank-trimmed entries
	m.steps[4].answer = "critical"
	m.steps[5].answer = "block"
	m.steps[6].answer = "" // blank name -> auto-generated
	m.steps[7].answer = "watch sensitive dirs"

	yaml := m.buildYAML()
	if !strings.Contains(yaml, "detect_file_filename") {
		t.Errorf("blank name should auto-generate detect_<type>_<field>:\n%s", yaml)
	}
	if !strings.Contains(yaml, `description: "watch sensitive dirs"`) {
		t.Errorf("description block missing:\n%s", yaml)
	}
	if !strings.Contains(yaml, `"/etc/"`) || !strings.Contains(yaml, `"/root/"`) {
		t.Errorf("comma-separated values not both present:\n%s", yaml)
	}
}

// TestWizardViewProgresses renders the view at a choose step, a text step,
// and the done screen — asserting content, not exact layout.
func TestWizardView(t *testing.T) {
	m := NewWizardModel()
	choose := m.View()
	if !strings.Contains(choose, "Step 1/") || !strings.Contains(choose, "event") {
		t.Errorf("choose-step view missing progress/question:\n%s", choose)
	}

	// Advance to a text step (values) and render.
	m.stepIdx = 3
	m.steps[3].input = "abc"
	text := m.View()
	if !strings.Contains(text, "Step 4/") {
		t.Errorf("text-step view missing progress:\n%s", text)
	}

	// Done screen.
	m.done = true
	m.yaml = "rules:\n  - id: custom_x\n"
	done := m.View()
	if !strings.Contains(done, "Rule generated") || !strings.Contains(done, "custom_x") {
		t.Errorf("done view should show generated YAML:\n%s", done)
	}
}

// TestFieldChoicesDefault covers the fallback branch for an unknown event type.
func TestFieldChoicesDefault(t *testing.T) {
	choices := fieldChoices("nonsense")
	if len(choices) != 1 || choices[0].value != "comm" {
		t.Errorf("unknown event type should fall back to [comm], got %+v", choices)
	}
}
