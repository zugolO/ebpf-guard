package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ─── Styles (wizard-specific) ─────────────────────────────────────────────

var (
	styleWizTitle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("39")).
			Bold(true).
			Padding(1, 2)
	stylePrompt = lipgloss.NewStyle().
			Foreground(lipgloss.Color("252"))
	styleSelected = lipgloss.NewStyle().
			Foreground(lipgloss.Color("82")).
			Bold(true)
	styleCursor = lipgloss.NewStyle().
			Foreground(lipgloss.Color("214")).
			Bold(true)
	styleInput = lipgloss.NewStyle().
			Foreground(lipgloss.Color("230")).
			Background(lipgloss.Color("236")).
			Padding(0, 1)
	styleHint = lipgloss.NewStyle().
			Foreground(lipgloss.Color("241")).
			Italic(true)
	styleStep = lipgloss.NewStyle().
			Foreground(lipgloss.Color("62")).
			Bold(true)
	styleDone = lipgloss.NewStyle().
			Foreground(lipgloss.Color("82")).
			Bold(true).
			Padding(1, 2).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("82"))
)

// ─── Choice ─────────────────────────────────────────────────────────────────

type choice struct {
	label string
	value string
	hint  string
}

// ─── Wizard step types ───────────────────────────────────────────────────────

type stepKind int

const (
	stepChoose stepKind = iota // single-choice from a list
	stepText                   // free-text input
)

type step struct {
	kind     stepKind
	question string
	choices  []choice // for stepChoose
	input    string   // accumulated text input (for stepText)
	answer   string   // final answer (value for choice, text for stepText)
}

// ─── Wizard model ────────────────────────────────────────────────────────────

// WizardModel is the bubbletea model for the rule-builder wizard.
type WizardModel struct {
	steps    []step
	cursor   int
	stepIdx  int
	done     bool
	yaml     string
	width    int
}

// NewWizardModel creates the wizard with all steps pre-populated.
func NewWizardModel() WizardModel {
	steps := []step{
		{
			kind:     stepChoose,
			question: "What type of event do you want to detect?",
			choices: []choice{
				{"Syscall", "syscall", "system calls made by processes (execve, open, connect…)"},
				{"Network connection", "network", "TCP connections to/from a process"},
				{"File access", "file", "open / read / write of files"},
				{"DNS query", "dns", "outbound DNS lookups"},
				{"TLS traffic", "tls", "encrypted TLS payloads captured via uprobes"},
				{"Privilege escalation", "privesc", "Linux capability changes (CAP_SYS_ADMIN…)"},
				{"Kernel module load", "kmod", "insmod / modprobe events"},
			},
		},
		{
			kind:     stepChoose,
			question: "Which field do you want to match on?",
			// Choices filled dynamically after event_type is chosen
		},
		{
			kind:     stepChoose,
			question: "Which operator should the condition use?",
			choices: []choice{
				{"eq", "eq", "exact match"},
				{"neq", "neq", "not equal"},
				{"in", "in", "value is in a list"},
				{"not_in", "not_in", "value is NOT in a list"},
				{"prefix", "prefix", "string starts with"},
				{"regex", "regex", "regular expression (RE2 syntax)"},
				{"gt", "gt", "greater than (numeric)"},
				{"lt", "lt", "less than (numeric)"},
				{"in_cidr", "in_cidr", "IP address is inside a CIDR range"},
			},
		},
		{
			kind:     stepText,
			question: "Enter the value(s) to match (comma-separated for lists):",
		},
		{
			kind:     stepChoose,
			question: "What is the alert severity?",
			choices: []choice{
				{"warning", "warning", "suspicious but not immediately dangerous"},
				{"critical", "critical", "high-priority — immediate response needed"},
			},
		},
		{
			kind:     stepChoose,
			question: "What action should ebpf-guard take when this rule matches?",
			choices: []choice{
				{"alert", "alert", "generate an alert only — no enforcement"},
				{"block", "block", "block network traffic via nftables/XDP"},
				{"kill", "kill", "send SIGKILL to the offending process"},
				{"throttle", "throttle", "CPU-throttle the process via cgroup v2"},
				{"drop", "drop", "silently drop the event (suppress noise)"},
			},
		},
		{
			kind:     stepText,
			question: "Give this rule a short name:",
		},
		{
			kind:     stepText,
			question: "Optional: rule description (leave blank to skip):",
		},
	}
	return WizardModel{steps: steps}
}

// fieldChoices returns field choices depending on the selected event type.
func fieldChoices(eventType string) []choice {
	switch eventType {
	case "syscall":
		return []choice{
			{"syscall_nr", "syscall_nr", "syscall number"},
			{"comm", "comm", "process name"},
			{"ppid", "ppid", "parent process ID"},
			{"uid", "uid", "user ID"},
			{"parent_comm", "parent_comm", "parent process name"},
		}
	case "network":
		return []choice{
			{"dport", "dport", "destination port"},
			{"sport", "sport", "source port"},
			{"daddr", "daddr", "destination IP address"},
			{"saddr", "saddr", "source IP address"},
			{"comm", "comm", "process name"},
			{"uid", "uid", "user ID"},
		}
	case "file":
		return []choice{
			{"filename", "filename", "file path"},
			{"flags", "flags", "open(2) flags bitmask"},
			{"op", "op", "operation: 0=open 1=read 2=write"},
			{"comm", "comm", "process name"},
			{"uid", "uid", "user ID"},
		}
	case "dns":
		return []choice{
			{"qname", "qname", "queried domain name"},
			{"qtype", "qtype", "record type (1=A, 28=AAAA, 16=TXT)"},
			{"comm", "comm", "process name"},
		}
	case "tls":
		return []choice{
			{"data", "data", "plaintext content (regex)"},
			{"direction", "direction", "0=write(outbound) 1=read(inbound)"},
			{"comm", "comm", "process name"},
		}
	case "privesc":
		return []choice{
			{"caps_gained", "caps_gained", "newly gained capability bits (bitmask)"},
			{"comm", "comm", "process name"},
		}
	case "kmod":
		return []choice{
			{"module_name", "module_name", "kernel module name"},
			{"from_tmpfs", "from_tmpfs", "loaded from /tmp or /dev/shm (true/false)"},
			{"comm", "comm", "process name"},
		}
	default:
		return []choice{
			{"comm", "comm", "process name"},
		}
	}
}

// Init implements tea.Model.
func (m WizardModel) Init() tea.Cmd { return nil }

// Update implements tea.Model.
func (m WizardModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.done {
		if key, ok := msg.(tea.KeyMsg); ok {
			if key.String() == "q" || key.String() == "ctrl+c" || key.String() == "enter" {
				return m, tea.Quit
			}
		}
		return m, nil
	}

	current := &m.steps[m.stepIdx]

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width

	case tea.KeyMsg:
		switch current.kind {
		case stepChoose:
			switch msg.String() {
			case "up", "k":
				if m.cursor > 0 {
					m.cursor--
				}
			case "down", "j":
				if m.cursor < len(current.choices)-1 {
					m.cursor++
				}
			case "enter", " ":
				current.answer = current.choices[m.cursor].value
				m.cursor = 0
				m.advance()
			case "ctrl+c", "q":
				return m, tea.Quit
			}

		case stepText:
			switch msg.String() {
			case "enter":
				current.answer = current.input
				m.cursor = 0
				m.advance()
			case "ctrl+c":
				return m, tea.Quit
			case "backspace":
				if len(current.input) > 0 {
					current.input = current.input[:len(current.input)-1]
				}
			default:
				if msg.Type == tea.KeyRunes {
					current.input += msg.String()
				}
			}
		}
	}
	return m, nil
}

// advance moves to the next step, skipping or populating dynamically.
func (m *WizardModel) advance() {
	m.stepIdx++
	if m.stepIdx >= len(m.steps) {
		m.yaml = m.buildYAML()
		m.done = true
		return
	}
	// Step 1 (field choices) depends on step 0 (event type).
	if m.stepIdx == 1 {
		eventType := m.steps[0].answer
		m.steps[1].choices = fieldChoices(eventType)
	}
}

// buildYAML renders the collected answers into a rule YAML string.
func (m *WizardModel) buildYAML() string {
	eventType := m.steps[0].answer
	field := m.steps[1].answer
	op := m.steps[2].answer
	rawValues := m.steps[3].answer
	severity := m.steps[4].answer
	action := m.steps[5].answer
	name := strings.TrimSpace(m.steps[6].answer)
	desc := strings.TrimSpace(m.steps[7].answer)

	// Parse values
	parts := strings.Split(rawValues, ",")
	valLines := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			valLines = append(valLines, fmt.Sprintf("        - %q", p))
		}
	}
	valBlock := strings.Join(valLines, "\n")

	if name == "" {
		name = fmt.Sprintf("detect_%s_%s", eventType, field)
	}
	// Generate a rule ID from the name
	ruleID := "custom_" + strings.ToLower(strings.ReplaceAll(name, " ", "_"))
	ruleID = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			return r
		}
		return '_'
	}, ruleID)

	descBlock := ""
	if desc != "" {
		descBlock = fmt.Sprintf("    description: %q\n", desc)
	}

	return fmt.Sprintf(`rules:
  - id: %s
    name: %q
%s    event_type: %s
    condition:
      field: %q
      op: %s
      values:
%s
    severity: %s
    action: %s
    tags:
      - custom
`, ruleID, name, descBlock, eventType, field, op, valBlock, severity, action)
}

// View implements tea.Model.
func (m WizardModel) View() string {
	if m.done {
		return styleDone.Render(
			styleWizTitle.Render("✓  Rule generated!") + "\n\n" +
				"Copy the YAML below into your rules directory:\n\n" +
				lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Render(m.yaml) +
				"\n\n" + styleHint.Render("Press Enter or q to exit"),
		)
	}

	current := m.steps[m.stepIdx]
	total := len(m.steps)
	progress := fmt.Sprintf("Step %d/%d", m.stepIdx+1, total)

	var sb strings.Builder
	sb.WriteString("\n")
	sb.WriteString(styleWizTitle.Render("ebpf-guard  rule wizard") + "\n")
	sb.WriteString(styleStep.Render("  "+progress) + "\n\n")
	sb.WriteString(stylePrompt.Render("  "+current.question) + "\n\n")

	switch current.kind {
	case stepChoose:
		for i, c := range current.choices {
			cursor := "  "
			label := stylePrompt.Render(c.label)
			if i == m.cursor {
				cursor = styleCursor.Render("▶ ")
				label = styleSelected.Render(c.label)
			}
			hint := ""
			if c.hint != "" {
				hint = styleDim.Render("  — " + c.hint)
			}
			sb.WriteString(fmt.Sprintf("  %s%s%s\n", cursor, label, hint))
		}
		sb.WriteString("\n" + styleHint.Render("  ↑/↓ or j/k to move  |  Enter to select  |  q to quit"))

	case stepText:
		displayInput := current.input
		if displayInput == "" {
			displayInput = " "
		}
		sb.WriteString("  " + styleInput.Render(displayInput+"_") + "\n\n")
		sb.WriteString(styleHint.Render("  Type your answer then press Enter  |  Ctrl+C to quit"))
	}

	return sb.String()
}

// RunWizard starts the bubbletea wizard and returns the generated YAML.
// Returns empty string if the user quit without completing.
func RunWizard() (string, error) {
	m := NewWizardModel()
	p := tea.NewProgram(m, tea.WithAltScreen())
	result, err := p.Run()
	if err != nil {
		return "", err
	}
	final, ok := result.(WizardModel)
	if !ok || !final.done {
		return "", nil
	}
	return final.yaml, nil
}
