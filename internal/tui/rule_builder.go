//go:build tui

package tui

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// ─── Styles (rule-builder-specific) ─────────────────────────────────────────

var (
	styleRBTitle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("39")).
			Bold(true)
	styleRBFocused = lipgloss.NewStyle().
			Foreground(lipgloss.Color("214")).
			Bold(true)
	styleRBActive = lipgloss.NewStyle().
			Foreground(lipgloss.Color("82")).
			Bold(true)
	styleRBField = lipgloss.NewStyle().
			Foreground(lipgloss.Color("39"))
	styleRBOp = lipgloss.NewStyle().
			Foreground(lipgloss.Color("141"))
	styleRBValue = lipgloss.NewStyle().
			Foreground(lipgloss.Color("252"))
	styleRBBtn = lipgloss.NewStyle().
			Foreground(lipgloss.Color("230")).
			Background(lipgloss.Color("62")).
			Padding(0, 1)
	styleRBBtnFocused = lipgloss.NewStyle().
				Foreground(lipgloss.Color("16")).
				Background(lipgloss.Color("214")).
				Padding(0, 1).
				Bold(true)
	styleRBStatus = lipgloss.NewStyle().
			Foreground(lipgloss.Color("82")).
			Italic(true)
	styleRBError = lipgloss.NewStyle().
			Foreground(lipgloss.Color("196")).
			Italic(true)
	styleRBEditBuf = lipgloss.NewStyle().
			Foreground(lipgloss.Color("230")).
			Background(lipgloss.Color("236")).
			Padding(0, 1)
)

// ─── Available operators ─────────────────────────────────────────────────────

var conditionOps = []string{
	"eq", "in", "not_in", "prefix", "suffix", "contains", "regex", "gt", "lt", "in_cidr",
}

var rbSeverities = []string{"warning", "critical"}
var rbActions = []string{"alert", "block", "kill", "throttle", "drop"}

// ─── Focus layout ────────────────────────────────────────────────────────────

// Focus positions: 0..N-1 = condition rows, N = severity, N+1 = action,
// N+2 = test button, N+3 = save button, N+4 = cancel button.

const (
	rbExtraRows = 5 // severity, action, test, save, cancel
)

// ─── Condition draft ─────────────────────────────────────────────────────────

// ConditionDraft is an editable condition pre-populated from a live event.
type ConditionDraft struct {
	Field string
	Op    string
	Value string
	opIdx int // index into conditionOps
}

// ─── Builder mode ────────────────────────────────────────────────────────────

type rbMode int

const (
	rbModeNav      rbMode = iota // navigating with j/k/arrows
	rbModeEditVal                // typing a new value for a condition
)

// ─── Result signals ──────────────────────────────────────────────────────────

// RuleBuilderResult signals the outcome of an Update call to the parent.
type RuleBuilderResult int

const (
	RuleBuilderContinue RuleBuilderResult = iota
	RuleBuilderCancel
	RuleBuilderSaved
)

// ─── Model ───────────────────────────────────────────────────────────────────

// RuleBuilderModel is the interactive rule builder pane embedded in the dashboard.
type RuleBuilderModel struct {
	event        types.Event
	eventType    string
	eventDesc    string
	conditions   []ConditionDraft
	severityIdx  int
	actionIdx    int
	recentEvents []types.Event

	width  int
	height int

	focusIdx int   // 0..N-1: conditions; N..N+4: severity/action/test/save/cancel
	mode     rbMode
	editBuf  string

	testResult string
	saveStatus string
	saveErr    bool
}

// NewRuleBuilderModel creates a rule builder pre-populated from the given event.
func NewRuleBuilderModel(e types.Event, recentEvents []types.Event, w, h int) RuleBuilderModel {
	etype, conds := extractEventFields(e)
	return RuleBuilderModel{
		event:        e,
		eventType:    etype,
		eventDesc:    formatEventDesc(e),
		conditions:   conds,
		recentEvents: recentEvents,
		width:        w,
		height:       h,
	}
}

// ─── Focus helpers ───────────────────────────────────────────────────────────

func (m *RuleBuilderModel) maxFocus() int    { return len(m.conditions) + rbExtraRows - 1 }
func (m *RuleBuilderModel) idxSeverity() int { return len(m.conditions) }
func (m *RuleBuilderModel) idxAction() int   { return len(m.conditions) + 1 }
func (m *RuleBuilderModel) idxTest() int     { return len(m.conditions) + 2 }
func (m *RuleBuilderModel) idxSave() int     { return len(m.conditions) + 3 }
func (m *RuleBuilderModel) idxCancel() int   { return len(m.conditions) + 4 }

func (m *RuleBuilderModel) currentSeverity() string { return rbSeverities[m.severityIdx] }
func (m *RuleBuilderModel) currentAction() string   { return rbActions[m.actionIdx] }

// ─── Update ──────────────────────────────────────────────────────────────────

// Update processes a key message and returns the updated model and result signal.
func (m RuleBuilderModel) Update(msg tea.Msg) (RuleBuilderModel, RuleBuilderResult) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, RuleBuilderContinue

	case tea.KeyMsg:
		if m.mode == rbModeEditVal {
			return m.handleEditKey(msg)
		}
		return m.handleNavKey(msg)
	}
	return m, RuleBuilderContinue
}

func (m RuleBuilderModel) handleNavKey(msg tea.KeyMsg) (RuleBuilderModel, RuleBuilderResult) {
	switch msg.String() {
	case "esc", "ctrl+c":
		return m, RuleBuilderCancel

	case "up", "k":
		if m.focusIdx > 0 {
			m.focusIdx--
		}

	case "down", "j":
		if m.focusIdx < m.maxFocus() {
			m.focusIdx++
		}

	case "left", "h":
		switch {
		case m.focusIdx < len(m.conditions):
			c := &m.conditions[m.focusIdx]
			c.opIdx = (c.opIdx - 1 + len(conditionOps)) % len(conditionOps)
			c.Op = conditionOps[c.opIdx]
		case m.focusIdx == m.idxSeverity():
			m.severityIdx = (m.severityIdx - 1 + len(rbSeverities)) % len(rbSeverities)
		case m.focusIdx == m.idxAction():
			m.actionIdx = (m.actionIdx - 1 + len(rbActions)) % len(rbActions)
		}

	case "right", "l":
		switch {
		case m.focusIdx < len(m.conditions):
			c := &m.conditions[m.focusIdx]
			c.opIdx = (c.opIdx + 1) % len(conditionOps)
			c.Op = conditionOps[c.opIdx]
		case m.focusIdx == m.idxSeverity():
			m.severityIdx = (m.severityIdx + 1) % len(rbSeverities)
		case m.focusIdx == m.idxAction():
			m.actionIdx = (m.actionIdx + 1) % len(rbActions)
		}

	case "e", "enter":
		switch {
		case m.focusIdx < len(m.conditions):
			// Enter value edit mode for the focused condition
			m.editBuf = m.conditions[m.focusIdx].Value
			m.mode = rbModeEditVal
		case m.focusIdx == m.idxTest():
			m.runTest()
		case m.focusIdx == m.idxSave():
			if err := m.save(); err != nil {
				m.saveStatus = "error: " + err.Error()
				m.saveErr = true
			} else {
				m.saveStatus = "saved → rules/custom.yaml (hot-reload triggered)"
				m.saveErr = false
				return m, RuleBuilderSaved
			}
		case m.focusIdx == m.idxCancel():
			return m, RuleBuilderCancel
		}

	case "t":
		m.runTest()

	case "s":
		if err := m.save(); err != nil {
			m.saveStatus = "error: " + err.Error()
			m.saveErr = true
		} else {
			m.saveStatus = "saved → rules/custom.yaml (hot-reload triggered)"
			m.saveErr = false
			return m, RuleBuilderSaved
		}
	}

	return m, RuleBuilderContinue
}

func (m RuleBuilderModel) handleEditKey(msg tea.KeyMsg) (RuleBuilderModel, RuleBuilderResult) {
	switch msg.String() {
	case "enter":
		if m.focusIdx < len(m.conditions) {
			m.conditions[m.focusIdx].Value = m.editBuf
		}
		m.mode = rbModeNav
	case "esc":
		m.mode = rbModeNav
	case "backspace":
		if len(m.editBuf) > 0 {
			m.editBuf = m.editBuf[:len(m.editBuf)-1]
		}
	default:
		if msg.Type == tea.KeyRunes {
			m.editBuf += msg.String()
		}
	}
	return m, RuleBuilderContinue
}

// ─── Test logic ──────────────────────────────────────────────────────────────

func (m *RuleBuilderModel) runTest() {
	cutoff := time.Now().Add(-5 * time.Minute)
	var matches int
	for _, e := range m.recentEvents {
		ts := time.Unix(0, int64(e.Timestamp))
		if ts.Before(cutoff) {
			continue
		}
		if m.matchEvent(e) {
			matches++
		}
	}
	total := 0
	for _, e := range m.recentEvents {
		ts := time.Unix(0, int64(e.Timestamp))
		if !ts.Before(cutoff) {
			total++
		}
	}
	m.testResult = fmt.Sprintf("%d matches in last 5 min  (checked %d events)", matches, total)
}

func (m *RuleBuilderModel) matchEvent(e types.Event) bool {
	if eventTypeName(e.Type) != m.eventType {
		return false
	}
	for _, cond := range m.conditions {
		if !rbMatchCondition(e, cond) {
			return false
		}
	}
	return true
}

func rbMatchCondition(e types.Event, cond ConditionDraft) bool {
	val := rbGetFieldValue(e, cond.Field)
	switch cond.Op {
	case "eq", "equals":
		return val == cond.Value
	case "neq", "not_equals":
		return val != cond.Value
	case "prefix":
		return strings.HasPrefix(val, cond.Value)
	case "suffix":
		return strings.HasSuffix(val, cond.Value)
	case "contains":
		return strings.Contains(val, cond.Value)
	case "in":
		for _, v := range strings.Split(cond.Value, ",") {
			if strings.TrimSpace(v) == val {
				return true
			}
		}
		return false
	case "not_in":
		for _, v := range strings.Split(cond.Value, ",") {
			if strings.TrimSpace(v) == val {
				return false
			}
		}
		return true
	case "gt":
		var a, b int64
		fmt.Sscanf(val, "%d", &a)
		fmt.Sscanf(cond.Value, "%d", &b)
		return a > b
	case "lt":
		var a, b int64
		fmt.Sscanf(val, "%d", &a)
		fmt.Sscanf(cond.Value, "%d", &b)
		return a < b
	}
	return false
}

func rbGetFieldValue(e types.Event, field string) string {
	comm := strings.TrimRight(string(e.Comm[:]), "\x00")
	switch field {
	case "comm":
		return comm
	case "uid":
		return fmt.Sprintf("%d", e.UID)
	}
	switch e.Type {
	case types.EventTCPConnect:
		if e.Network == nil {
			return ""
		}
		switch field {
		case "daddr":
			return ipStr(e.Network.Daddr, e.Network.Family)
		case "saddr":
			return ipStr(e.Network.Saddr, e.Network.Family)
		case "dport":
			return fmt.Sprintf("%d", e.Network.Dport)
		case "sport":
			return fmt.Sprintf("%d", e.Network.Sport)
		}
	case types.EventFileAccess:
		if e.File == nil {
			return ""
		}
		switch field {
		case "filename", "fd.name":
			f := strings.TrimRight(string(e.File.Filename[:]), "\x00")
			if f == "" {
				f = e.File.FDPath
			}
			return f
		case "op":
			return fmt.Sprintf("%d", e.File.Op)
		case "flags":
			return fmt.Sprintf("%d", e.File.Flags)
		}
	case types.EventSyscall:
		if e.Syscall == nil {
			return ""
		}
		switch field {
		case "nr":
			return fmt.Sprintf("%d", e.Syscall.Nr)
		case "ret":
			return fmt.Sprintf("%d", e.Syscall.Ret)
		}
	case types.EventDNS:
		if e.DNS == nil {
			return ""
		}
		switch field {
		case "qname":
			return e.DNS.QName
		case "qtype":
			return fmt.Sprintf("%d", e.DNS.QType)
		}
	case types.EventKmodLoad:
		if e.Kmod == nil {
			return ""
		}
		switch field {
		case "name":
			return e.Kmod.ModName
		}
	}
	return ""
}

// ─── Save logic ──────────────────────────────────────────────────────────────

func (m *RuleBuilderModel) save() error {
	yaml := m.buildRuleYAML()
	return saveToCustomRules(yaml)
}

func (m *RuleBuilderModel) buildRuleYAML() string {
	ruleID := fmt.Sprintf("custom_auto_%d", time.Now().UnixNano()/1e6%1e9)

	condBlock := m.buildConditionsBlock()

	return fmt.Sprintf(`rules:
  - id: %s
    name: "Auto-generated from live event"
    event_type: %s
%s
    severity: %s
    action: %s
    tags:
      - custom
      - auto-generated
`, ruleID, m.eventType, condBlock, m.currentSeverity(), m.currentAction())
}

func (m *RuleBuilderModel) buildConditionsBlock() string {
	if len(m.conditions) == 0 {
		return "    condition:\n      field: comm\n      op: eq\n      values:\n        - \"\""
	}
	if len(m.conditions) == 1 {
		c := m.conditions[0]
		return fmt.Sprintf("    condition:\n      field: %q\n      op: %s\n      values:\n%s",
			c.Field, c.Op, valuesBlock(c.Value, "        "))
	}

	var sb strings.Builder
	sb.WriteString("    condition_group:\n")
	sb.WriteString("      operator: and\n")
	sb.WriteString("      conditions:\n")
	for _, c := range m.conditions {
		sb.WriteString(fmt.Sprintf("      - field: %q\n", c.Field))
		sb.WriteString(fmt.Sprintf("        op: %s\n", c.Op))
		sb.WriteString("        values:\n")
		sb.WriteString(valuesBlock(c.Value, "          "))
		sb.WriteString("\n")
	}
	return sb.String()
}

func valuesBlock(value, indent string) string {
	parts := strings.Split(value, ",")
	var lines []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			lines = append(lines, fmt.Sprintf("%s- %q", indent, p))
		}
	}
	if len(lines) == 0 {
		lines = []string{indent + `- ""`}
	}
	return strings.Join(lines, "\n")
}

// saveToCustomRules appends the generated rule to rules/custom.yaml.
// If the file does not exist it is created. If it already contains a rules list
// the new entry is appended under the existing header.
func saveToCustomRules(fullYAML string) error {
	const path = "rules/custom.yaml"
	if err := os.MkdirAll("rules", 0755); err != nil {
		return err
	}

	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	var content string
	if len(strings.TrimSpace(string(existing))) == 0 {
		content = fullYAML
	} else {
		// Extract the rule entry lines (everything after "rules:") and append.
		entry := ruleEntryLines(fullYAML)
		content = strings.TrimRight(string(existing), "\n") + "\n" + entry + "\n"
	}

	return os.WriteFile(path, []byte(content), 0644)
}

// ruleEntryLines returns the lines from fullYAML that belong to the rule item
// (i.e. everything after the top-level "rules:" key).
func ruleEntryLines(fullYAML string) string {
	lines := strings.Split(fullYAML, "\n")
	for i, l := range lines {
		if strings.TrimSpace(l) == "rules:" {
			return strings.Join(lines[i+1:], "\n")
		}
	}
	return fullYAML
}

// ─── Field extraction ────────────────────────────────────────────────────────

// extractEventFields derives the event type string and a set of pre-populated
// condition drafts from a live kernel event.
func extractEventFields(e types.Event) (eventType string, conds []ConditionDraft) {
	comm := strings.TrimRight(string(e.Comm[:]), "\x00")

	switch e.Type {
	case types.EventTCPConnect:
		eventType = "network"
		if e.Network != nil {
			daddr := ipStr(e.Network.Daddr, e.Network.Family)
			if daddr != "" && daddr != "0.0.0.0" {
				conds = append(conds, cond("daddr", "eq", daddr))
			}
			if e.Network.Dport > 0 {
				conds = append(conds, cond("dport", "eq", fmt.Sprintf("%d", e.Network.Dport)))
			}
		}
		if comm != "" {
			conds = append(conds, cond("comm", "eq", comm))
		}

	case types.EventFileAccess:
		eventType = "file"
		if e.File != nil {
			filename := strings.TrimRight(string(e.File.Filename[:]), "\x00")
			if filename == "" {
				filename = e.File.FDPath
			}
			if filename != "" {
				conds = append(conds, cond("filename", "prefix", filename))
			}
		}
		if comm != "" {
			conds = append(conds, cond("comm", "eq", comm))
		}

	case types.EventSyscall:
		eventType = "syscall"
		if e.Syscall != nil {
			conds = append(conds, cond("nr", "eq", fmt.Sprintf("%d", e.Syscall.Nr)))
		}
		if e.UID == 0 && comm != "" {
			conds = append(conds, cond("uid", "eq", "0"))
		}
		if comm != "" {
			conds = append(conds, cond("comm", "eq", comm))
		}

	case types.EventDNS:
		eventType = "dns"
		if e.DNS != nil && e.DNS.QName != "" {
			conds = append(conds, cond("qname", "eq", e.DNS.QName))
		}
		if comm != "" {
			conds = append(conds, cond("comm", "eq", comm))
		}

	case types.EventPrivesc:
		eventType = "privesc"
		if comm != "" {
			conds = append(conds, cond("comm", "eq", comm))
		}

	case types.EventKmodLoad:
		eventType = "kmod"
		if e.Kmod != nil && e.Kmod.ModName != "" {
			conds = append(conds, cond("name", "eq", e.Kmod.ModName))
		}
		if comm != "" {
			conds = append(conds, cond("comm", "eq", comm))
		}

	default:
		eventType = "syscall"
		if comm != "" {
			conds = append(conds, cond("comm", "eq", comm))
		}
	}

	// Initialize opIdx for each condition.
	for i, c := range conds {
		for j, op := range conditionOps {
			if op == c.Op {
				conds[i].opIdx = j
				break
			}
		}
		_ = c
	}
	return eventType, conds
}

func cond(field, op, value string) ConditionDraft {
	return ConditionDraft{Field: field, Op: op, Value: value}
}

// ─── Event description ───────────────────────────────────────────────────────

func formatEventDesc(e types.Event) string {
	comm := strings.TrimRight(string(e.Comm[:]), "\x00")
	switch e.Type {
	case types.EventTCPConnect:
		if e.Network != nil {
			return fmt.Sprintf("NETWORK  %s(%d) → %s:%d",
				comm, e.PID,
				ipStr(e.Network.Daddr, e.Network.Family), e.Network.Dport)
		}
	case types.EventFileAccess:
		if e.File != nil {
			fname := strings.TrimRight(string(e.File.Filename[:]), "\x00")
			if fname == "" {
				fname = e.File.FDPath
			}
			return fmt.Sprintf("FILE  %s(%d)  %s", comm, e.PID, fname)
		}
	case types.EventSyscall:
		if e.Syscall != nil {
			return fmt.Sprintf("SYSCALL  %s(%d)  nr=%d  uid=%d", comm, e.PID, e.Syscall.Nr, e.UID)
		}
	case types.EventDNS:
		if e.DNS != nil {
			return fmt.Sprintf("DNS  %s(%d)  %s", comm, e.PID, e.DNS.QName)
		}
	}
	return fmt.Sprintf("EVENT  %s(%d)  type=%d", comm, e.PID, e.Type)
}

// eventTypeName maps an EventType to the string used in rule YAML.
func eventTypeName(t types.EventType) string {
	switch t {
	case types.EventTCPConnect:
		return "network"
	case types.EventFileAccess:
		return "file"
	case types.EventSyscall:
		return "syscall"
	case types.EventDNS:
		return "dns"
	case types.EventPrivesc:
		return "privesc"
	case types.EventNetClose:
		return "net_close"
	case types.EventKmodLoad:
		return "kmod"
	case types.EventCgroupEsc:
		return "cgroup_esc"
	case types.EventGPU:
		return "gpu"
	case types.EventLSMAudit:
		return "lsm_audit"
	case types.EventCloudAudit:
		return "cloud_audit"
	default:
		return "syscall"
	}
}

// ipStr converts a 16-byte address buffer to a string.
func ipStr(b [16]byte, family types.AddressFamily) string {
	if family == types.AFInet6 {
		return net.IP(b[:]).String()
	}
	return net.IP(b[:4]).String()
}

// ─── View ────────────────────────────────────────────────────────────────────

// View renders the rule builder pane.
func (m RuleBuilderModel) View() string {
	var sb strings.Builder

	// Header
	sb.WriteString("\n")
	sb.WriteString(styleRBTitle.Render("  Rule Builder") + "\n")
	sb.WriteString(styleDim.Render("  Event: "+m.eventDesc) + "\n\n")

	// Conditions list
	sb.WriteString(styleHeader.Render("  Conditions") + "  " +
		styleDim.Render("(←/→ change operator  e/Enter edit value)") + "\n")

	for i, c := range m.conditions {
		cursor := "  "
		if i == m.focusIdx {
			cursor = styleRBFocused.Render("► ")
		}

		fieldStr := styleRBField.Render(fmt.Sprintf("%-14s", c.Field))

		var opStr string
		if i == m.focusIdx && m.mode == rbModeNav {
			opStr = styleRBFocused.Render(fmt.Sprintf("[%-10s]", c.Op))
		} else {
			opStr = styleRBOp.Render(fmt.Sprintf("[%-10s]", c.Op))
		}

		var valStr string
		if i == m.focusIdx && m.mode == rbModeEditVal {
			buf := m.editBuf
			if buf == "" {
				buf = " "
			}
			valStr = styleRBEditBuf.Render(buf+"_") + styleDim.Render("  ← type, Enter to confirm, Esc cancel")
		} else {
			display := c.Value
			if len(display) > 30 {
				display = display[:27] + "..."
			}
			valStr = styleRBValue.Render(fmt.Sprintf("%q", display))
		}

		sb.WriteString(fmt.Sprintf("  %s%s  op: %s  val: %s\n", cursor, fieldStr, opStr, valStr))
	}

	sb.WriteString("\n")

	// Severity
	sevFocus := m.focusIdx == m.idxSeverity()
	sevStyle := styleRBActive
	if sevFocus {
		sevStyle = styleRBFocused
	}
	sb.WriteString(fmt.Sprintf("  %s  Severity: %s  %s\n",
		m.focusMark(m.idxSeverity()),
		sevStyle.Render(fmt.Sprintf("[◀ %-8s ▶]", m.currentSeverity())),
		styleDim.Render("(←/→ to change)"),
	))

	// Action
	actFocus := m.focusIdx == m.idxAction()
	actStyle := styleRBActive
	if actFocus {
		actStyle = styleRBFocused
	}
	sb.WriteString(fmt.Sprintf("  %s  Action:   %s  %s\n",
		m.focusMark(m.idxAction()),
		actStyle.Render(fmt.Sprintf("[◀ %-8s ▶]", m.currentAction())),
		styleDim.Render("(←/→ to change)"),
	))

	sb.WriteString("\n")

	// Buttons
	testBtn := styleRBBtn.Render("Test on last 5min events")
	if m.focusIdx == m.idxTest() {
		testBtn = styleRBBtnFocused.Render("Test on last 5min events")
	}
	saveBtn := styleRBBtn.Render("Save to rules/custom.yaml")
	if m.focusIdx == m.idxSave() {
		saveBtn = styleRBBtnFocused.Render("Save to rules/custom.yaml")
	}
	cancelBtn := styleRBBtn.Render("Cancel")
	if m.focusIdx == m.idxCancel() {
		cancelBtn = styleRBBtnFocused.Render("Cancel")
	}

	sb.WriteString("  " + testBtn + "  " + saveBtn + "  " + cancelBtn + "\n")

	// Test / save status
	if m.testResult != "" {
		sb.WriteString("\n  " + styleRBStatus.Render("✦ "+m.testResult) + "\n")
	}
	if m.saveStatus != "" {
		style := styleRBStatus
		if m.saveErr {
			style = styleRBError
		}
		sb.WriteString("  " + style.Render("✦ "+m.saveStatus) + "\n")
	}

	sb.WriteString("\n")
	sb.WriteString(styleDim.Render(
		"  ↑/↓ navigate  ←/→ change op/severity/action  e edit value  t test  s save  Esc cancel",
	))

	return sb.String()
}

func (m *RuleBuilderModel) focusMark(idx int) string {
	if m.focusIdx == idx {
		return styleRBFocused.Render("►")
	}
	return " "
}
