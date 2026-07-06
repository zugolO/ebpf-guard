//go:build tui

package tui

import (
	"os"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// newNetworkRB builds a rule builder pre-populated from a network event.
// The network event yields conditions: daddr, dport, comm (3 conditions).
func newNetworkRB() RuleBuilderModel {
	e := types.Event{
		Type: types.EventTCPConnect,
		Comm: commBytes("curl"),
		PID:  100,
		Network: &types.NetworkEvent{
			Daddr: ipv4Bytes(1, 2, 3, 4), Dport: 443, Family: types.AFInet,
		},
	}
	return NewRuleBuilderModel(e, nil, 100, 40)
}

func TestRBIndexHelpers(t *testing.T) {
	m := newNetworkRB()
	n := len(m.conditions)
	if n != 3 {
		t.Fatalf("expected 3 conditions from network event, got %d", n)
	}
	if m.idxSeverity() != n || m.idxAction() != n+1 || m.idxTest() != n+2 ||
		m.idxSave() != n+3 || m.idxCancel() != n+4 {
		t.Error("focus index helpers misaligned")
	}
	if m.maxFocus() != n+rbExtraRows-1 {
		t.Errorf("maxFocus=%d, want %d", m.maxFocus(), n+rbExtraRows-1)
	}
	if m.currentSeverity() != "warning" || m.currentAction() != "alert" {
		t.Errorf("defaults: sev=%q act=%q", m.currentSeverity(), m.currentAction())
	}
}

func TestRBNavUpDownClamp(t *testing.T) {
	m := newNetworkRB()
	// Down to the bottom, then one past (should clamp at maxFocus).
	for i := 0; i < m.maxFocus()+3; i++ {
		m, _ = m.Update(keyType(tea.KeyDown))
	}
	if m.focusIdx != m.maxFocus() {
		t.Errorf("focusIdx should clamp at maxFocus=%d, got %d", m.maxFocus(), m.focusIdx)
	}
	// Up past the top clamps at 0.
	for i := 0; i < m.maxFocus()+3; i++ {
		m, _ = m.Update(keyType(tea.KeyUp))
	}
	if m.focusIdx != 0 {
		t.Errorf("focusIdx should clamp at 0, got %d", m.focusIdx)
	}
}

func TestRBLeftRightChangesOperator(t *testing.T) {
	m := newNetworkRB()
	m.focusIdx = 0 // first condition
	start := m.conditions[0].opIdx
	m, _ = m.Update(keyType(tea.KeyRight))
	if m.conditions[0].opIdx != (start+1)%len(conditionOps) {
		t.Errorf("right should advance op index")
	}
	if m.conditions[0].Op != conditionOps[m.conditions[0].opIdx] {
		t.Errorf("Op string should track opIdx: %q vs %q", m.conditions[0].Op, conditionOps[m.conditions[0].opIdx])
	}
	m, _ = m.Update(keyType(tea.KeyLeft))
	if m.conditions[0].opIdx != start {
		t.Errorf("left should revert op index to %d, got %d", start, m.conditions[0].opIdx)
	}
}

func TestRBLeftRightChangesSeverityAndAction(t *testing.T) {
	m := newNetworkRB()
	m.focusIdx = m.idxSeverity()
	m, _ = m.Update(keyType(tea.KeyRight))
	if m.currentSeverity() != "critical" {
		t.Errorf("right on severity should move to critical, got %q", m.currentSeverity())
	}
	m.focusIdx = m.idxAction()
	m, _ = m.Update(keyType(tea.KeyRight))
	if m.currentAction() == "alert" {
		t.Error("right on action should change from default alert")
	}
	m, _ = m.Update(keyType(tea.KeyLeft))
	if m.currentAction() != "alert" {
		t.Errorf("left on action should return to alert, got %q", m.currentAction())
	}
}

func TestRBEditValueFlow(t *testing.T) {
	m := newNetworkRB()
	m.focusIdx = 1 // dport condition
	// Enter edit mode — the buffer is preloaded with the current value ("443").
	m, _ = m.Update(keyRunes("e"))
	if m.mode != rbModeEditVal {
		t.Fatal("e should enter value-edit mode")
	}
	if m.editBuf != "443" {
		t.Fatalf("edit mode should preload current value, got %q", m.editBuf)
	}
	// Clear the preloaded value with backspaces, then type a new one with a correction.
	for i := 0; i < 3; i++ {
		m, _ = m.Update(keyType(tea.KeyBackspace))
	}
	m, _ = m.Update(keyType(tea.KeyBackspace)) // backspace on empty buffer is a no-op
	m, _ = m.Update(keyRunes("8"))
	m, _ = m.Update(keyRunes("0"))
	m, _ = m.Update(keyRunes("9"))
	m, _ = m.Update(keyType(tea.KeyBackspace))
	m, _ = m.Update(keyRunes("8"))
	if m.editBuf != "808" {
		t.Fatalf("editBuf=%q, want 808", m.editBuf)
	}
	// Commit with Enter.
	m, _ = m.Update(keyType(tea.KeyEnter))
	if m.mode != rbModeNav {
		t.Error("enter should return to nav mode")
	}
	if m.conditions[1].Value != "808" {
		t.Errorf("condition value not committed: %q", m.conditions[1].Value)
	}
}

func TestRBEditValueEscCancels(t *testing.T) {
	m := newNetworkRB()
	m.focusIdx = 1
	orig := m.conditions[1].Value
	m, _ = m.Update(keyRunes("e"))
	m, _ = m.Update(keyRunes("9"))
	m, _ = m.Update(keyType(tea.KeyEsc))
	if m.mode != rbModeNav {
		t.Error("esc should exit edit mode")
	}
	if m.conditions[1].Value != orig {
		t.Errorf("esc should discard edit, value changed to %q", m.conditions[1].Value)
	}
}

func TestRBTestButton(t *testing.T) {
	m := newNetworkRB()
	m.focusIdx = m.idxTest()
	m, res := m.Update(keyType(tea.KeyEnter))
	if res != RuleBuilderContinue {
		t.Errorf("test should continue, got %v", res)
	}
	if !strings.Contains(m.testResult, "matches") {
		t.Errorf("test button should populate testResult, got %q", m.testResult)
	}
	// The 't' shortcut also runs the test.
	m2 := newNetworkRB()
	m2, _ = m2.Update(keyRunes("t"))
	if !strings.Contains(m2.testResult, "matches") {
		t.Errorf("t shortcut should run test, got %q", m2.testResult)
	}
}

func TestRBCancel(t *testing.T) {
	m := newNetworkRB()
	// Esc from nav mode cancels.
	_, res := m.Update(keyType(tea.KeyEsc))
	if res != RuleBuilderCancel {
		t.Errorf("esc should cancel, got %v", res)
	}
	// Cancel button + enter also cancels.
	m.focusIdx = m.idxCancel()
	_, res = m.Update(keyType(tea.KeyEnter))
	if res != RuleBuilderCancel {
		t.Errorf("cancel button should cancel, got %v", res)
	}
}

func TestRBSaveWritesFileAndSignals(t *testing.T) {
	dir := t.TempDir()
	orig, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(orig) }()

	// Save via the 's' shortcut.
	m := newNetworkRB()
	m, res := m.Update(keyRunes("s"))
	if res != RuleBuilderSaved {
		t.Fatalf("s should signal saved, got %v", res)
	}
	if m.saveErr {
		t.Errorf("save should succeed, saveStatus=%q", m.saveStatus)
	}
	if _, err := os.Stat("rules/custom.yaml"); err != nil {
		t.Errorf("save should write rules/custom.yaml: %v", err)
	}

	// Save via the Save button (Enter on idxSave).
	m2 := newNetworkRB()
	m2.focusIdx = m2.idxSave()
	_, res = m2.Update(keyType(tea.KeyEnter))
	if res != RuleBuilderSaved {
		t.Errorf("save button should signal saved, got %v", res)
	}
}

func TestRBWindowResize(t *testing.T) {
	m := newNetworkRB()
	m, res := m.Update(tea.WindowSizeMsg{Width: 77, Height: 22})
	if res != RuleBuilderContinue {
		t.Errorf("resize should continue, got %v", res)
	}
	if m.width != 77 || m.height != 22 {
		t.Errorf("resize not applied: %d/%d", m.width, m.height)
	}
}

func TestRBView(t *testing.T) {
	m := newNetworkRB()
	out := m.View()
	if !strings.Contains(out, "Rule Builder") {
		t.Errorf("view should render the header:\n%s", out)
	}
	if !strings.Contains(out, "Severity") || !strings.Contains(out, "Action") {
		t.Errorf("view should render severity/action rows:\n%s", out)
	}

	// View in edit mode with an active buffer and status lines.
	m.focusIdx = 0
	m.mode = rbModeEditVal
	m.editBuf = "editing"
	m.testResult = "2 matches in last 5 min  (checked 5 events)"
	m.saveStatus = "error: disk full"
	m.saveErr = true
	out = m.View()
	if !strings.Contains(out, "editing") {
		t.Errorf("edit-mode view should show the edit buffer:\n%s", out)
	}
	if !strings.Contains(out, "2 matches") || !strings.Contains(out, "disk full") {
		t.Errorf("view should show test/save status:\n%s", out)
	}
}

func TestRBViewLongValueTruncated(t *testing.T) {
	m := newNetworkRB()
	m.conditions[0].Value = strings.Repeat("x", 60)
	out := m.View()
	if !strings.Contains(out, "...") {
		t.Errorf("long condition value should be truncated with ellipsis:\n%s", out)
	}
}

// ─── formatEventDesc ──────────────────────────────────────────────────────────

func TestFormatEventDesc(t *testing.T) {
	cases := []struct {
		name  string
		event types.Event
		want  string
	}{
		{"network", types.Event{Type: types.EventTCPConnect, Comm: commBytes("curl"), PID: 5,
			Network: &types.NetworkEvent{Daddr: ipv4Bytes(1, 1, 1, 1), Dport: 53, Family: types.AFInet}}, "NETWORK"},
		{"file", types.Event{Type: types.EventFileAccess, Comm: commBytes("bash"), PID: 6,
			File: &types.FileEvent{Filename: filenameBytes("/etc/shadow")}}, "FILE"},
		{"syscall", types.Event{Type: types.EventSyscall, Comm: commBytes("sh"), PID: 7,
			Syscall: &types.SyscallEvent{Nr: 59}}, "SYSCALL"},
		{"dns", types.Event{Type: types.EventDNS, Comm: commBytes("curl"), PID: 8,
			DNS: &types.DNSEvent{QName: "evil.com"}}, "DNS"},
		{"unknown", types.Event{Type: types.EventKmodLoad, Comm: commBytes("insmod"), PID: 9}, "EVENT"},
	}
	for _, c := range cases {
		got := formatEventDesc(c.event)
		if !strings.Contains(got, c.want) {
			t.Errorf("%s: formatEventDesc=%q, want prefix %q", c.name, got, c.want)
		}
	}
}

// ─── rbGetFieldValue extra coverage ───────────────────────────────────────────

func TestRBGetFieldValueAllTypes(t *testing.T) {
	tests := []struct {
		name  string
		event types.Event
		field string
		want  string
	}{
		{"comm", types.Event{Comm: commBytes("bash")}, "comm", "bash"},
		{"uid", types.Event{UID: 1000}, "uid", "1000"},
		{"net-saddr", types.Event{Type: types.EventTCPConnect, Network: &types.NetworkEvent{Saddr: ipv4Bytes(10, 0, 0, 1), Family: types.AFInet}}, "saddr", "10.0.0.1"},
		{"net-sport", types.Event{Type: types.EventTCPConnect, Network: &types.NetworkEvent{Sport: 8080, Family: types.AFInet}}, "sport", "8080"},
		{"net-dport", types.Event{Type: types.EventTCPConnect, Network: &types.NetworkEvent{Dport: 443, Family: types.AFInet}}, "dport", "443"},
		{"file-op", types.Event{Type: types.EventFileAccess, File: &types.FileEvent{Op: 2}}, "op", "2"},
		{"file-flags", types.Event{Type: types.EventFileAccess, File: &types.FileEvent{Flags: 577}}, "flags", "577"},
		{"syscall-nr", types.Event{Type: types.EventSyscall, Syscall: &types.SyscallEvent{Nr: 101}}, "nr", "101"},
		{"syscall-ret", types.Event{Type: types.EventSyscall, Syscall: &types.SyscallEvent{Ret: -1}}, "ret", "-1"},
		{"dns-qname", types.Event{Type: types.EventDNS, DNS: &types.DNSEvent{QName: "x.com"}}, "qname", "x.com"},
		{"dns-qtype", types.Event{Type: types.EventDNS, DNS: &types.DNSEvent{QType: 28}}, "qtype", "28"},
		{"kmod-name", types.Event{Type: types.EventKmodLoad, Kmod: &types.KmodEvent{ModName: "rootkit"}}, "name", "rootkit"},
		{"unknown-field", types.Event{Type: types.EventTCPConnect, Network: &types.NetworkEvent{Family: types.AFInet}}, "nope", ""},
	}
	for _, tt := range tests {
		if got := rbGetFieldValue(tt.event, tt.field); got != tt.want {
			t.Errorf("%s: rbGetFieldValue(%q)=%q, want %q", tt.name, tt.field, got, tt.want)
		}
	}
}

func TestRBGetFieldValueNilPayloads(t *testing.T) {
	// When the typed payload pointer is nil, field lookups return "".
	nilCases := []struct {
		event types.Event
		field string
	}{
		{types.Event{Type: types.EventTCPConnect}, "dport"},
		{types.Event{Type: types.EventFileAccess}, "filename"},
		{types.Event{Type: types.EventSyscall}, "nr"},
		{types.Event{Type: types.EventDNS}, "qname"},
		{types.Event{Type: types.EventKmodLoad}, "name"},
	}
	for _, c := range nilCases {
		if got := rbGetFieldValue(c.event, c.field); got != "" {
			t.Errorf("nil payload lookup %q should be empty, got %q", c.field, got)
		}
	}
}

func TestRBFocusMark(t *testing.T) {
	m := newNetworkRB()
	m.focusIdx = m.idxSave()
	if m.focusMark(m.idxSave()) == " " {
		t.Error("focused index should render a marker, not a space")
	}
	if m.focusMark(m.idxCancel()) != " " {
		t.Error("non-focused index should render a space")
	}
}

// ─── eventTypeName remaining branches ─────────────────────────────────────────

func TestEventTypeNameAllBranches(t *testing.T) {
	cases := []struct {
		t    types.EventType
		want string
	}{
		{types.EventNetClose, "net_close"},
		{types.EventCgroupEsc, "cgroup_esc"},
		{types.EventGPU, "gpu"},
		{types.EventLSMAudit, "lsm_audit"},
		{types.EventCloudAudit, "cloud_audit"},
		{types.EventType(250), "syscall"}, // default fallback
	}
	for _, c := range cases {
		if got := eventTypeName(c.t); got != c.want {
			t.Errorf("eventTypeName(%d)=%q, want %q", c.t, got, c.want)
		}
	}
}

// ─── ipStr IPv4 + IPv6 ────────────────────────────────────────────────────────

func TestIPStr(t *testing.T) {
	if got := ipStr(ipv4Bytes(192, 168, 1, 1), types.AFInet); got != "192.168.1.1" {
		t.Errorf("ipStr v4=%q, want 192.168.1.1", got)
	}
	var v6 [16]byte
	v6[0] = 0x20
	v6[1] = 0x01
	v6[15] = 0x01
	got := ipStr(v6, types.AFInet6)
	if !strings.Contains(got, "2001:") || !strings.Contains(got, ":1") {
		t.Errorf("ipStr v6=%q, expected a full 16-byte IPv6 rendering", got)
	}
}

// ─── extractEventFields extra branches (privesc / kmod / default) ─────────────

func TestExtractEventFieldsMoreTypes(t *testing.T) {
	priv := types.Event{Type: types.EventPrivesc, Comm: commBytes("sudo")}
	if etype, _ := extractEventFields(priv); etype != "privesc" {
		t.Errorf("privesc event type=%q", etype)
	}

	kmod := types.Event{Type: types.EventKmodLoad, Comm: commBytes("insmod"), Kmod: &types.KmodEvent{ModName: "evil_mod"}}
	etype, conds := extractEventFields(kmod)
	if etype != "kmod" {
		t.Errorf("kmod event type=%q", etype)
	}
	assertCondExists(t, conds, "name", "eq", "evil_mod")

	// An unrecognized event type falls back to syscall with a comm condition.
	def := types.Event{Type: types.EventType(250), Comm: commBytes("mystery")}
	if etype, _ := extractEventFields(def); etype != "syscall" {
		t.Errorf("default event type=%q, want syscall", etype)
	}
}
