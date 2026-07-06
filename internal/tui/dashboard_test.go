//go:build tui

package tui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// ─── Shared key helpers (used across dashboard/wizard/rule-builder tests) ──────

func keyRunes(s string) tea.KeyMsg     { return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)} }
func keyType(t tea.KeyType) tea.KeyMsg { return tea.KeyMsg{Type: t} }

// isQuitCmd reports whether a tea.Cmd, when executed, yields tea.QuitMsg.
func isQuitCmd(cmd tea.Cmd) bool {
	if cmd == nil {
		return false
	}
	_, ok := cmd().(tea.QuitMsg)
	return ok
}

// updateModel drives a dashboard Model with one message and returns the concrete type.
func updateModel(m Model, msg tea.Msg) (Model, tea.Cmd) {
	nm, cmd := m.Update(msg)
	return nm.(Model), cmd
}

// ─── Feed helpers (real, -tags tui Feed) ──────────────────────────────────────

func TestFeedPushEventStats(t *testing.T) {
	f := NewFeed()
	f.PushEvent(types.Event{Comm: commBytes("nginx"), PID: 10})
	f.PushEvent(types.Event{Comm: commBytes("nginx"), PID: 11})
	f.PushEvent(types.Event{Comm: commBytes("curl"), PID: 12})

	_, events, stats := f.Snapshot(10, 10)
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}
	if stats.TotalEvents != 3 {
		t.Errorf("TotalEvents=%d, want 3", stats.TotalEvents)
	}
	if stats.TopProcesses["nginx"] != 2 {
		t.Errorf("nginx count=%d, want 2", stats.TopProcesses["nginx"])
	}
	if stats.TopProcesses["curl"] != 1 {
		t.Errorf("curl count=%d, want 1", stats.TopProcesses["curl"])
	}
}

func TestFeedSnapshotCaps(t *testing.T) {
	f := NewFeed()
	for i := 0; i < 10; i++ {
		f.PushAlert(types.Alert{RuleID: "r", Severity: types.SeverityWarning})
		f.PushEvent(types.Event{PID: uint32(i)})
	}
	alerts, events, _ := f.Snapshot(3, 4)
	if len(alerts) != 3 {
		t.Errorf("expected snapshot to cap alerts at 3, got %d", len(alerts))
	}
	if len(events) != 4 {
		t.Errorf("expected snapshot to cap events at 4, got %d", len(events))
	}
}

// ─── Model construction / Init ────────────────────────────────────────────────

func TestNewModelAndInit(t *testing.T) {
	f := NewFeed()
	m := NewModel(f)
	if m.feed != f {
		t.Error("NewModel should retain the feed")
	}
	if m.activeTab != TabAlerts {
		t.Errorf("default tab = %d, want TabAlerts", m.activeTab)
	}
	if cmd := m.Init(); cmd == nil {
		t.Error("Init should return a non-nil tick command")
	}
	// tickCmd must yield a tickMsg when run.
	if _, ok := tickCmd()().(tickMsg); !ok {
		t.Error("tickCmd should produce a tickMsg")
	}
}

// ─── Update: window sizing + tick ─────────────────────────────────────────────

func TestUpdateWindowSize(t *testing.T) {
	m := NewModel(NewFeed())
	m, _ = updateModel(m, tea.WindowSizeMsg{Width: 120, Height: 40})
	if m.width != 120 || m.height != 40 {
		t.Errorf("width/height = %d/%d, want 120/40", m.width, m.height)
	}
}

func TestUpdateTickPullsSnapshot(t *testing.T) {
	f := NewFeed()
	f.PushAlert(types.Alert{RuleID: "r1", Severity: types.SeverityCritical})
	f.PushEvent(types.Event{Comm: commBytes("bash"), PID: 5})

	m := NewModel(f)
	m, cmd := updateModel(m, tickMsg(time.Now()))
	if cmd == nil {
		t.Error("tick should reschedule another tick")
	}
	if len(m.alerts) != 1 || len(m.events) != 1 {
		t.Errorf("tick should copy feed data: alerts=%d events=%d", len(m.alerts), len(m.events))
	}
	if m.stats.TotalAlerts != 1 {
		t.Errorf("stats not pulled: TotalAlerts=%d", m.stats.TotalAlerts)
	}
}

func TestUpdateTickPausedSkipsSnapshot(t *testing.T) {
	f := NewFeed()
	f.PushAlert(types.Alert{RuleID: "r1", Severity: types.SeverityWarning})
	m := NewModel(f)
	m.paused = true
	m, _ = updateModel(m, tickMsg(time.Now()))
	if len(m.alerts) != 0 {
		t.Errorf("paused tick must not pull data, got %d alerts", len(m.alerts))
	}
}

// ─── Update: keyboard navigation ──────────────────────────────────────────────

func TestUpdateTabSwitchingNumberKeys(t *testing.T) {
	m := NewModel(NewFeed())
	cases := []struct {
		key  string
		want Tab
	}{
		{"2", TabEvents},
		{"3", TabRules},
		{"4", TabStatus},
		{"5", TabFleet},
		{"1", TabAlerts},
	}
	for _, c := range cases {
		m, _ = updateModel(m, keyRunes(c.key))
		if m.activeTab != c.want {
			t.Errorf("after key %q, activeTab=%d want %d", c.key, m.activeTab, c.want)
		}
	}
}

func TestUpdateTabCyclesAndGuardsEventsTab(t *testing.T) {
	m := NewModel(NewFeed())
	// From Alerts, tab advances to Events.
	m, _ = updateModel(m, keyType(tea.KeyTab))
	if m.activeTab != TabEvents {
		t.Fatalf("tab from Alerts should go to Events, got %d", m.activeTab)
	}
	// On Events tab, tab is a no-op (guarded so l/h can navigate events instead).
	m, _ = updateModel(m, keyType(tea.KeyTab))
	if m.activeTab != TabEvents {
		t.Errorf("tab on Events tab should be a no-op, got %d", m.activeTab)
	}
	// shift+tab from a non-Events tab cycles backwards.
	m.activeTab = TabRules
	m, _ = updateModel(m, keyType(tea.KeyShiftTab))
	if m.activeTab != TabEvents {
		t.Errorf("shift+tab from Rules should go to Events, got %d", m.activeTab)
	}
}

func TestUpdatePauseToggle(t *testing.T) {
	m := NewModel(NewFeed())
	m, _ = updateModel(m, keyRunes("p"))
	if !m.paused {
		t.Error("p should pause")
	}
	m, _ = updateModel(m, keyRunes("p"))
	if m.paused {
		t.Error("second p should unpause")
	}
}

func TestUpdateQuit(t *testing.T) {
	m := NewModel(NewFeed())
	_, cmd := updateModel(m, keyRunes("q"))
	if !isQuitCmd(cmd) {
		t.Error("q should return tea.Quit")
	}
	_, cmd = updateModel(m, keyType(tea.KeyCtrlC))
	if !isQuitCmd(cmd) {
		t.Error("ctrl+c should return tea.Quit")
	}
}

func TestUpdateScrollNonEventsTab(t *testing.T) {
	m := NewModel(NewFeed())
	m.activeTab = TabAlerts
	m, _ = updateModel(m, keyRunes("j")) // down
	if m.scrollTop != 1 {
		t.Errorf("j should scroll down, scrollTop=%d", m.scrollTop)
	}
	m, _ = updateModel(m, keyRunes("k")) // up
	if m.scrollTop != 0 {
		t.Errorf("k should scroll up, scrollTop=%d", m.scrollTop)
	}
	// up at top stays clamped.
	m, _ = updateModel(m, keyRunes("k"))
	if m.scrollTop != 0 {
		t.Errorf("k at top should clamp, scrollTop=%d", m.scrollTop)
	}
	m.scrollTop = 5
	m, _ = updateModel(m, keyRunes("g"))
	if m.scrollTop != 0 {
		t.Errorf("g should reset scroll to top, scrollTop=%d", m.scrollTop)
	}
}

func TestUpdateEventCursorNavigation(t *testing.T) {
	f := NewFeed()
	for i := 0; i < 3; i++ {
		f.PushEvent(types.Event{Comm: commBytes("proc"), PID: uint32(i)})
	}
	m := NewModel(f)
	m, _ = updateModel(m, tickMsg(time.Now())) // populate m.events
	m, _ = updateModel(m, keyRunes("2"))       // switch to Events tab
	if m.activeTab != TabEvents {
		t.Fatal("expected Events tab")
	}
	m, _ = updateModel(m, keyRunes("j")) // move cursor down
	if m.evtCursor != 1 {
		t.Errorf("evtCursor=%d, want 1", m.evtCursor)
	}
	m, _ = updateModel(m, keyRunes("j"))
	m, _ = updateModel(m, keyRunes("j")) // clamp at len-1
	if m.evtCursor != 2 {
		t.Errorf("evtCursor should clamp at 2, got %d", m.evtCursor)
	}
	m, _ = updateModel(m, keyRunes("k"))
	if m.evtCursor != 1 {
		t.Errorf("k should move cursor up, evtCursor=%d", m.evtCursor)
	}
	m, _ = updateModel(m, keyRunes("g"))
	if m.evtCursor != 0 {
		t.Errorf("g should reset cursor, evtCursor=%d", m.evtCursor)
	}
}

func TestUpdateOpenAndCloseRuleBuilder(t *testing.T) {
	f := NewFeed()
	f.PushEvent(types.Event{
		Type: types.EventTCPConnect,
		Comm: commBytes("curl"),
		PID:  100,
		Network: &types.NetworkEvent{
			Daddr: ipv4Bytes(1, 2, 3, 4), Dport: 443, Family: types.AFInet,
		},
	})
	m := NewModel(f)
	m.width, m.height = 100, 40
	m, _ = updateModel(m, tickMsg(time.Now()))
	m, _ = updateModel(m, keyRunes("2")) // Events tab
	m, _ = updateModel(m, keyRunes("r")) // build rule
	if !m.ruleBuilderOpen {
		t.Fatal("r on an event should open the rule builder")
	}
	if m.ruleBuilder.eventType != "network" {
		t.Errorf("rule builder eventType=%q, want network", m.ruleBuilder.eventType)
	}
	// A key now delegates to the rule builder; Esc cancels and closes it.
	m, _ = updateModel(m, keyType(tea.KeyEsc))
	if m.ruleBuilderOpen {
		t.Error("Esc in rule builder should close it")
	}
}

func TestUpdateRuleBuilderWindowResizeDelegates(t *testing.T) {
	f := NewFeed()
	f.PushEvent(types.Event{Type: types.EventSyscall, Comm: commBytes("sh"), PID: 1, Syscall: &types.SyscallEvent{Nr: 59}})
	m := NewModel(f)
	m, _ = updateModel(m, tickMsg(time.Now()))
	m, _ = updateModel(m, keyRunes("2"))
	m, _ = updateModel(m, keyRunes("r"))
	if !m.ruleBuilderOpen {
		t.Fatal("rule builder should be open")
	}
	m, _ = updateModel(m, tea.WindowSizeMsg{Width: 88, Height: 33})
	if m.ruleBuilder.width != 88 || m.ruleBuilder.height != 33 {
		t.Errorf("window resize should propagate into open rule builder: %d/%d", m.ruleBuilder.width, m.ruleBuilder.height)
	}
}

// ─── View rendering (drive, then assert content, not exact layout) ────────────

func TestViewLoadingBeforeSize(t *testing.T) {
	m := NewModel(NewFeed())
	if got := m.View(); !strings.Contains(got, "Loading") {
		t.Errorf("zero-width View should show a loading message, got %q", got)
	}
}

func TestViewRendersEachTab(t *testing.T) {
	f := NewFeed()
	f.PushAlert(types.Alert{RuleID: "rule_x", Severity: types.SeverityCritical, Comm: "evil", PID: 9})
	f.PushEvent(types.Event{Comm: commBytes("bash"), PID: 7})
	m := NewModel(f)
	m.width, m.height = 120, 40
	m, _ = updateModel(m, tickMsg(time.Now()))

	tabs := []Tab{TabAlerts, TabEvents, TabRules, TabStatus, TabFleet}
	for _, tab := range tabs {
		m.activeTab = tab
		out := m.View()
		if out == "" {
			t.Errorf("View for tab %d should not be empty", tab)
		}
		if !strings.Contains(out, "ebpf-guard") {
			t.Errorf("View for tab %d missing title bar", tab)
		}
	}
}

func TestViewPausedTag(t *testing.T) {
	m := NewModel(NewFeed())
	m.width, m.height = 100, 30
	m.paused = true
	if !strings.Contains(m.View(), "PAUSED") {
		t.Error("paused dashboard should show PAUSED tag")
	}
}

func TestViewRuleBuilderOverlay(t *testing.T) {
	f := NewFeed()
	m := NewModel(f)
	m.width, m.height = 100, 40
	m.ruleBuilder = NewRuleBuilderModel(
		types.Event{Type: types.EventDNS, Comm: commBytes("curl"), PID: 3, DNS: &types.DNSEvent{QName: "evil.example.com"}},
		nil, 100, 40)
	m.ruleBuilderOpen = true
	out := m.View()
	if !strings.Contains(out, "rule builder") {
		t.Errorf("open rule builder overlay should render its title, got:\n%s", out)
	}
}

func TestViewEmptyStates(t *testing.T) {
	m := NewModel(NewFeed())
	m.width, m.height = 100, 30

	m.activeTab = TabAlerts
	if !strings.Contains(m.View(), "No alerts yet") {
		t.Error("empty alerts tab should show 'No alerts yet'")
	}
	m.activeTab = TabEvents
	if !strings.Contains(m.View(), "Waiting for events") {
		t.Error("empty events tab should show waiting message")
	}
	m.activeTab = TabRules
	if !strings.Contains(m.View(), "No rules triggered") {
		t.Error("empty rules tab should show no-rules message")
	}
	m.activeTab = TabFleet
	if !strings.Contains(m.View(), "Not running in fleet mode") {
		t.Error("empty fleet tab should show not-in-fleet message")
	}
}

func TestViewFleetPopulated(t *testing.T) {
	f := NewFeed()
	f.SetAgentStatus(AgentStatus{Endpoint: "http://node-a:9090", NodeName: "node-a", Healthy: true, AlertCount: 3, LastSeen: time.Now()})
	f.SetAgentStatus(AgentStatus{Endpoint: "http://node-b:9090", NodeName: "node-b", Healthy: false, LastError: "connection refused"})
	m := NewModel(f)
	m.width, m.height = 120, 40
	m, _ = updateModel(m, tickMsg(time.Now()))
	m.activeTab = TabFleet
	out := m.View()
	if !strings.Contains(out, "node-a") || !strings.Contains(out, "node-b") {
		t.Errorf("fleet view should list both agents:\n%s", out)
	}
	if !strings.Contains(out, "connection refused") {
		t.Errorf("fleet view should surface the down agent's error:\n%s", out)
	}
}

// ─── Pure helpers ─────────────────────────────────────────────────────────────

func TestRenderScrollable(t *testing.T) {
	lines := []string{"a", "b", "c", "d", "e"}
	// Window of 2 from the top.
	if got := renderScrollable(lines, 0, 2); got != "a\nb" {
		t.Errorf("renderScrollable top window = %q", got)
	}
	// Scrolled past the middle.
	if got := renderScrollable(lines, 3, 2); got != "d\ne" {
		t.Errorf("renderScrollable mid window = %q", got)
	}
	// scrollTop beyond the end clamps to the last line.
	if got := renderScrollable(lines, 99, 2); got != "e" {
		t.Errorf("renderScrollable overscroll = %q", got)
	}
}

func TestRenderBar(t *testing.T) {
	if got := renderBar(0, 0, 10); got != "" {
		t.Errorf("renderBar with zero max should be empty, got %q", got)
	}
	full := renderBar(10, 10, 10)
	if strings.Count(full, "█") != 10 {
		t.Errorf("full bar should be all filled, got %q", full)
	}
	half := renderBar(5, 10, 10)
	if strings.Count(half, "█") != 5 || strings.Count(half, "░") != 5 {
		t.Errorf("half bar mismatch, got %q", half)
	}
	// Over-max value clamps to width.
	over := renderBar(100, 10, 10)
	if strings.Count(over, "█") != 10 {
		t.Errorf("over-max bar should clamp to width, got %q", over)
	}
}

func TestMaxHitsAndMax(t *testing.T) {
	pairs := []kv{{"a", 3}, {"b", 9}, {"c", 1}}
	if got := maxHits(pairs); got != 9 {
		t.Errorf("maxHits=%d, want 9", got)
	}
	if got := maxHits(nil); got != 0 {
		t.Errorf("maxHits(nil)=%d, want 0", got)
	}
	if max(3, 7) != 7 || max(7, 3) != 7 {
		t.Error("max returned wrong value")
	}
}
