//go:build tui

// Package tui provides interactive terminal UI components for ebpf-guard.
package tui

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// ─── Styles ─────────────────────────────────────────────────────────────────

var (
	styleCritical = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	styleWarning  = lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true)
	styleGood     = lipgloss.NewStyle().Foreground(lipgloss.Color("82"))
	styleDim      = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	styleHeader   = lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Bold(true)
	styleBorder   = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("62")).
			Padding(0, 1)
	styleTitleBar = lipgloss.NewStyle().
			Background(lipgloss.Color("62")).
			Foreground(lipgloss.Color("230")).
			Bold(true).
			Padding(0, 2)
	styleKey   = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	styleValue = lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
)

// ─── Events / messages ──────────────────────────────────────────────────────

type tickMsg time.Time
type alertMsg types.Alert
type eventMsg types.Event
type statsMsg DashboardStats

// kv is a key-value pair used for sorted stat rendering.
type kv struct {
	k string
	v int64
}

// DashboardStats holds aggregated runtime statistics.
type DashboardStats struct {
	TotalEvents  int64
	TotalAlerts  int64
	Critical     int64
	Warning      int64
	RuleHits     map[string]int64 // ruleID → hit count
	TopProcesses map[string]int64 // comm → event count
	UpdatedAt    time.Time
}

// ─── Alert feed ─────────────────────────────────────────────────────────────

// Feed is a thread-safe source of alerts and events consumed by the dashboard.
type Feed struct {
	mu     sync.Mutex
	alerts []types.Alert
	events []types.Event
	stats  DashboardStats
	// agents tracks per-endpoint health in fleet mode (--fleet), keyed by
	// endpoint URL. Empty in single-agent mode.
	agents map[string]AgentStatus
}

// NewFeed creates an empty Feed.
func NewFeed() *Feed {
	return &Feed{
		stats: DashboardStats{
			RuleHits:     make(map[string]int64),
			TopProcesses: make(map[string]int64),
		},
	}
}

// PushAlert adds an alert to the feed.
func (f *Feed) PushAlert(a types.Alert) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.alerts = append(f.alerts, a)
	f.stats.TotalAlerts++
	if a.Severity == types.SeverityCritical {
		f.stats.Critical++
	} else {
		f.stats.Warning++
	}
	f.stats.RuleHits[a.RuleID]++
	f.stats.UpdatedAt = time.Now()
}

// PushEvent adds an event to the feed.
func (f *Feed) PushEvent(e types.Event) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, e)
	f.stats.TotalEvents++
	comm := strings.TrimRight(string(e.Comm[:]), "\x00")
	if comm != "" {
		f.stats.TopProcesses[comm]++
	}
	f.stats.UpdatedAt = time.Now()
}

// Snapshot returns a stable copy of the current state (last N alerts and events).
func (f *Feed) Snapshot(maxAlerts, maxEvents int) ([]types.Alert, []types.Event, DashboardStats) {
	f.mu.Lock()
	defer f.mu.Unlock()

	alerts := f.alerts
	if len(alerts) > maxAlerts {
		alerts = alerts[len(alerts)-maxAlerts:]
	}
	aSnap := make([]types.Alert, len(alerts))
	copy(aSnap, alerts)

	events := f.events
	if len(events) > maxEvents {
		events = events[len(events)-maxEvents:]
	}
	eSnap := make([]types.Event, len(events))
	copy(eSnap, events)

	stats := f.stats
	stats.RuleHits = make(map[string]int64, len(f.stats.RuleHits))
	for k, v := range f.stats.RuleHits {
		stats.RuleHits[k] = v
	}
	stats.TopProcesses = make(map[string]int64, len(f.stats.TopProcesses))
	for k, v := range f.stats.TopProcesses {
		stats.TopProcesses[k] = v
	}
	return aSnap, eSnap, stats
}

// SetAgentStatus records (or updates) the health of one fleet agent. Used by
// the --fleet client-side fan-out poller; a no-op concept in single-agent mode.
func (f *Feed) SetAgentStatus(s AgentStatus) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.agents == nil {
		f.agents = make(map[string]AgentStatus)
	}
	f.agents[s.Endpoint] = s
}

// AgentStatuses returns a stable, sorted-by-endpoint snapshot of known fleet
// agent statuses. Empty when the dashboard is not running in fleet mode.
func (f *Feed) AgentStatuses() []AgentStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]AgentStatus, 0, len(f.agents))
	for _, s := range f.agents {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Endpoint < out[j].Endpoint })
	return out
}

// ─── Dashboard model ─────────────────────────────────────────────────────────

// Tab represents a dashboard pane.
type Tab int

const (
	TabAlerts Tab = iota
	TabEvents
	TabRules
	TabStatus
	TabFleet
	tabCount
)

var tabNames = [tabCount]string{"Alerts", "Events", "Top Rules", "Status", "Fleet"}

// Model is the bubbletea model for the dashboard.
type Model struct {
	feed      *Feed
	activeTab Tab
	width     int
	height    int
	alerts    []types.Alert
	events    []types.Event
	stats     DashboardStats
	agents    []AgentStatus
	scrollTop int
	paused    bool

	// Event cursor and rule builder state.
	evtCursor       int              // index into m.events (0 = newest)
	ruleBuilderOpen bool             // whether the rule builder pane is shown
	ruleBuilder     RuleBuilderModel // active rule builder state
}

// NewModel creates a dashboard model backed by feed.
func NewModel(feed *Feed) Model {
	return Model{feed: feed}
}

// Init implements tea.Model.
func (m Model) Init() tea.Cmd {
	return tickCmd()
}

func tickCmd() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// Update implements tea.Model.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		if m.ruleBuilderOpen {
			rb, _ := m.ruleBuilder.Update(msg)
			m.ruleBuilder = rb
		}

	case tickMsg:
		if !m.paused {
			a, e, s := m.feed.Snapshot(100, 200)
			m.alerts = a
			m.events = e
			m.stats = s
			m.agents = m.feed.AgentStatuses()
		}
		return m, tickCmd()

	case tea.KeyMsg:
		// Delegate to rule builder when it's open.
		if m.ruleBuilderOpen {
			rb, result := m.ruleBuilder.Update(msg)
			m.ruleBuilder = rb
			switch result {
			case RuleBuilderCancel, RuleBuilderSaved:
				m.ruleBuilderOpen = false
			}
			return m, nil
		}

		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "tab", "right", "l":
			if m.activeTab != TabEvents {
				m.activeTab = (m.activeTab + 1) % tabCount
				m.scrollTop = 0
			}
		case "shift+tab", "left", "h":
			if m.activeTab != TabEvents {
				m.activeTab = (m.activeTab + tabCount - 1) % tabCount
				m.scrollTop = 0
			}
		case "1":
			m.activeTab = TabAlerts
			m.scrollTop = 0
		case "2":
			m.activeTab = TabEvents
			m.scrollTop = 0
		case "3":
			m.activeTab = TabRules
			m.scrollTop = 0
		case "4":
			m.activeTab = TabStatus
			m.scrollTop = 0
		case "5":
			m.activeTab = TabFleet
			m.scrollTop = 0
		case "p":
			m.paused = !m.paused
		case "up", "k":
			if m.activeTab == TabEvents {
				if m.evtCursor > 0 {
					m.evtCursor--
				}
			} else if m.scrollTop > 0 {
				m.scrollTop--
			}
		case "down", "j":
			if m.activeTab == TabEvents {
				if m.evtCursor < len(m.events)-1 {
					m.evtCursor++
				}
			} else {
				m.scrollTop++
			}
		case "g":
			if m.activeTab == TabEvents {
				m.evtCursor = 0
			} else {
				m.scrollTop = 0
			}
		case "r", "R":
			if m.activeTab == TabEvents && len(m.events) > 0 {
				// Map cursor (0=newest) to actual slice index.
				idx := len(m.events) - 1 - m.evtCursor
				if idx < 0 {
					idx = 0
				}
				selectedEvt := m.events[idx]
				_, recentEvts, _ := m.feed.Snapshot(100, 500)
				m.ruleBuilder = NewRuleBuilderModel(selectedEvt, recentEvts, m.width, m.height)
				m.ruleBuilderOpen = true
			}
		}
	}
	return m, nil
}

// View implements tea.Model.
func (m Model) View() string {
	if m.width == 0 {
		return "Loading dashboard…"
	}

	// When rule builder is open, show it instead of the normal dashboard.
	if m.ruleBuilderOpen {
		return m.viewRuleBuilder()
	}

	var sb strings.Builder

	// ─ Title bar ─────────────────────────────────────────────────────────────
	pauseTag := ""
	if m.paused {
		pauseTag = styleWarning.Render("  [PAUSED]")
	}
	title := styleTitleBar.Width(m.width).Render(
		"  ebpf-guard  live security dashboard" + pauseTag,
	)
	sb.WriteString(title + "\n")

	// ─ Tab bar ───────────────────────────────────────────────────────────────
	tabs := make([]string, tabCount)
	for i, name := range tabNames {
		label := fmt.Sprintf(" %d:%s ", i+1, name)
		if Tab(i) == m.activeTab {
			tabs[i] = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("230")).
				Background(lipgloss.Color("62")).
				Padding(0, 1).
				Render(label)
		} else {
			tabs[i] = styleDim.Padding(0, 1).Render(label)
		}
	}
	sb.WriteString(strings.Join(tabs, "") + "\n\n")

	// ─ Content area ──────────────────────────────────────────────────────────
	contentHeight := m.height - 5
	if contentHeight < 5 {
		contentHeight = 5
	}

	var content string
	switch m.activeTab {
	case TabAlerts:
		content = m.renderAlerts(contentHeight)
	case TabEvents:
		content = m.renderEvents(contentHeight)
	case TabRules:
		content = m.renderRules(contentHeight)
	case TabStatus:
		content = m.renderStatus(contentHeight)
	case TabFleet:
		content = m.renderFleet(contentHeight)
	}
	sb.WriteString(content)

	// ─ Status bar ────────────────────────────────────────────────────────────
	updated := "–"
	if !m.stats.UpdatedAt.IsZero() {
		updated = m.stats.UpdatedAt.Format("15:04:05")
	}
	var statusBar string
	if m.activeTab == TabEvents && len(m.events) > 0 {
		statusBar = styleDim.Render(fmt.Sprintf(
			"  events:%d  alerts:%d  updated:%s  [↑/↓] select  [r] build rule  [q]uit [p]ause [tab]switch",
			m.stats.TotalEvents, m.stats.TotalAlerts, updated,
		))
	} else {
		statusBar = styleDim.Render(fmt.Sprintf(
			"  events:%d  alerts:%d  critical:%d  warning:%d  updated:%s  [q]uit [p]ause [tab]switch",
			m.stats.TotalEvents, m.stats.TotalAlerts,
			m.stats.Critical, m.stats.Warning,
			updated,
		))
	}
	sb.WriteString("\n" + statusBar)

	return sb.String()
}

// viewRuleBuilder renders the full-screen rule builder overlay.
func (m Model) viewRuleBuilder() string {
	var sb strings.Builder

	title := styleTitleBar.Width(m.width).Render("  ebpf-guard  rule builder")
	sb.WriteString(title + "\n")
	sb.WriteString(m.ruleBuilder.View())

	return sb.String()
}

// ─── Tab renderers ──────────────────────────────────────────────────────────

func (m *Model) renderAlerts(maxLines int) string {
	if len(m.alerts) == 0 {
		return styleGood.Render("  ✓  No alerts yet — monitoring active")
	}

	// Show most recent alerts last
	lines := make([]string, 0, len(m.alerts))
	for i := len(m.alerts) - 1; i >= 0; i-- {
		a := m.alerts[i]
		sevStyle := styleWarning
		icon := "⚠"
		if a.Severity == types.SeverityCritical {
			sevStyle = styleCritical
			icon = "☠"
		}
		ts := a.Timestamp.Format("15:04:05")
		loc := ""
		if a.Enrichment.PodName != "" {
			loc += styleDim.Render("  pod=" + a.Enrichment.PodName)
		}
		if a.Enrichment.NodeName != "" {
			loc += styleDim.Render("  node=" + a.Enrichment.NodeName)
		}
		line := fmt.Sprintf("  %s %s  %s  %s  pid=%-6d  %s%s",
			styleDim.Render(ts),
			sevStyle.Render(icon),
			sevStyle.Render(fmt.Sprintf("%-8s", string(a.Severity))),
			styleHeader.Render(fmt.Sprintf("%-22s", a.RuleID)),
			a.PID,
			styleValue.Render(a.Comm),
			loc,
		)
		lines = append(lines, line)
	}

	return renderScrollable(lines, m.scrollTop, maxLines)
}

func (m *Model) renderEvents(maxLines int) string {
	if len(m.events) == 0 {
		return styleDim.Render("  Waiting for events…")
	}

	// Clamp cursor to valid range.
	if m.evtCursor >= len(m.events) {
		m.evtCursor = len(m.events) - 1
	}

	lines := make([]string, 0, len(m.events))
	// Display newest first (index 0 in lines = newest event = evtCursor 0).
	for i := len(m.events) - 1; i >= 0; i-- {
		displayIdx := len(m.events) - 1 - i // 0 = newest
		e := m.events[i]
		comm := strings.TrimRight(string(e.Comm[:]), "\x00")
		ts := time.Unix(0, int64(e.Timestamp)).Format("15:04:05")

		cursor := "  "
		if displayIdx == m.evtCursor {
			cursor = styleCritical.Render("► ")
		}

		line := fmt.Sprintf("%s%s  %-12s  pid=%-7d  type=%-4d  uid=%d",
			cursor,
			styleDim.Render(ts),
			styleValue.Render(comm),
			e.PID,
			e.Type,
			e.UID,
		)
		lines = append(lines, line)
	}

	// Keep the selected event visible: scroll so cursor is in view.
	scrollTop := m.scrollTop
	if m.evtCursor < scrollTop {
		scrollTop = m.evtCursor
	}
	if m.evtCursor >= scrollTop+maxLines {
		scrollTop = m.evtCursor - maxLines + 1
	}

	hint := styleDim.Render("  [↑/↓] or [j/k] select event  [r] build rule from selected event")
	return renderScrollable(lines, scrollTop, maxLines) + "\n" + hint
}

func (m *Model) renderRules(maxLines int) string {
	if len(m.stats.RuleHits) == 0 {
		return styleDim.Render("  No rules triggered yet")
	}

	pairs := make([]kv, 0, len(m.stats.RuleHits))
	for k, v := range m.stats.RuleHits {
		pairs = append(pairs, kv{k, v})
	}
	// Sort by hit count descending
	for i := 0; i < len(pairs); i++ {
		for j := i + 1; j < len(pairs); j++ {
			if pairs[j].v > pairs[i].v {
				pairs[i], pairs[j] = pairs[j], pairs[i]
			}
		}
	}

	lines := make([]string, 0, len(pairs)+1)
	lines = append(lines, styleHeader.Render(fmt.Sprintf("  %-30s  %s", "Rule ID", "Triggers")))
	lines = append(lines, styleDim.Render("  "+strings.Repeat("─", 45)))
	for _, p := range pairs {
		bar := renderBar(p.v, maxHits(pairs), 20)
		lines = append(lines, fmt.Sprintf("  %-30s  %-6d  %s",
			styleValue.Render(p.k), p.v, styleGood.Render(bar)))
	}

	return renderScrollable(lines, m.scrollTop, maxLines)
}

func (m *Model) renderStatus(maxLines int) string {
	rows := []string{
		styleHeader.Render("  Agent Status"),
		"",
		fmt.Sprintf("  %s  %s", styleKey.Render("Total events   :"), styleValue.Render(fmt.Sprintf("%d", m.stats.TotalEvents))),
		fmt.Sprintf("  %s  %s", styleKey.Render("Total alerts   :"), styleValue.Render(fmt.Sprintf("%d", m.stats.TotalAlerts))),
		fmt.Sprintf("  %s  %s", styleKey.Render("Critical alerts:"), styleCritical.Render(fmt.Sprintf("%d", m.stats.Critical))),
		fmt.Sprintf("  %s  %s", styleKey.Render("Warning alerts :"), styleWarning.Render(fmt.Sprintf("%d", m.stats.Warning))),
		"",
		styleHeader.Render("  Top Processes (by event count)"),
		styleDim.Render("  " + strings.Repeat("─", 35)),
	}

	pairs := make([]kv, 0, len(m.stats.TopProcesses))
	for k, v := range m.stats.TopProcesses {
		pairs = append(pairs, kv{k, v})
	}
	for i := 0; i < len(pairs); i++ {
		for j := i + 1; j < len(pairs); j++ {
			if pairs[j].v > pairs[i].v {
				pairs[i], pairs[j] = pairs[j], pairs[i]
			}
		}
	}
	limit := 10
	if len(pairs) < limit {
		limit = len(pairs)
	}
	for _, p := range pairs[:limit] {
		rows = append(rows, fmt.Sprintf("  %-20s  %d", styleValue.Render(p.k), p.v))
	}

	rows = append(rows, "", styleDim.Render("  Keybindings: [tab] switch panel  [j/k] scroll  [p] pause  [q] quit"))

	return renderScrollable(rows, m.scrollTop, maxLines)
}

// renderFleet shows per-agent health for --fleet mode: one row per configured
// endpoint with up/down status, node attribution, last-seen time, and how
// many distinct alerts have been observed from it so far.
func (m *Model) renderFleet(maxLines int) string {
	if len(m.agents) == 0 {
		return styleDim.Render("  Not running in fleet mode — start with `dashboard --fleet <endpoints>`")
	}

	up, down := 0, 0
	for _, a := range m.agents {
		if a.Healthy {
			up++
		} else {
			down++
		}
	}

	summaryStyle := styleGood
	if down > 0 {
		summaryStyle = styleCritical
	}
	lines := []string{
		styleHeader.Render("  Fleet Agents"),
		"",
		fmt.Sprintf("  %s  %s / %d up",
			styleKey.Render("Status:"), summaryStyle.Render(fmt.Sprintf("%d", up)), len(m.agents)),
		"",
		fmt.Sprintf("  %-8s  %-28s  %-20s  %-8s  %s",
			"STATUS", "ENDPOINT", "NODE", "ALERTS", "LAST SEEN"),
		styleDim.Render("  " + strings.Repeat("─", 78)),
	}

	for _, a := range m.agents {
		statusIcon := styleGood.Render("● up  ")
		if !a.Healthy {
			statusIcon = styleCritical.Render("● down")
		}
		lastSeen := "–"
		if !a.LastSeen.IsZero() {
			lastSeen = a.LastSeen.Format("15:04:05")
		}
		row := fmt.Sprintf("  %s  %-28s  %-20s  %-8d  %s",
			statusIcon,
			styleValue.Render(truncate(a.Endpoint, 28)),
			styleValue.Render(truncate(a.NodeName, 20)),
			a.AlertCount,
			styleDim.Render(lastSeen),
		)
		lines = append(lines, row)
		if !a.Healthy && a.LastError != "" {
			lines = append(lines, styleCritical.Render("      "+truncate(a.LastError, 90)))
		}
	}

	return renderScrollable(lines, m.scrollTop, maxLines)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

// ─── Helpers ────────────────────────────────────────────────────────────────

func renderScrollable(lines []string, scrollTop, maxVisible int) string {
	if scrollTop >= len(lines) {
		scrollTop = max(0, len(lines)-1)
	}
	end := scrollTop + maxVisible
	if end > len(lines) {
		end = len(lines)
	}
	visible := lines[scrollTop:end]
	return strings.Join(visible, "\n")
}

func renderBar(val, maxVal int64, width int) string {
	if maxVal == 0 {
		return ""
	}
	filled := int(val * int64(width) / maxVal)
	if filled > width {
		filled = width
	}
	return strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
}

func maxHits(pairs []kv) int64 {
	var m int64
	for _, p := range pairs {
		if p.v > m {
			m = p.v
		}
	}
	return m
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ─── Run ─────────────────────────────────────────────────────────────────────

// Run starts the bubbletea dashboard and blocks until the user quits.
func Run(ctx context.Context, feed *Feed) error {
	p := tea.NewProgram(
		NewModel(feed),
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
		tea.WithContext(ctx),
	)
	_, err := p.Run()
	return err
}
