//go:build tui

package tui

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// ─── extractEventFields ───────────────────────────────────────────────────────

func TestExtractNetworkEvent(t *testing.T) {
	e := types.Event{
		Type:  types.EventTCPConnect,
		PID:   1234,
		UID:   0,
		Comm:  commBytes("curl"),
		Network: &types.NetworkEvent{
			Daddr: ipv4Bytes(185, 220, 101, 45),
			Dport: 443,
			Family: types.AFInet,
		},
	}

	etype, conds := extractEventFields(e)
	if etype != "network" {
		t.Errorf("expected event_type=network, got %q", etype)
	}
	assertCondExists(t, conds, "daddr", "eq", "185.220.101.45")
	assertCondExists(t, conds, "dport", "eq", "443")
	assertCondExists(t, conds, "comm", "eq", "curl")
}

func TestExtractFileEvent(t *testing.T) {
	e := types.Event{
		Type: types.EventFileAccess,
		PID:  9012,
		Comm: commBytes("bash"),
		File: &types.FileEvent{
			Filename: filenameBytes("/etc/shadow"),
			Op:       0,
		},
	}

	etype, conds := extractEventFields(e)
	if etype != "file" {
		t.Errorf("expected event_type=file, got %q", etype)
	}
	assertCondExists(t, conds, "filename", "prefix", "/etc/shadow")
	assertCondExists(t, conds, "comm", "eq", "bash")
}

func TestExtractSyscallEvent(t *testing.T) {
	e := types.Event{
		Type: types.EventSyscall,
		PID:  1111,
		UID:  0,
		Comm: commBytes("nginx"),
		Syscall: &types.SyscallEvent{
			Nr: 101, // ptrace
		},
	}

	etype, conds := extractEventFields(e)
	if etype != "syscall" {
		t.Errorf("expected event_type=syscall, got %q", etype)
	}
	assertCondExists(t, conds, "nr", "eq", "101")
}

func TestExtractDNSEvent(t *testing.T) {
	e := types.Event{
		Type: types.EventDNS,
		PID:  2222,
		Comm: commBytes("curl"),
		DNS: &types.DNSEvent{
			QName: "evil.example.com",
			QType: 1,
		},
	}

	etype, conds := extractEventFields(e)
	if etype != "dns" {
		t.Errorf("expected event_type=dns, got %q", etype)
	}
	assertCondExists(t, conds, "qname", "eq", "evil.example.com")
}

// ─── matchEvent ──────────────────────────────────────────────────────────────

func TestMatchEventNetwork(t *testing.T) {
	target := types.Event{
		Type: types.EventTCPConnect,
		Comm: commBytes("curl"),
		Network: &types.NetworkEvent{
			Daddr:  ipv4Bytes(185, 220, 101, 45),
			Dport:  443,
			Family: types.AFInet,
		},
	}

	_, conds := extractEventFields(target)
	m := RuleBuilderModel{
		eventType:  "network",
		conditions: conds,
	}

	if !m.matchEvent(target) {
		t.Error("expected target event to match its own conditions")
	}

	// Different IP should not match
	other := target
	other.Network = &types.NetworkEvent{
		Daddr:  ipv4Bytes(1, 2, 3, 4),
		Dport:  443,
		Family: types.AFInet,
	}
	if m.matchEvent(other) {
		t.Error("expected different daddr event not to match")
	}
}

func TestMatchEventTypeMismatch(t *testing.T) {
	e := types.Event{
		Type: types.EventFileAccess,
		Comm: commBytes("bash"),
		File: &types.FileEvent{Filename: filenameBytes("/etc/shadow")},
	}
	m := RuleBuilderModel{eventType: "network"}
	if m.matchEvent(e) {
		t.Error("file event should not match a network rule")
	}
}

func TestMatchConditionOps(t *testing.T) {
	e := types.Event{
		Type: types.EventTCPConnect,
		Comm: commBytes("curl"),
		Network: &types.NetworkEvent{
			Dport:  8443,
			Family: types.AFInet,
		},
	}

	tests := []struct {
		op    string
		value string
		want  bool
	}{
		{"eq", "8443", true},
		{"eq", "443", false},
		{"gt", "8000", true},
		{"lt", "9000", true},
		{"lt", "8000", false},
		{"in", "443,8443,9443", true},
		{"not_in", "443,9443", true},
		{"not_in", "443,8443", false},
	}

	for _, tt := range tests {
		c := ConditionDraft{Field: "dport", Op: tt.op, Value: tt.value}
		got := rbMatchCondition(e, c)
		if got != tt.want {
			t.Errorf("op=%q value=%q: got %v, want %v", tt.op, tt.value, got, tt.want)
		}
	}
}

func TestMatchConditionStrOps(t *testing.T) {
	e := types.Event{
		Type: types.EventFileAccess,
		Comm: commBytes("bash"),
		File: &types.FileEvent{Filename: filenameBytes("/etc/shadow")},
	}

	tests := []struct {
		op    string
		value string
		want  bool
	}{
		{"prefix", "/etc/", true},
		{"prefix", "/tmp/", false},
		{"suffix", "shadow", true},
		{"suffix", "passwd", false},
		{"contains", "shadow", true},
		{"contains", "passwd", false},
	}

	for _, tt := range tests {
		c := ConditionDraft{Field: "filename", Op: tt.op, Value: tt.value}
		got := rbMatchCondition(e, c)
		if got != tt.want {
			t.Errorf("op=%q value=%q: got %v, want %v", tt.op, tt.value, got, tt.want)
		}
	}
}

// ─── runTest ─────────────────────────────────────────────────────────────────

func TestRunTest(t *testing.T) {
	now := uint64(time.Now().UnixNano())
	old := uint64(time.Now().Add(-10 * time.Minute).UnixNano())

	recent := types.Event{
		Type:      types.EventTCPConnect,
		Timestamp: now,
		Comm:      commBytes("curl"),
		Network: &types.NetworkEvent{
			Daddr:  ipv4Bytes(1, 2, 3, 4),
			Dport:  443,
			Family: types.AFInet,
		},
	}
	stale := types.Event{
		Type:      types.EventTCPConnect,
		Timestamp: old,
		Comm:      commBytes("curl"),
		Network: &types.NetworkEvent{
			Daddr:  ipv4Bytes(1, 2, 3, 4),
			Dport:  443,
			Family: types.AFInet,
		},
	}

	m := RuleBuilderModel{
		eventType: "network",
		conditions: []ConditionDraft{
			{Field: "dport", Op: "eq", Value: "443"},
		},
		recentEvents: []types.Event{recent, stale},
	}

	m.runTest()
	if !strings.Contains(m.testResult, "1 matches") {
		t.Errorf("expected 1 match (stale event excluded), got: %q", m.testResult)
	}
}

// ─── buildRuleYAML ───────────────────────────────────────────────────────────

func TestBuildRuleYAMLSingle(t *testing.T) {
	m := RuleBuilderModel{
		eventType: "network",
		conditions: []ConditionDraft{
			{Field: "dport", Op: "eq", Value: "4444"},
		},
		severityIdx: 1, // critical
		actionIdx:   0, // alert
	}
	yaml := m.buildRuleYAML()

	for _, want := range []string{
		"event_type: network",
		`field: "dport"`,
		"op: eq",
		`"4444"`,
		"severity: critical",
		"action: alert",
		"- custom",
	} {
		if !strings.Contains(yaml, want) {
			t.Errorf("YAML missing %q:\n%s", want, yaml)
		}
	}
}

func TestBuildRuleYAMLMultiCondition(t *testing.T) {
	m := RuleBuilderModel{
		eventType: "network",
		conditions: []ConditionDraft{
			{Field: "daddr", Op: "eq", Value: "185.220.101.45"},
			{Field: "dport", Op: "eq", Value: "443"},
		},
	}
	yaml := m.buildRuleYAML()

	if !strings.Contains(yaml, "condition_group:") {
		t.Errorf("expected condition_group for multiple conditions:\n%s", yaml)
	}
	if !strings.Contains(yaml, "operator: and") {
		t.Errorf("expected operator: and:\n%s", yaml)
	}
}

// ─── saveToCustomRules ───────────────────────────────────────────────────────

func TestSaveToCustomRulesCreatesFile(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(origDir) }()

	yaml := `rules:
  - id: test_rule
    name: "Test rule"
    event_type: network
    condition:
      field: "dport"
      op: eq
      values:
        - "443"
    severity: warning
    action: alert
    tags:
      - custom
`
	if err := saveToCustomRules(yaml); err != nil {
		t.Fatalf("saveToCustomRules: %v", err)
	}

	content, err := os.ReadFile("rules/custom.yaml")
	if err != nil {
		t.Fatalf("read custom.yaml: %v", err)
	}
	if !strings.Contains(string(content), "id: test_rule") {
		t.Errorf("saved file missing rule id:\n%s", string(content))
	}
}

func TestSaveToCustomRulesAppends(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(origDir) }()

	first := "rules:\n  - id: rule_one\n    name: \"One\"\n"
	second := "rules:\n  - id: rule_two\n    name: \"Two\"\n"

	if err := saveToCustomRules(first); err != nil {
		t.Fatal(err)
	}
	if err := saveToCustomRules(second); err != nil {
		t.Fatal(err)
	}

	content, _ := os.ReadFile("rules/custom.yaml")
	if !strings.Contains(string(content), "rule_one") || !strings.Contains(string(content), "rule_two") {
		t.Errorf("expected both rules in file:\n%s", string(content))
	}
}

// ─── opIdx initialisation ────────────────────────────────────────────────────

func TestConditionOpIdxInitialized(t *testing.T) {
	e := types.Event{
		Type: types.EventFileAccess,
		Comm: commBytes("bash"),
		File: &types.FileEvent{Filename: filenameBytes("/etc/passwd")},
	}
	_, conds := extractEventFields(e)

	for _, c := range conds {
		if conditionOps[c.opIdx] != c.Op {
			t.Errorf("opIdx mismatch for field %q: conditionOps[%d]=%q, Op=%q",
				c.Field, c.opIdx, conditionOps[c.opIdx], c.Op)
		}
	}
}

// ─── eventTypeName ───────────────────────────────────────────────────────────

func TestEventTypeName(t *testing.T) {
	tests := []struct {
		t    types.EventType
		want string
	}{
		{types.EventTCPConnect, "network"},
		{types.EventFileAccess, "file"},
		{types.EventSyscall, "syscall"},
		{types.EventDNS, "dns"},
		{types.EventPrivesc, "privesc"},
		{types.EventKmodLoad, "kmod"},
	}
	for _, tt := range tests {
		if got := eventTypeName(tt.t); got != tt.want {
			t.Errorf("eventTypeName(%d): got %q, want %q", tt.t, got, tt.want)
		}
	}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func commBytes(s string) [16]byte {
	var b [16]byte
	copy(b[:], s)
	return b
}

func filenameBytes(s string) [256]byte {
	var b [256]byte
	copy(b[:], s)
	return b
}

func ipv4Bytes(a, b, c, d byte) [16]byte {
	var buf [16]byte
	buf[0] = a
	buf[1] = b
	buf[2] = c
	buf[3] = d
	return buf
}

func assertCondExists(t *testing.T, conds []ConditionDraft, field, op, value string) {
	t.Helper()
	for _, c := range conds {
		if c.Field == field && c.Op == op && c.Value == value {
			return
		}
	}
	t.Errorf("expected condition {field:%q op:%q value:%q} not found in %+v", field, op, value, conds)
}
