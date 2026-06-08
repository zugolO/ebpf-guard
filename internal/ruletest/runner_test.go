package ruletest

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// ─────────────────────────────────────────────────────────────────────────────
// EventSpec.Build tests
// ─────────────────────────────────────────────────────────────────────────────

func TestEventSpec_Build_Syscall(t *testing.T) {
	spec := EventSpec{
		Type: "syscall",
		PID:  42,
		Comm: "strace",
		Syscall: &SyscallSpec{
			NR:   101,
			Args: []uint64{0, 1234, 0, 0, 0, 0},
		},
	}
	event, err := spec.Build()
	require.NoError(t, err)
	assert.Equal(t, types.EventSyscall, event.Type)
	assert.Equal(t, uint32(42), event.PID)
	assert.Equal(t, "strace", strings.TrimRight(string(event.Comm[:]), "\x00"))
	require.NotNil(t, event.Syscall)
	assert.Equal(t, int64(101), event.Syscall.Nr)
	assert.Equal(t, uint64(1234), event.Syscall.Args[1])
}

func TestEventSpec_Build_Network(t *testing.T) {
	spec := EventSpec{
		Type: "network",
		Network: &NetworkSpec{
			DstIP: "185.220.101.45",
			Dport: 443,
		},
	}
	event, err := spec.Build()
	require.NoError(t, err)
	assert.Equal(t, types.EventTCPConnect, event.Type)
	require.NotNil(t, event.Network)
	assert.Equal(t, uint16(443), event.Network.Dport)
	assert.Equal(t, types.AFInet, event.Network.Family)
}

func TestEventSpec_Build_File(t *testing.T) {
	spec := EventSpec{
		Type: "file",
		File: &FileSpec{
			Filename: "/etc/passwd",
			Op:       "write",
		},
	}
	event, err := spec.Build()
	require.NoError(t, err)
	assert.Equal(t, types.EventFileAccess, event.Type)
	require.NotNil(t, event.File)
	assert.Equal(t, uint8(2), event.File.Op) // write
	assert.Equal(t, "/etc/passwd", event.File.FDPath)
}

func TestEventSpec_Build_DNS(t *testing.T) {
	spec := EventSpec{
		Type: "dns",
		DNS:  &DNSSpec{QName: "pool.supportxmr.com", QType: 1},
	}
	event, err := spec.Build()
	require.NoError(t, err)
	assert.Equal(t, types.EventDNS, event.Type)
	require.NotNil(t, event.DNS)
	assert.Equal(t, "pool.supportxmr.com", event.DNS.QName)
}

func TestEventSpec_Build_Privesc_CapsGained(t *testing.T) {
	spec := EventSpec{
		Type: "privesc",
		Privesc: &PrivescSpec{
			CapsGained: []string{"CAP_SYS_ADMIN"},
		},
	}
	event, err := spec.Build()
	require.NoError(t, err)
	assert.Equal(t, types.EventPrivesc, event.Type)
	require.NotNil(t, event.Privesc)
	assert.Equal(t, uint64(0), event.Privesc.OldCaps)
	assert.Equal(t, uint64(1<<21), event.Privesc.NewCaps) // CAP_SYS_ADMIN = bit 21
}

func TestEventSpec_Build_InvalidType(t *testing.T) {
	spec := EventSpec{Type: "bogus"}
	_, err := spec.Build()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown event type")
}

func TestEventSpec_Build_SyscallMissingBlock(t *testing.T) {
	spec := EventSpec{Type: "syscall"}
	_, err := spec.Build()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires a 'syscall:'")
}

func TestEventSpec_Build_BadIP(t *testing.T) {
	spec := EventSpec{
		Type: "network",
		Network: &NetworkSpec{DstIP: "not-an-ip", Dport: 80},
	}
	_, err := spec.Build()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid IP address")
}

// ─────────────────────────────────────────────────────────────────────────────
// RunSuite tests
// ─────────────────────────────────────────────────────────────────────────────

// alertEngine always fires one alert with the given ruleID and severity.
type alertEngine struct {
	ruleID   string
	severity types.Severity
}

func (e *alertEngine) Evaluate(_ types.Event) []types.Alert {
	return []types.Alert{{RuleID: e.ruleID, Severity: e.severity, Action: "alert"}}
}

// silentEngine never fires.
type silentEngine struct{}

func (e *silentEngine) Evaluate(_ types.Event) []types.Alert { return nil }

func TestRunSuite_ExpectAlert_Pass(t *testing.T) {
	suite := Suite{
		Suite: "demo",
		Tests: []TestCase{
			{
				Name:   "ptrace fires",
				Event:  EventSpec{Type: "syscall", Syscall: &SyscallSpec{NR: 101}},
				Expect: ExpectAlert,
			},
		},
	}
	results := RunSuite(suite, &alertEngine{ruleID: "proc_inject_ptrace", severity: types.SeverityWarning})
	require.Len(t, results, 1)
	assert.True(t, results[0].Passed)
}

func TestRunSuite_ExpectAlert_WithRuleID_Pass(t *testing.T) {
	suite := Suite{
		Suite: "demo",
		Tests: []TestCase{
			{
				Name:         "specific rule fires",
				Event:        EventSpec{Type: "syscall", Syscall: &SyscallSpec{NR: 101}},
				Expect:       ExpectAlert,
				ExpectRuleID: "proc_inject_ptrace",
			},
		},
	}
	results := RunSuite(suite, &alertEngine{ruleID: "proc_inject_ptrace", severity: types.SeverityWarning})
	require.Len(t, results, 1)
	assert.True(t, results[0].Passed)
}

func TestRunSuite_ExpectAlert_WrongRuleID_Fail(t *testing.T) {
	suite := Suite{
		Suite: "demo",
		Tests: []TestCase{
			{
				Name:         "wrong rule fires",
				Event:        EventSpec{Type: "syscall", Syscall: &SyscallSpec{NR: 101}},
				Expect:       ExpectAlert,
				ExpectRuleID: "rule_x",
			},
		},
	}
	results := RunSuite(suite, &alertEngine{ruleID: "different_rule", severity: types.SeverityWarning})
	require.Len(t, results, 1)
	assert.False(t, results[0].Passed)
}

func TestRunSuite_ExpectNoAlert_Pass(t *testing.T) {
	suite := Suite{
		Suite: "demo",
		Tests: []TestCase{
			{
				Name:   "no alert for safe event",
				Event:  EventSpec{Type: "syscall", Syscall: &SyscallSpec{NR: 1}},
				Expect: ExpectNoAlert,
			},
		},
	}
	results := RunSuite(suite, &silentEngine{})
	require.Len(t, results, 1)
	assert.True(t, results[0].Passed)
}

func TestRunSuite_ExpectNoAlert_Fail(t *testing.T) {
	suite := Suite{
		Suite: "demo",
		Tests: []TestCase{
			{
				Name:   "unexpected alert",
				Event:  EventSpec{Type: "syscall", Syscall: &SyscallSpec{NR: 101}},
				Expect: ExpectNoAlert,
			},
		},
	}
	results := RunSuite(suite, &alertEngine{ruleID: "proc_inject_ptrace", severity: types.SeverityWarning})
	require.Len(t, results, 1)
	assert.False(t, results[0].Passed)
	assert.Equal(t, ExpectNoAlert, results[0].Expected)
	assert.Equal(t, ExpectAlert, results[0].Got)
}

func TestRunSuite_ExpectSeverity_Pass(t *testing.T) {
	suite := Suite{
		Suite: "demo",
		Tests: []TestCase{
			{
				Name:           "severity matches",
				Event:          EventSpec{Type: "syscall", Syscall: &SyscallSpec{NR: 319}},
				Expect:         ExpectAlert,
				ExpectSeverity: "critical",
			},
		},
	}
	results := RunSuite(suite, &alertEngine{ruleID: "proc_inject_memfd", severity: types.SeverityCritical})
	require.Len(t, results, 1)
	assert.True(t, results[0].Passed)
}

func TestRunSuite_ExpectSeverity_Fail(t *testing.T) {
	suite := Suite{
		Suite: "demo",
		Tests: []TestCase{
			{
				Name:           "severity mismatch",
				Event:          EventSpec{Type: "syscall", Syscall: &SyscallSpec{NR: 319}},
				Expect:         ExpectAlert,
				ExpectSeverity: "critical",
			},
		},
	}
	results := RunSuite(suite, &alertEngine{ruleID: "proc_inject_memfd", severity: types.SeverityWarning})
	require.Len(t, results, 1)
	assert.False(t, results[0].Passed)
}

// ─────────────────────────────────────────────────────────────────────────────
// File discovery
// ─────────────────────────────────────────────────────────────────────────────

func TestDiscover(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a_test.yaml", "b_test.yaml", "notes.yaml", "c_test.yml"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte("suite: x\ntests: []\n"), 0o600))
	}

	files, err := Discover(dir)
	require.NoError(t, err)
	assert.Len(t, files, 3) // a_test.yaml, b_test.yaml, c_test.yml — notes.yaml excluded
}

func TestDiscover_SingleFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "mytest.yaml")
	require.NoError(t, os.WriteFile(p, []byte("suite: x\ntests: []\n"), 0o600))

	files, err := Discover(p)
	require.NoError(t, err)
	assert.Equal(t, []string{p}, files)
}

// ─────────────────────────────────────────────────────────────────────────────
// YAML loading
// ─────────────────────────────────────────────────────────────────────────────

func TestLoadSuite(t *testing.T) {
	yaml := `
suite: my_suite
tests:
  - name: "ptrace fires"
    event:
      type: syscall
      syscall:
        nr: 101
    expect: alert
    expect_severity: warning
`
	dir := t.TempDir()
	path := filepath.Join(dir, "my_suite_test.yaml")
	require.NoError(t, os.WriteFile(path, []byte(yaml), 0o600))

	suite, rulesPath, err := LoadSuite(path)
	require.NoError(t, err)
	assert.Equal(t, "my_suite", suite.Suite)
	assert.Equal(t, "", rulesPath)
	require.Len(t, suite.Tests, 1)
	assert.Equal(t, "ptrace fires", suite.Tests[0].Name)
	assert.Equal(t, ExpectAlert, suite.Tests[0].Expect)
	assert.Equal(t, "warning", suite.Tests[0].ExpectSeverity)
}

func TestLoadSuite_RelativeRulesPath(t *testing.T) {
	dir := t.TempDir()
	yaml := "suite: x\nrules_path: ../../rules/container-escape.yaml\ntests: []\n"
	path := filepath.Join(dir, "x_test.yaml")
	require.NoError(t, os.WriteFile(path, []byte(yaml), 0o600))

	_, rulesPath, err := LoadSuite(path)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(dir, "../../rules/container-escape.yaml"), rulesPath)
}

// ─────────────────────────────────────────────────────────────────────────────
// TAP output
// ─────────────────────────────────────────────────────────────────────────────

func TestTAPWriter(t *testing.T) {
	var buf bytes.Buffer
	w := NewTAPWriter(&buf)
	w.Plan(2)
	w.WriteResult(Result{Suite: "demo", Name: "passes", Passed: true, Expected: ExpectAlert, Got: ExpectAlert})
	w.WriteResult(Result{Suite: "demo", Name: "fails", Passed: false, Expected: ExpectAlert, Got: ExpectNoAlert})

	out := buf.String()
	assert.Contains(t, out, "TAP version 13")
	assert.Contains(t, out, "1..2")
	assert.Contains(t, out, "ok 1 - demo: passes")
	assert.Contains(t, out, "not ok 2 - demo: fails")
	assert.Contains(t, out, "# expected: alert")
	assert.Contains(t, out, "# got:      no_alert")
}

// ─────────────────────────────────────────────────────────────────────────────
// JUnit XML output
// ─────────────────────────────────────────────────────────────────────────────

func TestWriteJUnit(t *testing.T) {
	results := []Result{
		{Suite: "demo", Name: "passes", Passed: true, Expected: ExpectAlert, Got: ExpectAlert},
		{Suite: "demo", Name: "fails", Passed: false, Expected: ExpectAlert, Got: ExpectNoAlert, MatchedIDs: []string{}},
	}
	var buf bytes.Buffer
	require.NoError(t, WriteJUnit(&buf, results))
	out := buf.String()
	assert.Contains(t, out, `<testsuites>`)
	assert.Contains(t, out, `name="demo"`)
	assert.Contains(t, out, `failures="1"`)
	assert.Contains(t, out, `<testcase name="passes"`)
	assert.Contains(t, out, `<failure`)
}

// ─────────────────────────────────────────────────────────────────────────────
// Integration with real rule engine (process-injection rules)
// ─────────────────────────────────────────────────────────────────────────────

func TestRunner_RealRuleEngine(t *testing.T) {
	rules, err := correlator.LoadRulesFromFile("../../rules/process-injection.yaml")
	if err != nil {
		t.Skipf("rules/process-injection.yaml not found: %v", err)
	}
	eng := correlator.NewRuleEngine(rules)

	suite := Suite{
		Suite: "proc_inject",
		Tests: []TestCase{
			{
				Name:         "ptrace fires",
				Event:        EventSpec{Type: "syscall", Syscall: &SyscallSpec{NR: 101}},
				Expect:       ExpectAlert,
				ExpectRuleID: "proc_inject_ptrace",
			},
			{
				Name:         "memfd_create fires",
				Event:        EventSpec{Type: "syscall", Syscall: &SyscallSpec{NR: 319}},
				Expect:       ExpectAlert,
				ExpectRuleID: "proc_inject_memfd_create",
				ExpectSeverity: "critical",
			},
			{
				Name:   "write syscall does not fire any injection rule",
				Event:  EventSpec{Type: "syscall", Syscall: &SyscallSpec{NR: 1}},
				Expect: ExpectNoAlert,
			},
		},
	}

	results := RunSuite(suite, eng)
	for _, r := range results {
		assert.Truef(t, r.Passed, "test %q failed: expected=%s got=%s matched=%v err=%s",
			r.Name, r.Expected, r.Got, r.MatchedIDs, r.Error)
	}
}
