package ruletest

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// ─────────────────────────────────────────────────────────────────────────────
// runCase — event build failure
// ─────────────────────────────────────────────────────────────────────────────

func TestRunSuite_EventBuildFailure(t *testing.T) {
	suite := Suite{
		Suite: "demo",
		Tests: []TestCase{
			{Name: "bogus event type", Event: EventSpec{Type: "not-a-real-type"}, Expect: ExpectAlert},
		},
	}
	results := RunSuite(suite, &silentEngine{})
	require.Len(t, results, 1)
	assert.False(t, results[0].Passed)
	assert.NotEmpty(t, results[0].Error)
	assert.Equal(t, ExpectNoAlert, results[0].Got)
}

func TestRunSuite_EventBuildFailure_ExpectNoAlertPasses(t *testing.T) {
	suite := Suite{
		Suite: "demo",
		Tests: []TestCase{
			{Name: "bogus event type, but no_alert expected", Event: EventSpec{Type: "bogus"}, Expect: ExpectNoAlert},
		},
	}
	results := RunSuite(suite, &silentEngine{})
	require.Len(t, results, 1)
	assert.True(t, results[0].Passed)
}

// ─────────────────────────────────────────────────────────────────────────────
// Discover — error path
// ─────────────────────────────────────────────────────────────────────────────

func TestDiscover_MissingPath(t *testing.T) {
	_, err := Discover(filepath.Join(t.TempDir(), "does-not-exist"))
	require.Error(t, err)
}

// ─────────────────────────────────────────────────────────────────────────────
// RunPath — error branches and failing-test accounting
// ─────────────────────────────────────────────────────────────────────────────

func TestRunPath_DiscoverError(t *testing.T) {
	r := &Runner{}
	_, err := r.RunPath(filepath.Join(t.TempDir(), "does-not-exist"), NewTAPWriter(io.Discard))
	require.Error(t, err)
}

func TestRunPath_LoadSuiteError(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bad_test.yaml"), []byte("suite: [not valid"), 0o600))

	r := &Runner{}
	_, err := r.RunPath(dir, NewTAPWriter(io.Discard))
	require.Error(t, err)
}

func TestRunPath_BuildEngineError(t *testing.T) {
	dir := t.TempDir()
	// Suite with no rules_path and a Runner with no RulesDir → BuildEngine fails
	// with "no rules loaded".
	require.NoError(t, os.WriteFile(filepath.Join(dir, "demo_test.yaml"), []byte("suite: demo\ntests: []\n"), 0o600))

	r := &Runner{}
	_, err := r.RunPath(dir, NewTAPWriter(io.Discard))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "load rules for")
}

func TestRunPath_FailingTestIsCounted(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	require.NoError(t, os.WriteFile(rulesPath, []byte(rulesYAML), 0o644))

	// "evil" should fire, but this suite expects no_alert — a deliberate failure.
	suite := `suite: demo
rules_path: ` + rulesPath + `
tests:
  - name: evil incorrectly expected quiet
    event:
      type: syscall
      comm: evil
      syscall:
        nr: 1
    expect: no_alert
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "demo_test.yaml"), []byte(suite), 0o644))

	r := &Runner{}
	var buf bytes.Buffer
	sum, err := r.RunPath(dir, NewTAPWriter(&buf))
	require.NoError(t, err)
	assert.Equal(t, 1, sum.Total)
	assert.Equal(t, 0, sum.Passed)
	assert.Equal(t, 1, sum.Failed)
	assert.Contains(t, buf.String(), "not ok")
}

// ─────────────────────────────────────────────────────────────────────────────
// BuildEngine — merge behavior and error branches
// ─────────────────────────────────────────────────────────────────────────────

const invalidRulesYAML = `rules:
  - id: rule_bad_field
    name: Bad field
    event_type: syscall
    condition:
      field: "this_field_does_not_exist_anywhere"
      op: eq
      values: ["x"]
    severity: warning
    action: alert
`

func TestRunner_BuildEngine_InvalidRulesFile(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(rulesPath, []byte(invalidRulesYAML), 0o644))

	r := &Runner{}
	_, err := r.BuildEngine(rulesPath)
	require.Error(t, err)
}

func TestRunner_BuildEngine_InvalidRulesDir(t *testing.T) {
	r := &Runner{RulesDir: filepath.Join(t.TempDir(), "does-not-exist")}
	_, err := r.BuildEngine("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "load rules dir")
}

const rulesYAML2 = `rules:
  - id: rule_second
    name: Second rule
    event_type: syscall
    condition:
      field: "comm"
      op: eq
      values: ["also_evil"]
    severity: warning
    action: alert
`

func TestRunner_BuildEngine_MergesRulesPathAndRulesDir(t *testing.T) {
	suiteDir := t.TempDir()
	rulesFile := filepath.Join(suiteDir, "rules.yaml")
	require.NoError(t, os.WriteFile(rulesFile, []byte(rulesYAML), 0o644))

	globalDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(globalDir, "extra.yaml"), []byte(rulesYAML2), 0o644))

	r := &Runner{RulesDir: globalDir}
	eng, err := r.BuildEngine(rulesFile)
	require.NoError(t, err)

	// Both rule_evil (from rulesPath) and rule_second (from RulesDir) should fire.
	evilEvent := types.Event{Type: types.EventSyscall, Syscall: &types.SyscallEvent{Nr: 1}}
	copy(evilEvent.Comm[:], "evil")
	alerts := eng.Evaluate(evilEvent)
	require.Len(t, alerts, 1)
	assert.Equal(t, "rule_evil", alerts[0].RuleID)

	secondEvent := types.Event{Type: types.EventSyscall, Syscall: &types.SyscallEvent{Nr: 1}}
	copy(secondEvent.Comm[:], "also_evil")
	alerts = eng.Evaluate(secondEvent)
	require.Len(t, alerts, 1)
	assert.Equal(t, "rule_second", alerts[0].RuleID)
}

func TestRunner_BuildEngine_RulesDirDoesNotDuplicateSamePath(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	require.NoError(t, os.WriteFile(rulesPath, []byte(rulesYAML), 0o644))

	// r.RulesDir equals rulesPath: the "r.RulesDir != rulesPath" guard should
	// skip the redundant load.
	r := &Runner{RulesDir: rulesPath}
	eng, err := r.BuildEngine(rulesPath)
	require.NoError(t, err)
	require.NotNil(t, eng)
}

// ─────────────────────────────────────────────────────────────────────────────
// Watch
// ─────────────────────────────────────────────────────────────────────────────

func TestWatch_InvalidDir(t *testing.T) {
	err := Watch([]string{filepath.Join(t.TempDir(), "does-not-exist")}, func() {})
	require.Error(t, err)
}

func TestWatch_TriggersRunOnFileChange(t *testing.T) {
	dir := t.TempDir()
	ran := make(chan struct{}, 1)

	errCh := make(chan error, 1)
	go func() {
		errCh <- Watch([]string{dir}, func() {
			select {
			case ran <- struct{}{}:
			default:
			}
		})
	}()

	// Give the watcher a moment to start, then trigger an event.
	time.Sleep(100 * time.Millisecond)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "changed_test.yaml"), []byte("suite: x\n"), 0o600))

	select {
	case <-ran:
		// run() was invoked as expected.
	case err := <-errCh:
		t.Fatalf("Watch returned early: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Watch to react to file change")
	}
}
