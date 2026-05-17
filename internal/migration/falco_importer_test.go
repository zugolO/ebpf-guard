package migration

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFalcoImporter_BasicRule(t *testing.T) {
	yaml := `
- rule: Read sensitive file
  desc: An attempt to read /etc/shadow
  condition: evt.type = open and fd.name contains "/etc/shadow"
  output: Sensitive file read (file=%fd.name proc=%proc.name)
  priority: WARNING
  tags: [filesystem, mitre_credential_access]
`
	imp := NewFalcoImporter()
	result, err := imp.Import([]byte(yaml))
	require.NoError(t, err)
	require.Len(t, result.Results, 1)
	assert.Equal(t, 1, result.Converted)
	assert.Equal(t, 0, result.Unsupported)

	r := result.Results[0]
	assert.Equal(t, "converted", r.Status)
	assert.Equal(t, "warning", r.Converted.Severity)
	assert.Equal(t, "alert", r.Converted.Action)
	assert.Contains(t, r.Converted.Tags, "filesystem")
}

func TestFalcoImporter_CriticalPriority(t *testing.T) {
	yaml := `
- rule: Privilege escalation
  desc: sudo used
  condition: proc.name = sudo
  output: Sudo executed
  priority: CRITICAL
`
	imp := NewFalcoImporter()
	result, err := imp.Import([]byte(yaml))
	require.NoError(t, err)
	require.Len(t, result.Results, 1)
	assert.Equal(t, "critical", result.Results[0].Converted.Severity)
}

func TestFalcoImporter_ProcNameInList(t *testing.T) {
	yaml := `
- rule: Shell spawn by web server
  desc: Web server spawned shell
  condition: proc.name in (nginx, apache2, node) and evt.type = execve
  output: Web server spawned shell
  priority: ERROR
  tags: [container-escape]
`
	imp := NewFalcoImporter()
	result, err := imp.Import([]byte(yaml))
	require.NoError(t, err)
	require.Len(t, result.Results, 1)
	r := result.Results[0]
	assert.Equal(t, "critical", r.Converted.Severity)
	assert.Equal(t, "syscall", r.Converted.EventType)
}

func TestFalcoImporter_ContainerCheck(t *testing.T) {
	yaml := `
- rule: Container escape
  desc: Possible escape
  condition: container.id != host and proc.name = nsenter
  output: Container escape attempt
  priority: CRITICAL
`
	imp := NewFalcoImporter()
	result, err := imp.Import([]byte(yaml))
	require.NoError(t, err)
	require.Len(t, result.Results, 1)
	assert.Equal(t, "converted", result.Results[0].Status)
}

func TestFalcoImporter_DisabledRule(t *testing.T) {
	yaml := `
- rule: Disabled rule
  desc: This rule is disabled
  condition: proc.name = bash
  output: Something
  priority: WARNING
  enabled: false
`
	imp := NewFalcoImporter()
	result, err := imp.Import([]byte(yaml))
	require.NoError(t, err)
	require.Len(t, result.Results, 1)
	assert.Equal(t, "disabled", result.Results[0].Status)
	assert.Equal(t, 1, result.Disabled)
}

func TestFalcoImporter_UnsupportedSyntax(t *testing.T) {
	yaml := `
- rule: Complex rule
  desc: Uses unsupported Falco macro
  condition: spawned_process and proc.name = evil
  output: Something happened
  priority: WARNING
`
	imp := NewFalcoImporter()
	result, err := imp.Import([]byte(yaml))
	require.NoError(t, err)
	require.Len(t, result.Results, 1)
	// "spawned_process" is a macro reference → unsupported
	assert.Equal(t, "unsupported", result.Results[0].Status)
	assert.NotEmpty(t, result.Results[0].UnsupportedReasons)
}

func TestFalcoImporter_SkipNonRuleItems(t *testing.T) {
	yaml := `
- macro: open_file
  condition: evt.type in (open, openat, openat2)

- list: web_servers
  items: [nginx, apache2, lighttpd]

- rule: My rule
  desc: Simple rule
  condition: proc.name = evil
  output: Evil found
  priority: WARNING
`
	imp := NewFalcoImporter()
	result, err := imp.Import([]byte(yaml))
	require.NoError(t, err)
	// Only the rule item is processed
	assert.Len(t, result.Results, 1)
}

func TestFalcoImporter_WriteOutput(t *testing.T) {
	yaml := `
- rule: Test rule
  desc: A rule
  condition: proc.name = bash
  output: Bash executed
  priority: WARNING
`
	imp := NewFalcoImporter()
	result, err := imp.Import([]byte(yaml))
	require.NoError(t, err)

	out, err := imp.WriteOutput(result)
	require.NoError(t, err)
	assert.Contains(t, string(out), "rules:")
	assert.Contains(t, string(out), "severity: warning")
}

func TestMapPriority(t *testing.T) {
	cases := []struct{ input, want string }{
		{"CRITICAL", "critical"},
		{"EMERGENCY", "critical"},
		{"ALERT", "critical"},
		{"ERROR", "critical"},
		{"WARNING", "warning"},
		{"NOTICE", "warning"},
		{"INFO", "warning"},
		{"DEBUG", "warning"},
		{"", "warning"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, mapPriority(tc.input), "priority=%s", tc.input)
	}
}

func TestExtractInList(t *testing.T) {
	assert.Equal(t, []string{"nginx", "apache2", "node"}, extractInList("proc.name in (nginx, apache2, node)"))
	assert.Equal(t, []string{"open", "openat"}, extractInList(`evt.type in ("open", "openat")`))
}

func TestSplitTopLevelAnd(t *testing.T) {
	parts := splitTopLevelAnd(`proc.name = bash and evt.type = execve and fd.name contains "/etc"`)
	assert.Len(t, parts, 3)

	// Should not split inside parentheses
	parts2 := splitTopLevelAnd(`proc.name in (a, b) and evt.type = open`)
	assert.Len(t, parts2, 2)
}
