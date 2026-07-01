package migration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/pkg/types"
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
	assert.Equal(t, "file", r.Converted.EventType)
	assert.Contains(t, r.Converted.Tags, "filesystem")
	require.NotNil(t, r.Converted.ConditionGroup)
	assert.Equal(t, "and", r.Converted.ConditionGroup.Operator)
	require.Len(t, r.Converted.ConditionGroup.Conditions, 2)
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
	assert.Equal(t, "proc.comm", result.Results[0].Converted.Condition.Field)
	assert.Equal(t, "eq", result.Results[0].Converted.Condition.Op)
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
	assert.Equal(t, "converted", r.Status)
	assert.Equal(t, "critical", r.Converted.Severity)
	assert.Equal(t, "syscall", r.Converted.EventType)
}

func TestFalcoImporter_ContainerFieldsDropped(t *testing.T) {
	// container.id has no ebpf-guard equivalent; it should be dropped (with a
	// reason recorded) while the still-mappable proc.name clause survives.
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
	r := result.Results[0]
	assert.Equal(t, "converted", r.Status)
	require.NotEmpty(t, r.UnsupportedReasons)
	require.NotNil(t, r.Converted.Condition)
	assert.Equal(t, "proc.comm", r.Converted.Condition.Field)
	assert.Equal(t, []string{"nsenter"}, r.Converted.Condition.Values)
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

func TestFalcoImporter_UnresolvedMacroReference(t *testing.T) {
	// "spawned_process" is not defined as a macro: block anywhere in this
	// document, so it remains a bare identifier and the whole rule is
	// unsupported (no clause survives).
	yaml := `
- rule: Complex rule
  desc: Uses an undefined macro
  condition: spawned_process
  output: Something happened
  priority: WARNING
`
	imp := NewFalcoImporter()
	result, err := imp.Import([]byte(yaml))
	require.NoError(t, err)
	require.Len(t, result.Results, 1)
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
	// Only the rule item is processed.
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

// ── Macro and list expansion ────────────────────────────────────────────────

func TestFalcoImporter_MacroExpansion(t *testing.T) {
	yaml := `
- macro: spawned_process
  condition: evt.type = execve

- rule: Shell in container
  desc: Uses a defined macro
  condition: spawned_process and proc.name = bash
  output: Shell spawned
  priority: WARNING
`
	imp := NewFalcoImporter()
	result, err := imp.Import([]byte(yaml))
	require.NoError(t, err)
	require.Len(t, result.Results, 1)
	r := result.Results[0]
	require.Equal(t, "converted", r.Status, "reasons: %v", r.UnsupportedReasons)
	assert.Equal(t, "syscall", r.Converted.EventType)
	require.NotNil(t, r.Converted.ConditionGroup)
	require.Len(t, r.Converted.ConditionGroup.Conditions, 2)

	var sawNr, sawComm bool
	for _, c := range r.Converted.ConditionGroup.Conditions {
		if c.Field == "nr" {
			sawNr = true
			assert.Equal(t, []string{"59"}, c.Values) // execve == 59 on x86_64
		}
		if c.Field == "proc.comm" {
			sawComm = true
		}
	}
	assert.True(t, sawNr, "expected macro-expanded evt.type=execve to produce an nr condition")
	assert.True(t, sawComm)
}

func TestFalcoImporter_NestedMacroExpansion(t *testing.T) {
	// container_shell references the container macro, which is itself
	// referenced (indirectly) alongside spawned_process.
	yaml := `
- macro: spawned_process
  condition: evt.type = execve

- macro: container_shell
  condition: spawned_process and proc.name in (bash, sh, dash)

- rule: Shell nested macro
  desc: Nested macro expansion
  condition: container_shell
  output: Shell spawned
  priority: CRITICAL
`
	imp := NewFalcoImporter()
	result, err := imp.Import([]byte(yaml))
	require.NoError(t, err)
	require.Len(t, result.Results, 1)
	r := result.Results[0]
	require.Equal(t, "converted", r.Status, "reasons: %v", r.UnsupportedReasons)
	require.NotNil(t, r.Converted.ConditionGroup)
	require.Len(t, r.Converted.ConditionGroup.Conditions, 2)
}

func TestFalcoImporter_ListResolution(t *testing.T) {
	yaml := `
- list: shell_binaries
  items: [bash, sh, dash, zsh]

- rule: Shell exec
  desc: Uses a named list inside in (...)
  condition: proc.name in (shell_binaries, custom_shell)
  output: Shell executed
  priority: WARNING
`
	imp := NewFalcoImporter()
	result, err := imp.Import([]byte(yaml))
	require.NoError(t, err)
	require.Len(t, result.Results, 1)
	r := result.Results[0]
	require.Equal(t, "converted", r.Status, "reasons: %v", r.UnsupportedReasons)
	require.NotNil(t, r.Converted.Condition)
	assert.Equal(t, "in", r.Converted.Condition.Op)
	assert.ElementsMatch(t, []string{"bash", "sh", "dash", "zsh", "custom_shell"}, r.Converted.Condition.Values)
}

// ── Boolean logic: AND / OR / NOT / parentheses ─────────────────────────────

func TestFalcoImporter_OrLogic(t *testing.T) {
	yaml := `
- rule: Suspicious shell
  desc: OR across two shells
  condition: proc.name = bash or proc.name = zsh
  output: shell
  priority: WARNING
`
	imp := NewFalcoImporter()
	result, err := imp.Import([]byte(yaml))
	require.NoError(t, err)
	r := result.Results[0]
	require.Equal(t, "converted", r.Status)
	require.NotNil(t, r.Converted.ConditionGroup)
	assert.Equal(t, "or", r.Converted.ConditionGroup.Operator)
	assert.Len(t, r.Converted.ConditionGroup.Conditions, 2)
}

func TestFalcoImporter_AndOrPrecedence(t *testing.T) {
	// "a and (b or c)" — parens should keep the or grouped as a subgroup of the and.
	yaml := `
- rule: Precedence check
  desc: parenthesized OR inside AND
  condition: proc.name = bash and (fd.name contains "/etc/shadow" or fd.name contains "/etc/passwd")
  output: x
  priority: WARNING
`
	imp := NewFalcoImporter()
	result, err := imp.Import([]byte(yaml))
	require.NoError(t, err)
	r := result.Results[0]
	require.Equal(t, "converted", r.Status, "reasons: %v", r.UnsupportedReasons)
	require.NotNil(t, r.Converted.ConditionGroup)
	assert.Equal(t, "and", r.Converted.ConditionGroup.Operator)
	require.Len(t, r.Converted.ConditionGroup.Conditions, 1)
	require.Len(t, r.Converted.ConditionGroup.SubGroups, 1)
	assert.Equal(t, "or", r.Converted.ConditionGroup.SubGroups[0].Operator)
	assert.Len(t, r.Converted.ConditionGroup.SubGroups[0].Conditions, 2)
}

func TestFalcoImporter_NotNegatesOperator(t *testing.T) {
	yaml := `
- rule: Not equals
  desc: NOT of a simple equality becomes neq
  condition: not proc.name = bash
  output: x
  priority: WARNING
`
	imp := NewFalcoImporter()
	result, err := imp.Import([]byte(yaml))
	require.NoError(t, err)
	r := result.Results[0]
	require.Equal(t, "converted", r.Status, "reasons: %v", r.UnsupportedReasons)
	require.NotNil(t, r.Converted.Condition)
	assert.Equal(t, "neq", r.Converted.Condition.Op)
	assert.Equal(t, "proc.comm", r.Converted.Condition.Field)
}

func TestFalcoImporter_NotOfComplexExpressionDropped(t *testing.T) {
	// NOT of a compound (and/or) expression can't be represented; it should
	// be dropped with a reason, while a sibling AND clause still converts.
	yaml := `
- rule: Not of compound
  desc: NOT wraps an AND group
  condition: proc.name = evil and not (proc.name = bash and fd.name contains "/etc")
  output: x
  priority: WARNING
`
	imp := NewFalcoImporter()
	result, err := imp.Import([]byte(yaml))
	require.NoError(t, err)
	r := result.Results[0]
	require.Equal(t, "converted", r.Status)
	require.NotEmpty(t, r.UnsupportedReasons)
	require.NotNil(t, r.Converted.Condition)
	assert.Equal(t, "proc.comm", r.Converted.Condition.Field)
	assert.Equal(t, []string{"evil"}, r.Converted.Condition.Values)
}

// ── Field mapping reconciliation against rule_loader.go ─────────────────────

func TestFalcoImporter_FieldMapping(t *testing.T) {
	cases := []struct {
		name      string
		condition string
		wantField string
		wantOp    string
	}{
		{"proc.name eq", `proc.name = "sshd"`, "proc.comm", "eq"},
		{"proc.args contains", `evt.type = execve and proc.args contains "--exploit"`, "proc.args", "contains"},
		{"user.uid eq", `evt.type = execve and user.uid = "0"`, "uid", "eq"},
		{"fd.filename eq", `fd.filename = "shadow"`, "filename", "eq"},
		{"fd.directory eq", `fd.directory = "/etc"`, "directory", "eq"},
		{"fd.proto eq", `fd.proto = "tcp"`, "proto", "eq"},
	}

	imp := NewFalcoImporter()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := []byte("- rule: Test\n  desc: d\n  condition: " + tc.condition + "\n  output: o\n  priority: WARNING\n")
			result, err := imp.Import(input)
			require.NoError(t, err)
			require.Len(t, result.Results, 1)
			r := result.Results[0]
			require.Equal(t, "converted", r.Status, "condition %q should convert; reasons: %v", tc.condition, r.UnsupportedReasons)

			var found bool
			if r.Converted.Condition != nil && r.Converted.Condition.Field == tc.wantField {
				found = true
				assert.Equal(t, tc.wantOp, r.Converted.Condition.Op)
			} else if r.Converted.ConditionGroup != nil {
				for _, c := range r.Converted.ConditionGroup.Conditions {
					if c.Field == tc.wantField {
						found = true
						assert.Equal(t, tc.wantOp, c.Op)
					}
				}
			}
			assert.True(t, found, "expected field %q in converted rule", tc.wantField)
		})
	}
}

func TestFalcoImporter_FdSportDport(t *testing.T) {
	imp := NewFalcoImporter()

	t.Run("fd.sport", func(t *testing.T) {
		input := []byte("- rule: Test\n  desc: d\n  condition: fd.sport = 1234\n  output: o\n  priority: WARNING\n")
		result, err := imp.Import(input)
		require.NoError(t, err)
		r := result.Results[0]
		require.Equal(t, "converted", r.Status)
		assert.Equal(t, "sport", r.Converted.Condition.Field)
	})

	t.Run("fd.dport", func(t *testing.T) {
		input := []byte("- rule: Test\n  desc: d\n  condition: fd.dport = 4444\n  output: o\n  priority: WARNING\n")
		result, err := imp.Import(input)
		require.NoError(t, err)
		r := result.Results[0]
		require.Equal(t, "converted", r.Status)
		assert.Equal(t, "dport", r.Converted.Condition.Field)
	})
}

func TestFalcoImporter_IpFields(t *testing.T) {
	imp := NewFalcoImporter()

	t.Run("fd.sip cidr", func(t *testing.T) {
		input := []byte(`- rule: Test
  desc: d
  condition: fd.sip = "10.0.0.0/8"
  output: o
  priority: WARNING
`)
		result, err := imp.Import(input)
		require.NoError(t, err)
		r := result.Results[0]
		require.Equal(t, "converted", r.Status)
		assert.Equal(t, "saddr", r.Converted.Condition.Field)
		assert.Equal(t, "in_cidr", r.Converted.Condition.Op)
	})

	t.Run("fd.dip plain ip", func(t *testing.T) {
		input := []byte(`- rule: Test
  desc: d
  condition: fd.dip = "1.2.3.4"
  output: o
  priority: WARNING
`)
		result, err := imp.Import(input)
		require.NoError(t, err)
		r := result.Results[0]
		require.Equal(t, "converted", r.Status)
		assert.Equal(t, "daddr", r.Converted.Condition.Field)
		assert.Equal(t, "eq", r.Converted.Condition.Op)
	})

	t.Run("fd.net unsupported", func(t *testing.T) {
		input := []byte(`- rule: Test
  desc: d
  condition: fd.net = "10.0.0.0/8"
  output: o
  priority: WARNING
`)
		result, err := imp.Import(input)
		require.NoError(t, err)
		r := result.Results[0]
		assert.Equal(t, "unsupported", r.Status)
	})
}

func TestFalcoImporter_EvtTypeFileOps(t *testing.T) {
	imp := NewFalcoImporter()

	t.Run("open maps to file op", func(t *testing.T) {
		input := []byte("- rule: Test\n  desc: d\n  condition: evt.type in (open, openat, openat2)\n  output: o\n  priority: WARNING\n")
		result, err := imp.Import(input)
		require.NoError(t, err)
		r := result.Results[0]
		require.Equal(t, "converted", r.Status)
		assert.Equal(t, "file", r.Converted.EventType)
		assert.Equal(t, "op", r.Converted.Condition.Field)
		assert.Equal(t, []string{"open"}, r.Converted.Condition.Values)
	})

	t.Run("write maps to file op", func(t *testing.T) {
		input := []byte("- rule: Test\n  desc: d\n  condition: evt.type = write\n  output: o\n  priority: WARNING\n")
		result, err := imp.Import(input)
		require.NoError(t, err)
		r := result.Results[0]
		require.Equal(t, "converted", r.Status)
		assert.Equal(t, "file", r.Converted.EventType)
		assert.Equal(t, []string{"write"}, r.Converted.Condition.Values)
	})
}

func TestFalcoImporter_EvtTypeNetworkDroppedButSiblingSurvives(t *testing.T) {
	// evt.type=connect is fully implied by the "network" event type; it's
	// dropped as a no-op (not an error), and the dport clause survives.
	yaml := `
- rule: Mining pool connect
  desc: Outbound connect to mining port
  condition: evt.type = connect and fd.dport in (3333, 4444)
  output: x
  priority: CRITICAL
`
	imp := NewFalcoImporter()
	result, err := imp.Import([]byte(yaml))
	require.NoError(t, err)
	r := result.Results[0]
	require.Equal(t, "converted", r.Status, "reasons: %v", r.UnsupportedReasons)
	assert.Equal(t, "network", r.Converted.EventType)
	require.NotNil(t, r.Converted.Condition)
	assert.Equal(t, "dport", r.Converted.Condition.Field)
	assert.Equal(t, "in", r.Converted.Condition.Op)
}

func TestFalcoImporter_EvtTypeGenericSyscall(t *testing.T) {
	imp := NewFalcoImporter()
	input := []byte("- rule: Test\n  desc: d\n  condition: evt.type = mount\n  output: o\n  priority: WARNING\n")
	result, err := imp.Import(input)
	require.NoError(t, err)
	r := result.Results[0]
	require.Equal(t, "converted", r.Status)
	assert.Equal(t, "syscall", r.Converted.EventType)
	assert.Equal(t, "nr", r.Converted.Condition.Field)
	assert.Equal(t, []string{"165"}, r.Converted.Condition.Values) // mount == 165 on x86_64
}

func TestFalcoImporter_UnknownSyscallNameUnsupported(t *testing.T) {
	imp := NewFalcoImporter()
	input := []byte("- rule: Test\n  desc: d\n  condition: evt.type = totally_made_up_syscall\n  output: o\n  priority: WARNING\n")
	result, err := imp.Import(input)
	require.NoError(t, err)
	r := result.Results[0]
	assert.Equal(t, "unsupported", r.Status)
	assert.NotEmpty(t, r.UnsupportedReasons)
}

// ── Fields with no ebpf-guard equivalent ─────────────────────────────────────

func TestFalcoImporter_UnmappedFieldsAreUnsupported(t *testing.T) {
	cases := []string{
		`proc.pname = "sshd"`,
		`proc.exepath = "/bin/sh"`,
		`proc.tty != 0`,
		`container.privileged = true`,
		`k8s.pod.name = "my-pod"`,
		`user.name = "root"`,
		`group.gid = "0"`,
		`evt.dir = "<"`,
		`fd.typechar = "f"`,
	}
	imp := NewFalcoImporter()
	for _, cond := range cases {
		t.Run(cond, func(t *testing.T) {
			input := []byte("- rule: Weird\n  desc: d\n  condition: " + cond + "\n  output: o\n  priority: WARNING\n")
			result, err := imp.Import(input)
			require.NoError(t, err)
			require.Len(t, result.Results, 1)
			r := result.Results[0]
			assert.Equal(t, "unsupported", r.Status, "condition %q should be unsupported", cond)
			assert.NotEmpty(t, r.UnsupportedReasons, "unmapped field must produce a non-empty reason (not silently dropped)")
		})
	}
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

func TestSplitTopLevelKeyword(t *testing.T) {
	parts := splitTopLevelKeyword(`proc.name = bash and evt.type = execve and fd.name contains "/etc"`, "and")
	assert.Len(t, parts, 3)

	// Should not split inside parentheses.
	parts2 := splitTopLevelKeyword(`proc.name in (a, b) and evt.type = open`, "and")
	assert.Len(t, parts2, 2)

	// Word boundaries: "android" must not match a split on "and".
	parts3 := splitTopLevelKeyword(`proc.name = android`, "and")
	assert.Len(t, parts3, 1)
}

// ── ImportDir ────────────────────────────────────────────────────────────

func TestFalcoImporter_ImportDir(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(
		"- rule: A\n  desc: d\n  condition: proc.name = a\n  output: o\n  priority: WARNING\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "b.yaml"), []byte(
		"- rule: B\n  desc: d\n  condition: proc.name = b\n  output: o\n  priority: WARNING\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ignore.txt"), []byte("not yaml"), 0o644))

	imp := NewFalcoImporter()
	result, err := imp.ImportDir(dir)
	require.NoError(t, err)
	assert.Equal(t, 2, result.Converted)
}

// ── Round-trip: converted output must load through the real correlator ─────

func TestFalcoImporter_RoundTrip_Syscall(t *testing.T) {
	yaml := `
- macro: spawned_process
  condition: evt.type = execve

- rule: Shell spawn roundtrip
  desc: Round trip through the real loader
  condition: spawned_process and proc.name = bash
  output: shell
  priority: CRITICAL
`
	imp := NewFalcoImporter()
	result, err := imp.Import([]byte(yaml))
	require.NoError(t, err)
	require.Equal(t, 1, result.Converted)

	out, err := imp.WriteOutput(result)
	require.NoError(t, err)

	tmpFile := filepath.Join(t.TempDir(), "rules.yaml")
	require.NoError(t, os.WriteFile(tmpFile, out, 0o644))

	rules, err := correlator.LoadRulesFromFile(tmpFile)
	require.NoError(t, err, "LoadRulesFromFile must accept the converted YAML:\n%s", string(out))
	require.Len(t, rules, 1)

	engine := correlator.NewRuleEngine(rules)

	comm := [16]byte{}
	copy(comm[:], "bash")
	event := types.Event{
		Type:    types.EventSyscall,
		Comm:    comm,
		Syscall: &types.SyscallEvent{Nr: 59}, // execve
	}
	alerts := engine.Evaluate(event)
	assert.Len(t, alerts, 1, "rule should fire on execve of bash")
}

func TestFalcoImporter_RoundTrip_File(t *testing.T) {
	yaml := `
- rule: Shadow file access roundtrip
  desc: file event round trip
  condition: evt.type = open and fd.name contains "/etc/shadow"
  output: x
  priority: CRITICAL
`
	imp := NewFalcoImporter()
	result, err := imp.Import([]byte(yaml))
	require.NoError(t, err)
	require.Equal(t, 1, result.Converted)

	out, err := imp.WriteOutput(result)
	require.NoError(t, err)

	tmpFile := filepath.Join(t.TempDir(), "rules.yaml")
	require.NoError(t, os.WriteFile(tmpFile, out, 0o644))

	rules, err := correlator.LoadRulesFromFile(tmpFile)
	require.NoError(t, err, "LoadRulesFromFile must accept the converted YAML:\n%s", string(out))

	engine := correlator.NewRuleEngine(rules)

	event := types.Event{
		Type: types.EventFileAccess,
		File: &types.FileEvent{
			Op:       0, // "open"
			FDPath:   "/etc/shadow",
			Filename: [256]byte{},
		},
	}
	alerts := engine.Evaluate(event)
	assert.Len(t, alerts, 1, "rule should fire on open of /etc/shadow")
}

func TestFalcoImporter_RoundTrip_Network(t *testing.T) {
	yaml := `
- rule: Mining pool port roundtrip
  desc: network event round trip
  condition: evt.type = connect and fd.dport in (3333, 4444)
  output: x
  priority: CRITICAL
`
	imp := NewFalcoImporter()
	result, err := imp.Import([]byte(yaml))
	require.NoError(t, err)
	require.Equal(t, 1, result.Converted)

	out, err := imp.WriteOutput(result)
	require.NoError(t, err)

	tmpFile := filepath.Join(t.TempDir(), "rules.yaml")
	require.NoError(t, os.WriteFile(tmpFile, out, 0o644))

	rules, err := correlator.LoadRulesFromFile(tmpFile)
	require.NoError(t, err, "LoadRulesFromFile must accept the converted YAML:\n%s", string(out))

	engine := correlator.NewRuleEngine(rules)

	event := types.Event{
		Type: types.EventTCPConnect,
		Network: &types.NetworkEvent{
			Dport:  3333,
			Family: types.AFInet,
		},
	}
	alerts := engine.Evaluate(event)
	assert.Len(t, alerts, 1, "rule should fire on connect to port 3333")
}

// TestFalcoImporter_RoundTrip_RealisticSample imports a rules file shaped
// like real falcosecurity/rules content (macros, lists, nested and/or/not,
// and several fields with no ebpf-guard equivalent) and checks that the
// mappable rules convert and load cleanly through the real rule loader.
func TestFalcoImporter_RoundTrip_RealisticSample(t *testing.T) {
	imp := NewFalcoImporter()
	result, err := imp.ImportFile("testdata/falco_sample.yaml")
	require.NoError(t, err)
	require.Greater(t, result.Converted, 0, "expected at least one rule to convert")

	out, err := imp.WriteOutput(result)
	require.NoError(t, err)

	tmpFile := filepath.Join(t.TempDir(), "rules.yaml")
	require.NoError(t, os.WriteFile(tmpFile, out, 0o644))

	rules, err := correlator.LoadRulesFromFile(tmpFile)
	require.NoError(t, err, "converted realistic sample must load without invalid field name errors:\n%s", string(out))
	assert.Len(t, rules, result.Converted)

	// Building an engine must not panic/error on the converted rule set.
	engine := correlator.NewRuleEngine(rules)
	require.NotNil(t, engine)
}
