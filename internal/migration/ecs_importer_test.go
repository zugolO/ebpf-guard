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

func TestECSImporter_ProcessLuceneQuery(t *testing.T) {
	input := `
name: Suspicious Shell Execution
type: query
language: lucene
query: process.name:bash
severity: high
`
	imp := NewECSImporter()
	result, err := imp.Import([]byte(input))
	require.NoError(t, err)
	require.Len(t, result.Results, 1)
	assert.Equal(t, 1, result.Converted)

	r := result.Results[0]
	assert.Equal(t, "converted", r.Status)
	assert.Equal(t, "syscall", r.Converted.EventType)
	assert.Equal(t, "critical", r.Converted.Severity)
	assert.Equal(t, "alert", r.Converted.Action)
	require.NotNil(t, r.Converted.ConditionGroup)
	assert.Equal(t, "and", r.Converted.ConditionGroup.Operator)
	require.Len(t, r.Converted.ConditionGroup.Conditions, 1)
	assert.Equal(t, "comm", r.Converted.ConditionGroup.Conditions[0].Field)
	assert.Equal(t, "equals", r.Converted.ConditionGroup.Conditions[0].Op)
	assert.Equal(t, []string{"bash"}, r.Converted.ConditionGroup.Conditions[0].Values)
}

func TestECSImporter_NetworkLucene(t *testing.T) {
	input := `
name: Connection to Mining Pool
type: query
language: lucene
query: destination.port:3333
risk_score: 80
`
	imp := NewECSImporter()
	result, err := imp.Import([]byte(input))
	require.NoError(t, err)
	require.Len(t, result.Results, 1)
	assert.Equal(t, 1, result.Converted)

	r := result.Results[0]
	assert.Equal(t, "converted", r.Status)
	assert.Equal(t, "network", r.Converted.EventType)
	assert.Equal(t, "critical", r.Converted.Severity)
	cond := r.Converted.ConditionGroup.Conditions[0]
	assert.Equal(t, "dport", cond.Field)
	assert.Equal(t, "3333", cond.Values[0])
}

func TestECSImporter_FileLucene(t *testing.T) {
	input := `
name: Sensitive File Read
type: query
language: lucene
query: file.path:"/etc/shadow"
risk_score: 73
`
	imp := NewECSImporter()
	result, err := imp.Import([]byte(input))
	require.NoError(t, err)
	require.Len(t, result.Results, 1)
	assert.Equal(t, 1, result.Converted)

	r := result.Results[0]
	assert.Equal(t, "file", r.Converted.EventType)
	assert.Equal(t, "critical", r.Converted.Severity)
	cond := r.Converted.ConditionGroup.Conditions[0]
	assert.Equal(t, "filename", cond.Field)
	assert.Equal(t, []string{"/etc/shadow"}, cond.Values)
}

func TestECSImporter_DNSLucene(t *testing.T) {
	input := `
name: Suspicious DNS Query
type: query
language: lucene
query: dns.question.name:evil.com
severity: medium
`
	imp := NewECSImporter()
	result, err := imp.Import([]byte(input))
	require.NoError(t, err)
	require.Len(t, result.Results, 1)
	assert.Equal(t, 1, result.Converted)

	r := result.Results[0]
	assert.Equal(t, "dns", r.Converted.EventType)
	assert.Equal(t, "warning", r.Converted.Severity)
	cond := r.Converted.ConditionGroup.Conditions[0]
	assert.Equal(t, "qname", cond.Field)
	assert.Equal(t, []string{"evil.com"}, cond.Values)
}

func TestECSImporter_LuceneWildcard(t *testing.T) {
	input := `
name: Wildcard Process Match
type: query
language: lucene
query: process.name:*sh*
severity: low
`
	imp := NewECSImporter()
	result, err := imp.Import([]byte(input))
	require.NoError(t, err)
	require.Len(t, result.Results, 1)
	assert.Equal(t, 1, result.Converted)

	cond := result.Results[0].Converted.ConditionGroup.Conditions[0]
	assert.Equal(t, "comm", cond.Field)
	assert.Equal(t, "regex", cond.Op)
	assert.Contains(t, cond.Values[0], ".*sh.*")
}

func TestECSImporter_ANDCondition(t *testing.T) {
	input := `
name: Bash with User
type: query
language: lucene
query: process.name:bash and user.name:root
severity: high
`
	imp := NewECSImporter()
	result, err := imp.Import([]byte(input))
	require.NoError(t, err)
	require.Len(t, result.Results, 1)
	assert.Equal(t, 1, result.Converted)

	r := result.Results[0]
	assert.Equal(t, "and", r.Converted.ConditionGroup.Operator)
	assert.Len(t, r.Converted.ConditionGroup.Conditions, 2)
}

func TestECSImporter_ORCondition(t *testing.T) {
	input := `
name: Bash or Sh
type: query
language: lucene
query: process.name:bash or process.name:sh
severity: medium
`
	imp := NewECSImporter()
	result, err := imp.Import([]byte(input))
	require.NoError(t, err)
	require.Len(t, result.Results, 1)
	assert.Equal(t, 1, result.Converted)

	r := result.Results[0]
	assert.Equal(t, "or", r.Converted.ConditionGroup.Operator)
	assert.Len(t, r.Converted.ConditionGroup.Conditions, 2)
}

func TestECSImporter_EQLCondition(t *testing.T) {
	input := `
name: EQL Process Detection
type: eql
language: eql
query: process where process.name == "bash"
severity: high
`
	imp := NewECSImporter()
	result, err := imp.Import([]byte(input))
	require.NoError(t, err)
	require.Len(t, result.Results, 1)
	assert.Equal(t, 1, result.Converted)

	cond := result.Results[0].Converted.ConditionGroup.Conditions[0]
	assert.Equal(t, "comm", cond.Field)
	assert.Equal(t, "equals", cond.Op)
	assert.Equal(t, []string{"bash"}, cond.Values)
}

func TestECSImporter_StructuredDetection(t *testing.T) {
	input := `
name: Structured Detection Rule
description: Detects access to sensitive file
type: query
detection:
  file.path: /etc/shadow
severity: high
`
	imp := NewECSImporter()
	result, err := imp.Import([]byte(input))
	require.NoError(t, err)
	require.Len(t, result.Results, 1)
	assert.Equal(t, 1, result.Converted)

	r := result.Results[0]
	assert.Equal(t, "converted", r.Status)
	cond := r.Converted.ConditionGroup.Conditions[0]
	assert.Equal(t, "filename", cond.Field)
	assert.Equal(t, []string{"/etc/shadow"}, cond.Values)
}

func TestECSImporter_MultiFieldDetection(t *testing.T) {
	input := `
name: Multi-Field Detection
description: Detects malicious process
type: query
detection:
  process.name: bash
  user.name: root
severity: high
`
	imp := NewECSImporter()
	result, err := imp.Import([]byte(input))
	require.NoError(t, err)
	require.Len(t, result.Results, 1)
	assert.Equal(t, 1, result.Converted)

	r := result.Results[0]
	assert.Equal(t, "and", r.Converted.ConditionGroup.Operator)
	assert.Len(t, r.Converted.ConditionGroup.Conditions, 2)
}

func TestECSImporter_UnknownFieldSkipped(t *testing.T) {
	input := `
name: Mixed Fields
type: query
language: lucene
query: process.name:bash and host.name:webserver
severity: medium
`
	imp := NewECSImporter()
	result, err := imp.Import([]byte(input))
	require.NoError(t, err)
	require.Len(t, result.Results, 1)

	r := result.Results[0]
	assert.Equal(t, "converted", r.Status)
	assert.Len(t, r.Converted.ConditionGroup.Conditions, 1)
	assert.Equal(t, "comm", r.Converted.ConditionGroup.Conditions[0].Field)
}

func TestECSImporter_AllUnknownFields(t *testing.T) {
	input := `
name: Unsupported Fields
type: query
language: lucene
query: host.name:webserver and agent.type:filebeat
severity: low
`
	imp := NewECSImporter()
	result, err := imp.Import([]byte(input))
	require.NoError(t, err)
	require.Len(t, result.Results, 1)

	r := result.Results[0]
	assert.Equal(t, "unsupported", r.Status)
	assert.NotEmpty(t, r.UnsupportedReasons)
}

func TestECSImporter_NoQueryOrDetection(t *testing.T) {
	input := `
name: Empty Rule
type: query
`
	imp := NewECSImporter()
	result, err := imp.Import([]byte(input))
	require.NoError(t, err)
	require.Len(t, result.Results, 1)

	r := result.Results[0]
	assert.Equal(t, "unsupported", r.Status)
}

func TestECSImporter_IDSemantics(t *testing.T) {
	input := `
name: Rule With ID Only
id: elastic-rule-uuid
type: query
language: lucene
query: process.name:bash
severity: high
`
	imp := NewECSImporter()
	result, err := imp.Import([]byte(input))
	require.NoError(t, err)
	assert.Equal(t, 1, result.Converted)

	assert.Contains(t, result.Results[0].Converted.ID, "ecs_")
}

func TestECSImporter_SeverityMapping(t *testing.T) {
	cases := []struct {
		severity  string
		riskScore int
		want      string
	}{
		{"critical", 0, "critical"},
		{"high", 0, "critical"},
		{"high", 73, "critical"},
		{"medium", 0, "warning"},
		{"medium", 47, "critical"},
		{"low", 0, "warning"},
		{"low", 73, "critical"},
		{"", 0, "warning"},
		{"unknown", 0, "warning"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, mapECSSeverity(tc.severity, tc.riskScore),
			"severity=%s risk=%d", tc.severity, tc.riskScore)
	}
}

func TestECSImporter_TagNormalization(t *testing.T) {
	tags := normalizeECSTags([]string{"attack.t1059", "attack.execution", "linux", "ml"})
	assert.Contains(t, tags, "mitre:T1059")
	assert.Contains(t, tags, "execution")
	assert.Contains(t, tags, "linux")
	assert.Contains(t, tags, "ml")
}

func TestECSImporter_WriteOutput(t *testing.T) {
	input := `
name: Shell Detection
type: query
language: lucene
query: process.name:bash
severity: high
`
	imp := NewECSImporter()
	result, err := imp.Import([]byte(input))
	require.NoError(t, err)

	out, err := imp.WriteOutput(result)
	require.NoError(t, err)
	yamlStr := string(out)
	assert.Contains(t, yamlStr, "rules:")
	assert.Contains(t, yamlStr, "event_type: syscall")
	assert.Contains(t, yamlStr, "severity: critical")
	assert.Contains(t, yamlStr, "action: alert")
}

func TestECSImporter_ImportDir(t *testing.T) {
	dir := t.TempDir()

	rule1 := `
name: Process Rule
type: query
language: lucene
query: process.name:bash
severity: high
`
	rule2 := `
name: Network Rule
type: query
language: lucene
query: destination.port:4444
severity: medium
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "rule1.yaml"), []byte(rule1), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "rule2.yml"), []byte(rule2), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "README.txt"), []byte("ignore me"), 0o644))

	imp := NewECSImporter()
	result, err := imp.ImportDir(dir)
	require.NoError(t, err)
	assert.Equal(t, 2, result.Converted)
}

func TestECSImporter_RoundTrip_Process(t *testing.T) {
	input := `
name: Process Roundtrip
type: query
language: lucene
query: process.name:bash
severity: high
`
	imp := NewECSImporter()
	result, err := imp.Import([]byte(input))
	require.NoError(t, err)
	require.Equal(t, 1, result.Converted)

	out, err := imp.WriteOutput(result)
	require.NoError(t, err)

	tmpFile := filepath.Join(t.TempDir(), "rules.yaml")
	require.NoError(t, os.WriteFile(tmpFile, out, 0o644))

	rules, err := correlator.LoadRulesFromFile(tmpFile)
	require.NoError(t, err, "LoadRulesFromFile must accept the converted YAML")
	require.Len(t, rules, 1)

	engine := correlator.NewRuleEngine(rules)

	comm := [16]byte{}
	copy(comm[:], "bash")
	event := types.Event{
		Type:    types.EventSyscall,
		Comm:    comm,
		Syscall: &types.SyscallEvent{Nr: 59},
	}

	alerts := engine.Evaluate(event)
	assert.Len(t, alerts, 1, "rule should fire on comm=bash")
}

func TestECSImporter_RoundTrip_Network(t *testing.T) {
	input := `
name: Network Roundtrip
type: query
language: lucene
query: destination.port:3333
severity: high
`
	imp := NewECSImporter()
	result, err := imp.Import([]byte(input))
	require.NoError(t, err)
	require.Equal(t, 1, result.Converted)

	out, err := imp.WriteOutput(result)
	require.NoError(t, err)

	tmpFile := filepath.Join(t.TempDir(), "rules.yaml")
	require.NoError(t, os.WriteFile(tmpFile, out, 0o644))

	rules, err := correlator.LoadRulesFromFile(tmpFile)
	require.NoError(t, err)

	engine := correlator.NewRuleEngine(rules)

	event := types.Event{
		Type: types.EventTCPConnect,
		Network: &types.NetworkEvent{
			Dport:  3333,
			Family: types.AFInet,
		},
	}
	alerts := engine.Evaluate(event)
	assert.Len(t, alerts, 1, "rule should fire on port 3333")
}

func TestECSImporter_RoundTrip_File(t *testing.T) {
	input := `
name: File Roundtrip
type: query
language: lucene
query: file.path:"/etc/shadow"
severity: high
`
	imp := NewECSImporter()
	result, err := imp.Import([]byte(input))
	require.NoError(t, err)
	require.Equal(t, 1, result.Converted)

	out, err := imp.WriteOutput(result)
	require.NoError(t, err)

	tmpFile := filepath.Join(t.TempDir(), "rules.yaml")
	require.NoError(t, os.WriteFile(tmpFile, out, 0o644))

	rules, err := correlator.LoadRulesFromFile(tmpFile)
	require.NoError(t, err)

	engine := correlator.NewRuleEngine(rules)

	fname := [256]byte{}
	copy(fname[:], "/etc/shadow")
	event := types.Event{
		Type: types.EventFileAccess,
		File: &types.FileEvent{Filename: fname},
	}
	alerts := engine.Evaluate(event)
	assert.Len(t, alerts, 1, "rule should fire on /etc/shadow access")
}

func TestECSImporter_parseECSAtom_Invalid(t *testing.T) {
	imp := NewECSImporter()
	_, reason := imp.parseECSAtom("garbage without structure", "syscall")
	assert.NotEmpty(t, reason)
}

func TestECSImporter_splitECSQueryOp_QuotedStrings(t *testing.T) {
	// " and " inside quotes should not be treated as a separator.
	query := `process.name:bash and user.name:"root and admin"`
	parts := splitECSQueryOp(query, " and ")
	assert.Len(t, parts, 2)
	assert.Contains(t, parts[1], "root and admin")
}
