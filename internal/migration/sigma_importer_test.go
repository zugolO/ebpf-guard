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

// ── Basic conversion tests ────────────────────────────────────────────────────

func TestSigmaImporter_ProcessCreation(t *testing.T) {
	input := `
title: Suspicious Shell
id: aaaabbbb-1234-5678-9abc-def012345678
status: stable
logsource:
  category: process_creation
detection:
  selection:
    Image: bash
  condition: selection
level: high
`
	imp := NewSigmaImporter()
	result, err := imp.Import([]byte(input))
	require.NoError(t, err)
	require.Len(t, result.Results, 1)
	assert.Equal(t, 1, result.Converted)

	r := result.Results[0]
	assert.Equal(t, "converted", r.Status)
	assert.Equal(t, "syscall", r.Converted.EventType)
	assert.Equal(t, "critical", r.Converted.Severity)
	assert.Equal(t, "alert", r.Converted.Action)
	require.NotNil(t, r.Converted.Condition)
	assert.Equal(t, "comm", r.Converted.Condition.Field)
	assert.Equal(t, "equals", r.Converted.Condition.Op)
	assert.Equal(t, []string{"bash"}, r.Converted.Condition.Values)
}

func TestSigmaImporter_NetworkConnection(t *testing.T) {
	input := `
title: Connection to Mining Pool
logsource:
  category: network_connection
detection:
  selection:
    DestinationPort:
      - 3333
      - 4444
  condition: selection
level: critical
`
	imp := NewSigmaImporter()
	result, err := imp.Import([]byte(input))
	require.NoError(t, err)
	require.Len(t, result.Results, 1)

	r := result.Results[0]
	assert.Equal(t, "converted", r.Status)
	assert.Equal(t, "network", r.Converted.EventType)
	assert.Equal(t, "critical", r.Converted.Severity)
	require.NotNil(t, r.Converted.Condition)
	assert.Equal(t, "dport", r.Converted.Condition.Field)
	assert.Equal(t, "in", r.Converted.Condition.Op)
	assert.ElementsMatch(t, []string{"3333", "4444"}, r.Converted.Condition.Values)
}

func TestSigmaImporter_FileEvent(t *testing.T) {
	input := `
title: Sensitive File Access
logsource:
  category: file_event
detection:
  selection:
    TargetFilename|startswith: /etc/shadow
  condition: selection
level: high
`
	imp := NewSigmaImporter()
	result, err := imp.Import([]byte(input))
	require.NoError(t, err)
	require.Len(t, result.Results, 1)

	r := result.Results[0]
	assert.Equal(t, "converted", r.Status)
	assert.Equal(t, "file", r.Converted.EventType)
	require.NotNil(t, r.Converted.Condition)
	assert.Equal(t, "filename", r.Converted.Condition.Field)
	assert.Equal(t, "prefix", r.Converted.Condition.Op)
	assert.Equal(t, []string{"/etc/shadow"}, r.Converted.Condition.Values)
}

func TestSigmaImporter_DNSQuery(t *testing.T) {
	input := `
title: DNS Query to Suspicious Domain
logsource:
  category: dns_query
detection:
  selection:
    QueryName|endswith: .mining.pool
  condition: selection
level: medium
`
	imp := NewSigmaImporter()
	result, err := imp.Import([]byte(input))
	require.NoError(t, err)
	require.Len(t, result.Results, 1)

	r := result.Results[0]
	assert.Equal(t, "converted", r.Status)
	assert.Equal(t, "dns", r.Converted.EventType)
	require.NotNil(t, r.Converted.Condition)
	assert.Equal(t, "qname", r.Converted.Condition.Field)
	assert.Equal(t, "suffix", r.Converted.Condition.Op)
}

// ── AND/OR condition logic ────────────────────────────────────────────────────

func TestSigmaImporter_ANDCondition(t *testing.T) {
	input := `
title: Malicious Shell
logsource:
  category: process_creation
detection:
  selection:
    Image: bash
    User: root
  condition: selection
level: high
`
	imp := NewSigmaImporter()
	result, err := imp.Import([]byte(input))
	require.NoError(t, err)
	require.Len(t, result.Results, 1)

	r := result.Results[0]
	assert.Equal(t, "converted", r.Status)
	// Two fields in one selection → condition_group AND
	require.NotNil(t, r.Converted.ConditionGroup)
	assert.Equal(t, "and", r.Converted.ConditionGroup.Operator)
	assert.Len(t, r.Converted.ConditionGroup.Conditions, 2)
}

func TestSigmaImporter_TwoGroupsAND(t *testing.T) {
	input := `
title: Network Mining with Port and IP
logsource:
  category: network_connection
detection:
  port_check:
    DestinationPort: 3333
  ip_check:
    DestinationIp: 1.2.3.4
  condition: port_check and ip_check
level: critical
`
	imp := NewSigmaImporter()
	result, err := imp.Import([]byte(input))
	require.NoError(t, err)
	require.Len(t, result.Results, 1)

	r := result.Results[0]
	assert.Equal(t, "converted", r.Status)
	require.NotNil(t, r.Converted.ConditionGroup)
	assert.Equal(t, "and", r.Converted.ConditionGroup.Operator)
	assert.Len(t, r.Converted.ConditionGroup.Conditions, 2)
}

func TestSigmaImporter_TwoGroupsOR(t *testing.T) {
	input := `
title: Suspicious Process
logsource:
  category: process_creation
detection:
  sel_bash:
    Image: bash
  sel_sh:
    Image: sh
  condition: sel_bash or sel_sh
level: medium
`
	imp := NewSigmaImporter()
	result, err := imp.Import([]byte(input))
	require.NoError(t, err)
	require.Len(t, result.Results, 1)

	r := result.Results[0]
	assert.Equal(t, "converted", r.Status)
	require.NotNil(t, r.Converted.ConditionGroup)
	assert.Equal(t, "or", r.Converted.ConditionGroup.Operator)
}

// ── Modifier mapping ──────────────────────────────────────────────────────────

func TestSigmaImporter_ContainsModifier(t *testing.T) {
	input := `
title: Evil File Access
logsource:
  category: file_event
detection:
  selection:
    TargetFilename|contains: evil
  condition: selection
level: high
`
	imp := NewSigmaImporter()
	result, err := imp.Import([]byte(input))
	require.NoError(t, err)
	require.Equal(t, "converted", result.Results[0].Status)
	cond := result.Results[0].Converted.Condition
	require.NotNil(t, cond)
	assert.Equal(t, "regex", cond.Op)
	assert.Equal(t, []string{"evil"}, cond.Values)
}

func TestSigmaImporter_ContainsAllModifier(t *testing.T) {
	input := `
title: Multi-keyword file
logsource:
  category: file_event
detection:
  selection:
    TargetFilename|contains|all:
      - evil
      - pwned
  condition: selection
level: high
`
	imp := NewSigmaImporter()
	result, err := imp.Import([]byte(input))
	require.NoError(t, err)
	require.Equal(t, "converted", result.Results[0].Status)
	r := result.Results[0].Converted
	// Two values with contains|all → condition_group AND with two regex conditions
	require.NotNil(t, r.ConditionGroup)
	assert.Equal(t, "and", r.ConditionGroup.Operator)
	assert.Len(t, r.ConditionGroup.Conditions, 2)
	for _, c := range r.ConditionGroup.Conditions {
		assert.Equal(t, "regex", c.Op)
	}
}

func TestSigmaImporter_RegexModifier(t *testing.T) {
	input := `
title: Regex DNS
logsource:
  category: dns_query
detection:
  selection:
    QueryName|re: "^.*\\.evil\\.com$"
  condition: selection
level: high
`
	imp := NewSigmaImporter()
	result, err := imp.Import([]byte(input))
	require.NoError(t, err)
	require.Equal(t, "converted", result.Results[0].Status)
	cond := result.Results[0].Converted.Condition
	require.NotNil(t, cond)
	assert.Equal(t, "regex", cond.Op)
}

func TestSigmaImporter_CIDRModifier(t *testing.T) {
	input := `
title: Private Network Connection
logsource:
  category: network_connection
detection:
  selection:
    DestinationIp|cidr: 10.0.0.0/8
  condition: selection
level: medium
`
	imp := NewSigmaImporter()
	result, err := imp.Import([]byte(input))
	require.NoError(t, err)
	require.Equal(t, "converted", result.Results[0].Status)
	cond := result.Results[0].Converted.Condition
	require.NotNil(t, cond)
	assert.Equal(t, "in_cidr", cond.Op)
	assert.Equal(t, "daddr", cond.Field)
	assert.Equal(t, []string{"10.0.0.0/8"}, cond.Values)
}

// ── Unknown fields / unsupported scenarios ────────────────────────────────────

func TestSigmaImporter_UnknownFieldSkipped(t *testing.T) {
	// CommandLine has no mapping → warn and skip, but Image does → still convert
	input := `
title: Shell with CommandLine
logsource:
  category: process_creation
detection:
  selection:
    Image: bash
    CommandLine|contains: evil
  condition: selection
level: medium
`
	imp := NewSigmaImporter()
	result, err := imp.Import([]byte(input))
	require.NoError(t, err)
	// CommandLine is skipped, Image is converted → partial success
	r := result.Results[0]
	assert.Equal(t, "converted", r.Status)
	// Only the Image condition should be present
	assert.NotNil(t, r.Converted.Condition)
	assert.Equal(t, "comm", r.Converted.Condition.Field)
}

func TestSigmaImporter_AllFieldsUnsupported(t *testing.T) {
	input := `
title: Only CommandLine
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains: evil
    ParentImage|endswith: /cmd.exe
  condition: selection
level: medium
`
	imp := NewSigmaImporter()
	result, err := imp.Import([]byte(input))
	require.NoError(t, err)
	r := result.Results[0]
	// All fields unsupported → whole rule unsupported
	assert.Equal(t, "unsupported", r.Status)
	assert.NotEmpty(t, r.UnsupportedReasons)
}

func TestSigmaImporter_UnsupportedLogsource(t *testing.T) {
	input := `
title: Windows Registry
logsource:
  category: registry_event
  product: windows
detection:
  selection:
    TargetObject|contains: evil
  condition: selection
level: medium
`
	imp := NewSigmaImporter()
	result, err := imp.Import([]byte(input))
	require.NoError(t, err)
	assert.Equal(t, 1, result.Unsupported)
	assert.NotEmpty(t, result.Results[0].UnsupportedReasons)
}

func TestSigmaImporter_DeprecatedStatus(t *testing.T) {
	input := `
title: Old Rule
status: deprecated
logsource:
  category: process_creation
detection:
  selection:
    Image: bash
  condition: selection
level: low
`
	imp := NewSigmaImporter()
	result, err := imp.Import([]byte(input))
	require.NoError(t, err)
	assert.Equal(t, 1, result.Disabled)
	assert.Equal(t, "disabled", result.Results[0].Status)
}

func TestSigmaImporter_NOTConditionUnsupported(t *testing.T) {
	input := `
title: NOT rule
logsource:
  category: process_creation
detection:
  selection:
    Image: bash
  condition: not selection
level: medium
`
	imp := NewSigmaImporter()
	result, err := imp.Import([]byte(input))
	require.NoError(t, err)
	assert.Equal(t, "unsupported", result.Results[0].Status)
	assert.NotEmpty(t, result.Results[0].UnsupportedReasons)
}

// ── Level / severity mapping ──────────────────────────────────────────────────

func TestMapSigmaLevel(t *testing.T) {
	cases := []struct{ in, want string }{
		{"critical", "critical"},
		{"high", "critical"},
		{"medium", "warning"},
		{"low", "warning"},
		{"informational", "warning"},
		{"", "warning"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, mapSigmaLevel(tc.in), "level=%s", tc.in)
	}
}

// ── Tag normalization ─────────────────────────────────────────────────────────

func TestNormalizeSigmaTags(t *testing.T) {
	tags := normalizeSigmaTags([]string{"attack.t1059", "attack.execution", "detection.sigma"})
	assert.Contains(t, tags, "mitre:T1059")
	assert.Contains(t, tags, "execution")
	assert.Contains(t, tags, "detection.sigma")
}

// ── WriteOutput / serialization ───────────────────────────────────────────────

func TestSigmaImporter_WriteOutput(t *testing.T) {
	input := `
title: Shell Execution
logsource:
  category: process_creation
detection:
  selection:
    Image: bash
  condition: selection
level: high
`
	imp := NewSigmaImporter()
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

// ── 1 of / all of ────────────────────────────────────────────────────────────

func TestSigmaImporter_OneOfThem(t *testing.T) {
	input := `
title: Any Shell
logsource:
  category: process_creation
detection:
  sel_bash:
    Image: bash
  sel_sh:
    Image: sh
  condition: 1 of sel_*
level: medium
`
	imp := NewSigmaImporter()
	result, err := imp.Import([]byte(input))
	require.NoError(t, err)
	r := result.Results[0]
	assert.Equal(t, "converted", r.Status)
	require.NotNil(t, r.Converted.ConditionGroup)
	assert.Equal(t, "or", r.Converted.ConditionGroup.Operator)
}

func TestSigmaImporter_AllOfThem(t *testing.T) {
	input := `
title: Combined Network
logsource:
  category: network_connection
detection:
  check_port:
    DestinationPort: 4444
  check_ip:
    DestinationIp: 5.5.5.5
  condition: all of check_*
level: high
`
	imp := NewSigmaImporter()
	result, err := imp.Import([]byte(input))
	require.NoError(t, err)
	r := result.Results[0]
	assert.Equal(t, "converted", r.Status)
	require.NotNil(t, r.Converted.ConditionGroup)
	assert.Equal(t, "and", r.Converted.ConditionGroup.Operator)
}

// ── ImportDir ─────────────────────────────────────────────────────────────────

func TestSigmaImporter_ImportDir(t *testing.T) {
	dir := t.TempDir()

	rule1 := `title: Rule One
logsource:
  category: process_creation
detection:
  selection:
    Image: bash
  condition: selection
level: high
`
	rule2 := `title: Rule Two
logsource:
  category: file_event
detection:
  selection:
    TargetFilename|startswith: /etc
  condition: selection
level: medium
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "rule1.yaml"), []byte(rule1), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "rule2.yml"), []byte(rule2), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "README.txt"), []byte("ignore me"), 0o644))

	imp := NewSigmaImporter()
	result, err := imp.ImportDir(dir)
	require.NoError(t, err)
	assert.Equal(t, 2, result.Converted)
}

// ── dry-run flag (CLI-level) uses WriteOutput ─────────────────────────────────

func TestSigmaImporter_DryRun(t *testing.T) {
	input := `
title: Dry Run Test
logsource:
  category: dns_query
detection:
  selection:
    QueryName|endswith: .evil.com
  condition: selection
level: high
`
	imp := NewSigmaImporter()
	result, err := imp.Import([]byte(input))
	require.NoError(t, err)
	assert.Equal(t, 1, result.Converted)

	// WriteOutput is what dry-run mode calls; verify it produces non-empty YAML.
	out, err := imp.WriteOutput(result)
	require.NoError(t, err)
	assert.NotEmpty(t, out)
	assert.Contains(t, string(out), "rules:")
}

// ── Round-trip test ───────────────────────────────────────────────────────────
// Verifies that an imported Sigma rule produces YAML that ebpf-guard's rule
// loader accepts, and that the resulting RuleEngine fires on a matching event.

func TestSigmaImporter_RoundTrip_ProcessCreation(t *testing.T) {
	input := `
title: Shell Roundtrip
logsource:
  category: process_creation
detection:
  selection:
    Image: bash
  condition: selection
level: high
`
	imp := NewSigmaImporter()
	result, err := imp.Import([]byte(input))
	require.NoError(t, err)
	require.Equal(t, 1, result.Converted)

	// Serialize to ebpf-guard YAML and write to a temp file.
	out, err := imp.WriteOutput(result)
	require.NoError(t, err)

	tmpFile := filepath.Join(t.TempDir(), "rules.yaml")
	require.NoError(t, os.WriteFile(tmpFile, out, 0o644))

	// Load with correlator's rule loader (full validation).
	rules, err := correlator.LoadRulesFromFile(tmpFile)
	require.NoError(t, err, "LoadRulesFromFile must accept the converted YAML")
	require.Len(t, rules, 1)

	// Build a rule engine and evaluate a matching synthetic event.
	engine := correlator.NewRuleEngine(rules)

	comm := [16]byte{}
	copy(comm[:], "bash")
	event := types.Event{
		Type:    types.EventSyscall,
		Comm:    comm,
		Syscall: &types.SyscallEvent{Nr: 59}, // execve
	}

	alerts := engine.Evaluate(event)
	assert.Len(t, alerts, 1, "rule should fire on process comm=bash")
}

func TestSigmaImporter_RoundTrip_FileEvent(t *testing.T) {
	input := `
title: Shadow File Access Roundtrip
logsource:
  category: file_event
detection:
  selection:
    TargetFilename|startswith: /etc/shadow
  condition: selection
level: high
`
	imp := NewSigmaImporter()
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

func TestSigmaImporter_RoundTrip_NetworkConnection(t *testing.T) {
	input := `
title: Mining Port Roundtrip
logsource:
  category: network_connection
detection:
  selection:
    DestinationPort:
      - 3333
      - 4444
  condition: selection
level: critical
`
	imp := NewSigmaImporter()
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
