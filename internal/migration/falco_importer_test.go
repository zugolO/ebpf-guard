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

// TestFalcoImporter_ProcFields verifies mapping of proc.* fields added in issue #111.
func TestFalcoImporter_ProcFields(t *testing.T) {
	cases := []struct {
		name      string
		condition string
		wantField string
		wantOp    string
	}{
		{"proc.pname eq", `proc.pname = "sshd"`, "parent_comm", "eq"},
		{"proc.cmdline eq", `proc.cmdline = "bash -c evil"`, "cmdline", "eq"},
		{"proc.pcmdline eq", `proc.pcmdline = "sh -c evil"`, "parent_cmdline", "eq"},
		{"proc.args contains", `proc.args contains "--exploit"`, "args", "contains"},
		{"proc.exe eq", `proc.exe = "/bin/sh"`, "exe_path", "eq"},
		{"proc.exepath eq", `proc.exepath = "/usr/bin/python"`, "exe_path", "eq"},
		{"proc.vpid eq", `proc.vpid = "1"`, "pid", "eq"},
		{"proc.pvpid eq", `proc.pvpid = "0"`, "ppid", "eq"},
		{"proc.sid eq", `proc.sid = "42"`, "session_id", "eq"},
		{"proc.sname eq", `proc.sname = "pts0"`, "session_name", "eq"},
		{"proc.tty eq", `proc.tty = "1"`, "tty", "eq"},
		{"proc.loginuid eq", `proc.loginuid = "1000"`, "loginuid", "eq"},
	}

	imp := NewFalcoImporter()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := []byte("- rule: Test\n  desc: d\n  condition: " + tc.condition + "\n  output: o\n  priority: WARNING\n")
			result, err := imp.Import(input)
			require.NoError(t, err)
			require.Len(t, result.Results, 1)
			r := result.Results[0]
			assert.Equal(t, "converted", r.Status, "condition %q should convert; reasons: %v", tc.condition, r.UnsupportedReasons)
			assert.Equal(t, tc.wantField, r.Converted.Condition["field"])
			assert.Equal(t, tc.wantOp, r.Converted.Condition["op"])
		})
	}
}

// TestFalcoImporter_FdFields verifies mapping of fd.* fields added in issue #111.
func TestFalcoImporter_FdFields(t *testing.T) {
	cases := []struct {
		name      string
		condition string
		wantField string
		wantOp    string
	}{
		{"fd.directory eq", `fd.directory = "/etc"`, "dir", "eq"},
		{"fd.filename eq", `fd.filename = "shadow"`, "filename", "eq"},
		{"fd.typechar eq", `fd.typechar = "f"`, "fd_type", "eq"},
		{"fd.type eq", `fd.type = "file"`, "fd_type", "eq"},
		{"fd.proto eq", `fd.proto = "tcp"`, "protocol", "eq"},
		{"fd.sport eq", `fd.sport = 1234`, "dst_port", "eq"},
	}

	imp := NewFalcoImporter()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := []byte("- rule: Test\n  desc: d\n  condition: " + tc.condition + "\n  output: o\n  priority: WARNING\n")
			result, err := imp.Import(input)
			require.NoError(t, err)
			require.Len(t, result.Results, 1)
			r := result.Results[0]
			assert.Equal(t, "converted", r.Status, "condition %q should convert; reasons: %v", tc.condition, r.UnsupportedReasons)
			assert.Equal(t, tc.wantField, r.Converted.Condition["field"])
		})
	}
}

// TestFalcoImporter_UserGroupFields verifies mapping of user.* and group.* fields.
func TestFalcoImporter_UserGroupFields(t *testing.T) {
	cases := []struct {
		name      string
		condition string
		wantField string
	}{
		{"user.uid eq", `user.uid = "0"`, "uid"},
		{"user.gid eq", `user.gid = "0"`, "gid"},
		{"user.loginuid eq", `user.loginuid = "1000"`, "loginuid"},
		{"user.loginname eq", `user.loginname = "root"`, "loginname"},
		{"group.name eq", `group.name = "docker"`, "group_name"},
		{"group.gid eq", `group.gid = "999"`, "group_gid"},
	}

	imp := NewFalcoImporter()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := []byte("- rule: Test\n  desc: d\n  condition: " + tc.condition + "\n  output: o\n  priority: WARNING\n")
			result, err := imp.Import(input)
			require.NoError(t, err)
			require.Len(t, result.Results, 1)
			r := result.Results[0]
			assert.Equal(t, "converted", r.Status, "condition %q should convert; reasons: %v", tc.condition, r.UnsupportedReasons)
			assert.Equal(t, tc.wantField, r.Converted.Condition["field"])
		})
	}
}

// TestFalcoImporter_ContainerK8sFields verifies mapping of container.* and k8s.* fields.
func TestFalcoImporter_ContainerK8sFields(t *testing.T) {
	cases := []struct {
		name      string
		condition string
		wantField string
		wantValue string
	}{
		{"container.name eq", `container.name = "nginx"`, "container_name", "nginx"},
		{"container.image eq", `container.image = "alpine"`, "container_image", "alpine"},
		{"container.image.id eq", `container.image.id = "sha256:abc"`, "container_image_id", "sha256:abc"},
		{"container.privileged true", `container.privileged = true`, "container_privileged", "true"},
		{"container.privileged false", `container.privileged = false`, "container_privileged", "false"},
		{"k8s.pod.name eq", `k8s.pod.name = "my-pod"`, "pod_name", "my-pod"},
		{"k8s.ns.name eq", `k8s.ns.name = "production"`, "namespace", "production"},
	}

	imp := NewFalcoImporter()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := []byte("- rule: Test\n  desc: d\n  condition: " + tc.condition + "\n  output: o\n  priority: WARNING\n")
			result, err := imp.Import(input)
			require.NoError(t, err)
			require.Len(t, result.Results, 1)
			r := result.Results[0]
			assert.Equal(t, "converted", r.Status, "condition %q should convert; reasons: %v", tc.condition, r.UnsupportedReasons)
			assert.Equal(t, tc.wantField, r.Converted.Condition["field"])
			if tc.wantValue != "" {
				vals, _ := r.Converted.Condition["values"].([]string)
				assert.Contains(t, vals, tc.wantValue)
			}
		})
	}
}

// TestFalcoImporter_IpCidrFields verifies fd.sip/fd.dip/fd.net CIDR mapping.
func TestFalcoImporter_IpCidrFields(t *testing.T) {
	cases := []struct {
		name      string
		condition string
	}{
		{"fd.sip cidr", `fd.sip = "10.0.0.0/8"`},
		{"fd.dip cidr", `fd.dip = "192.168.1.0/24"`},
		{"fd.net cidr", `fd.net = "172.16.0.0/12"`},
	}

	imp := NewFalcoImporter()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := []byte("- rule: Test\n  desc: d\n  condition: " + tc.condition + "\n  output: o\n  priority: WARNING\n")
			result, err := imp.Import(input)
			require.NoError(t, err)
			require.Len(t, result.Results, 1)
			r := result.Results[0]
			assert.Equal(t, "converted", r.Status, "condition %q should convert; reasons: %v", tc.condition, r.UnsupportedReasons)
			assert.Equal(t, "remote_ip", r.Converted.Condition["field"])
			assert.Equal(t, "in_cidr", r.Converted.Condition["op"])
		})
	}
}

// TestFalcoImporter_SyscallEvtFields verifies syscall.type and evt.dir mapping.
func TestFalcoImporter_SyscallEvtFields(t *testing.T) {
	imp := NewFalcoImporter()

	t.Run("syscall.type", func(t *testing.T) {
		input := []byte("- rule: Test\n  desc: d\n  condition: syscall.type = open\n  output: o\n  priority: WARNING\n")
		result, err := imp.Import(input)
		require.NoError(t, err)
		r := result.Results[0]
		assert.Equal(t, "converted", r.Status)
		assert.Equal(t, "syscall_name", r.Converted.Condition["field"])
	})

	t.Run("evt.dir", func(t *testing.T) {
		input := []byte("- rule: Test\n  desc: d\n  condition: evt.dir = \">\"\n  output: o\n  priority: WARNING\n")
		result, err := imp.Import(input)
		require.NoError(t, err)
		r := result.Results[0]
		assert.Equal(t, "converted", r.Status)
		assert.Equal(t, "evt_dir", r.Converted.Condition["field"])
	})
}

// TestFalcoImporter_UnmappedFieldEmitsWarn verifies that an unknown Falco field
// causes the rule to be marked unsupported with a non-empty reason (WARN is
// emitted to the log rather than silently dropped).
func TestFalcoImporter_UnmappedFieldEmitsWarn(t *testing.T) {
	input := []byte("- rule: Weird\n  desc: d\n  condition: proc.unknown_field = \"value\"\n  output: o\n  priority: WARNING\n")
	imp := NewFalcoImporter()
	result, err := imp.Import(input)
	require.NoError(t, err)
	require.Len(t, result.Results, 1)
	r := result.Results[0]
	assert.Equal(t, "unsupported", r.Status)
	assert.NotEmpty(t, r.UnsupportedReasons, "unmapped field must produce a non-empty reason (not silently dropped)")
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
