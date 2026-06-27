package runtime

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validID is a 64-char hex string that satisfies containerIDRe.
const validID = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

func TestParseCgroupContent(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{
			name:    "docker cgroup v1",
			content: "12:devices:/docker/" + validID + "\n11:memory:/docker/" + validID,
			want:    validID,
		},
		{
			name:    "containerd cgroup v2 scope",
			content: "0::/system.slice/containerd-" + validID + ".scope",
			want:    validID,
		},
		{
			name:    "cri-containerd scope",
			content: "0::/system.slice/cri-containerd-" + validID + ".scope",
			want:    validID,
		},
		{
			name:    "crio scope",
			content: "0::/system.slice/crio-" + validID + ".scope",
			want:    validID,
		},
		{
			name:    "non-container process — systemd service",
			content: "12:devices:/system.slice/sshd.service\n0::/user.slice/user-1000.slice",
			want:    "",
		},
		{
			name:    "empty content",
			content: "",
			want:    "",
		},
		{
			name:    "docker keyword present but ID too short",
			content: "12:devices:/docker/shortid",
			want:    "",
		},
		{
			name:    "containerd keyword present but ID is 63 chars",
			content: "0::/system.slice/containerd-abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456789.scope",
			want:    "",
		},
		{
			name: "first matching line wins",
			content: "12:devices:/docker/" + validID + "\n" +
				"11:memory:/docker/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			want: validID,
		},
		{
			name:    "cgroup v2 with kubernetes containerd full path",
			content: "0::/kubepods/besteffort/pod123/cri-containerd-" + validID + ".scope",
			want:    validID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCgroupContent(strings.NewReader(tt.content))
			require.NoError(t, err, "parseCgroupContent should not error on valid input")
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestExtractContainerID_CurrentProcess(t *testing.T) {
	pid := uint32(os.Getpid())
	// The test runner is not a container; expect ("", nil) — no error, no ID.
	id, err := extractContainerID(pid)
	require.NoError(t, err)
	assert.Equal(t, "", id)
}

func TestExtractContainerID_NonexistentPID(t *testing.T) {
	// PID 0 has no /proc entry; expect an os.Open error.
	_, err := extractContainerID(0)
	require.Error(t, err)
}
