package runtime

import (
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

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
		{
			// cgroupfs cgroup driver (classic k8s ≤1.21, still reachable via
			// cri-dockerd): no runtime keyword, only /kubepods/. The pid fallback
			// parses this, so the shared resolver must too or attribution drifts.
			name:    "cgroupfs kubepods layout without runtime keyword",
			content: "12:devices:/kubepods/burstable/pod1234/" + validID,
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

// TestClassifyCgroupReadError pins the wave 8.1 item 2 review follow-up: only a
// vanished process is the pid→pod race (ErrProcGone). A permission failure
// (EACCES under hidepid=2) is a visibility failure, not a race, and must not be
// filed as proc_gone — it stays a plain no_container miss. Both keep the OS
// cause so the miss is diagnosable.
func TestClassifyCgroupReadError(t *testing.T) {
	gone := classifyCgroupReadError(1, syscall.ENOENT)
	require.True(t, errors.Is(gone, ErrProcGone), "ENOENT is the pid→pod race")
	require.NotEqual(t, ErrProcGone.Error(), gone.Error(), "cause must survive for diagnostics")

	esrch := classifyCgroupReadError(1, syscall.ESRCH)
	require.True(t, errors.Is(esrch, ErrProcGone), "ESRCH (exit mid-read) is the pid→pod race")

	eacces := classifyCgroupReadError(1, syscall.EACCES)
	require.False(t, errors.Is(eacces, ErrProcGone), "EACCES under hidepid=2 is not a pid→pod race")
}

// TestContainerIDResolver_IdentityWithPIDPath is the wave 8.1 item 2 identity
// guard: across one synthetic event stream the new cgroup-id-keyed resolver and
// the old per-pid path must attribute the same container id. container_id is a
// rule-exclusion axis ([[exclusions-key-on-cgroup-not-comm]]), so a change here
// is a detection change, not only a performance change.
func TestContainerIDResolver_IdentityWithPIDPath(t *testing.T) {
	const (
		cidDocker     = "1111111111111111111111111111111111111111111111111111111111111111"
		cidContainerd = "2222222222222222222222222222222222222222222222222222222222222222"
	)
	content := map[uint32]string{
		100: "12:devices:/docker/" + cidDocker + "\n11:memory:/docker/" + cidDocker,
		101: "0::/system.slice/cri-containerd-" + cidContainerd + ".scope",
		102: "12:freezer:/\n11:cpu,cpuacct:/system.slice/sshd.service", // host
	}
	reads := 0
	resolver := NewContainerIDResolverWithReader(time.Minute, func(pid uint32) (string, error) {
		reads++
		c, ok := content[pid]
		if !ok {
			return "", ErrProcGone
		}
		return c, nil
	})

	type event struct {
		cgroupID uint64
		pid      uint32
	}
	stream := []event{
		{10, 100}, {11, 101}, {12, 102}, // first touch of each cgroup
		{10, 100}, {11, 101}, {12, 102}, // repeats must not read /proc
		{13, 999}, // pid already gone: not cached
		{13, 100}, // same cgroup, live pid: resolves
	}

	for i, ev := range stream {
		oldContent, pidAlive := content[ev.pid]
		// Old path: parse the pid's cgroup content directly.
		oldID, _ := parseCgroupContent(strings.NewReader(oldContent))

		gotID, _, gotErr := resolver.Resolve(ev.cgroupID, ev.pid)

		if !pidAlive {
			if !errors.Is(gotErr, ErrProcGone) {
				t.Fatalf("event %d: want ErrProcGone for a vanished pid, got %v", i, gotErr)
			}
			continue
		}
		if oldID == "" {
			if !errors.Is(gotErr, ErrNotContainer) || gotID != "" {
				t.Fatalf("event %d: host process want ErrNotContainer/empty, got %q %v", i, gotID, gotErr)
			}
			continue
		}
		if gotErr != nil || gotID != oldID {
			t.Fatalf("event %d: attribution changed with the cache key: old=%q new=%q err=%v", i, oldID, gotID, gotErr)
		}
	}

	// Three cgroups paid one /proc read each; the repeats were free and the
	// proc_gone probe cost no cache entry, so the later live pid read again.
	if reads != 5 {
		t.Fatalf("resolver read /proc %d times, want 5 (3 cgroups + 1 retry + 1 proc_gone probe)", reads)
	}
}

// On a cgroup-v1-only host bpf_get_current_cgroup_id() returns the cgroup2 root
// id for every task; keying the cache on it would give the whole node one
// container identity.
func TestContainerIDResolver_RootCgroupIDIsNotACacheKey(t *testing.T) {
	calls := 0
	r := NewContainerIDResolverWithReader(0, func(uint32) (string, error) {
		calls++
		return "", nil
	})
	for _, id := range []uint64{0, 1} {
		_, cached, err := r.Resolve(id, 42)
		if !errors.Is(err, ErrNoCgroupID) || cached {
			t.Fatalf("cgroup id %d: want ErrNoCgroupID uncached, got cached=%v err=%v", id, cached, err)
		}
	}
	if calls != 0 || len(r.cache) != 0 {
		t.Fatalf("root/zero id must not read /proc or populate the cache (calls=%d, cache=%d)", calls, len(r.cache))
	}
	if UsableCgroupID(0) || UsableCgroupID(1) || !UsableCgroupID(2) {
		t.Fatal("UsableCgroupID boundary wrong")
	}
}
