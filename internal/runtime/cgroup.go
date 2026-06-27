// Package runtime provides container runtime metadata enrichment via CRI/Docker sockets.
package runtime

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// containerIDRe matches 64-char lowercase hex container IDs as they appear in cgroup paths:
//
//	cgroup v1: "12:devices:/docker/abc123...64chars"
//	cgroup v2: "0::/system.slice/docker-abc123...64chars.scope"
//	containerd: "0::/system.slice/containerd-abc123...64chars.scope"
var containerIDRe = regexp.MustCompile(`\b([a-f0-9]{64})\b`)

// parseCgroupContent scans cgroup lines from r looking for a container ID.
// Extracted from extractContainerID so the regex logic can be unit-tested
// without touching /proc.
func parseCgroupContent(r io.Reader) (string, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		// Only inspect lines that reference a container runtime namespace.
		if !strings.Contains(line, "docker") &&
			!strings.Contains(line, "containerd") &&
			!strings.Contains(line, "cri-containerd") &&
			!strings.Contains(line, "crio") {
			continue
		}
		if m := containerIDRe.FindStringSubmatch(line); len(m) == 2 {
			return m[1], nil
		}
	}
	return "", scanner.Err()
}

// extractContainerID reads /proc/[pid]/cgroup and returns the container ID.
// Returns ("", nil) when the process is not inside a container cgroup.
func extractContainerID(pid uint32) (string, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	return parseCgroupContent(f)
}
