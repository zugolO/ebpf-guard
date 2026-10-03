// Package runtime provides container runtime metadata enrichment via CRI/Docker sockets.
package runtime

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

// containerIDRe matches 64-char lowercase hex container IDs as they appear in cgroup paths:
//
//	cgroup v1: "12:devices:/docker/abc123...64chars"
//	cgroup v2: "0::/system.slice/docker-abc123...64chars.scope"
//	containerd: "0::/system.slice/containerd-abc123...64chars.scope"
var containerIDRe = regexp.MustCompile(`\b([a-f0-9]{64})\b`)

// Container-ID resolution misses are sentinels, not fmt.Errorf strings (wave
// 8.1 item 2 (г)): callers classify them with errors.Is. The k8s enricher maps
// them onto the proc_gone/no_container miss reasons.
var (
	// ErrProcGone means /proc/<pid>/cgroup was unreadable because the process
	// (or its /proc entry) is already gone — the pid→pod race.
	ErrProcGone = errors.New("container id: process cgroup is gone")
	// ErrNotContainer is a normal, cacheable outcome: the process runs in a
	// host cgroup, not a container cgroup.
	ErrNotContainer = errors.New("container id: process is not in a container cgroup")
	// ErrNoCgroupID means the event carried no in-kernel cgroup id, so only the
	// pid fallback can resolve it.
	ErrNoCgroupID = errors.New("container id: event carries no cgroup id")
)

// rootCgroupID is the id of the cgroup2 root. bpf_get_current_cgroup_id()
// reports ids from the unified hierarchy only, so on a cgroup-v1-only host every
// task resolves to this one id (and root-cgroup tasks do on any host). It
// identifies nothing, and as a cache key it would attribute every process on the
// node to whichever container resolved first.
const rootCgroupID = 1

// UsableCgroupID reports whether an event's cgroup id can key an attribution
// cache: non-zero and not the shared cgroup2 root. Callers fall back to the pid
// path otherwise.
func UsableCgroupID(id uint64) bool { return id > rootCgroupID }

// parseCgroupContent scans cgroup lines from r looking for a container ID.
// Extracted from extractContainerID so the regex logic can be unit-tested
// without touching /proc.
func parseCgroupContent(r io.Reader) (string, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		// Only inspect lines that reference a container runtime namespace.
		// "kubepods" is required for the cgroupfs cgroup driver (classic k8s
		// ≤1.21, still reachable via cri-dockerd), where a container line is
		// "12:devices:/kubepods/burstable/pod<uid>/<64hex>" with no runtime
		// keyword. watcher.extractContainerID (the pid fallback) matches that
		// line, so skipping it here would silently change attribution — and
		// with it every rule-exclusion axis keyed on container_id/pod_name.
		if !strings.Contains(line, "docker") &&
			!strings.Contains(line, "containerd") &&
			!strings.Contains(line, "cri-containerd") &&
			!strings.Contains(line, "crio") &&
			!strings.Contains(line, "kubepods") {
			continue
		}
		if m := containerIDRe.FindStringSubmatch(line); len(m) == 2 {
			return m[1], nil
		}
	}
	return "", scanner.Err()
}

// ReadCgroupContent reads /proc/<pid>/cgroup. It is the single /proc read in
// this package; the resolver and the k8s pid fallback both go through it so a
// read failure is classified identically on either path.
//
// A vanished process (ENOENT/ESRCH) is the pid→pod race and reports ErrProcGone
// with the OS cause attached. Anything else — notably EACCES under hidepid=2 —
// is a visibility failure, not a race: it keeps classifying as no_container via
// the k8s missReason, exactly as it did before the cgroup-keyed path existed.
func ReadCgroupContent(pid uint32) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", classifyCgroupReadError(pid, err)
	}
	return string(data), nil
}

// classifyCgroupReadError maps a /proc/<pid>/cgroup read failure onto the
// miss sentinels. Split out so the EACCES/ENOENT split is unit-testable without
// a real /proc (macOS always answers ENOENT for the whole path).
func classifyCgroupReadError(pid uint32, err error) error {
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("%w: %v", ErrProcGone, err)
	}
	return fmt.Errorf("container id: read /proc/%d/cgroup: %w", pid, err)
}

// extractContainerID reads /proc/[pid]/cgroup and returns the container ID.
// Returns ("", nil) when the process is not inside a container cgroup.
func extractContainerID(pid uint32) (string, error) {
	content, err := ReadCgroupContent(pid)
	if err != nil {
		return "", err
	}
	return parseCgroupContent(strings.NewReader(content))
}

// cgroupIDEntry is one resolver cache slot. An empty containerID is the
// negative ("host, not container") entry, cached because host processes are
// 91.4% of the stream (night #3).
type cgroupIDEntry struct {
	containerID string
	at          time.Time
}

// ContainerIDResolver maps an event's in-kernel cgroup id (types.Event.CgroupID)
// to its container id, reading /proc/<pid>/cgroup only on a cache miss.
//
// The cache key is the cgroup id, not the pid (wave 8.1 item 2 (а)): the kernel
// already puts the cgroup id on every event, a node holds hundreds of cgroups
// rather than millions of pids, and pid reuse stops mattering. Negative
// ("host, not container") answers are cached too (b). One instance is shared by
// the k8s and runtime enrichers (DefaultContainerIDResolver), so a single event
// resolves /proc at most once (в).
type ContainerIDResolver struct {
	ttl    time.Duration
	mu     sync.RWMutex
	cache  map[uint64]cgroupIDEntry
	now    func() time.Time
	reader func(pid uint32) (string, error)
}

// NewContainerIDResolver returns a resolver whose entries live for ttl. A
// non-positive ttl defaults to 30s.
//
// The shared DefaultContainerIDResolver is fixed at that 30s and deliberately
// does not follow EnricherConfig.CacheTTL: it is one instance serving both
// enrichers, so it cannot honour two different values. CacheTTL sizes each
// enricher's own metadata/pid caches; cgroup-id entries still live 30s.
func NewContainerIDResolver(ttl time.Duration) *ContainerIDResolver {
	return newContainerIDResolver(ttl, ReadCgroupContent)
}

// NewContainerIDResolverWithReader is NewContainerIDResolver with an injected
// cgroup reader. Tests use it to drive a synthetic pid stream without /proc.
func NewContainerIDResolverWithReader(ttl time.Duration, reader func(pid uint32) (string, error)) *ContainerIDResolver {
	return newContainerIDResolver(ttl, reader)
}

func newContainerIDResolver(ttl time.Duration, reader func(pid uint32) (string, error)) *ContainerIDResolver {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return &ContainerIDResolver{
		ttl:    ttl,
		cache:  make(map[uint64]cgroupIDEntry),
		now:    time.Now,
		reader: reader,
	}
}

// Resolve returns the container id for an event. cgroupID is the in-kernel
// cgroup id (0 and the shared cgroup2 root mean "none"); pid is read only on a cache
// miss. cached reports that the answer came from the cgroup-keyed cache without
// touching /proc. A host process returns "" with ErrNotContainer, cached like
// any other answer.
func (r *ContainerIDResolver) Resolve(cgroupID uint64, pid uint32) (containerID string, cached bool, err error) {
	if !UsableCgroupID(cgroupID) {
		return "", false, ErrNoCgroupID
	}

	r.mu.RLock()
	entry, ok := r.cache[cgroupID]
	r.mu.RUnlock()
	if ok && r.now().Sub(entry.at) < r.ttl {
		if entry.containerID == "" {
			return "", true, ErrNotContainer
		}
		return entry.containerID, true, nil
	}

	content, readErr := r.reader(pid)
	if readErr != nil {
		// Not cached: another live pid sharing this cgroup can still resolve
		// it. That is exactly how events from processes that exited before the
		// agent saw them get attributed (night #3: 2.37M proc_gone, recovery 0).
		return "", false, readErr
	}
	id, parseErr := parseCgroupContent(strings.NewReader(content))
	if parseErr != nil {
		return "", false, parseErr
	}

	// Negative answers are cached too (b), including a read that resolved a
	// host process. The key is the event's cgroup id while the read used pid, so
	// a pid recycled into a different cgroup between kernel event and this read
	// can cache a host answer under a live container's cgroup id, dropping that
	// cgroup for the TTL. The pid-keyed caches this replaces bounded the race to
	// one pid slot; here it is one whole cgroup, but pid reuse inside the
	// event→userspace latency is rare and the TTL bounds the damage.
	r.mu.Lock()
	r.cache[cgroupID] = cgroupIDEntry{containerID: id, at: r.now()}
	r.mu.Unlock()

	if id == "" {
		return "", false, ErrNotContainer
	}
	return id, false, nil
}

// EvictExpired drops entries older than the TTL. Called from the enrichers'
// cleanup loops: without it a long-lived node accumulates one entry per cgroup
// ever seen, since pod churn mints new cgroup ids.
func (r *ContainerIDResolver) EvictExpired() {
	now := r.now()
	r.mu.Lock()
	for id, entry := range r.cache {
		if now.Sub(entry.at) >= r.ttl {
			delete(r.cache, id)
		}
	}
	r.mu.Unlock()
}

// defaultContainerIDResolver is shared by the k8s and runtime enrichers so one
// event reads /proc at most once (wave 8.1 item 2 (в)).
var defaultContainerIDResolver = NewContainerIDResolver(0)

// DefaultContainerIDResolver returns the process-wide shared resolver. A
// per-enricher instance would read /proc once per enricher for the same cgroup.
func DefaultContainerIDResolver() *ContainerIDResolver { return defaultContainerIDResolver }
