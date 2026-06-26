package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// RuntimeClient provides container metadata lookups given a container ID.
type RuntimeClient interface {
	GetContainerInfo(ctx context.Context, containerID string) (*ContainerInfo, error)
	Close() error
}

// ContainerInfo holds metadata for a single container returned by the runtime.
type ContainerInfo struct {
	ContainerID   string
	ContainerName string
	Image         string
	Labels        map[string]string
	CachedAt      time.Time
}

// ── Docker client ─────────────────────────────────────────────────────────────

// dockerClient queries the Docker Engine REST API over its Unix socket.
// Uses only stdlib net/http; does not require the moby SDK.
type dockerClient struct {
	httpClient *http.Client
	socketPath string
}

func newDockerClient(socketPath string) (*dockerClient, error) {
	if socketPath == "" {
		socketPath = "/var/run/docker.sock"
	}
	if _, err := os.Stat(socketPath); err != nil {
		return nil, fmt.Errorf("docker socket not found at %s: %w", socketPath, err)
	}
	hc := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", socketPath)
			},
		},
	}
	return &dockerClient{httpClient: hc, socketPath: socketPath}, nil
}

type dockerInspect struct {
	ID   string `json:"Id"`
	Name string `json:"Name"`
	Config struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
}

func (c *dockerClient) GetContainerInfo(ctx context.Context, containerID string) (*ContainerInfo, error) {
	url := "http://docker/v1.41/containers/" + containerID + "/json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("docker inspect: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("docker inspect: HTTP %d for %s", resp.StatusCode, containerID)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("docker inspect read: %w", err)
	}
	var result dockerInspect
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("docker inspect decode: %w", err)
	}
	return &ContainerInfo{
		ContainerID:   containerID,
		ContainerName: strings.TrimPrefix(result.Name, "/"),
		Image:         result.Config.Image,
		Labels:        result.Config.Labels,
		CachedAt:      time.Now(),
	}, nil
}

func (c *dockerClient) Close() error { return nil }

// ── CRI client ────────────────────────────────────────────────────────────────

// criClient resolves container metadata via the OCI spec files written by the
// container runtime to its state directory. This works for both containerd and CRI-O
// without requiring a gRPC dependency.
//
// State directory layouts:
//
//	containerd: /run/containerd/io.containerd.runtime.v2.task/{ns}/{id}/config.json
//	crio:       /run/crio/bundles/{id}/config.json
type criClient struct {
	runtimeType string // "containerd" or "crio"
	socketPath  string
	stateDir    string
}

// criSocketPaths lists the well-known CRI socket locations probed during
// auto-detection when no explicit socket path is configured.
var criSocketPaths = []string{
	"/run/containerd/containerd.sock",
	"/run/crio/crio.sock",
}

func newCRIClient(socketPath string) (*criClient, error) {
	if socketPath == "" {
		for _, path := range criSocketPaths {
			if _, err := os.Stat(path); err == nil {
				socketPath = path
				break
			}
		}
	}
	if socketPath == "" {
		return nil, fmt.Errorf("no CRI socket found (tried %s)", strings.Join(criSocketPaths, ", "))
	}

	rt, stateDir := "containerd", "/run/containerd/io.containerd.runtime.v2.task"
	if strings.Contains(socketPath, "crio") {
		rt, stateDir = "crio", "/run/crio/bundles"
	}

	return &criClient{
		runtimeType: rt,
		socketPath:  socketPath,
		stateDir:    stateDir,
	}, nil
}

// ociSpec is the minimal OCI runtime spec we need for metadata extraction.
type ociSpec struct {
	Annotations map[string]string `json:"annotations"`
}

func (c *criClient) GetContainerInfo(ctx context.Context, containerID string) (*ContainerInfo, error) {
	if c.runtimeType == "crio" {
		return c.getFromCrioDir(containerID)
	}
	return c.getFromContainerdDir(containerID)
}

func (c *criClient) getFromContainerdDir(containerID string) (*ContainerInfo, error) {
	// Containerd organises bundles by namespace; iterate all namespaces.
	entries, err := os.ReadDir(c.stateDir)
	if err != nil {
		return nil, fmt.Errorf("read containerd state dir %s: %w", c.stateDir, err)
	}
	for _, ns := range entries {
		if !ns.IsDir() {
			continue
		}
		specPath := filepath.Join(c.stateDir, ns.Name(), containerID, "config.json")
		if info, err := parseOCISpec(specPath, containerID); err == nil {
			return info, nil
		}
	}
	return nil, fmt.Errorf("container %s not found in containerd state", containerID)
}

func (c *criClient) getFromCrioDir(containerID string) (*ContainerInfo, error) {
	specPath := filepath.Join(c.stateDir, containerID, "config.json")
	return parseOCISpec(specPath, containerID)
}

func parseOCISpec(specPath, containerID string) (*ContainerInfo, error) {
	data, err := os.ReadFile(specPath)
	if err != nil {
		return nil, err
	}
	var spec ociSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("parse OCI spec: %w", err)
	}
	ann := spec.Annotations
	name := coalesce(ann,
		"io.kubernetes.container.name",
		"io.cri-containerd.name",
		"nerdctl/name",
	)
	image := coalesce(ann,
		"io.kubernetes.container.image",
		"io.cri-containerd.image-name",
		"nerdctl/image-name",
	)
	return &ContainerInfo{
		ContainerID:   containerID,
		ContainerName: name,
		Image:         image,
		Labels:        ann,
		CachedAt:      time.Now(),
	}, nil
}

// coalesce returns the first non-empty value from m for any of the given keys.
func coalesce(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := m[k]; v != "" {
			return v
		}
	}
	return ""
}

func (c *criClient) Close() error { return nil }

// ── Auto-detection ────────────────────────────────────────────────────────────

// autoDetect returns the first available runtime client.
// Docker is tried first since it is more common on non-Kubernetes hosts.
func autoDetect(socketOverride string) (RuntimeClient, string, error) {
	if socketOverride != "" {
		if strings.Contains(socketOverride, "docker") {
			c, err := newDockerClient(socketOverride)
			return c, "docker", err
		}
		c, err := newCRIClient(socketOverride)
		if err != nil {
			return nil, "", err
		}
		return c, c.runtimeType, nil
	}

	if c, err := newDockerClient(""); err == nil {
		return c, "docker", nil
	}
	if c, err := newCRIClient(""); err == nil {
		return c, c.runtimeType, nil
	}
	return nil, "", fmt.Errorf("no container runtime detected (tried Docker and CRI sockets)")
}
