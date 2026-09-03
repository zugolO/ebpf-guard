package runtime

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

const dockerInspectResp = `{
	"Id": "fullcontainerid123",
	"Name": "/my-nginx",
	"Config": {
		"Image": "nginx:1.25",
		"Labels": {
			"env": "production",
			"io.kubernetes.pod.namespace": "default",
			"io.kubernetes.pod.name": "nginx-0"
		}
	}
}`

func newFakeDockerServer(t *testing.T, handler http.Handler) (socketPath string) {
	t.Helper()
	socketPath = filepath.Join(t.TempDir(), "docker.sock")
	ln, err := net.Listen("unix", socketPath)
	require.NoError(t, err, "listen on unix socket")

	srv := httptest.NewUnstartedServer(handler)
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	return socketPath
}

func TestNewDockerClient_ValidSocket(t *testing.T) {
	socketPath := newFakeDockerServer(t, http.NotFoundHandler())
	c, err := newDockerClient(socketPath)
	require.NoError(t, err)
	require.NotNil(t, c)
	assert.NoError(t, c.Close())
}

func TestNewDockerClient_MissingSocket(t *testing.T) {
	_, err := newDockerClient(filepath.Join(t.TempDir(), "absent.sock"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "docker socket not found")
}

func TestDockerClient_GetContainerInfo_Success(t *testing.T) {
	socketPath := newFakeDockerServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, dockerInspectResp)
	}))

	c, err := newDockerClient(socketPath)
	require.NoError(t, err)

	info, err := c.GetContainerInfo(context.Background(), "fullcontainerid123")
	require.NoError(t, err)

	assert.Equal(t, "fullcontainerid123", info.ContainerID)
	assert.Equal(t, "my-nginx", info.ContainerName, "leading slash should be stripped")
	assert.Equal(t, "nginx:1.25", info.Image)
	assert.Equal(t, "production", info.Labels["env"])
}

func TestDockerClient_GetContainerInfo_HTTP404(t *testing.T) {
	socketPath := newFakeDockerServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	}))

	c, err := newDockerClient(socketPath)
	require.NoError(t, err)

	_, err = c.GetContainerInfo(context.Background(), "nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 404")
}

func TestDockerClient_GetContainerInfo_MalformedJSON(t *testing.T) {
	socketPath := newFakeDockerServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "{not valid json")
	}))

	c, err := newDockerClient(socketPath)
	require.NoError(t, err)

	_, err = c.GetContainerInfo(context.Background(), "cid")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "docker inspect decode")
}

func TestDockerClient_Close(t *testing.T) {
	socketPath := newFakeDockerServer(t, http.NotFoundHandler())
	c, err := newDockerClient(socketPath)
	require.NoError(t, err)
	assert.NoError(t, c.Close())
}

func TestAutoDetect_DockerSocketOverride(t *testing.T) {
	socketPath := newFakeDockerServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, dockerInspectResp)
	}))

	// Path contains "docker" → should select the Docker client.
	client, source, err := autoDetect(socketPath)
	require.NoError(t, err)
	assert.Equal(t, "docker", source)
	assert.NotNil(t, client)
}

// TestNewEnricher_DockerMode exercises NewEnricher with mode="docker" using a
// fake unix-socket server so the socket-exists check passes.
func TestNewEnricher_DockerMode(t *testing.T) {
	socketPath := newFakeDockerServer(t, http.NotFoundHandler())
	e, err := NewEnricher(EnricherConfig{
		Mode:       "docker",
		SocketPath: socketPath,
	}, newTestLogger())
	require.NoError(t, err)
	assert.Equal(t, "docker", e.Source())
	require.NoError(t, e.Stop())
}

// TestNewEnricher_CRIMode_NoSocket exercises the error path when no CRI socket exists.
// newCRIClient only probes existence when no explicit path is given, so we override
// criSocketPaths to nonexistent paths and omit SocketPath to trigger the error.
func TestNewEnricher_CRIMode_NoSocket(t *testing.T) {
	orig := criSocketPaths
	criSocketPaths = []string{
		filepath.Join(t.TempDir(), "absent-containerd.sock"),
		filepath.Join(t.TempDir(), "absent-crio.sock"),
	}
	t.Cleanup(func() { criSocketPaths = orig })

	_, err := NewEnricher(EnricherConfig{Mode: "cri"}, newTestLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "runtime/cri")
}

// TestNewEnricher_AutoMode_NoRuntime exercises the auto-detect error path.
// Both Docker and CRI socket paths are redirected to absent files so the test
// is deterministic even on CI runners where /var/run/docker.sock exists.
func TestNewEnricher_AutoMode_NoRuntime(t *testing.T) {
	origCRI := criSocketPaths
	origDocker := defaultDockerSocketPath
	criSocketPaths = []string{
		filepath.Join(t.TempDir(), "absent-containerd.sock"),
		filepath.Join(t.TempDir(), "absent-crio.sock"),
	}
	defaultDockerSocketPath = filepath.Join(t.TempDir(), "absent-docker.sock")
	t.Cleanup(func() {
		criSocketPaths = origCRI
		defaultDockerSocketPath = origDocker
	})

	// Wave 6.1: auto mode no longer fails when no socket is reachable — it
	// degrades to the cgroup-only client so container.id stays a usable rule
	// axis. Losing the axis silently disarmed every container-keyed rule.
	e, err := NewEnricher(EnricherConfig{Mode: "auto"}, newTestLogger())
	require.NoError(t, err)
	require.NotNil(t, e)
	assert.Equal(t, cgroupOnlySource, e.Source())

	// The degraded client still yields the container ID the cgroup walk found.
	const containerID = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	e.pidCache[4242] = containerID
	event := &types.Event{PID: 4242}
	e.EnrichEvent(event)
	require.NotNil(t, event.Enrichment)
	assert.Equal(t, containerID, event.Enrichment.ContainerID)
	assert.Empty(t, event.Enrichment.ContainerName, "no socket means no name/image")
}

// Explicit "docker"/"cri" modes must still fail loudly when the socket the
// operator named is absent — that is a misconfiguration, not a degraded host,
// and the cgroup fallback exists only for auto-detection.
func TestNewEnricher_ExplicitMode_MissingSocketStillErrors(t *testing.T) {
	absent := filepath.Join(t.TempDir(), "absent-docker.sock")
	_, err := NewEnricher(EnricherConfig{Mode: "docker", SocketPath: absent}, newTestLogger())
	require.Error(t, err)
}
