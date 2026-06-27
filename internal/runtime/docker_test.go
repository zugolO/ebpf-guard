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
func TestNewEnricher_AutoMode_NoRuntime(t *testing.T) {
	// Override CRI socket probe paths to ensure auto-detection finds nothing.
	orig := criSocketPaths
	criSocketPaths = []string{
		filepath.Join(t.TempDir(), "absent-containerd.sock"),
		filepath.Join(t.TempDir(), "absent-crio.sock"),
	}
	t.Cleanup(func() { criSocketPaths = orig })

	_, err := NewEnricher(EnricherConfig{Mode: "auto"}, newTestLogger())
	require.Error(t, err)
}
