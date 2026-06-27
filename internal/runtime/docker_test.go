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
