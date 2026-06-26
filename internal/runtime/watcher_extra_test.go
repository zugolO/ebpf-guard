package runtime

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCoalesce(t *testing.T) {
	m := map[string]string{"b": "two", "c": "three"}
	assert.Equal(t, "two", coalesce(m, "a", "b", "c"))
	assert.Equal(t, "three", coalesce(m, "x", "c"))
	assert.Equal(t, "", coalesce(m, "x", "y"))
}

func writeSpec(t *testing.T, path string, body string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(body), 0o644))
}

const ociSpecJSON = `{
  "annotations": {
    "io.kubernetes.container.name": "web",
    "io.kubernetes.container.image": "nginx:1.25"
  }
}`

func TestParseOCISpec(t *testing.T) {
	dir := t.TempDir()
	specPath := filepath.Join(dir, "config.json")
	writeSpec(t, specPath, ociSpecJSON)

	info, err := parseOCISpec(specPath, "abc123")
	require.NoError(t, err)
	assert.Equal(t, "abc123", info.ContainerID)
	assert.Equal(t, "web", info.ContainerName)
	assert.Equal(t, "nginx:1.25", info.Image)

	// Missing file → error.
	_, err = parseOCISpec(filepath.Join(dir, "missing.json"), "x")
	require.Error(t, err)

	// Malformed JSON → error.
	bad := filepath.Join(dir, "bad.json")
	writeSpec(t, bad, "{not json")
	_, err = parseOCISpec(bad, "x")
	require.Error(t, err)
}

func TestCRIClient_GetFromDirs(t *testing.T) {
	// crio layout: <stateDir>/<id>/config.json
	crioState := t.TempDir()
	writeSpec(t, filepath.Join(crioState, "cid", "config.json"), ociSpecJSON)
	crio := &criClient{runtimeType: "crio", stateDir: crioState}
	info, err := crio.GetContainerInfo(context.Background(), "cid")
	require.NoError(t, err)
	assert.Equal(t, "web", info.ContainerName)

	_, err = crio.GetContainerInfo(context.Background(), "missing")
	require.Error(t, err)

	// containerd layout: <stateDir>/<namespace>/<id>/config.json
	cdState := t.TempDir()
	writeSpec(t, filepath.Join(cdState, "k8s.io", "cid", "config.json"), ociSpecJSON)
	cd := &criClient{runtimeType: "containerd", stateDir: cdState}
	info, err = cd.GetContainerInfo(context.Background(), "cid")
	require.NoError(t, err)
	assert.Equal(t, "nginx:1.25", info.Image)

	_, err = cd.GetContainerInfo(context.Background(), "nope")
	require.Error(t, err)

	assert.NoError(t, cd.Close())
}

func TestNewCRIClient(t *testing.T) {
	c, err := newCRIClient("/run/crio/crio.sock")
	require.NoError(t, err)
	assert.Equal(t, "crio", c.runtimeType)

	c, err = newCRIClient("/run/containerd/containerd.sock")
	require.NoError(t, err)
	assert.Equal(t, "containerd", c.runtimeType)

	// Empty path with no sockets present in this environment → error.
	_, err = newCRIClient("")
	require.Error(t, err)
}

func TestAutoDetect_SocketOverride(t *testing.T) {
	// A crio socket override yields a CRI client of the crio type.
	c, name, err := autoDetect("/run/crio/crio.sock")
	require.NoError(t, err)
	assert.Equal(t, "crio", name)
	require.NotNil(t, c)
}
