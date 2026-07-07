package correlator

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyRuleChecksums_EmptyChecksumFile(t *testing.T) {
	dir := t.TempDir()
	checksumPath := filepath.Join(dir, "checksums.sha256")
	require.NoError(t, os.WriteFile(checksumPath, []byte("# just a comment\n\n"), 0o644))

	err := VerifyRuleChecksums(dir, checksumPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "is empty")
}

func TestComputeRuleFileChecksums_ReadDirError(t *testing.T) {
	_, err := ComputeRuleFileChecksums(filepath.Join(t.TempDir(), "does-not-exist"))
	require.Error(t, err)
}

func TestComputeRuleFileChecksums_SkipsSubdirsAndNonYAML(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "rule1.yaml"), []byte("rules: []\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "rule2.yml"), []byte("rules: []\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "README.md"), []byte("not a rule"), 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "subdir"), 0o755))

	sums, err := ComputeRuleFileChecksums(dir)
	require.NoError(t, err)
	assert.Len(t, sums, 2)
	assert.Contains(t, sums, "rule1.yaml")
	assert.Contains(t, sums, "rule2.yml")
}

func TestWriteChecksumFile_CreateError(t *testing.T) {
	// A path inside a nonexistent directory: os.Create must fail.
	badPath := filepath.Join(t.TempDir(), "no-such-dir", "checksums.sha256")
	err := WriteChecksumFile(badPath, map[string]string{"a.yaml": "deadbeef"})
	require.Error(t, err)
}

func TestSha256File_OpenError(t *testing.T) {
	_, err := sha256File(filepath.Join(t.TempDir(), "nope.yaml"))
	require.Error(t, err)
}

func TestReadChecksumFile_MalformedEntry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.sha256")
	require.NoError(t, os.WriteFile(path, []byte("onlyonefield\n"), 0o644))

	_, err := readChecksumFile(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "malformed entry")
}

func TestReadChecksumFile_InvalidDigestLength(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.sha256")
	require.NoError(t, os.WriteFile(path, []byte("deadbeef  rule.yaml\n"), 0o644))

	_, err := readChecksumFile(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid SHA-256 digest length")
}

func TestReadChecksumFile_BSDStyleEntry(t *testing.T) {
	dir := t.TempDir()
	digest := "0000000000000000000000000000000000000000000000000000000000000000"[:64]
	path := filepath.Join(dir, "bsd.sha256")
	// BSD sha256sum style: "<digest> *<filename>"
	require.NoError(t, os.WriteFile(path, []byte(digest+" *rule.yaml\n"), 0o644))

	result, err := readChecksumFile(path)
	require.NoError(t, err)
	assert.Equal(t, digest, result["rule.yaml"])
}

func TestReadChecksumFile_SkipsBlankLinesAndComments(t *testing.T) {
	dir := t.TempDir()
	digest := "1111111111111111111111111111111111111111111111111111111111111111"[:64]
	path := filepath.Join(dir, "commented.sha256")
	content := "# header comment\n\n" + digest + "  rule.yaml\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	result, err := readChecksumFile(path)
	require.NoError(t, err)
	assert.Equal(t, digest, result["rule.yaml"])
}
