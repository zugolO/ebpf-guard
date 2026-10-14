package correlator

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyRuleChecksums_OK(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "test_001.yaml", minimalRuleYAML("test_001"))
	writeRule(t, dir, "test_002.yaml", minimalRuleYAML("test_002"))

	checksums, err := ComputeRuleFileChecksums(dir)
	require.NoError(t, err)
	require.Len(t, checksums, 2)

	checksumFile := filepath.Join(dir, "checksums.sha256")
	require.NoError(t, WriteChecksumFile(checksumFile, checksums))

	assert.NoError(t, VerifyRuleChecksums(dir, checksumFile))
}

func TestVerifyRuleChecksums_Tampered(t *testing.T) {
	dir := t.TempDir()
	ruleFile := filepath.Join(dir, "test_001.yaml")
	writeRule(t, dir, "test_001.yaml", minimalRuleYAML("test_001"))

	checksums, err := ComputeRuleFileChecksums(dir)
	require.NoError(t, err)

	checksumFile := filepath.Join(dir, "checksums.sha256")
	require.NoError(t, WriteChecksumFile(checksumFile, checksums))

	// Tamper with rule file after generating checksums
	require.NoError(t, os.WriteFile(ruleFile, []byte(minimalRuleYAML("test_001_tampered")), 0o644))

	err = VerifyRuleChecksums(dir, checksumFile)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "checksum mismatch")
}

func TestVerifyRuleChecksums_MissingFile(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "test_001.yaml", minimalRuleYAML("test_001"))

	checksums, err := ComputeRuleFileChecksums(dir)
	require.NoError(t, err)

	checksumFile := filepath.Join(dir, "checksums.sha256")
	require.NoError(t, WriteChecksumFile(checksumFile, checksums))

	// Remove the rule file
	require.NoError(t, os.Remove(filepath.Join(dir, "test_001.yaml")))

	err = VerifyRuleChecksums(dir, checksumFile)
	assert.Error(t, err)
}

func TestVerifyRuleChecksums_DefaultPath(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "test_001.yaml", minimalRuleYAML("test_001"))

	checksums, err := ComputeRuleFileChecksums(dir)
	require.NoError(t, err)
	require.NoError(t, WriteChecksumFile(filepath.Join(dir, "checksums.sha256"), checksums))

	// Pass empty checksumFile — should default to <dir>/checksums.sha256
	assert.NoError(t, VerifyRuleChecksums(dir, ""))
}

func TestLoadRulesFromDirWithChecksums_Valid(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "test_001.yaml", minimalRuleYAML("test_001"))

	checksums, err := ComputeRuleFileChecksums(dir)
	require.NoError(t, err)
	require.NoError(t, WriteChecksumFile(filepath.Join(dir, "checksums.sha256"), checksums))

	rules, err := LoadRulesFromDirWithChecksums(dir, true, "")
	require.NoError(t, err)
	assert.Len(t, rules, 1)
}

func TestLoadRulesFromDirWithChecksums_InvalidChecksum(t *testing.T) {
	dir := t.TempDir()
	ruleFile := filepath.Join(dir, "test_001.yaml")
	writeRule(t, dir, "test_001.yaml", minimalRuleYAML("test_001"))

	checksums, err := ComputeRuleFileChecksums(dir)
	require.NoError(t, err)
	require.NoError(t, WriteChecksumFile(filepath.Join(dir, "checksums.sha256"), checksums))

	require.NoError(t, os.WriteFile(ruleFile, []byte(minimalRuleYAML("test_001_tampered")), 0o644))

	_, err = LoadRulesFromDirWithChecksums(dir, true, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "rule integrity check failed")
}

// helpers

func writeRule(t *testing.T, dir, name, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644))
}

func minimalRuleYAML(id string) string {
	return `rules:
  - id: ` + id + `
    name: ` + id + ` test rule
    event_type: syscall
    severity: warning
    action: alert
    condition:
      field: nr
      op: in
      values: ["1"]
`
}

// Д5 (№561, остаток): .yaml, которого нет в списке сумм, при проверке — ошибка,
// а не молчаливая загрузка без проверки.
func TestVerifyRuleChecksums_UnlistedFileRejected(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "test_001.yaml", minimalRuleYAML("test_001"))
	checksums, err := ComputeRuleFileChecksums(dir)
	require.NoError(t, err)
	checksumFile := filepath.Join(dir, "checksums.sha256")
	require.NoError(t, WriteChecksumFile(checksumFile, checksums))
	require.NoError(t, VerifyRuleChecksums(dir, checksumFile))

	for _, name := range []string{"planted.yaml", "planted.YML"} {
		writeRule(t, dir, name, minimalRuleYAML("planted"))
		err = VerifyRuleChecksums(dir, checksumFile)
		require.Errorf(t, err, "%s: неперечисленный файл правил обязан отвергаться", name)
		assert.Contains(t, err.Error(), name+": not listed in checksum file")
		require.NoError(t, os.Remove(filepath.Join(dir, name)))
	}

	// Не-правила и подкаталоги проверку не ломают: загрузчик их не берёт.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "README.md"), []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "._test_001.yaml"), []byte("appledouble"), 0o644))
	require.NoError(t, os.Mkdir(filepath.Join(dir, "rego"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "rego", "extra.yaml"), []byte("x"), 0o644))
	assert.NoError(t, VerifyRuleChecksums(dir, checksumFile))
}

// Загрузка с verify_checksums=true отказывает на неперечисленном файле целиком.
func TestLoadRulesFromDirWithChecksums_UnlistedFileRejected(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "test_001.yaml", minimalRuleYAML("test_001"))
	checksums, err := ComputeRuleFileChecksums(dir)
	require.NoError(t, err)
	require.NoError(t, WriteChecksumFile(filepath.Join(dir, "checksums.sha256"), checksums))
	writeRule(t, dir, "planted.yaml", minimalRuleYAML("planted"))

	_, err = LoadRulesFromDirWithChecksums(dir, true, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not listed in checksum file")
	rules, err := LoadRulesFromDirWithChecksums(dir, false, "")
	require.NoError(t, err, "без verify_checksums поведение прежнее")
	assert.Len(t, rules, 2)
}
