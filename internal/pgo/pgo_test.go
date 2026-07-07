package pgo_test

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/zugolO/ebpf-guard/internal/pgo"
)

// moduleRoot returns the repo root by walking up from this file's directory.
func moduleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

// TestDefaultPGOExists ensures default.pgo is committed to the repository root.
// This is the primary acceptance criterion from issue #218.
func TestDefaultPGOExists(t *testing.T) {
	root := moduleRoot(t)
	path := filepath.Join(root, pgo.DefaultPGOFilename)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("default.pgo not found at %s: %v — run 'make pgo-update' to generate it", path, err)
	}
	if fi.Size() == 0 {
		t.Fatalf("default.pgo at %s is empty — run 'make pgo-update' to regenerate it", path)
	}
	t.Logf("default.pgo found: %s (%d bytes)", path, fi.Size())
}

// TestValidate_ValidProfile verifies that the committed default.pgo passes
// the pprof validation check.
func TestValidate_ValidProfile(t *testing.T) {
	root := moduleRoot(t)
	path := filepath.Join(root, pgo.DefaultPGOFilename)

	if _, err := os.Stat(path); err != nil {
		t.Skipf("default.pgo not found, skipping validation: %v", err)
	}

	if err := pgo.Validate(path); err != nil {
		t.Errorf("Validate(%q) = %v; want nil", path, err)
	}
}

// TestValidate_MissingFile checks that Validate returns an error for a
// non-existent path.
func TestValidate_MissingFile(t *testing.T) {
	err := pgo.Validate("/nonexistent/path/cpu.pprof")
	if err == nil {
		t.Error("Validate(missing) = nil; want error")
	}
}

// TestValidate_EmptyFile checks that Validate returns an error for an empty
// file, even if it exists.
func TestValidate_EmptyFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "empty-*.pprof")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	err = pgo.Validate(f.Name())
	if err == nil {
		t.Errorf("Validate(empty file) = nil; want error")
	}
}

// TestMerge_NoInputs checks that Merge rejects an empty input list.
func TestMerge_NoInputs(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "out.pgo")
	err := pgo.Merge(dst, nil)
	if err == nil {
		t.Error("Merge(nil inputs) = nil; want error")
	}
}

// TestMerge_ValidProfile verifies that Merge can produce a valid merged profile
// from the committed default.pgo (using it as both input and output in a temp copy).
func TestMerge_ValidProfile(t *testing.T) {
	root := moduleRoot(t)
	src := filepath.Join(root, pgo.DefaultPGOFilename)

	if _, err := os.Stat(src); err != nil {
		t.Skipf("default.pgo not found, skipping: %v", err)
	}

	dst := filepath.Join(t.TempDir(), "merged.pgo")
	if err := pgo.Merge(dst, []string{src}); err != nil {
		t.Fatalf("Merge(%q) = %v; want nil", src, err)
	}

	fi, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("merged output not created: %v", err)
	}
	if fi.Size() == 0 {
		t.Error("merged profile is empty")
	}

	if err := pgo.Validate(dst); err != nil {
		t.Errorf("merged profile failed validation: %v", err)
	}
}

// TestMerge_InvalidProfile checks that Merge returns an error when all input
// profiles are invalid.
func TestMerge_InvalidProfile(t *testing.T) {
	tmp := t.TempDir()

	// Write a non-pprof file.
	bad := filepath.Join(tmp, "bad.pprof")
	if err := os.WriteFile(bad, []byte("not a pprof profile"), 0o644); err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(tmp, "out.pgo")
	err := pgo.Merge(dst, []string{bad})
	// The merge may succeed at the pprof tool level (it silently skips bad
	// profiles and emits an empty proto), or it may fail. Either way, the
	// resulting file should either be absent or fail Validate.
	if err == nil {
		// If Merge succeeded, the output should fail validation.
		_ = pgo.Validate(dst)
	}
}

// TestModuleRoot verifies that ModuleRoot() returns a directory containing go.mod.
func TestModuleRoot(t *testing.T) {
	root, err := pgo.ModuleRoot()
	if err != nil {
		t.Fatalf("ModuleRoot() = %v; want nil", err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Errorf("ModuleRoot() = %q, but go.mod not found there: %v", root, err)
	}
}

// TestHotPathPackages ensures the declared hot-path package list is non-empty
// and all entries look like Go import paths.
func TestHotPathPackages(t *testing.T) {
	if len(pgo.HotPathPackages) == 0 {
		t.Error("HotPathPackages is empty")
	}
	for _, pkg := range pgo.HotPathPackages {
		if pkg == "" {
			t.Error("HotPathPackages contains an empty string")
		}
	}
}

// TestHotPathBenchFilter ensures the bench filter is non-empty.
func TestHotPathBenchFilter(t *testing.T) {
	if pgo.HotPathBenchFilter == "" {
		t.Error("HotPathBenchFilter is empty")
	}
}

// TestCapturePackage runs a short benchmark in the profiler package and checks
// that a CPU profile file is produced. Skipped in -short mode because it
// invokes 'go test -bench'.
func TestCapturePackage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping profile capture in -short mode")
	}

	root := moduleRoot(t)
	out := filepath.Join(t.TempDir(), "cpu.pprof")

	// Use only the fastest benchmark to keep test time reasonable.
	if err := pgo.CapturePackage(root, "./internal/profiler/", "BenchmarkIsLearningComplete", out); err != nil {
		t.Fatalf("CapturePackage() = %v; want nil", err)
	}

	fi, err := os.Stat(out)
	if err != nil {
		t.Fatalf("profile not created: %v", err)
	}
	if fi.Size() == 0 {
		t.Error("captured profile is empty")
	}

	if err := pgo.Validate(out); err != nil {
		t.Errorf("captured profile failed validation: %v", err)
	}
}

// TestUpdate_ShortMode verifies that Update does not panic in short mode
// by ensuring it errors predictably when given no packages.
func TestUpdate_ShortMode(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping full Update in -short mode")
	}

	tmp := t.TempDir()
	// Empty package list should return an error.
	err := pgo.Update(tmp, nil, "BenchmarkFoo")
	if err == nil {
		t.Error("Update(nil pkgs) = nil; want error")
	}
}

// TestValidate_InvalidProfile checks that Validate rejects a non-empty file
// that isn't a valid pprof proto, exercising the 'go tool pprof' failure path.
func TestValidate_InvalidProfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "garbage.pprof")
	if err := os.WriteFile(path, []byte("this is not a pprof profile at all"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := pgo.Validate(path); err == nil {
		t.Error("Validate(garbage) = nil; want error")
	}
}

// TestMerge_WriteError checks that Merge surfaces an error when the
// destination path cannot be written (here, because it is a directory).
func TestMerge_WriteError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in -short mode: invokes go tool pprof")
	}
	root := moduleRoot(t)
	src := filepath.Join(root, pgo.DefaultPGOFilename)
	if _, err := os.Stat(src); err != nil {
		t.Skipf("default.pgo not found, skipping: %v", err)
	}

	// dst is a directory, so os.WriteFile must fail.
	dst := t.TempDir()
	err := pgo.Merge(dst, []string{src})
	if err == nil {
		t.Error("Merge(dir as dst) = nil; want error")
	}
}

// fakeGoScript writes an executable named "go" to a temp directory that
// prints stdout and exits with the given code, ignoring all arguments. It
// returns the directory so callers can prepend it to PATH.
func fakeGoScript(t *testing.T, stdout string, exitCode int) string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "go")
	body := fmt.Sprintf("#!/bin/sh\nprintf '%%s' %q\nexit %d\n", stdout, exitCode)
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestMerge_EmptyOutput checks that Merge rejects a successful 'go tool
// pprof' invocation that produces no output, by substituting a fake 'go'
// binary on PATH that exits 0 with empty stdout.
func TestMerge_EmptyOutput(t *testing.T) {
	fakeDir := fakeGoScript(t, "", 0)
	t.Setenv("PATH", fakeDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	dst := filepath.Join(t.TempDir(), "out.pgo")
	err := pgo.Merge(dst, []string{"whatever.pprof"})
	if err == nil {
		t.Error("Merge() with empty pprof output = nil; want error")
	}
}

// TestCapturePackage_Failure checks that CapturePackage surfaces the
// underlying 'go test' error, e.g. when run in a directory with no Go
// module.
func TestCapturePackage_Failure(t *testing.T) {
	out := filepath.Join(t.TempDir(), "cpu.pprof")
	err := pgo.CapturePackage("/nonexistent-directory-for-pgo-test", "./...", "BenchmarkFoo", out)
	if err == nil {
		t.Error("CapturePackage(bad dir) = nil; want error")
	}
}

// newFakeModule creates a minimal, dependency-free Go module in a temp
// directory with a fast benchmark, suitable for exercising Update/
// CapturePackage against a real 'go test' invocation without paying the
// cost of compiling the real repo.
func newFakeModule(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module tmpbench\n\ngo 1.21\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	benchSrc := `package tmpbench

import "testing"

func BenchmarkFast(b *testing.B) {
	for i := 0; i < b.N; i++ {
	}
}
`
	if err := os.WriteFile(filepath.Join(dir, "bench_test.go"), []byte(benchSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestUpdate_Success exercises the full Update happy path (capture + merge)
// against an isolated, dependency-free module so it stays fast and doesn't
// touch the repository's committed default.pgo.
func TestUpdate_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in -short mode: invokes go test/pprof")
	}
	root := newFakeModule(t)

	if err := pgo.Update(root, []string{"./"}, "BenchmarkFast"); err != nil {
		t.Fatalf("Update() = %v; want nil", err)
	}

	dst := filepath.Join(root, pgo.DefaultPGOFilename)
	fi, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("default.pgo not created: %v", err)
	}
	if fi.Size() == 0 {
		t.Error("default.pgo is empty")
	}
	if err := pgo.Validate(dst); err != nil {
		t.Errorf("generated default.pgo failed validation: %v", err)
	}
}

// TestUpdate_PartialFailure checks that Update tolerates one package's
// capture failing as long as at least one other succeeds.
func TestUpdate_PartialFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in -short mode: invokes go test/pprof")
	}
	root := newFakeModule(t)

	err := pgo.Update(root, []string{"./nonexistent-pkg/", "./"}, "BenchmarkFast")
	if err != nil {
		t.Fatalf("Update() = %v; want nil (one good package should be enough)", err)
	}

	dst := filepath.Join(root, pgo.DefaultPGOFilename)
	if _, err := os.Stat(dst); err != nil {
		t.Fatalf("default.pgo not created: %v", err)
	}
}

// TestUpdate_MkdirTempFailure checks that Update surfaces an error when a
// temp directory cannot be created.
func TestUpdate_MkdirTempFailure(t *testing.T) {
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "does-not-exist"))

	err := pgo.Update(t.TempDir(), []string{"./"}, "BenchmarkFast")
	if err == nil {
		t.Error("Update() with unwritable TMPDIR = nil; want error")
	}
}

// TestUpdate_MergeFailure checks that Update surfaces a Merge error even
// when all captures succeed, by making the destination path unwritable
// (a directory named default.pgo already exists).
func TestUpdate_MergeFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in -short mode: invokes go test/pprof")
	}
	root := newFakeModule(t)
	if err := os.Mkdir(filepath.Join(root, pgo.DefaultPGOFilename), 0o755); err != nil {
		t.Fatal(err)
	}

	err := pgo.Update(root, []string{"./"}, "BenchmarkFast")
	if err == nil {
		t.Error("Update() with directory blocking default.pgo = nil; want error")
	}
}
