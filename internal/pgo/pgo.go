// Package pgo provides utilities for managing Profile-Guided Optimization
// profiles used to guide the Go compiler's inlining and register allocation
// decisions on the hot paths (event parsing → correlation).
//
// Go 1.21+ picks up a file named "default.pgo" in the module root
// automatically when building with -pgo=auto (the default). No extra flags
// are required — just keep default.pgo up to date and rebuild.
//
// # Profile update process
//
//  1. Run 'make pgo-profile' (or scripts/pgo-update.sh) to capture a fresh
//     CPU profile from the correlator + profiler benchmarks.
//  2. Review the generated default.pgo with 'go tool pprof default.pgo'.
//  3. Commit and push; the CI bench.yml pgo-refresh job handles nightly
//     updates automatically and opens a PR when the profile drifts.
//
// # Risks
//
// An unrepresentative profile can hurt performance by inlining the wrong
// functions. The profile must reflect real traffic patterns. Re-run after
// significant changes to the hot path (RuleEngine.EvaluateInto, EWMA scoring).
package pgo

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// DefaultPGOFilename is the file name Go looks for in the module root.
const DefaultPGOFilename = "default.pgo"

// HotPathPackages lists the packages whose benchmark profiles are merged into
// default.pgo. These cover the full event-parsing → correlation hot path.
var HotPathPackages = []string{
	"./internal/correlator/",
	"./internal/profiler/",
}

// HotPathBenchFilter is the -bench regexp used when capturing profiles.
// It selects only benchmarks that exercise the real hot path, avoiding
// setup-heavy or one-shot benchmarks that skew the profile.
const HotPathBenchFilter = "BenchmarkRuleEval|BenchmarkProcessEvent|BenchmarkIsLearningComplete"

// Validate checks that path is a readable pprof profile. It returns an error
// if the file is missing, empty, or cannot be parsed by 'go tool pprof'.
func Validate(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("profile not found: %w", err)
	}
	if fi.Size() == 0 {
		return errors.New("profile is empty")
	}

	// Ask 'go tool pprof -top' to parse the file; exit 0 means valid.
	cmd := exec.Command("go", "tool", "pprof", "-top", path)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("invalid pprof profile: %w", err)
	}
	return nil
}

// Merge merges one or more pprof profiles into dst using 'go tool pprof -proto'.
// dst is created (or overwritten). Returns an error if no valid input profiles
// are provided or the merge command fails.
func Merge(dst string, inputs []string) error {
	if len(inputs) == 0 {
		return errors.New("no input profiles provided")
	}

	args := append([]string{"tool", "pprof", "-proto"}, inputs...)
	cmd := exec.Command("go", args...)

	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("pprof merge failed: %w", err)
	}
	if len(out) == 0 {
		return errors.New("pprof merge produced empty output")
	}

	if err := os.WriteFile(dst, out, 0o644); err != nil {
		return fmt.Errorf("writing merged profile: %w", err)
	}
	return nil
}

// CapturePackage runs 'go test -bench=benchFilter -cpuprofile=out pkg' in dir
// and returns the path of the generated CPU profile. The caller is responsible
// for removing the file when done.
func CapturePackage(dir, pkg, benchFilter, out string) error {
	args := []string{
		"test",
		"-bench=" + benchFilter,
		"-benchtime=2s",
		"-run=^$",
		"-count=1",
		"-cpuprofile=" + out,
		pkg,
	}
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	var stderr strings.Builder
	cmd.Stdout = io.Discard
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("go test -cpuprofile failed for %s: %w\n%s", pkg, err, stderr.String())
	}
	return nil
}

// Update generates a fresh default.pgo in moduleRoot by:
//  1. Capturing CPU profiles from each package in pkgs using benchFilter.
//  2. Merging all profiles into moduleRoot/default.pgo.
//
// Partial failures (one package fails) are logged but do not abort; at least
// one valid profile is required for the merge to succeed.
func Update(moduleRoot string, pkgs []string, benchFilter string) error {
	var (
		profiles []string
		errs     []string
	)

	tmpDir, err := os.MkdirTemp("", "ebpf-guard-pgo-*")
	if err != nil {
		return fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	for i, pkg := range pkgs {
		safe := strings.NewReplacer("/", "_", ".", "_").Replace(pkg)
		out := filepath.Join(tmpDir, fmt.Sprintf("cpu-%d-%s.pprof", i, safe))

		if err := CapturePackage(moduleRoot, pkg, benchFilter, out); err != nil {
			errs = append(errs, err.Error())
			continue
		}
		profiles = append(profiles, out)
	}

	if len(profiles) == 0 {
		return fmt.Errorf("all profile captures failed:\n%s", strings.Join(errs, "\n"))
	}

	dst := filepath.Join(moduleRoot, DefaultPGOFilename)
	if err := Merge(dst, profiles); err != nil {
		return fmt.Errorf("merging profiles: %w", err)
	}
	return nil
}

// ModuleRoot returns the absolute path to the module root (the directory
// containing go.mod). It walks up from the directory of the calling file.
func ModuleRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", errors.New("runtime.Caller failed")
	}
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", errors.New("go.mod not found in any parent directory")
}
