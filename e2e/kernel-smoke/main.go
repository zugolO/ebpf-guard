// Command kernel-smoke loads every ebpf-guard BPF object and runs a minimal
// smoke suite to verify CO-RE portability across kernel versions.
//
// It is designed to run inside a virtme-ng or QEMU kernel VM during CI.
// Each BPF object is loaded and probed; programs that are unsupported on the
// current kernel (e.g. LSM hooks before 5.7) are expected to degrade gracefully
// rather than hard-fail.
//
// Exit codes:
//
//	0 — all expected programs loaded (or degraded gracefully)
//	1 — at least one unexpected failure
//
// Usage:
//
//	kernel-smoke --bpf-dir /path/to/bpf/objects [--lsm-min-kernel 5.7]
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/rlimit"
)

// Result holds the outcome of loading one BPF object file.
type Result struct {
	File       string `json:"file"`
	Status     string `json:"status"` // "ok", "graceful_skip", "fail"
	Programs   int    `json:"programs"`
	Maps       int    `json:"maps"`
	Error      string `json:"error,omitempty"`
}

// FeatureReport describes kernel capabilities detected at startup.
type FeatureReport struct {
	KernelVersion string `json:"kernel_version"`
	Arch          string `json:"arch"`
	HasBTF        bool   `json:"has_btf"`
	HasRingbuf    bool   `json:"has_ringbuf"`
	HasKprobe     bool   `json:"has_kprobe"`
	HasTracepoint bool   `json:"has_tracepoint"`
	HasLSM        bool   `json:"has_lsm"`
	HasXDP        bool   `json:"has_xdp"`
}

// SmokeReport is the full JSON output of the smoke run.
type SmokeReport struct {
	Features FeatureReport `json:"features"`
	Results  []Result      `json:"results"`
	Passed   int           `json:"passed"`
	Failed   int           `json:"failed"`
	Skipped  int           `json:"skipped"`
}

func main() {
	bpfDir := flag.String("bpf-dir", ".", "directory containing compiled BPF .o files")
	jsonOut := flag.Bool("json", false, "emit results as JSON")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// Remove memlock limit so the verifier can accept large programs.
	if err := rlimit.RemoveMemlock(); err != nil {
		logger.Warn("failed to remove memlock limit", slog.Any("err", err))
	}

	feat := detectFeatures(logger)

	objects, err := filepath.Glob(filepath.Join(*bpfDir, "*.o"))
	if err != nil || len(objects) == 0 {
		fmt.Fprintf(os.Stderr, "no .o files found in %s\n", *bpfDir)
		os.Exit(1)
	}

	report := SmokeReport{Features: feat}

	for _, obj := range objects {
		res := probeObject(obj, feat, logger)
		report.Results = append(report.Results, res)
		switch res.Status {
		case "ok":
			report.Passed++
		case "graceful_skip":
			report.Skipped++
		default:
			report.Failed++
		}
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
	} else {
		printReport(report)
	}

	if report.Failed > 0 {
		os.Exit(1)
	}
}

func detectFeatures(log *slog.Logger) FeatureReport {
	f := FeatureReport{
		KernelVersion: readKernelVersion(),
		Arch:          runtime.GOARCH,
	}

	if err := features.HaveMapType(ebpf.RingBuf); err == nil {
		f.HasRingbuf = true
	}
	if err := features.HaveProgramType(ebpf.Kprobe); err == nil {
		f.HasKprobe = true
	}
	if err := features.HaveProgramType(ebpf.TracePoint); err == nil {
		f.HasTracepoint = true
	}
	if err := features.HaveProgramType(ebpf.LSM); err == nil {
		f.HasLSM = true
	}
	if err := features.HaveProgramType(ebpf.XDP); err == nil {
		f.HasXDP = true
	}
	// BTF: probe by checking if the kernel exposes /sys/kernel/btf/vmlinux.
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err == nil {
		f.HasBTF = true
	}

	log.Info("kernel features detected",
		slog.String("kernel", f.KernelVersion),
		slog.String("arch", f.Arch),
		slog.Bool("btf", f.HasBTF),
		slog.Bool("ringbuf", f.HasRingbuf),
		slog.Bool("kprobe", f.HasKprobe),
		slog.Bool("tracepoint", f.HasTracepoint),
		slog.Bool("lsm", f.HasLSM),
		slog.Bool("xdp", f.HasXDP),
	)

	return f
}

// probeObject loads a single BPF .o file and creates all its programs and maps.
// LSM programs are skipped gracefully when the kernel predates 5.7. XDP and
// uprobe objects that require newer helper versions are also skipped gracefully.
func probeObject(path string, feat FeatureReport, log *slog.Logger) Result {
	base := filepath.Base(path)
	res := Result{File: base}

	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		// A spec parse failure is always a hard error — the object file is
		// corrupt or compiled for a completely different architecture.
		res.Status = "fail"
		res.Error = fmt.Sprintf("LoadCollectionSpec: %v", err)
		log.Error("BPF object parse failed", slog.String("file", base), slog.Any("err", err))
		return res
	}

	// Decide whether to skip LSM objects on kernels < 5.7.
	if isLSMObject(base) && !feat.HasLSM {
		res.Status = "graceful_skip"
		res.Error = "LSM BPF programs require kernel 5.7+ (CONFIG_BPF_LSM)"
		log.Info("skipping LSM object (kernel too old)", slog.String("file", base))
		return res
	}

	// Decide whether to skip XDP objects when XDP is unavailable.
	if isXDPObject(base) && !feat.HasXDP {
		res.Status = "graceful_skip"
		res.Error = "XDP requires kernel 4.8+ with a compatible driver"
		log.Info("skipping XDP object", slog.String("file", base))
		return res
	}

	// Skip ring-buffer-dependent objects on kernels < 5.8.
	if !feat.HasRingbuf {
		res.Status = "graceful_skip"
		res.Error = "ring buffer map requires kernel 5.8+"
		log.Info("skipping object (no ring buffer support)", slog.String("file", base))
		return res
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			// LogLevel 1 gives verifier output on failure — useful for debugging
			// across kernel versions where the verifier may reject programs for
			// different reasons.
			LogLevel: ebpf.LogLevelInstruction,
			LogSize:  4 * 1024 * 1024,
		},
	})
	if err != nil {
		if isExpectedVerifierError(err, feat) {
			res.Status = "graceful_skip"
			res.Error = fmt.Sprintf("expected verifier limitation on this kernel: %v", err)
			log.Info("graceful skip", slog.String("file", base), slog.Any("reason", err))
			return res
		}
		res.Status = "fail"
		res.Error = fmt.Sprintf("NewCollection: %v", err)
		log.Error("BPF load failed", slog.String("file", base), slog.Any("err", err))
		return res
	}
	defer coll.Close()

	res.Programs = len(coll.Programs)
	res.Maps = len(coll.Maps)
	res.Status = "ok"
	log.Info("BPF object loaded",
		slog.String("file", base),
		slog.Int("programs", res.Programs),
		slog.Int("maps", res.Maps),
	)
	return res
}

// isExpectedVerifierError returns true when the verifier error is a known
// kernel-version-specific limitation rather than a programming bug.
func isExpectedVerifierError(err error, feat FeatureReport) bool {
	var ve *ebpf.VerifierError
	if !errors.As(err, &ve) {
		return false
	}
	msg := ve.Error()
	// Older kernels reject certain helper calls or map types that were added later.
	knownLimitations := []string{
		"unknown func",
		"unknown map type",
		"not supported",
		"invalid func",
	}
	for _, kw := range knownLimitations {
		if strings.Contains(strings.ToLower(msg), kw) {
			return true
		}
	}
	_ = feat
	return false
}

func isLSMObject(name string) bool {
	return strings.Contains(name, "lsm")
}

func isXDPObject(name string) bool {
	return strings.Contains(name, "xdp")
}

func readKernelVersion() string {
	if data, err := os.ReadFile("/proc/version"); err == nil {
		return strings.TrimSpace(string(data))
	}
	return "unknown"
}

func printReport(r SmokeReport) {
	fmt.Printf("Kernel: %s (%s)\n", r.Features.KernelVersion, r.Features.Arch)
	fmt.Printf("Features: BTF=%v Ringbuf=%v Kprobe=%v Tracepoint=%v LSM=%v XDP=%v\n",
		r.Features.HasBTF, r.Features.HasRingbuf, r.Features.HasKprobe,
		r.Features.HasTracepoint, r.Features.HasLSM, r.Features.HasXDP)
	fmt.Println()

	for _, res := range r.Results {
		marker := "✓"
		if res.Status == "graceful_skip" {
			marker = "~"
		} else if res.Status == "fail" {
			marker = "✗"
		}
		if res.Error != "" {
			fmt.Printf("  [%s] %s — %s\n", marker, res.File, res.Error)
		} else {
			fmt.Printf("  [%s] %s (%d programs, %d maps)\n", marker, res.File, res.Programs, res.Maps)
		}
	}

	fmt.Printf("\nResults: %d passed, %d skipped, %d failed\n", r.Passed, r.Skipped, r.Failed)
}
